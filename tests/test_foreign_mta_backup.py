"""Exim/Sendmail root-only configuration backup is verifiable and non-mutating."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "linux" / "foreign-mta-config-backup.py"
spec = importlib.util.spec_from_file_location("foreign_mta_backup", str(PATH))
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class ForeignMtaBackupTests(unittest.TestCase):
    def fixture(self, temporary, mta):
        root = Path(temporary)
        (root / "etc").mkdir()
        if mta == "sendmail":
            source = root / "etc" / "mail"
            source.mkdir()
            (source / "sendmail.cf").write_text(
                "O DaemonPortOptions=Port=smtp,Addr=127.0.0.1\nDSrelay.test\n")
            (source / "access").write_text("Connect:127.0.0.1 RELAY\n")
        else:
            source = root / "etc" / "exim4"
            source.mkdir()
            (source / "update-exim4.conf.conf").write_text(
                "dc_eximconfig_configtype='smarthost'\n")
            (source / "passwd.client").write_text("sample.invalid:user:never-output-this\n")
            os.chmod(str(source / "passwd.client"), 0o640)
        return root, root / "backups", source

    def test_roundtrip_and_no_primary_modification(self):
        for mta in ("exim", "sendmail"):
            with self.subTest(mta=mta), tempfile.TemporaryDirectory() as directory:
                root, backups, config = self.fixture(directory, mta)
                original = {p.name: p.read_bytes() for p in config.iterdir()}
                backup_id, info = snapshot.backup(
                    mta, root=root, base=backups, owner_uid=os.getuid())
                self.assertEqual(info["files"], len(original))
                self.assertEqual(snapshot.listed(
                    mta, base=backups, owner_uid=os.getuid()), [backup_id])
                accepted = snapshot.verify(backups / mta / backup_id, mta,
                                           owner_uid=os.getuid())
                self.assertEqual(accepted["sha256"], info["sha256"])
                self.assertEqual({p.name: p.read_bytes() for p in config.iterdir()},
                                 original)
                for f in (backups / mta / backup_id).iterdir():
                    self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)

    def test_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, backups, config = self.fixture(directory, "sendmail")
            link = config / "unsafe.cf"
            link.symlink_to(config / "sendmail.cf")
            with self.assertRaises(snapshot.Refused):
                snapshot.backup("sendmail", root=root, base=backups,
                                owner_uid=os.getuid())

    def test_manifest_and_archive_tampering_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, backups, config = self.fixture(directory, "exim")
            bid, _ = snapshot.backup("exim", root=root, base=backups,
                                     owner_uid=os.getuid())
            folder = backups / "exim" / bid
            archive = folder / "config.tar.gz"
            with archive.open("ab") as target:
                target.write(b"tampered")
            with self.assertRaises(snapshot.Refused):
                snapshot.verify(folder, "exim", owner_uid=os.getuid())
            self.assertEqual(snapshot.listed("exim", backups, os.getuid()), [])

    def test_missing_and_nonregular_config_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            with self.assertRaises(snapshot.Refused):
                snapshot.selected_files("sendmail", root=root, owner_uid=os.getuid())
            with self.assertRaises(snapshot.Refused):
                snapshot.selected_files("unknown", root=root, owner_uid=os.getuid())

    def test_listing_missing_dir_does_not_modify_filesystem(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            absent = root / "archive-root"
            self.assertEqual(snapshot.listed(
                "exim", base=absent, owner_uid=os.getuid()), [])
            self.assertFalse(absent.exists())

    def test_wizard_reports_v2_package_snapshot_and_requires_inert_export(self):
        source = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(
            encoding="utf-8")
        snapshot = (ROOT / "linux/foreign-mta-config-backup.py").read_text(
            encoding="utf-8")
        self.assertIn("private static string ParseForeignBackupFormat(", source)
        self.assertIn("FOREIGN_BACKUP_FORMAT=(v1_regular_files|v2_package_metadata)",
                      source)
        self.assertIn('format == "v2_package_metadata"', source)
        self.assertIn('bool packageV2 = format == "v2_package_metadata";', source)
        self.assertIn("EXPORT INERT SENDMAIL SNAPSHOT", source)
        self.assertIn("FOREIGN_BACKUP_OFFLINE_LINKS_MATERIALIZED=no", source)
        self.assertIn("Package links are JSON metadata ONLY", source)
        self.assertNotIn("Offline Export blocked: Sendmail package Snapshot v2", source)
        self.assertIn('BuildForeignMtaBackupBundle(mta, "verify", id)', source)
        self.assertIn('print("FOREIGN_BACKUP_FORMAT=" + result["format"])', snapshot)
        self.assertIn('"format": ("v2_package_metadata"', snapshot)
        self.assertNotIn("RestoreForeignMtaAsync(", source)

    def test_wizard_excludes_postfix_recovery_for_foreign_mta(self):
        source = (ROOT / "src" / "LinuxMailRelay365" / "MainForm.cs").read_text()
        resources = (ROOT / "src" / "LinuxMailRelay365" / "EmbeddedAssets.cs").read_text()
        project = (ROOT / "src" / "LinuxMailRelay365" /
                   "LinuxMailRelay365.csproj").read_text()
        for fragment in ("BackupForeignMtaAsync", "ListForeignMtaBackupsAsync",
                         "VerifyForeignMtaBackupAsync", "RequirePostfixBackup",
                         "PreviewForeignMtaRecoveryAsync", "ExportForeignMtaOfflineAsync",
                         'inspectedMail?.Mta == "postfix"',
                         "FOREIGN_BACKUP_RESTORE_ENABLED=no"):
            self.assertIn(fragment, source)
        self.assertIn("BuildForeignMtaBackupBundle", resources)
        self.assertIn("foreign-mta-config-backup.py", project)
        self.assertNotIn("RestoreForeignMtaAsync", source)

    def test_recovery_preview_compares_config_without_revealing_secret(self):
        for mta in ("exim", "sendmail"):
            with self.subTest(mta=mta), tempfile.TemporaryDirectory() as folder:
                root, base, source = self.fixture(folder, mta)
                backup_id, info = snapshot.backup(
                    mta, root=root, base=base, owner_uid=os.getuid())
                result = snapshot.recovery_preview(
                    mta, backup_id, root=root, base=base, owner_uid=os.getuid())
                self.assertEqual(result["current"], "identical")
                self.assertEqual(result["snapshot"]["sha256"], info["sha256"])
                self.assertNotIn("never-output-this", str(result))
                self.assertNotIn("passwd.client", str(result))
                target = next(iter(source.iterdir()))
                target.write_text("different config", encoding="utf-8")
                changed = snapshot.recovery_preview(
                    mta, backup_id, root=root, base=base, owner_uid=os.getuid())
                self.assertEqual(changed["current"], "different")
                target.unlink()
                unavailable = snapshot.recovery_preview(
                    mta, backup_id, root=root, base=base, owner_uid=os.getuid())
                self.assertEqual(unavailable["current"], "different")

    def test_offline_export_protects_sources_and_isolated_directory(self):
        for mta in ("exim", "sendmail"):
            with self.subTest(mta=mta), tempfile.TemporaryDirectory() as folder:
                root, base, source = self.fixture(folder, mta)
                baseline = {file.name: file.read_bytes() for file in source.iterdir()}
                bid, info = snapshot.backup(
                    mta, root=root, base=base, owner_uid=os.getuid())
                name, exported = snapshot.extract_offline(
                    mta, bid, base=base, owner_uid=os.getuid())
                stage = Path(name)
                self.assertEqual(stage.parent, base / mta)
                self.assertTrue(stage.name.startswith(".offline-recovery-"))
                self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
                self.assertEqual(exported["sha256"], info["sha256"])
                self.assertEqual(
                    {file.name: (stage / "etc" /
                        ("exim4" if mta == "exim" else "mail") /
                        file.name).read_bytes() for file in source.iterdir()},
                    baseline)
                for item in stage.rglob("*"):
                    self.assertFalse(item.is_symlink())
                    self.assertEqual(stat.S_IMODE(item.stat().st_mode),
                                     0o700 if item.is_dir() else 0o600)
                self.assertEqual({file.name: file.read_bytes()
                                  for file in source.iterdir()}, baseline)

    def test_invalid_snapshot_ids_and_archive_tampering_block_export(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, source = self.fixture(folder, "exim")
            bid, _ = snapshot.backup(
                "exim", root=root, base=base, owner_uid=os.getuid())
            for value in ("../../etc/passwd", "bad", bid + "/.."):
                with self.subTest(value=value), self.assertRaises(snapshot.Refused):
                    snapshot.recovery_preview(
                        "exim", value, root=root, base=base,
                        owner_uid=os.getuid())
                with self.assertRaises(snapshot.Refused):
                    snapshot.extract_offline(
                        "exim", value, base=base, owner_uid=os.getuid())
            with (base / "exim" / bid / "config.tar.gz").open("ab") as item:
                item.write(b"ALTERED")
            with self.assertRaises(snapshot.Refused):
                snapshot.extract_offline("exim", bid, base=base,
                                         owner_uid=os.getuid())
            self.assertFalse(any((base / "exim").glob(".offline-recovery-*")))

    def test_offline_export_requires_explicit_cli_confirmation(self):
        source = PATH.read_text()
        self.assertIn("EXTRACT_VERIFIED_FOREIGN_MTA_SNAPSHOT", source)
        result = subprocess.run(
            [sys.executable, str(PATH), "--mta", "exim",
             "--export-offline", "20261121T005501Z-abcdef012345"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("confirmation_required", result.stderr)
        self.assertNotIn("OFFLINE_DIRECTORY=", result.stdout)

    def test_offline_preflight_readonly_stop_process_listener_and_queue_evidence(self):
        for mta in ("exim", "sendmail"):
            with self.subTest(mta=mta), tempfile.TemporaryDirectory() as directory:
                root, base, config = self.fixture(directory, mta)
                archive_id, archive = snapshot.backup(
                    mta, root=root, base=base, owner_uid=os.getuid())
                before = {p.name: p.read_bytes() for p in config.iterdir()}
                requested = []
                def probe(args):
                    requested.append(tuple(args))
                    if args[:2] == ["systemctl", "show"]:
                        name = args[-1]
                        primary = name == ("exim.service" if mta == "exim"
                                           else "sendmail.service")
                        return (0, "LoadState={}\nActiveState=inactive\n".format(
                            "loaded" if primary else "not-found"))
                    if args[:2] == ["pgrep", "-x"]:
                        return (1, "")
                    if mta == "exim" and args == ["exim4", "-bpc"]:
                        return (0, "0\n")
                    if mta == "sendmail" and args in (
                            ["sendmail", "-bp"], ["sendmail", "-Ac", "-bp"]):
                        return (0, "Mail queue is empty\n")
                    if args == ["ss", "-ltnp"]:
                        return (0, "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n")
                    raise AssertionError("unsafe preflight query: " + str(args))
                status = snapshot.offline_recovery_preflight(
                    mta, archive_id, root=root, base=base,
                    owner_uid=os.getuid(), probe=probe)
                self.assertEqual(status["gate"], "offline_candidate_manual_recovery_only")
                self.assertEqual(status["queue"], "empty_reported")
                self.assertEqual(status["service"], "stopped_declared")
                self.assertEqual(status["processes"], "none_observed")
                self.assertEqual(status["listener"], "none_observed")
                self.assertEqual(status["current"], "identical")
                self.assertEqual(status["archive_sha256"], archive["sha256"])
                self.assertRegex(status["preflight_sha256"], r"^[a-f0-9]{64}$")
                self.assertNotIn("never-output-this", str(status))
                self.assertIn(("ss", "-ltnp"), requested)
                self.assertEqual({p.name: p.read_bytes() for p in config.iterdir()}, before)

    def test_offline_preflight_fails_closed_when_running_nonempty_or_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root, base, _ = self.fixture(directory, "exim")
            archive_id, _ = snapshot.backup("exim", root, base, os.getuid())
            def fake(service="inactive", process=None, queue="0", listen="none"):
                def probe(argv):
                    if argv[:2] == ["systemctl", "show"]:
                        return (0, "LoadState=loaded\nActiveState={}\n".format(service)
                                if argv[-1] == "exim.service" else
                                "LoadState=not-found\nActiveState=inactive\n")
                    if argv[:2] == ["pgrep", "-x"]:
                        return process if process is not None else (1, "")
                    if argv == ["exim4", "-bpc"]:
                        return (0, queue)
                    if argv == ["ss", "-ltnp"]:
                        if listen == "mta":
                            return (0, 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n' +
                                    'LISTEN 0 100 0.0.0.0:25 0.0.0.0:* users:(("exim4",pid=1,fd=1))\n')
                        if listen == "unverified":
                            return None
                        return (0, "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n")
                    raise AssertionError(str(argv))
                return probe
            scenarios = [
                ({"service": "active"}, "blocked_running"),
                ({"service": "inactive", "process": (0, "1234\n")}, "blocked_running"),
                ({"queue": "9\n"}, "blocked_nonempty_queue"),
                ({"queue": "oops"}, "blocked_unverified"),
                ({"listen": "mta"}, "blocked_running"),
                ({"listen": "unverified"}, "blocked_unverified"),
                ({"service": "failed"}, "blocked_unverified"),
            ]
            for choices, expect in scenarios:
                with self.subTest(choices=choices):
                    status = snapshot.offline_recovery_preflight(
                        "exim", archive_id, root, base, os.getuid(),
                        probe=fake(**choices))
                    self.assertEqual(status["gate"], expect)
                    self.assertEqual(status["snapshot_id"], archive_id)

    def test_non_mta_smtp_listener_blocks_offline_recovery(self):
        header = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        cases = (
            ("0.0.0.0:25", "unverified"),
            ("192.168.20.5:25", "unverified"),
            ("[::]:25", "unverified"),
            (":::587", "unverified"),
            ("127.0.0.1:465", "unverified"),
            ("*:2525", "unverified"),
            ("127.0.0.1:22", "none_observed"),
            ("127.0.0.1:2500", "none_observed"),
            ("0.0.0.0:65536", "unverified"),
            ("0.0.0.0:notaport", "unverified"),
        )
        for address, expected in cases:
            with self.subTest(address=address):
                rows = header + "LISTEN 0 100 " + address + (
                    ' 0.0.0.0:* users:(("other",pid=123,fd=4))\n')
                self.assertEqual(snapshot.offline_listener_state(
                    "exim", lambda args: (0, rows)), expected)

    def test_sendmail_client_queue_unknown_blocks_manual_restore_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            root, base, _ = self.fixture(directory, "sendmail")
            archive_id, _ = snapshot.backup("sendmail", root, base, os.getuid())
            def probe(args):
                if args[:2] == ["systemctl", "show"]:
                    return (0, "LoadState=loaded\nActiveState=inactive\n"
                            if args[-1] == "sendmail.service" else
                            "LoadState=not-found\nActiveState=inactive\n")
                if args[:2] == ["pgrep", "-x"]:
                    return (1, "")
                if args == ["ss", "-ltnp"]:
                    return (0, "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n")
                if args == ["sendmail", "-bp"]:
                    return (0, "Mail queue is empty\n")
                if args == ["sendmail", "-Ac", "-bp"]:
                    return None
                raise AssertionError(str(args))
            value = snapshot.offline_recovery_preflight(
                "sendmail", archive_id, root, base, os.getuid(), probe)
            self.assertEqual(value["queue"], "unverified")
            self.assertEqual(value["gate"], "blocked_unverified")

    def test_gui_exposes_nonmutating_readonly_foreign_preflight(self):
        form = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text()
        assets = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text()
        self.assertIn("PreflightForeignMtaRecoveryAsync", form)
        self.assertIn('"offline-preflight"', form)
        self.assertIn('"offline-preflight" => "--offline-preflight " + backupId', assets)
        for key in ("FOREIGN_PREFLIGHT_SERVICE", "FOREIGN_PREFLIGHT_PROCESSES",
                    "FOREIGN_PREFLIGHT_QUEUE", "FOREIGN_PREFLIGHT_LISTENER",
                    "FOREIGN_PREFLIGHT_PLAN_SHA256", "FOREIGN_PREFLIGHT_GATE"):
            self.assertIn(key, form)
        self.assertIn("Manual recovery only.", form)

    def test_gui_readonly_operations_allow_verified_inactive_mta(self):
        gui = (ROOT / 'src/LinuxMailRelay365/MainForm.cs').read_text()
        self.assertIn('private string ConfirmedForeignBackupMta(bool allowStopped = false)', gui)
        self.assertIn('inspectedHost.MtaState == "installed_inactive"', gui)
        for method in ('ListForeignMtaBackupsAsync',
                       'VerifyForeignMtaBackupAsync',
                       'PreviewForeignMtaRecoveryAsync',
                       'PreflightForeignMtaRecoveryAsync',
                       'ExportForeignMtaOfflineAsync'):
            section = gui.split('private async Task ' + method + '()', 1)[1]
            self.assertIn('ConfirmedForeignBackupMta(allowStopped: true);',
                          section[:260], method)
        active_backup = gui.split('private async Task BackupForeignMtaAsync()', 1)[1]
        self.assertIn('ConfirmedForeignBackupMta();', active_backup[:260])
    def test_preflight_never_runs_shell_or_untrusted_path(self):
        for value in (['bash', '-c', 'cat /etc/shadow'],
                      ['sh', '-c', 'systemctl status sendmail']):
            with self.assertRaises(snapshot.Refused):
                snapshot.read_only_probe(value)
        with patch.object(snapshot.shutil, 'which', return_value='/tmp/evil-systemctl'), \
             patch.object(snapshot.subprocess, 'run') as runner:
            self.assertIsNone(snapshot.read_only_probe(['systemctl', 'show']))
            runner.assert_not_called()
    def test_cli_restoration_and_nonroot_are_refused(self):
        source = PATH.read_text()
        self.assertNotIn("--restore", source)
        self.assertNotIn("systemctl restart ", source)
        self.assertNotIn("systemctl stop ", source)
        self.assertNotIn("postconf -e ", source)
        self.assertNotIn("mail from:", source.lower())
        self.assertIn("FOREIGN_BACKUP_RESTORE_ENABLED=no", source)
        proc = subprocess.run([sys.executable, str(PATH), "--mta", "exim",
                               "--self-test"], capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bad = subprocess.run([sys.executable, str(PATH), "--mta", "exim",
                              "--restore", "someid"], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
