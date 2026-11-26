"""Multi-mailbox offline Restore: verified archive, SHA approval, rollback.

Uses disposable file fixtures, no systemd, Postfix, Microsoft 365 or SMTP.
"""
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

LINUX = Path(__file__).resolve().parents[1] / "linux"
spec = importlib.util.spec_from_file_location(
    "test_multi_mail_restore", str(LINUX / "restore-multi-mailbox-postfix.py"))
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)
install = restore.install


def digest(data):
    return hashlib.sha256(data).hexdigest()


def put(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


class MultiMailboxRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.conf = self.root / "sidecar"
        self.primary = self.root / "primary"
        self.recovery = self.root / "recovery"
        self.target = self.root / "runtime-code"
        self.runtime = self.root / "runtime-map.tsv"
        self.proof = self.root / "ingress-proof.json"
        self.active = self.recovery / "active.json"
        self.lock = self.root / "sidecar-auth.lock"
        for item in (self.conf, self.primary, self.recovery, self.target):
            item.mkdir()
        self.recovery.chmod(0o700)
        self.backup_id = "pre-multi-A1b2C3d4"
        self.archive = self.recovery / self.backup_id
        self.archive.mkdir(mode=0o700)
        self.original = {
            "main.cf": b"default_transport = smtp:[mail.protection.outlook.com]:25\n",
            "master.cf": b"# original private SMTP listener\n",
        }
        self.installed = {
            "main.cf": b"default_transport = m365multi:\n",
            "master.cf": b"m365multi unix - n n - 2 pipe\n",
        }
        self.primary_bytes = {
            "main.cf": b"myhostname = mail.test.example\n",
            "master.cf": b"smtp inet n - n - - smtpd\n",
        }
        for name, data in self.original.items():
            put(self.archive / name, data, 0o600)
            put(self.conf / name, self.installed[name], 0o644)
            put(self.primary / name, self.primary_bytes[name], 0o644)
        self.map_bytes = b"smtp_login\tenvelope_from\tm365_mailbox\tidentity_config_path\n"
        put(self.runtime, self.map_bytes, 0o640)
        self.proof_bytes = b'{"version":1,"issued_at":100}\n'
        put(self.proof, self.proof_bytes, 0o640)
        self.source = {}
        for name in install.FILES:
            data = ("# simulated protected file: " + name + "\n").encode("ascii")
            self.source[name] = data
            put(self.target / name, data, 0o644)
        evidence = {
            "version": 1,
            "config": {name: digest(data) for name, data in self.original.items()},
            "source": {name: digest(data) for name, data in self.source.items()},
            "primary": [digest(self.primary_bytes[name])
                        for name in ("main.cf", "master.cf")],
            "identities": ["a" * 64],
            "map_sha256": digest(self.map_bytes), "mailboxes": 1,
        }
        put(self.archive / "manifest.json", json.dumps(evidence, sort_keys=True).encode(), 0o600)
        self.record = {
            "version": 1,
            "backup_id": self.backup_id,
            "plan_sha256": digest(json.dumps(
                evidence, sort_keys=True, separators=(",", ":")).encode("ascii")),
            "before": evidence["config"],
            "active": {name: digest(data) for name, data in self.installed.items()},
            "source": evidence["source"],
            "primary": evidence["primary"],
            "runtime_map_sha256": evidence["map_sha256"],
        }
        put(self.active, json.dumps(self.record, sort_keys=True).encode("ascii"), 0o600)

        def permissive_fixture_reader(path, limit, modes=(0o600, 0o640, 0o644, 0o755)):
            path = Path(path)
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) not in modes or info.st_size > limit):
                raise restore.Refused("untrusted_test_fixture")
            return info, path.read_bytes()

        # Production root ownership checks are exercised in dedicated
        # installer/backup tests; this fixture mocks only root and systemd.
        self.inject(install, "CONF", self.conf)
        self.inject(install, "PRIMARY", self.primary)
        self.inject(install, "RECOVERY", self.recovery)
        self.inject(install, "ACTIVE", self.active)
        self.inject(install, "TARGET", self.target)
        self.inject(install, "RUNTIME", self.runtime)
        self.inject(install, "LOCK", self.lock)
        self.inject(restore, "PROOF", self.proof)
        self.inject(restore, "TIMER_ARTIFACTS", (
            self.root / "timer.service", self.root / "timer.timer",
            self.root / "timer-state"))
        self.inject(install, "secure_dir", lambda path: None)
        self.inject(install, "read", permissive_fixture_reader)
        self.inject(restore.os, "geteuid", lambda: 0)
        self.inject(restore.grp, "getgrnam",
                    lambda name: SimpleNamespace(gr_gid=os.getgid()))
        # The CI runner is unprivileged. Mock only the root-owned lock
        # metadata gate; exercise the actual exclusive kernel flock.
        def fixture_lock():
            fd = os.open(str(self.lock), os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        self.inject(restore, "locked", fixture_lock)
        self.offline = mock.Mock(return_value=True)
        self.run = mock.Mock(return_value="")
        self.inject(install, "offline", self.offline)
        self.inject(install, "run", self.run)

        def atomic_write(path, raw, metadata):
            path = Path(path)
            path.write_bytes(raw)
            path.chmod(stat.S_IMODE(metadata[0].st_mode))
        self.writer = atomic_write
        self.inject(install, "replace_file", atomic_write)

    def inject(self, obj, key, value):
        p = mock.patch.object(obj, key, value)
        p.start()
        self.addCleanup(p.stop)

    def test_restore_plan_binds_selinux_mode_and_refuses_drift(self):
        # Existing fixture is unprivileged: use a synthetic policy sampler.
        sample={"mode":"enforcing","labels":{}}
        with mock.patch.object(install,"policy_snapshot",side_effect=lambda paths:dict(sample)), \
             mock.patch.object(install,"require_policy"):
            first=restore.preview()
            self.assertEqual(first["review"]["selinux_mode"],"enforcing")
            sample["mode"]="permissive"
            second=restore.preview()
            self.assertNotEqual(first["sha"],second["sha"])
            with self.assertRaisesRegex(restore.Refused,"review_has_changed"):
                restore.apply_offline(first["sha"],self.backup_id,restore.CONFIRM)
            self.assertEqual((self.conf/"main.cf").read_bytes(),self.installed["main.cf"])
            self.assertFalse(list(self.recovery.glob("pre-restore-*")))

    def test_active_timer_artifacts_refuse_restore_before_looking_at_snapshot(self):
        for artifact in restore.TIMER_ARTIFACTS:
            with self.subTest(artifact=str(artifact)):
                # Existing unit file, state directory, or broken symlink
                # means the renewal timer must be disabled first.
                artifact.symlink_to(self.root / "nonexistent-timer")
                with mock.patch.object(restore, "checked_record") as checked:
                    with self.assertRaisesRegex(
                            restore.Refused,
                            "multi_ingress_timer_must_be_disabled_before_restore"):
                        restore.preview()
                    checked.assert_not_called()
                artifact.unlink()
        self.assertEqual(len(restore.preview()["sha"]), 64)

    def test_restore_apply_refuses_when_timer_exists_without_modifying_mail(self):
        state = restore.preview()
        timerunit = restore.TIMER_ARTIFACTS[1]
        timerunit.write_text("experimental\n", encoding="ascii")
        with self.assertRaisesRegex(
                restore.Refused, "multi_ingress_timer_must_be_disabled_before_restore"):
            restore.apply_offline(state["sha"], self.backup_id, restore.CONFIRM)
        self.assertEqual((self.conf / "main.cf").read_bytes(), self.installed["main.cf"])
        self.assertTrue(self.active.is_file())
        self.assertFalse(list(self.recovery.glob("pre-restore-*")))

    def test_readonly_preview_binds_exact_active_state_and_archive(self):
        before = self.active.read_bytes()
        current = {name: (self.conf / name).read_bytes()
                   for name in self.installed}
        state = restore.preview()
        self.assertEqual(state["backup_id"], self.backup_id)
        self.assertEqual(len(state["sha"]), 64)
        self.assertEqual(self.active.read_bytes(), before)
        self.assertEqual({name: (self.conf / name).read_bytes()
                          for name in current}, current)
        self.assertFalse(list(self.recovery.glob("pre-restore-*")))

    def test_offline_restore_quarantines_runtime_and_keeps_both_backups(self):
        state = restore.preview()
        result = restore.apply_offline(state["sha"], self.backup_id, restore.CONFIRM)
        self.assertEqual(result["backup_id"], self.backup_id)
        self.assertTrue(result["safety"].is_dir())
        self.assertFalse(self.active.exists())
        self.assertFalse(self.target.exists())
        self.assertFalse(self.runtime.exists())
        self.assertFalse(self.proof.exists())
        for name, raw in self.original.items():
            self.assertEqual((self.conf / name).read_bytes(), raw)
            self.assertEqual((self.archive / name).read_bytes(), raw)
        self.assertEqual((result["safety"] / "retired-runtime-map.tsv").read_bytes(),
                         self.map_bytes)
        self.assertEqual((result["safety"] / "retired-ingress-proof.json").read_bytes(),
                         self.proof_bytes)
        self.assertTrue((result["safety"] / "retired-runtime-code").is_dir())
        self.assertTrue((result["safety"] / "retired-active.json").is_file())
        self.assertEqual((result["safety"] / "installed-marker.json").read_bytes(),
                         json.dumps(self.record, sort_keys=True).encode("ascii"))
        self.assertGreater(self.offline.call_count, 2)
        self.run.assert_called_with(
            ["postfix", "-c", str(self.conf), "check"])

    def test_reviewed_sha_is_one_time_and_backup_id_exact(self):
        state = restore.preview()
        for sha, backup in ((("f" if state["sha"][0] != "f" else "e") +
                             state["sha"][1:], self.backup_id),
                            (state["sha"], "pre-multi-A1b2C3d5"),
                            (state["sha"], "../etc")):
            with self.subTest(backup=backup), self.assertRaises(restore.Refused):
                restore.apply_offline(sha, backup, restore.CONFIRM)
        self.assertEqual((self.conf / "main.cf").read_bytes(),
                         self.installed["main.cf"])
        self.assertTrue(self.active.is_file())

    def test_offline_guard_blocks_mutation_when_service_active(self):
        state = restore.preview()
        self.offline.side_effect = restore.Refused("sidecar_not_stopped")
        with self.assertRaisesRegex(restore.Refused, "sidecar_not_stopped"):
            restore.apply_offline(state["sha"], self.backup_id, restore.CONFIRM)
        self.assertEqual((self.conf / "master.cf").read_bytes(),
                         self.installed["master.cf"])
        self.assertTrue(self.active.is_file())
        self.assertFalse(list(self.recovery.glob("pre-restore-*")))

    def test_injected_second_file_write_failure_rolls_back_active_bytes(self):
        state = restore.preview()
        calls = [0]
        def fail_second(path, data, metadata):
            calls[0] += 1
            if calls[0] == 2:
                raise OSError("injected_failure")
            self.writer(path, data, metadata)
        self.inject(install, "replace_file", fail_second)
        with self.assertRaises(OSError):
            restore.apply_offline(state["sha"], self.backup_id, restore.CONFIRM)
        for name, data in self.installed.items():
            self.assertEqual((self.conf / name).read_bytes(), data)
        self.assertTrue(self.active.exists())
        self.assertTrue(self.runtime.exists())
        self.assertTrue(self.target.exists())
        self.assertTrue(list(self.recovery.glob("pre-restore-*")))

    def test_modified_active_config_or_runtime_map_blocks_restore(self):
        state = restore.preview()
        put(self.conf / "main.cf", b"unauthorized change\n", 0o644)
        with self.assertRaises(restore.Refused):
            restore.apply_offline(state["sha"], self.backup_id, restore.CONFIRM)
        put(self.conf / "main.cf", self.installed["main.cf"], 0o644)
        put(self.runtime, self.map_bytes + b"tamper", 0o640)
        with self.assertRaises(restore.Refused):
            restore.preview()

    def test_tampered_source_and_preinstall_backup_refused(self):
        put(self.target / install.FILES[0], b"wrong code\n", 0o644)
        with self.assertRaises(restore.Refused):
            restore.preview()
        put(self.target / install.FILES[0], self.source[install.FILES[0]], 0o644)
        put(self.archive / "main.cf", b"wrong old config\n", 0o600)
        with self.assertRaises(restore.Refused):
            restore.preview()

    def test_forged_active_record_and_duplicate_json_key_refused(self):
        before = self.active.read_bytes()
        put(self.active, before.replace(b'"version": 1',
            b'"version": 1, "version": 1'), 0o600)
        with self.assertRaises(restore.Refused):
            restore.preview()
        put(self.active, before, 0o600)
        self.record["backup_id"] = "pre-multi-../../.."
        put(self.active, json.dumps(self.record).encode(), 0o600)
        with self.assertRaises(restore.Refused):
            restore.preview()

    def test_no_implicit_live_restore_on_preview_or_script_import(self):
        source = (LINUX / "restore-multi-mailbox-postfix.py").read_text()
        for forbidden in ("systemctl start", "systemctl restart",
                          "postfix reload", "smtp.office365.com",
                          "New-InboundConnector", "postsuper -d"):
            self.assertNotIn(forbidden, source)
        self.assertIn("RESTORE_MULTI_MAILBOX_OFFLINE", source)
        self.assertIn("pre-restore-", source)
        installer = (LINUX / "manage-multi-mailbox-postfix.py").read_text()
        self.assertIn('ACTIVE = RECOVERY / "active.json"', installer)
        self.assertIn('LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")',
                      installer)
        self.assertIn('LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")',
                      (LINUX / "manage-sidecar-eop-route.py").read_text())


if __name__ == "__main__":
    unittest.main()
