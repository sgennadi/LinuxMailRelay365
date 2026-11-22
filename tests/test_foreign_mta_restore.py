"""Offline Exim/Sendmail configuration restore must remain fail-closed."""
import importlib.util
import io
import stat
from contextlib import redirect_stdout, redirect_stderr
from types import SimpleNamespace
import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "restore-foreign-mta-config.py"
spec = importlib.util.spec_from_file_location("foreign_mta_restore", str(SCRIPT))
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)
snapshot = restore.backup


class ForeignMtaRestoreTests(unittest.TestCase):
    def fixture(self, folder, mta):
        root = Path(folder) / "root"
        (root / "etc").mkdir(parents=True)
        tree = root / "etc" / ("mail" if mta == "sendmail" else "exim4")
        tree.mkdir()
        filenames = ("sendmail.cf", "access") if mta == "sendmail" else (
            "update-exim4.conf.conf", "passwd.client")
        for index, name in enumerate(filenames):
            (tree / name).write_text("snapshot file {}\n".format(index))
        uid = os.getuid()
        base = Path(folder) / "backups"
        snap_id, _ = snapshot.backup(mta, root=root, base=base, owner_uid=uid)
        return root, base, tree, snap_id, uid

    @staticmethod
    def safe_preflight(mta, snapshot_id, root, base, uid):
        current = snapshot.recovery_preview(
            mta, snapshot_id, root, base, uid)["current"]
        return {"mta": mta, "snapshot_id": snapshot_id, "current": current,
                "service": "stopped_declared", "processes": "none_observed",
                "queue": "empty_reported", "listener": "none_observed",
                "gate": "offline_candidate_manual_recovery_only"}

    @staticmethod
    def kwargs(folder, root, base, uid, offline=lambda mta: True,
               preflight=None):
        return {"root": root, "base": base, "uid": uid,
                "offline_check": offline,
                "preflight_check": preflight or ForeignMtaRestoreTests.safe_preflight,
                "static_check": lambda mta, root, uid: True,
                "lock_path": Path(folder) / "restore.lock"}

    def test_sendmail_package_directory_is_backup_only_not_restorable(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "sendmail")
            config = tree / "sendmail.cf"
            config.write_text("live edit remains\n")
            review = restore.preview("sendmail", snap_id, root, base, uid)
            original_dir_check = snapshot.safe_dir
            def reject_nonroot_package_owner(path, owner_uid=0):
                if path == root / "etc" / "mail":
                    raise snapshot.Refused("unsafe_snapshot_directory")
                return original_dir_check(path, owner_uid)
            with patch.object(snapshot, "safe_dir", side_effect=reject_nonroot_package_owner):
                with self.assertRaisesRegex(restore.Refused, "nonroot_config_directory"):
                    restore.apply("sendmail", snap_id, review["sha"],
                                  restore.APPROVAL,
                                  **self.kwargs(folder, root, base, uid))
            self.assertEqual(config.read_text(), "live edit remains\n")
            self.assertEqual(snapshot.listed("sendmail", base, uid), [snap_id])

    def test_preview_has_no_side_effects_and_changes_bind_review_sha(self):
        for mta in ("exim", "sendmail"):
            with self.subTest(mta=mta), tempfile.TemporaryDirectory() as folder:
                root, base, tree, snap_id, uid = self.fixture(folder, mta)
                edited = next(tree.iterdir())
                edited.write_text("edited now\n")
                review = restore.preview(mta, snap_id, root, base, uid)
                self.assertEqual(review["changed"], 1)
                self.assertEqual(len(review["sha"]), 64)
                self.assertEqual(edited.read_text(), "edited now\n")
                self.assertEqual(snapshot.listed(mta, base, uid), [snap_id])
                edited.write_text("modified again\n")
                self.assertNotEqual(
                    review["sha"], restore.preview(mta, snap_id, root, base, uid)["sha"])

    def test_confirmation_and_revised_config_refused_before_change(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "exim")
            edited = next(tree.iterdir())
            edited.write_text("live edit\n")
            review = restore.preview("exim", snap_id, root, base, uid)
            options = self.kwargs(folder, root, base, uid)
            with self.assertRaises(restore.Refused):
                restore.apply("exim", snap_id, review["sha"], "WRONG", **options)
            edited.write_text("changed after review\n")
            with self.assertRaisesRegex(restore.Refused, "plan_changed"):
                restore.apply("exim", snap_id, review["sha"],
                              restore.APPROVAL, **options)
            self.assertEqual(edited.read_text(), "changed after review\n")

    def test_stopped_only_snapshot_before_mutation(self):
        for mta in ("exim", "sendmail"):
            with self.subTest(mta=mta), tempfile.TemporaryDirectory() as folder:
                root, base, tree, snap_id, uid = self.fixture(folder, mta)
                edited = next(tree.iterdir())
                original = edited.read_text()
                edited.write_text("live version\n")
                review = restore.preview(mta, snap_id, root, base, uid)
                with self.assertRaisesRegex(restore.Refused, "not_stopped"):
                    restore.apply(mta, snap_id, review["sha"], restore.APPROVAL,
                                  **self.kwargs(folder, root, base, uid,
                                                lambda m: False))
                self.assertEqual(edited.read_text(), "live version\n")
                result = restore.apply(mta, snap_id, review["sha"],
                                       restore.APPROVAL,
                                       **self.kwargs(folder, root, base, uid))
                self.assertEqual(result["changed"], 1)
                self.assertEqual(edited.read_text(), original)
                self.assertNotEqual(result["safety_id"], snap_id)
                offline, _ = snapshot.extract_offline(mta, result["safety_id"],
                                                      base, uid)
                recovery_file = Path(offline) / "etc" / tree.name / edited.name
                self.assertEqual(recovery_file.read_text(), "live version\n")
                self.assertEqual(stat.S_IMODE(edited.stat().st_mode), 0o644)

    def test_new_file_or_symlink_blocks_preview(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "sendmail")
            (tree / "extra.conf").write_text("new")
            with self.assertRaisesRegex(restore.Refused, "file_set_mismatch"):
                restore.preview("sendmail", snap_id, root, base, uid)
            (tree / "extra.conf").unlink()
            (tree / "extra.conf").symlink_to(tree / "access")
            with self.assertRaises(restore.Refused):
                restore.preview("sendmail", snap_id, root, base, uid)

    def test_corrupt_snapshot_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "exim")
            with (base / "exim" / snap_id / "config.tar.gz").open("ab") as stream:
                stream.write(b"tamper")
            with self.assertRaises(restore.Refused):
                restore.preview("exim", snap_id, root, base, uid)

    def test_same_bytes_new_inode_invalidates_approval(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "sendmail")
            first = restore.preview("sendmail", snap_id, root, base, uid)["sha"]
            target = next(tree.iterdir())
            temporary = target.with_name("replace.tmp")
            temporary.write_bytes(target.read_bytes())
            os.replace(str(temporary), str(target))
            second = restore.preview("sendmail", snap_id, root, base, uid)["sha"]
            self.assertNotEqual(first, second)

    def test_failed_second_file_restores_previous_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "sendmail")
            for file in tree.iterdir():
                file.write_text("current\n")
            review = restore.preview("sendmail", snap_id, root, base, uid)
            real = restore.replace_one
            counter = [0]

            def fail_second(*args, **kwargs):
                counter[0] += 1
                if counter[0] == 2:
                    raise OSError("injected write failure")
                return real(*args, **kwargs)

            with patch.object(restore, "replace_one", side_effect=fail_second):
                with self.assertRaisesRegex(restore.Refused, "rollback_verified"):
                    restore.apply("sendmail", snap_id, review["sha"],
                                  restore.APPROVAL,
                                  **self.kwargs(folder, root, base, uid))
            self.assertTrue(all(p.read_text() == "current\n" for p in tree.iterdir()))
            self.assertEqual(len(snapshot.listed("sendmail", base, uid)), 2)

    def test_service_inactive_check_fails_closed(self):
        def probe(loaded=True, active=False, process=False, port=46500):
            def command(argv, timeout=8):
                if argv[0] == "systemctl":
                    is_loaded = loaded and argv[-1] == "exim4.service"
                    return (0, "LoadState={}\nActiveState={}\n".format(
                        "loaded" if is_loaded else "not-found",
                        "active" if is_loaded and active else "inactive"))
                if argv[0] == "pgrep":
                    return (0, "1234\n") if process else (1, "")
                if argv[0] == "ss":
                    return (0, "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                            "LISTEN 0 128 0.0.0.0:{} 0.0.0.0:* users:((\"other\",pid=4321,fd=4))\n".format(port))
                raise AssertionError(argv)
            with patch.object(restore.backup, "read_only_probe", side_effect=command):
                return restore.stopped("exim")
        self.assertTrue(probe())
        for case in ({"loaded": False}, {"active": True},
                     {"process": True}, {"port": 25}, {"port": 2525}):
            with self.subTest(case=case), self.assertRaises(restore.Refused):
                probe(**case)

    def test_sendmail_packaged_config_directory_only_smmsp_and_2755(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config = root / "etc" / "mail"
            config.parent.mkdir()
            config.mkdir()
            regular = config.lstat()
            synthetic = SimpleNamespace(st_mode=stat.S_IFDIR | 0o2755,
                                        st_uid=112, st_gid=122)
            with patch.object(restore.pwd, "getpwnam",
                              return_value=SimpleNamespace(pw_uid=112, pw_gid=122)):
                with patch.object(Path, "lstat", autospec=True,
                                  side_effect=lambda item: synthetic if item == config
                                  else regular):
                    self.assertTrue(restore.safe_native_sendmail_directory(
                        config, root, 0))
                    for invalid in (SimpleNamespace(st_mode=stat.S_IFDIR | 0o2755,
                                                    st_uid=113, st_gid=122),
                                    SimpleNamespace(st_mode=stat.S_IFDIR | 0o2775,
                                                    st_uid=112, st_gid=122),
                                    SimpleNamespace(st_mode=stat.S_IFDIR | 0o2777,
                                                    st_uid=112, st_gid=122)):
                        with patch.object(Path, "lstat", return_value=invalid):
                            with self.assertRaises(restore.Refused):
                                restore.safe_native_sendmail_directory(
                                    config, root, 0)
            # Debian's smmta account is also recognized by its exact UID/GID.
            with patch.object(restore.pwd, "getpwnam",
                              side_effect=lambda name:
                              SimpleNamespace(pw_uid=112, pw_gid=122)
                              if name == "smmta" else
                              (_ for _ in ()).throw(KeyError(name))):
                with patch.object(Path, "lstat", return_value=synthetic):
                    self.assertTrue(restore.safe_native_sendmail_directory(
                        config, root, 0))
            # The same foreign-owner exception must not work on /etc.
            with patch.object(Path, "lstat", autospec=True,
                              return_value=synthetic):
                with patch.object(restore.pwd, "getpwnam",
                                  return_value=SimpleNamespace(pw_uid=112,pw_gid=122)):
                    with self.assertRaises(restore.Refused):
                        restore.safe_native_sendmail_directory(config.parent, root, 0)

    def test_native_directory_supports_debian_smmta_smmsp_group(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config = root / "etc" / "mail"
            config.parent.mkdir()
            config.mkdir()
            value = SimpleNamespace(st_mode=stat.S_IFDIR | 0o2755,
                                    st_uid=109, st_gid=119)
            def passwd(name):
                if name == "smmta":
                    return SimpleNamespace(pw_uid=109, pw_gid=111)
                raise KeyError(name)
            with patch.object(restore.pwd, "getpwnam", side_effect=passwd), \
                 patch.object(restore.grp, "getgrnam",
                              return_value=SimpleNamespace(gr_gid=119)), \
                 patch.object(Path, "lstat", return_value=value):
                self.assertTrue(restore.safe_native_sendmail_directory(
                    config, root, 0))
            invalid = SimpleNamespace(st_mode=stat.S_IFDIR | 0o2755,
                                      st_uid=109, st_gid=211)
            with patch.object(restore.pwd, "getpwnam", side_effect=passwd), \
                 patch.object(restore.grp, "getgrnam",
                              return_value=SimpleNamespace(gr_gid=119)), \
                 patch.object(Path, "lstat", return_value=invalid):
                with self.assertRaises(restore.Refused):
                    restore.safe_native_sendmail_directory(config, root, 0)

    def test_native_parser_timeout_is_categorized_and_fails_closed(self):
        with patch.object(restore, "trusted_native_tool", return_value="/usr/sbin/exim"):
            with patch.object(restore.subprocess, "run",
                              side_effect=restore.subprocess.TimeoutExpired(
                                  ["/usr/sbin/exim", "-bV"], 15)):
                with self.assertRaisesRegex(
                        restore.Refused, "native_mta_static_parser_timed_out"):
                    restore.native_static_config_check("exim")
            with patch.object(restore.subprocess, "run",
                              side_effect=OSError("test missing binary")):
                with self.assertRaisesRegex(
                        restore.Refused, "native_mta_static_parser_unavailable"):
                    restore.native_static_config_check("exim")

    def test_native_static_check_uses_only_compiler_parse_modes(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "sendmail")
            (tree / "submit.cf").write_text("V10\n")
            captured = []
            def run(args):
                captured.append(args)
                return 0
            with patch.object(restore, "trusted_native_tool", return_value="/usr/sbin/sendmail"):
                self.assertTrue(restore.native_static_config_check(
                    "sendmail", root, uid, run))
            self.assertEqual(len(captured), 2)
            self.assertTrue(all(args[1] == "-bt" and args[2].startswith("-C")
                                for args in captured))
            captured.clear()
            with patch.object(restore, "trusted_native_tool", return_value="/usr/sbin/exim"):
                self.assertTrue(restore.native_static_config_check(
                    "exim", root, uid, run))
            self.assertEqual(captured, [["/usr/sbin/exim", "-bV"]])

    def test_failed_native_static_check_rolls_back_configuration(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "sendmail")
            edited = next(tree.iterdir())
            edited.write_text("current but valid version\n")
            plan = restore.preview("sendmail", snap_id, root, base, uid)
            kwargs = self.kwargs(folder, root, base, uid)
            kwargs["static_check"] = lambda mta, root, uid: False
            with self.assertRaisesRegex(restore.Refused, "rollback_verified"):
                restore.apply("sendmail", snap_id, plan["sha"], restore.APPROVAL,
                              **kwargs)
            self.assertEqual(edited.read_text(), "current but valid version\n")
            self.assertEqual(len(snapshot.listed("sendmail", base, uid)), 2)

    def test_native_checker_refuses_untrusted_binary_and_failed_parse(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "sendmail")
            with patch.object(restore, "trusted_native_tool", return_value="/usr/sbin/sendmail"):
                with self.assertRaisesRegex(restore.Refused,
                                            "native_mta_static_configuration_invalid"):
                    restore.native_static_config_check(
                        "sendmail", root, uid, lambda args: 1)
            with patch.object(restore.os.path, "lexists", return_value=False):
                with self.assertRaisesRegex(restore.Refused, "native_mta_binary_missing"):
                    restore.trusted_native_tool("exim")
            for mta, alternative in (
                    ("sendmail", "/usr/sbin/exim4"),
                    ("sendmail", "/usr/sbin/sendmail.postfix"),
                    ("exim", "/usr/sbin/postfix")):
                with self.subTest(mta=mta, alternative=alternative):
                    with patch.object(restore.os.path, "lexists", return_value=True):
                        with patch.object(restore.os.path, "realpath", return_value=alternative):
                            with self.assertRaisesRegex(
                                    restore.Refused, "native_mta_alternative_mismatch"):
                                restore.trusted_native_tool(mta)


    def test_queue_listener_service_gates_block_before_safety_backup(self):
        cases = (("queue", "nonempty_reported", "blocked_nonempty_queue"),
                 ("queue", "unverified", "blocked_unverified"),
                 ("listener", "running", "blocked_running"),
                 ("service", "running", "blocked_running"),
                 ("processes", "unverified", "blocked_unverified"))
        for field, value, gate in cases:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as folder:
                root, base, tree, snap_id, uid = self.fixture(folder, "exim")
                edited = next(tree.iterdir())
                edited.write_text("current edit\n")
                plan = restore.preview("exim", snap_id, root, base, uid)
                def unsafe(mta, sid, root, base, uid):
                    result = self.safe_preflight(mta, sid, root, base, uid)
                    result[field], result["gate"] = value, gate
                    return result
                with self.assertRaisesRegex(restore.Refused, "offline_preflight_" + gate):
                    restore.apply("exim", snap_id, plan["sha"], restore.APPROVAL,
                                  **self.kwargs(folder, root, base, uid, preflight=unsafe))
                self.assertEqual(edited.read_text(), "current edit\n")
                self.assertEqual(snapshot.listed("exim", base, uid), [snap_id])

    def test_queue_becomes_nonempty_after_safety_backup(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "sendmail")
            edited = next(tree.iterdir())
            edited.write_text("new content\n")
            plan = restore.preview("sendmail", snap_id, root, base, uid)
            calls = [0]
            def drift(mta, sid, root, base, uid):
                calls[0] += 1
                result = self.safe_preflight(mta, sid, root, base, uid)
                if calls[0] >= 2:
                    result["queue"] = "nonempty_reported"
                    result["gate"] = "blocked_nonempty_queue"
                return result
            with self.assertRaisesRegex(restore.Refused, "blocked_nonempty_queue"):
                restore.apply("sendmail", snap_id, plan["sha"], restore.APPROVAL,
                              **self.kwargs(folder, root, base, uid, preflight=drift))
            self.assertEqual(edited.read_text(), "new content\n")
            self.assertEqual(len(snapshot.listed("sendmail", base, uid)), 2)

    def test_listener_changes_after_write_trigger_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "exim")
            edited = next(tree.iterdir())
            edited.write_text("live content\n")
            plan = restore.preview("exim", snap_id, root, base, uid)
            calls = [0]
            def drift(mta, sid, root, base, uid):
                calls[0] += 1
                result = self.safe_preflight(mta, sid, root, base, uid)
                if calls[0] >= 3:
                    result["listener"], result["gate"] = "running", "blocked_running"
                return result
            with self.assertRaisesRegex(restore.Refused, "rollback_verified"):
                restore.apply("exim", snap_id, plan["sha"], restore.APPROVAL,
                              **self.kwargs(folder, root, base, uid, preflight=drift))
            self.assertEqual(edited.read_text(), "live content\n")
            self.assertEqual(len(snapshot.listed("exim", base, uid)), 2)

    def test_wrong_preflight_identity_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root, base, tree, snap_id, uid = self.fixture(folder, "exim")
            edited = next(tree.iterdir())
            edited.write_text("new content\n")
            plan = restore.preview("exim", snap_id, root, base, uid)
            def wrong(mta, sid, root, base, uid):
                result = self.safe_preflight(mta, sid, root, base, uid)
                result["snapshot_id"] = "other"
                return result
            with self.assertRaisesRegex(restore.Refused, "offline_preflight_identity_unverified"):
                restore.apply("exim", snap_id, plan["sha"], restore.APPROVAL,
                              **self.kwargs(folder, root, base, uid, preflight=wrong))
            self.assertEqual(edited.read_text(), "new content\n")

    def test_static_check_requires_root_and_never_enters_restore_path(self):
        captured = io.StringIO()
        with patch.object(restore.os, "geteuid", return_value=0), \
             patch.object(restore.backup, "selected_files", return_value={"etc/mail/sendmail.cf": object()}) as files, \
             patch.object(restore, "native_static_config_check", return_value=True) as checker, \
             patch.object(restore, "apply", side_effect=AssertionError("restore forbidden")), \
             redirect_stdout(captured):
            self.assertEqual(restore.main(["--mta", "sendmail", "--static-check"]), 0)
        files.assert_not_called()
        checker.assert_called_once()
        response = captured.getvalue()
        for item in ("FOREIGN_STATIC_VERSION=1",
                     "FOREIGN_STATIC_MTA=sendmail",
                     "FOREIGN_STATIC_CHECK=passed_partial_parse_only",
                     "FOREIGN_STATIC_CONFIG_CHANGED=no",
                     "FOREIGN_STATIC_QUEUE_CHANGED=no",
                     "FOREIGN_STATIC_SERVICE_CHANGED=no",
                     "FOREIGN_STATIC_DELIVERY_VERIFIED=no"):
            self.assertIn(item + "\n", response)
        self.assertNotIn("FOREIGN_RESTORE_STATUS=config_replaced", response)

    def test_static_check_refuses_approval_and_failed_native_parse(self):
        for approved in (["--confirm", "RESTORE_STOPPED_FOREIGN_MTA_CONFIG"],
                         ["--approve-sha256", "0" * 64]):
            with self.subTest(approved=approved):
                with patch.object(restore.os, "geteuid", return_value=0), \
                     patch.object(restore, "native_static_config_check",
                                       side_effect=AssertionError("must not execute")), \
                     redirect_stderr(io.StringIO()):
                    self.assertEqual(restore.main(["--mta", "exim", "--static-check"] +
                                                  approved), 2)
        with patch.object(restore.os, "geteuid", return_value=0), \
             patch.object(restore.backup, "selected_files", return_value={}), \
             patch.object(restore, "native_static_config_check",
                          side_effect=restore.Refused("native_check_failed")), \
             redirect_stderr(io.StringIO()):
            self.assertEqual(restore.main(["--mta", "exim", "--static-check"]), 2)
        with patch.object(restore.os, "geteuid", return_value=1000), \
             patch.object(restore, "native_static_config_check",
                          side_effect=AssertionError("nonroot execution forbidden")), \
             redirect_stderr(io.StringIO()):
            self.assertEqual(restore.main(["--mta", "exim", "--static-check"]), 2)

    def test_wizard_static_check_is_readonly_and_embedded(self):
        form = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        assets = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text(encoding="utf-8")
        project = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        for required in ("CheckForeignMtaNativeSyntaxAsync",
                         "FOREIGN_STATIC_CHECK=passed_partial_parse_only",
                         "FOREIGN_STATIC_DELIVERY_VERIFIED=no",
                         "ConfirmedForeignBackupMta(allowStopped: true)"):
            self.assertIn(required, form)
        for required in ("BuildForeignMtaNativeCheckBundle", "ForeignMtaRestore",
                         "foreign-mta-config-backup.py", "--static-check"):
            self.assertIn(required, assets)
        self.assertIn('LogicalName="LinuxMailRelay365.linux.foreign-mta-restore.py"', project)

    def test_no_implicit_service_or_queue_changes(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for token in ("systemctl stop", "systemctl restart",
                      "systemctl start", "--root", "--base", "postconf -e"):
            self.assertNotIn(token, source)
        self.assertIn("RESTORE_STOPPED_FOREIGN_MTA_CONFIG", source)
        self.assertNotIn("--restore",
            (ROOT / "linux" / "foreign-mta-config-backup.py").read_text())


if __name__ == "__main__":
    unittest.main()
