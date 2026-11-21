"""Offline Exim/Sendmail configuration restore must remain fail-closed."""
import importlib.util
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
    def kwargs(folder, root, base, uid, offline=lambda mta: True):
        return {"root": root, "base": base, "uid": uid,
                "offline_check": offline, "lock_path": Path(folder) / "restore.lock"}

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
        def probe(loaded=True, active=False, process=False, port=2525):
            def command(argv, **kwargs):
                if argv[0] == "systemctl":
                    is_loaded = loaded and argv[2] == "exim4.service"
                    return SimpleNamespace(
                        returncode=0,
                        stdout="LoadState={}\nActiveState={}\n".format(
                            "loaded" if is_loaded else "not-found",
                            "active" if is_loaded and active else "inactive"))
                if argv[0] == "pgrep":
                    return SimpleNamespace(returncode=0 if process else 1, stdout="")
                if argv[0] == "ss":
                    return SimpleNamespace(returncode=0,
                        stdout="LISTEN 0 128 0.0.0.0:{} 0.0.0.0:*\n".format(port))
                raise AssertionError(argv)
            with patch.object(restore.shutil, "which", return_value="/usr/bin/tool"):
                with patch.object(restore.subprocess, "run", side_effect=command):
                    return restore.stopped("exim")
        self.assertTrue(probe())
        for case in ({"loaded": False}, {"active": True},
                     {"process": True}, {"port": 25}):
            with self.subTest(case=case), self.assertRaises(restore.Refused):
                probe(**case)

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
