"""Exact-file conditional routing transaction; isolated temporary directories."""
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "conditional_txn", str(ROOT / "linux/conditional-postfix-transaction.py"))
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.config = self.root / "postfix"
        self.config.mkdir(mode=0o700)
        self.parent = os.open(str(self.root), T.M.DIR_FLAGS)
        self.fd = os.open(str(self.config), T.M.DIR_FLAGS)
        self.addCleanup(os.close, self.fd)
        self.addCleanup(os.close, self.parent)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.main = b"mydestination = localhost\ninet_interfaces = loopback-only\n"
        self.master = b"smtp unix - - n - - smtp\n"
        for name, data in (("main.cf", self.main), ("master.cf", self.master)):
            (self.config / name).write_bytes(data)
            (self.config / name).chmod(0o644)
        self.plan = "a" * 64
        self.db = b"fixture database"
        self.guard = lambda: None
        self.sha, self.info, self.files = self.preview()
        self.target = self.config / (T.checked_name(self.plan, "hash")[0] + ".db")

    def preview(self):
        return T.preview(self.fd, self.plan, "hash", "b"*64, "c"*64,
                         self.db, self.uid, self.guard)

    def verify(self, value):
        if value:
            self.assertIn(value.encode(), (self.config / "main.cf").read_bytes())
        else:
            self.assertEqual((self.config / "main.cf").read_bytes(), self.main)

    def apply(self, verify=None, sha=None):
        return T.apply(self.fd, self.parent, sha or self.sha, T.CONFIRM,
                       self.uid, self.gid, self.guard, verify or self.verify, self.preview)

    def restore(self):
        return T.restore(self.fd, self.parent, self.sha, T.RESTORE,
                         self.uid, self.gid, self.guard, self.verify)

    def test_apply_and_restore_exact_bytes(self):
        self.assertEqual(self.apply(), self.sha)
        self.assertEqual(self.target.read_bytes(), self.db)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.config / "master.cf").read_bytes(), self.master)
        self.assertEqual(T.load_backup(self.parent, self.sha, self.uid),
                         (self.info, self.files))
        self.assertEqual(self.restore(), self.sha)
        self.assertFalse(self.target.exists())
        self.assertEqual((self.config / "main.cf").read_bytes(), self.main)
        self.assertEqual((self.config / "main.cf").stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.restore(), self.sha)

    def test_wrong_sha_and_foreign_map_refused(self):
        with self.assertRaises(T.Refused):
            self.apply(sha="f"*64)
        self.target.write_bytes(b"admin map")
        with self.assertRaises(T.Refused):
            self.apply()
        self.assertEqual(self.target.read_bytes(), b"admin map")
        self.assertFalse((self.root / T.BACKUP_BASE).exists())

    def test_failed_verification_restores_and_retains_backup(self):
        def fail(value):
            if value:
                raise T.Refused("injected verification failure")
            self.verify(value)
        with self.assertRaises(T.Refused):
            self.apply(verify=fail)
        self.assertFalse(self.target.exists())
        self.assertEqual((self.config / "main.cf").read_bytes(), self.main)
        self.assertEqual(T.load_backup(self.parent, self.sha, self.uid)[0], self.info)

    def test_no_clobber_race_never_removes_external_map(self):
        original = T.atomic_write
        def race(fd, name, data, meta, uid, replace, published=None):
            if not replace:
                self.target.write_bytes(data)
                self.target.chmod(0o640)
            return original(fd, name, data, meta, uid, replace, published)
        with patch.object(T, "atomic_write", side_effect=race):
            with self.assertRaises(FileExistsError):
                self.apply()
        self.assertEqual(self.target.read_bytes(), self.db)
        self.assertEqual((self.config / "main.cf").read_bytes(), self.main)
        # A later manual Restore must not delete that external map either.
        with self.assertRaisesRegex(T.Refused, "map_publication_unproven"):
            self.restore()
        self.assertEqual(self.target.read_bytes(), self.db)

    def test_equal_bytes_replacement_is_not_owned(self):
        self.apply()
        original = self.config / "retained-original.db"
        self.target.rename(original)
        self.target.write_bytes(self.db)
        self.target.chmod(0o640)
        with self.assertRaisesRegex(T.Refused, "published_map_identity_or_content_changed"):
            self.restore()
        self.assertTrue(self.target.exists())
        self.assertTrue(original.exists())

    def test_publication_receipt_failure_never_writes_main_cf(self):
        original = T.publication_receipt
        def failure(parent, sha, uid, identity=None):
            if identity is not None:
                raise OSError("injected durable receipt failure")
            return original(parent, sha, uid)
        with patch.object(T, "publication_receipt", side_effect=failure):
            with self.assertRaises(T.RollbackRequired):
                self.apply()
        self.assertEqual((self.config / "main.cf").read_bytes(), self.main)
        self.assertTrue(self.target.exists())
        # Even a matching candidate is left for explicit manual recovery.
        with self.assertRaisesRegex(T.Refused, "map_publication_unproven"):
            self.restore()
        self.assertTrue(self.target.exists())

    def test_drift_blocks_restore(self):
        self.apply()
        path = self.config / "main.cf"
        altered = path.read_bytes() + b"# administrator edit\n"
        path.write_bytes(altered)
        with self.assertRaises(T.Refused):
            self.restore()
        self.assertEqual(path.read_bytes(), altered)
        self.assertTrue(self.target.exists())

    def test_tampered_backup_refused(self):
        self.apply()
        path = self.root / T.BACKUP_BASE / self.sha / "main.before"
        path.write_bytes(b"tampered")
        with self.assertRaises(T.Refused):
            self.restore()
        self.assertTrue(self.target.exists())

    def test_guard_failure_creates_no_backup(self):
        def fail():
            raise T.Refused("maintenance not proved")
        self.guard = fail
        with self.assertRaises(T.Refused):
            self.apply()
        self.assertFalse((self.root / T.BACKUP_BASE).exists())

    def test_labeled_manifest_apply_restore_and_legacy_compatibility(self):
        # Exercise real filesystem xattrs using an unprivileged user namespace
        # label substitute. This is not a kernel SELinux acceptance test.
        attribute = "user.lmr365_test_selinux"
        config_label = b"system_u:object_r:postfix_etc_t:s0\0"
        master_label = b"system_u:object_r:postfix_etc_t:s0:c0,c2\0"
        map_label = b"system_u:object_r:postfix_etc_t:s0\0"
        main_path = self.config / "main.cf"
        master_path = self.config / "master.cf"
        try:
            os.setxattr(str(main_path), attribute, config_label)
            os.setxattr(str(master_path), attribute, master_label)
        except OSError as exc:
            self.skipTest("filesystem user xattrs unavailable: " + str(exc.errno))
        with patch.object(T, "SELINUX_XATTR", attribute):
            # No label-bearing config may silently fall back to v1.
            with self.assertRaises(T.Refused):
                self.preview()
            def labeled():
                return T.preview(self.fd, self.plan, "hash", "b"*64, "c"*64,
                                 self.db, self.uid, self.guard, map_label.hex())
            sha, info, files = labeled()
            self.assertEqual(info["version"], 2)
            self.assertEqual(info["main_meta"]["selinux"], config_label.hex())
            self.assertEqual(info["master_meta"]["selinux"], master_label.hex())
            self.assertEqual(info["map_selinux"], map_label.hex())
            self.assertEqual(T.apply(self.fd, self.parent, sha, T.CONFIRM,
                self.uid, self.gid, self.guard, self.verify, labeled), sha)
            self.assertEqual(os.getxattr(str(main_path), attribute), config_label)
            self.assertEqual(os.getxattr(str(master_path), attribute), master_label)
            self.assertEqual(os.getxattr(str(self.target), attribute), map_label)
            self.assertEqual(T.load_backup(self.parent, sha, self.uid), (info, files))
            self.assertEqual(T.restore(self.fd, self.parent, sha, T.RESTORE,
                self.uid, self.gid, self.guard, self.verify), sha)
            self.assertEqual(main_path.read_bytes(), self.main)
            self.assertEqual(os.getxattr(str(main_path), attribute), config_label)
            self.assertEqual(os.getxattr(str(master_path), attribute), master_label)
            self.assertFalse(self.target.exists())

    def test_unrecognized_attributes_and_bad_labels_refused(self):
        path = self.config / "main.cf"
        try:
            os.setxattr(str(path), "user.lmr365_unknown", b"unmanaged")
        except OSError as exc:
            self.skipTest("filesystem user xattrs unavailable: " + str(exc.errno))
        with self.assertRaisesRegex(T.Refused, "unsupported_extended_file_metadata"):
            self.preview()
        for raw in (b"", b"wrong", b"u:r:t:s0\n", b"u:r:t:s0\0extra"):
            with self.assertRaises(T.Refused):
                T.checked_label(raw)

    def test_label_install_failure_does_not_replace_original(self):
        path = self.config / "main.cf"
        with patch.object(T, "restore_file_metadata", side_effect=OSError("relabel denied")):
            with self.assertRaises(OSError):
                T.atomic_write(self.fd, "main.cf", b"changed\n",
                               {"mode": 0o644, "gid": self.gid}, self.uid, True)
        self.assertEqual(path.read_bytes(), self.main)
        self.assertFalse(any(x.name.startswith(".lmr365-txn-")
                             for x in self.config.iterdir()))

    def test_existing_assignment_is_not_rewritten(self):
        with self.assertRaises(T.Refused):
            T.proposed(self.main + b"sender_dependent_relayhost_maps =\n",
                       self.plan, "hash")

    def test_symlink_and_hardlink_rejected(self):
        path = self.config / "main.cf"
        path.unlink()
        path.symlink_to(self.config / "master.cf")
        with self.assertRaises(OSError):
            self.preview()
        path.unlink()
        os.link(str(self.config / "master.cf"), str(path))
        with self.assertRaises(T.Refused):
            self.preview()


if __name__ == "__main__":
    unittest.main()
