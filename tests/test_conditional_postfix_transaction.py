"""Exact-file conditional routing transaction; isolated temporary directories."""
import importlib.util
import os
import pathlib
import tempfile
import unittest

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
