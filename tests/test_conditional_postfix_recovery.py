"""Read-only conditional recovery inventory, entirely in temporary directories."""
import importlib.util
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "recovery", str(ROOT / "linux/inspect-conditional-postfix-recovery.py"))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
T = R.T


class RecoveryInventoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
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
            path = self.config / name
            path.write_bytes(data)
            path.chmod(0o644)
        self.plan = "a" * 64
        self.db = b"fixture map"
        self.sha, self.info, self.files = self.preview()
        self.target = self.config / (T.checked_name(self.plan, "hash")[0] + ".db")
        self.base = self.root / T.BACKUP_BASE

    def guard(self):
        pass

    def verify(self, value):
        if value:
            self.assertIn(value.encode("ascii"), (self.config / "main.cf").read_bytes())
        else:
            self.assertEqual((self.config / "main.cf").read_bytes(), self.main)

    def preview(self):
        return T.preview(self.fd, self.plan, "hash", "b"*64, "c"*64,
                         self.db, self.uid, self.guard)

    def apply(self):
        T.apply(self.fd, self.parent, self.sha, T.CONFIRM,
                self.uid, self.gid, self.guard, self.verify, self.preview)

    def backup(self):
        T.backup(self.parent, self.sha, self.info, self.files, self.uid)

    def inspect(self):
        return R.inspect(self.fd, self.parent, self.sha, self.uid, self.gid)

    def inventory(self):
        return R.list_recovery(self.fd, self.parent, self.uid, self.gid)

    def test_missing_inventory_never_creates_directory(self):
        self.assertEqual(self.inventory(), [])
        self.assertEqual(self.inspect(), "invalid_or_missing_backup")
        self.assertFalse(self.base.exists())

    def test_applied_and_restored_snapshots_are_read_only(self):
        self.apply()
        before = (self.config / "main.cf").read_bytes()
        receipt = (self.base / self.sha / T.PUBLICATION).read_bytes()
        map_identity = T.file_identity(self.target.stat())
        self.assertEqual(self.inventory(), [(self.sha, "configured_owned_map")])
        self.assertEqual(self.inspect(), "configured_owned_map")
        self.assertEqual((self.config / "main.cf").read_bytes(), before)
        self.assertEqual((self.base / self.sha / T.PUBLICATION).read_bytes(), receipt)
        self.assertEqual(T.file_identity(self.target.stat()), map_identity)
        T.restore(self.fd, self.parent, self.sha, T.RESTORE,
                  self.uid, self.gid, self.guard, self.verify)
        self.assertEqual(self.inventory(), [(self.sha, "original_no_map")])

    def test_incomplete_write_original_with_owned_map(self):
        self.apply()
        (self.config / "main.cf").write_bytes(self.main)
        self.assertEqual(self.inspect(), "original_owned_map")
        self.assertTrue(self.target.exists())

    def test_configured_map_missing(self):
        self.apply()
        self.target.unlink()
        self.assertEqual(self.inspect(), "configured_map_missing")

    def test_equal_bytes_without_receipt_never_proves_ownership(self):
        self.backup()
        self.target.write_bytes(self.db)
        self.target.chmod(0o640)
        self.assertEqual(self.inspect(), "map_ownership_unproven")
        self.assertTrue(self.target.exists())

    def test_replaced_map_and_config_drift(self):
        self.apply()
        old = self.config / "old.db"
        self.target.rename(old)
        self.target.write_bytes(self.db)
        self.target.chmod(0o640)
        self.assertEqual(self.inspect(), "map_identity_or_content_changed")
        (self.config / "main.cf").write_bytes(self.main + b"# admin edit\n")
        self.assertEqual(self.inspect(), "config_drift")
        self.assertTrue(old.exists() and self.target.exists())

    def test_incomplete_backup_visible_and_unexpected_names_refused(self):
        self.backup()
        incomplete = self.base / ("f"*64)
        incomplete.mkdir(mode=0o700)
        self.assertEqual(self.inventory(), [
            (self.sha, "original_no_map"),
            ("f"*64, "invalid_or_missing_backup")] if self.sha < "f"*64 else [
            ("f"*64, "invalid_or_missing_backup"), (self.sha, "original_no_map")])
        (self.base / "unknown").mkdir()
        with self.assertRaises(R.Refused):
            self.inventory()


if __name__ == "__main__":
    unittest.main()
