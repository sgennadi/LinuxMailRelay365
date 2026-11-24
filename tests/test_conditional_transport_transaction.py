"""New transport sets: private snapshot, ordered publication and fault recovery."""
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "transport_transaction", str(ROOT / "linux/conditional-transport-transaction.py"))
X = importlib.util.module_from_spec(spec)
spec.loader.exec_module(X)


class MultiTransportTransactionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.config = self.root / "postfix"
        self.config.mkdir(mode=0o700)
        self.parent = os.open(str(self.root), X.M.DIR_FLAGS)
        self.fd = os.open(str(self.config), X.M.DIR_FLAGS)
        self.addCleanup(os.close, self.parent)
        self.addCleanup(os.close, self.fd)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.original = {
            "main.cf": b"inet_interfaces = loopback-only\nmydestination = localhost\n",
            "master.cf": b"smtp unix - - n - - smtp\n"}
        for name, data in self.original.items():
            path = self.config / name
            path.write_bytes(data)
            path.chmod(0o644)
        self.rules = [
            dict(selector="exact-envelope-sender", pattern="first@example.org",
                 host="smtp.example.net", port=587, tls="starttls", auth="password"),
            dict(selector="exact-envelope-sender", pattern="second@example.org",
                 host="smtp.example.net", port=465, tls="implicit", auth="password")]
        _, plan = X.C.plan(self.rules)
        self.databases = {X.C.ROUTE_MAP: b"synthetic routing database",
                          X.C.profile_name(plan, 1) + "-sasl": b"synthetic private A",
                          X.C.profile_name(plan, 2) + "-sasl": b"synthetic private B"}
        self.reviewed = self.review()
        self.info, self.files = self.reviewed
        self.maps = X.native_database_set(self.info, self.databases)

    def guard(self):
        pass

    def review(self):
        return X.R.observe(self.fd, self.rules, "hash", X.C.CA_FILES[0],
                           self.uid, self.guard)

    def verify(self, active, info):
        self.assertEqual(info, self.info)
        suffix = ".after" if active else ".before"
        for name in X.CONFIGS:
            self.assertEqual((self.config / (name + ".cf")).read_bytes(),
                             self.files[name + suffix])

    def apply(self, verify=None):
        return X.apply(self.fd, self.parent, self.reviewed, self.databases,
                       self.gid, X.APPLY, self.uid, self.guard,
                       verify or self.verify, self.review)

    def restore(self, revision):
        return X.restore(self.fd, self.parent, revision, X.RESTORE,
                         self.uid, self.guard, self.verify)

    def assert_original(self):
        self.verify(False, self.info)
        self.assertFalse(any((self.config / name).exists() for name in self.maps))

    def test_backup_without_activation_is_readable(self):
        rev = X.R.backup(self.fd, self.parent, self.reviewed, X.R.CONFIRM,
                         self.uid, self.guard, self.review)
        self.assertEqual(X.R.load(self.parent, rev, self.uid), self.reviewed)
        self.assert_original()
        with self.assertRaises(FileNotFoundError):
            self.restore(rev)

    def test_apply_restore_no_duplicate_password_database(self):
        rev = self.apply()
        self.verify(True, self.info)
        record = X.load(self.parent, rev, self.uid)
        self.assertEqual(record[:2], self.reviewed)
        self.assertTrue(all(record[3].values()))
        for name, data in self.maps.items():
            path = self.config / name
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        backup = self.root / X.R.BASE / rev
        for path in backup.rglob("*"):
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                for data in self.databases.values():
                    self.assertNotIn(data, path.read_bytes())
        self.assertEqual(self.restore(rev), rev)
        self.assert_original()
        self.assertEqual(self.restore(rev), rev)

    def test_failure_after_native_verification_rolls_back(self):
        def fail(active, info):
            self.verify(active, info)
            if active:
                raise X.Refused("injected_failure")
        with self.assertRaises(X.ApplyFailed) as result:
            self.apply(fail)
        self.assertTrue(result.exception.rolled_back)
        self.assert_original()
        X.load(self.parent, result.exception.revision, self.uid)

    def test_failure_between_master_and_main_rolls_back(self):
        original = X.T.atomic_write
        def fail(fd, name, data, meta, uid, replace, published=None):
            if name == "main.cf" and data == self.files["main.after"]:
                raise OSError("injected main publication failure")
            return original(fd, name, data, meta, uid, replace, published)
        with patch.object(X.T, "atomic_write", side_effect=fail):
            with self.assertRaises(X.ApplyFailed) as result:
                self.apply()
        self.assertTrue(result.exception.rolled_back)
        self.assert_original()

    def test_existing_map_refused_before_backup(self):
        target = self.config / next(iter(self.maps))
        target.write_bytes(b"foreign")
        with self.assertRaises(X.Refused):
            self.apply()
        self.assertEqual(target.read_bytes(), b"foreign")
        self.assertFalse((self.root / X.R.BASE).exists())

    def test_equal_bytes_replacement_blocks_restore(self):
        rev = self.apply()
        name = next(iter(self.maps))
        target = self.config / name
        target.rename(self.config / "old.db")
        target.write_bytes(self.maps[name])
        target.chmod(0o640)
        with self.assertRaisesRegex(X.Refused, "map_identity_or_content_changed"):
            self.restore(rev)
        self.verify(True, self.info)
        self.assertTrue(target.exists())

    def test_missing_receipt_refuses_deletion(self):
        rev = self.apply()
        name = next(iter(self.maps))
        path = self.root / X.R.BASE / rev / X.R.ACTIVATION / X.receipt_name(name)
        path.unlink()
        with self.assertRaisesRegex(X.Refused, "map_publication_unproven"):
            self.restore(rev)
        self.verify(True, self.info)
        self.assertTrue((self.config / name).is_file())

    def test_unrelated_configuration_edit_blocks_restore(self):
        rev = self.apply()
        path = self.config / "master.cf"
        changed = path.read_bytes() + b"# administrator edit\n"
        path.write_bytes(changed)
        with self.assertRaisesRegex(X.Refused, "unrelated_configuration_drift"):
            self.restore(rev)
        self.assertEqual(path.read_bytes(), changed)

    def test_no_clobber_race_does_not_delete_external_map(self):
        original = X.T.atomic_write
        first = sorted(self.maps)[0]
        def race(fd, name, data, meta, uid, replace, published=None):
            if name == first and not replace:
                path = self.config / name
                path.write_bytes(data)
                path.chmod(0o640)
            return original(fd, name, data, meta, uid, replace, published)
        with patch.object(X.T, "atomic_write", side_effect=race):
            with self.assertRaises(X.ApplyFailed) as result:
                self.apply()
        self.assertFalse(result.exception.rolled_back)
        self.verify(False, self.info)
        self.assertEqual((self.config / first).read_bytes(), self.maps[first])
        with self.assertRaisesRegex(X.Refused, "map_publication_unproven"):
            self.restore(result.exception.revision)

    def test_conflicting_assignments_refused(self):
        for key in X.R.CONFLICTS:
            (self.config / "main.cf").write_bytes(
                self.original["main.cf"] + key.encode("ascii") + b" =\n")
            with self.assertRaisesRegex(X.Refused, "existing_routing_map_assignment"):
                self.review()


if __name__ == "__main__":
    unittest.main()
