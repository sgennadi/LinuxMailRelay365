"""Read-only recovery inventory over disposable multi-transport transactions."""
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "recovery_inventory", str(ROOT / "linux/inspect-conditional-transport-recovery.py"))
I = importlib.util.module_from_spec(spec)
spec.loader.exec_module(I)
fixture_spec = importlib.util.spec_from_file_location(
    "transaction_fixture", str(ROOT / "tests/test_conditional_transport_transaction.py"))
F = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(F)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = F.MultiTransportTransactionTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def scan(self):
        f = self.fixture
        return I.inventory(f.fd, f.parent, f.uid, f.gid)

    def test_empty_inventory_does_not_create_backup(self):
        self.assertEqual(self.scan(), [])
        self.assertFalse((self.fixture.root / I.R.BASE).exists())

    def test_snapshot_apply_restore_and_missing_map(self):
        f = self.fixture
        revision = f.apply()
        self.assertEqual(self.scan(), [(revision, "configured_owned_maps")])
        path = f.config / next(iter(f.maps))
        path.unlink()
        self.assertEqual(self.scan(), [(revision, "configured_maps_missing")])
        f.restore(revision)
        self.assertEqual(self.scan(), [(revision, "original_no_maps")])

    def test_unrelated_edit_is_observed_not_overwritten(self):
        f = self.fixture
        revision = f.apply()
        path = f.config / "master.cf"
        value = path.read_bytes() + b"# unrelated edit\n"
        path.write_bytes(value)
        self.assertEqual(self.scan(), [(revision, "configuration_drift")])
        self.assertEqual(path.read_bytes(), value)

    def test_snapshot_only(self):
        f = self.fixture
        revision = I.R.backup(f.fd, f.parent, f.reviewed, I.R.CONFIRM,
                              f.uid, f.guard, f.review)
        self.assertEqual(self.scan(), [(revision, "snapshot_only")])


if __name__ == "__main__":
    unittest.main()
