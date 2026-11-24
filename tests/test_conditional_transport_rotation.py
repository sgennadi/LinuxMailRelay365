"""Single credential DB rotation, using only disposable test configs."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

Q = load("rotation", "linux/conditional-transport-rotation.py")
F = load("transaction_fixture", "tests/test_conditional_transport_transaction.py")


class CredentialRotationTests(unittest.TestCase):
    def setUp(self):
        self.f = F.MultiTransportTransactionTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        self.revision = self.f.apply()
        self.record = Q.X.load(self.f.parent, self.revision, self.f.uid)
        self.target = Q.target_name(self.record[0], 1)
        self.candidate = b"synthetic rotated private credential database"
        self.activation = self.f.root / Q.R.BASE / self.revision / Q.R.ACTIVATION

    def review(self):
        return Q.X.load(self.f.parent, self.revision, self.f.uid)

    def verify(self, active, info, name, data):
        self.assertEqual(info, self.record[0])
        self.assertEqual(name, self.target)
        self.assertEqual((self.f.config / name).read_bytes(), data)

    def rotate(self, verify=None, index=1):
        return Q.rotate(self.f.fd, self.f.parent, self.revision, index,
                        self.record, self.candidate, self.f.gid, Q.CONFIRM,
                        self.f.uid, self.f.guard, verify or self.verify, self.review)

    def check_untouched(self):
        self.f.verify(True, self.record[0])
        for name, data in self.f.maps.items():
            if name != self.target:
                self.assertEqual((self.f.config / name).read_bytes(), data)
                self.assertEqual(Q.T.file_identity((self.f.config / name).stat()),
                                 self.record[3][name])

    def test_single_map_replaced_and_normal_restore_still_works(self):
        self.assertTrue(Q.R.valid_sha(self.rotate()))
        self.check_untouched()
        result = self.review()
        self.assertEqual(result[2]["maps"][self.target], Q.M.digest(self.candidate))
        self.assertNotEqual(result[3][self.target], self.record[3][self.target])
        self.assertFalse((self.activation / Q.X.ROTATION_PENDING).exists())
        for path in self.activation.iterdir():
            if path.is_file():
                self.assertNotIn(self.candidate, path.read_bytes())
                self.assertNotIn(self.f.maps[self.target], path.read_bytes())
        Q.X.restore(self.f.fd, self.f.parent, self.revision, Q.X.RESTORE,
                    self.f.uid, self.f.guard, self.f.verify)
        self.f.assert_original()

    def test_repeated_rotation_preserves_other_maps(self):
        self.rotate()
        self.record = self.review()
        self.candidate = b"synthetic third credential database"
        self.rotate()
        self.check_untouched()
        self.assertEqual(self.review()[2]["maps"][self.target], Q.M.digest(self.candidate))

    def test_native_failure_rolls_back_old_bytes_and_updates_identity(self):
        def fail(active, info, name, data):
            self.verify(active, info, name, data)
            if active:
                raise Q.Refused("injected verification failure")
        with self.assertRaises(Q.RotationFailed) as exc:
            self.rotate(fail)
        self.assertTrue(exc.exception.rolled_back)
        self.check_untouched()
        self.assertEqual((self.f.config / self.target).read_bytes(), self.f.maps[self.target])
        self.assertEqual(self.review()[2]["maps"], self.record[2]["maps"])
        self.assertFalse((self.activation / Q.X.ROTATION_PENDING).exists())

    def test_foreign_replacement_refused_before_marker(self):
        path = self.f.config / self.target
        path.rename(self.f.config / "external-old")
        path.write_bytes(self.f.maps[self.target])
        path.chmod(0o640)
        with self.assertRaises(Q.Refused):
            self.rotate()
        self.assertFalse((self.activation / Q.X.ROTATION_PENDING).exists())

    def test_pending_marker_blocks_normal_load_and_restore(self):
        with patch.object(Q, "commit_overlay", side_effect=OSError("injected commit failure")):
            with self.assertRaises(Q.RotationFailed) as exc:
                self.rotate()
        self.assertFalse(exc.exception.rolled_back)
        self.assertTrue((self.activation / Q.X.ROTATION_PENDING).is_file())
        self.assertEqual((self.f.config / self.target).read_bytes(), self.candidate)
        with self.assertRaisesRegex(Q.Refused, "credential_rotation_recovery_required"):
            self.review()
        with self.assertRaisesRegex(Q.Refused, "credential_rotation_recovery_required"):
            Q.X.restore(self.f.fd, self.f.parent, self.revision, Q.X.RESTORE,
                        self.f.uid, self.f.guard, self.f.verify)
        self.check_untouched()

    def test_invalid_route_index_refused(self):
        with self.assertRaisesRegex(Q.Refused, "password_transport_required"):
            self.rotate(index=0)
        self.assertFalse((self.activation / Q.X.ROTATION_PENDING).exists())


if __name__ == "__main__":
    unittest.main()
