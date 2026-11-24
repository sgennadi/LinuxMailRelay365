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



    def review_pending(self):
        return Q.pending_review(self.f.fd, self.f.parent, self.revision, self.f.uid, self.f.gid)

    def recover_pending(self, observed=None, verify=None):
        return Q.recover(self.f.fd, self.f.parent, self.revision,
                         self.review_pending() if observed is None else observed,
                         self.f.gid, Q.RECOVER, self.f.uid, self.f.guard, verify or self.verify)

    def interrupt_before_overlay(self):
        with patch.object(Q, "commit_overlay", side_effect=OSError("interrupted commit")):
            with self.assertRaises(Q.RotationFailed) as exc:
                self.rotate()
        self.assertFalse(exc.exception.rolled_back)

    def test_recover_new_retained_map(self):
        self.interrupt_before_overlay()
        self.assertEqual(self.review_pending()[3], "new_retained")
        self.assertEqual(self.recover_pending(), "new_retained")
        self.assertFalse((self.activation / Q.X.ROTATION_PENDING).exists())
        self.check_untouched()
        self.assertEqual(self.review()[2]["maps"][self.target], Q.M.digest(self.candidate))
        Q.X.restore(self.f.fd, self.f.parent, self.revision, Q.X.RESTORE,
                    self.f.uid, self.f.guard, self.f.verify)
        self.f.assert_original()

    def test_recover_old_retained_map(self):
        original = Q.T.atomic_write
        def kill(fd, name, data, meta, uid, replace, published=None, before_replace=None):
            if name == self.target:
                raise KeyboardInterrupt()
            return original(fd, name, data, meta, uid, replace, published, before_replace)
        with patch.object(Q.T, "atomic_write", side_effect=kill):
            with self.assertRaises(KeyboardInterrupt):
                self.rotate()
        self.assertEqual(self.review_pending()[3], "old_retained")
        self.assertEqual(self.recover_pending(), "old_retained")
        self.assertEqual(self.review(), self.record)
        self.check_untouched()

    def test_recover_already_committed_overlay(self):
        original = Q.commit_overlay
        def kill(*args, **kwargs):
            original(*args, **kwargs)
            raise KeyboardInterrupt()
        with patch.object(Q, "commit_overlay", side_effect=kill):
            with self.assertRaises(KeyboardInterrupt):
                self.rotate()
        observed = self.review_pending()
        self.assertEqual(observed[3], "new_retained")
        self.assertEqual(self.recover_pending(observed), "new_retained")
        self.assertEqual(self.review(), observed[0])

    def test_recover_after_rollback_rename(self):
        def fail(active, info, name, data):
            self.verify(active, info, name, data)
            if active:
                raise Q.Refused("native failure")
        with patch.object(Q, "commit_overlay", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                self.rotate(fail)
        self.assertEqual(self.review_pending()[3], "old_restored")
        self.assertEqual(self.recover_pending(), "old_restored")
        self.assertEqual(self.review()[2]["maps"], self.record[2]["maps"])
        self.check_untouched()

    def test_recovery_refuses_foreign_inode(self):
        self.interrupt_before_overlay()
        path = self.f.config / self.target
        path.rename(self.f.config / "foreign-replacement")
        path.write_bytes(self.candidate)
        path.chmod(0o640)
        with self.assertRaisesRegex(Q.Refused, "rotation_map_publication_unproven"):
            self.review_pending()
        self.assertTrue((self.activation / Q.X.ROTATION_PENDING).exists())

    def test_recovery_refuses_orphan_and_native_failure(self):
        self.interrupt_before_overlay()
        scratch = self.f.config / ".lmr365-txn-unknown"
        scratch.write_bytes(b"foreign scratch")
        with self.assertRaisesRegex(Q.Refused, "rotation_scratch_requires_manual_review"):
            self.review_pending()
        self.assertTrue(scratch.exists())
        scratch.unlink()
        def fail(*args):
            raise Q.Refused("native lookup refused")
        with self.assertRaisesRegex(Q.Refused, "native lookup refused"):
            self.recover_pending(verify=fail)
        self.assertTrue((self.activation / Q.X.ROTATION_PENDING).exists())


    def test_recover_new_map_when_rollback_prepared_before_rename(self):
        original = Q.T.atomic_write
        def fail(active, info, name, data):
            self.verify(active, info, name, data)
            if active:
                raise Q.Refused("native failure")
        def kill(fd, name, data, meta, uid, replace, published=None, before_replace=None):
            if name == self.target and data == self.f.maps[self.target]:
                def interrupt(identity):
                    before_replace(identity)
                    raise KeyboardInterrupt()
                return original(fd, name, data, meta, uid, replace, published, interrupt)
            return original(fd, name, data, meta, uid, replace, published, before_replace)
        with patch.object(Q.T, "atomic_write", side_effect=kill):
            with self.assertRaises(KeyboardInterrupt):
                self.rotate(fail)
        self.assertEqual(self.review_pending()[3], "new_retained")
        self.assertEqual(self.recover_pending(), "new_retained")
        self.check_untouched()


    def test_recovery_rejects_stale_approval(self):
        self.interrupt_before_overlay()
        observed = self.review_pending()
        with self.assertRaisesRegex(Q.Refused, "rotation_recovery_review_changed"):
            self.recover_pending(observed=observed[:3] + ("old_retained",))
        self.assertTrue((self.activation / Q.X.ROTATION_PENDING).exists())

    def test_compile_single_selected_account_no_other_credentials(self):
        info = self.record[0]
        credential = {"username": "fixture", "password": "synthetic-new"}
        rule = info["rules"][1]
        selected, plan = Q.C.plan([rule])
        calls = []
        def compile_one(request, digest, confirmation, uid, scratch, ca, **kwargs):
            calls.append(request)
            self.assertEqual(request, {"rules": selected, "credentials": [credential]})
            self.assertEqual(digest, plan)
            self.assertEqual(kwargs["forced_backend"], info["backend"])
            kwargs["verified_consumer"](selected, plan, info["backend"], ca,
                {Q.C.ROUTE_MAP: b"route", Q.C.profile_name(plan, 1) + "-sasl": self.candidate})
            return plan, info["backend"], 1, 1
        with patch.object(Q.C, "tmpfs_parent", return_value="/dev/shm"), \
                patch.object(Q.C, "compile_profiles", side_effect=compile_one):
            self.assertEqual(Q.compile_rotation_candidate(info, 2, credential), self.candidate)
        self.assertEqual(len(calls), 1)
        self.check_untouched()

    def test_compiler_failure_is_redacted(self):
        credential = {"username": "fixture", "password": "private-test-secret"}
        with patch.object(Q.C, "tmpfs_parent", return_value="/dev/shm"), \
                patch.object(Q.C, "compile_profiles", side_effect=OSError(credential["password"])):
            with self.assertRaisesRegex(Q.Refused, "^rotation_candidate_compilation_failed$") as exc:
                Q.compile_rotation_candidate(self.record[0], 1, credential)
            self.assertNotIn(credential["password"], str(exc.exception))
            self.assertTrue(exc.exception.__suppress_context__)

    def test_native_lookup_exact_target_and_redaction(self):
        info = self.record[0]
        key = Q.C.endpoint(info["rules"][0])
        credential = {"username": "fixture", "password": "synthetic-new"}
        expected = Q.C.rows({key: "fixture:synthetic-new"})
        calls = []
        def run(args, identity, data=None):
            calls.append((args, data))
            self.assertEqual(args[-1], "hash:" + str(self.f.config / self.target[:-3]))
            if "-s" in args or data is not None:
                return 0, expected
            return 1, b""
        old = self.f.maps[self.target]
        Q.verify_retained_native(self.f.fd, str(self.f.config), info, self.target,
            old, self.f.uid, (self.f.uid, self.f.gid), run, credential)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1][1], (key + "\n").encode("ascii"))
        with self.assertRaisesRegex(Q.Refused, "^rotation_native_map_verification_failed$"):
            Q.verify_retained_native(self.f.fd, str(self.f.config), info, self.target,
                old, self.f.uid, (self.f.uid, self.f.gid), run,
                {"username": "fixture", "password": "different"})
        self.check_untouched()

    def test_native_lookup_refuses_wrong_directory_or_extra_key(self):
        info = self.record[0]
        key = Q.C.endpoint(info["rules"][0])
        old = self.f.maps[self.target]
        def run(*args):
            return 0, Q.C.rows({key: "fixture:secret", "foreign": "other:secret"})
        for directory in (str(self.f.root), str(self.f.config)):
            with self.assertRaisesRegex(Q.Refused, "rotation_native_map_verification_failed"):
                Q.verify_retained_native(self.f.fd, directory, info, self.target,
                    old, self.f.uid, (self.f.uid, self.f.gid), run)
        self.check_untouched()


if __name__ == "__main__":
    unittest.main()
