"""Real user-xattr substitutes for labeled map/config publication.

This exercises metadata-preserving filesystem operations, NOT SELinux
kernel authorization, actual policy, or production activation.
"""
import importlib.util
import os
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "labeled_fixture", str(ROOT / "tests/test_conditional_transport_transaction.py"))
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
X, R, T = F.X, F.X.R, F.X.T
Q = R.sibling("labeled_rotation_fixture", "conditional-transport-rotation.py")
ATTRIBUTE = "user.lmr365_test_selinux"


def label(kind, level="s0"):
    return ("system_u:object_r:" + kind + ":" + level + "\0").encode("ascii")


class LabeledTransportTests(unittest.TestCase):
    def setUp(self):
        self.f = F.MultiTransportTransactionTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        self.labels = {".": label("postfix_etc_t"),
                       "main.cf": label("postfix_etc_t"),
                       "master.cf": label("postfix_etc_t", "s0:c0,c2")}
        for index, name in enumerate(self.f.maps):
            self.labels[name] = label("postfix_etc_t", "s0:c" + str(index + 3))
        try:
            for name in (".", "main.cf", "master.cf"):
                os.setxattr(str(self.f.config / name), ATTRIBUTE, self.labels[name])
        except OSError as exc:
            self.skipTest("filesystem user xattrs unavailable: " + str(exc.errno))
        p = patch.object(T, "SELINUX_XATTR", ATTRIBUTE)
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(Q.T, "SELINUX_XATTR", ATTRIBUTE)
        p.start()
        self.addCleanup(p.stop)
        self.policy = {name: value.hex() for name, value in self.labels.items()}

    def review(self):
        return R.observe(self.f.fd, self.f.rules, "hash", X.C.CA_FILES[0],
                         self.f.uid, self.f.guard, policy_labels=self.policy)

    def verify(self, active, info):
        phase = ".after" if active else ".before"
        record = self.reviewed
        self.assertEqual(info, record[0])
        X.assert_pair(self.f.fd, info, record[1], phase, self.f.uid)
        for name in ("main.cf", "master.cf"):
            self.assertEqual(os.getxattr(str(self.f.config / name), ATTRIBUTE),
                             self.labels[name])

    def apply(self):
        self.reviewed = self.review()
        return X.apply(self.f.fd, self.f.parent, self.reviewed, self.f.databases,
                       self.f.gid, X.APPLY, self.f.uid, self.f.guard, self.verify, self.review)

    def restore(self, revision):
        return X.restore(self.f.fd, self.f.parent, revision, X.RESTORE,
                         self.f.uid, self.f.guard, self.verify)

    def test_distinct_labels_preserved_by_apply_restore(self):
        with self.assertRaises(X.Refused):
            self.f.review()
        revision = self.apply()
        info, files, journal, receipts = X.load(self.f.parent, revision, self.f.uid)
        self.assertEqual(info["format"], R.LABELED_FORMAT)
        self.assertEqual(journal["format"], "LMR365-TRANSPORT-PUBLICATION-V2")
        self.assertEqual(journal["map_selinux"], info["map_selinux"])
        for name, data in self.f.maps.items():
            path = self.f.config / name
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(os.getxattr(str(path), ATTRIBUTE), self.labels[name])
            self.assertEqual(X.map_meta(journal, name)["selinux"], self.labels[name].hex())
            X.checked_map(self.f.fd, name, journal, receipts[name], self.f.uid)
        with self.assertRaises(X.Refused):
            X.map_meta(journal)
        self.assertEqual(self.restore(revision), revision)
        for name in ("main.cf", "master.cf"):
            self.assertEqual((self.f.config / name).read_bytes(), self.f.original[name])
            self.assertEqual(os.getxattr(str(self.f.config / name), ATTRIBUTE), self.labels[name])
        self.assertFalse(any((self.f.config / name).exists() for name in self.f.maps))

    def test_relabelled_directory_blocks_restore(self):
        revision = self.apply()
        os.setxattr(str(self.f.config), ATTRIBUTE, label("postfix_etc_t", "s0:c9"))
        with self.assertRaisesRegex(X.Refused, "transport_directory_label_changed"):
            self.restore(revision)
        self.assertTrue(all((self.f.config / name).exists() for name in self.f.maps))

    def test_relabelled_map_blocks_restore_before_config_write(self):
        revision = self.apply()
        name = next(iter(self.f.maps))
        path = self.f.config / name
        original_main = (self.f.config / "main.cf").read_bytes()
        os.setxattr(str(path), ATTRIBUTE, label("postfix_etc_t", "s0:c9"))
        with self.assertRaisesRegex(X.Refused, "map_identity_or_content_changed"):
            self.restore(revision)
        self.assertEqual((self.f.config / "main.cf").read_bytes(), original_main)
        self.assertTrue(path.exists())

    def test_reject_missing_labels_wrong_contexts_and_unknown_attributes(self):
        name = next(iter(self.f.maps))
        good = self.policy.copy()
        for invalid in (dict(good, **{name: label("etc_t").hex()}),
                        dict(good, **{"main.cf": label("postfix_etc_t","s0:c9").hex()}),
                        {k: v for k, v in good.items() if k != name}):
            self.policy = invalid
            with self.assertRaises(X.Refused):
                self.review()
        self.policy = good
        os.setxattr(str(self.f.config / "main.cf"), "user.lmr365_unknown", b"foreign")
        with self.assertRaisesRegex(X.Refused, "unsupported_extended_file_metadata"):
            self.review()

    def test_label_snapshot_cannot_downgrade_or_omit_map(self):
        info, files = self.review()
        for changed in (dict(info, format=R.LEGACY_FORMAT),
                        dict(info, map_selinux={}),
                        dict(info, directory_selinux=label("unlabeled_t").hex())):
            with self.assertRaises(X.Refused):
                R.validate(changed, files)

    def test_failed_label_write_does_not_mutate_original_configs(self):
        self.reviewed = self.review()
        with patch.object(T, "restore_file_metadata", side_effect=OSError("label refused")):
            with self.assertRaises(X.ApplyFailed) as result:
                X.apply(self.f.fd, self.f.parent, self.reviewed, self.f.databases,
                        self.f.gid, X.APPLY, self.f.uid, self.f.guard, self.verify, self.review)
        self.assertTrue(result.exception.rolled_back)
        for name in ("main.cf", "master.cf"):
            self.assertEqual((self.f.config / name).read_bytes(), self.f.original[name])
            self.assertEqual(os.getxattr(str(self.f.config / name), ATTRIBUTE), self.labels[name])
        self.assertFalse(any((self.f.config / name).exists() for name in self.f.maps))

    def rotation_fixture(self):
        revision = self.apply()
        record = Q.X.load(self.f.parent, revision, self.f.uid)
        name = Q.target_name(record[0], 1)
        candidate = b"synthetic labeled rotated database"
        others = {n: Q.T.file_identity((self.f.config / n).stat())
                  for n in self.f.maps if n != name}

        def verify(active, info, target, data):
            self.assertEqual(info, record[0])
            self.assertEqual(target, name)
            self.assertEqual((self.f.config / name).read_bytes(), data)
            self.assertEqual(os.getxattr(str(self.f.config / name), ATTRIBUTE),
                             self.labels[name])
            for n, identity in others.items():
                self.assertEqual(Q.T.file_identity((self.f.config / n).stat()), identity)
                self.assertEqual(os.getxattr(str(self.f.config / n), ATTRIBUTE), self.labels[n])

        def fresh():
            return Q.X.load(self.f.parent, revision, self.f.uid)

        def rotate(verification=verify):
            return Q.rotate(self.f.fd, self.f.parent, revision, 1, record, candidate,
                            self.f.gid, Q.CONFIRM, self.f.uid, self.f.guard, verification, fresh)

        return revision, record, name, candidate, rotate, verify, fresh

    def test_labeled_rotation_keeps_map_metadata_and_restore(self):
        revision, old, name, candidate, rotate, verify, fresh = self.rotation_fixture()
        self.assertTrue(Q.R.valid_sha(rotate()))
        actual = fresh()
        self.assertEqual(actual[2]["map_selinux"], old[2]["map_selinux"])
        self.assertEqual(actual[2]["maps"][name], Q.M.digest(candidate))
        self.assertNotEqual(actual[3][name], old[3][name])
        verify(True, actual[0], name, candidate)
        self.assertEqual(self.restore(revision), revision)

    def test_labeled_rotation_native_failure_restores_bytes_and_label(self):
        revision, old, name, candidate, rotate, verify, fresh = self.rotation_fixture()

        def fail(active, info, target, data):
            verify(active, info, target, data)
            if active:
                raise Q.Refused("synthetic verification failure")

        with self.assertRaises(Q.RotationFailed) as result:
            rotate(fail)
        self.assertTrue(result.exception.rolled_back)
        self.assertEqual(fresh()[2]["maps"], old[2]["maps"])
        self.assertEqual(fresh()[2]["map_selinux"], old[2]["map_selinux"])
        verify(False, old[0], name, self.f.maps[name])
        self.assertEqual(self.restore(revision), revision)

    def test_labeled_rotation_pending_recovery_keeps_new_label(self):
        revision, old, name, candidate, rotate, verify, fresh = self.rotation_fixture()
        with patch.object(Q, "commit_overlay", side_effect=OSError("fixture interruption")):
            with self.assertRaises(Q.RotationFailed) as result:
                rotate()
        self.assertFalse(result.exception.rolled_back)
        pending = Q.pending_review(self.f.fd, self.f.parent, revision, self.f.uid, self.f.gid)
        self.assertEqual(pending[3], "new_retained")
        self.assertEqual(Q.recover(self.f.fd, self.f.parent, revision, pending, self.f.gid,
                                  Q.RECOVER, self.f.uid, self.f.guard, verify), "new_retained")
        self.assertEqual(fresh()[2]["map_selinux"], old[2]["map_selinux"])
        verify(True, old[0], name, candidate)
        self.assertEqual(self.restore(revision), revision)

    def test_labeled_private_store_refused_before_marker_or_map_write(self):
        revision, old, name, candidate, rotate, verify, fresh = self.rotation_fixture()
        activation = self.f.root / Q.R.BASE / revision / Q.R.ACTIVATION
        os.setxattr(str(activation / Q.X.JOURNAL), ATTRIBUTE, label("var_lib_t"))
        with self.assertRaisesRegex(Q.Refused, "labeled_private_recovery_store_unsupported"):
            rotate()
        self.assertFalse((activation / Q.X.ROTATION_PENDING).exists())
        self.assertEqual((self.f.config / name).read_bytes(), self.f.maps[name])
        verify(False, old[0], name, self.f.maps[name])

    def test_labeled_native_lookup_requires_exact_metadata_before_query(self):
        revision, old, name, candidate, rotate, verify, fresh = self.rotation_fixture()
        credential = {"username": "fixture", "password": "synthetic"}
        key = Q.C.endpoint(old[0]["rules"][0])
        rows = Q.C.rows({key: "fixture:synthetic"})
        calls = []

        def native(args, identity, data=None):
            calls.append(args)
            return (0, rows) if "-s" in args or data is not None else (1, b"")

        Q.verify_retained_native(self.f.fd, str(self.f.config), old[0], name,
                                 self.f.maps[name], self.f.uid, (self.f.uid, self.f.gid),
                                 native, credential)
        self.assertEqual(len(calls), 3)
        os.setxattr(str(self.f.config / name), ATTRIBUTE, label("postfix_etc_t", "s0:c99"))
        with self.assertRaisesRegex(Q.Refused, "rotation_native_map_verification_failed"):
            Q.verify_retained_native(self.f.fd, str(self.f.config), old[0], name,
                                     self.f.maps[name], self.f.uid, (self.f.uid, self.f.gid),
                                     native, credential)
        self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
