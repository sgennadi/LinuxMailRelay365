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


if __name__ == "__main__":
    unittest.main()
