"""Real filesystem user-xattr substitute for private recovery metadata."""
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "private_store", str(ROOT / "linux/conditional-transport-private-store.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
ATTRIBUTE = "user.lmr365_test_selinux"
REV = "a" * 64


def label(kind):
    return ("system_u:object_r:" + kind + ":s0\0").encode("ascii").hex()


class PrivateStoreTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = pathlib.Path(work.name)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.parent = os.open(str(self.root), P.M.DIR_FLAGS)
        self.addCleanup(os.close, self.parent)
        rules = [dict(selector="exact-envelope-sender", pattern="one@example.org",
                      host="smtp.example.net", port=587, tls="starttls", auth="password")]
        rules, plan = P.X.C.plan(rules)
        self.info = dict(rules=rules, plan=plan, backend="hash",
                         map_names=["lmr365-" + plan + "-sender-transport",
                                    P.X.C.profile_name(plan, 1) + "-sasl"])
        self.paths = P.policy_paths(self.info, REV)
        self.labels = {name: label("var_lib_t" if mode == "dir" else "lmr365_journal_t")
                       for name, mode in self.paths.items()}
        self.activation = P.R.BASE + "/" + REV + "/" + P.R.ACTIVATION
        self.pending = self.activation + "/" + P.X.ROTATION_PENDING
        self.overlay = self.activation + "/" + P.X.ROTATION_CURRENT
        self.journal = self.activation + "/" + P.X.JOURNAL
        try:
            for name, mode in self.paths.items():
                if mode == "dir":
                    path = self.root / name
                    path.mkdir(mode=0o700)
                    os.setxattr(str(path), ATTRIBUTE, bytes.fromhex(self.labels[name]))
        except OSError as exc:
            self.skipTest("user xattrs unavailable: " + str(exc.errno))
        p = patch.object(P.T, "SELINUX_XATTR", ATTRIBUTE)
        p.start()
        self.addCleanup(p.stop)

        def policy(relative, mode):
            self.assertEqual(self.paths[relative], mode)
            return self.labels[relative]

        self.store = P.PrivateStore(self.parent, self.info, REV, self.uid,
                                    self.gid, lambda: None, policy)

    def test_create_replace_and_separate_destination_labels(self):
        self.labels[self.overlay] = label("other_journal_t")
        first = self.store.write_json(self.pending, {"phase": "pending"})
        updated = self.store.write_json(self.pending, {"phase": "commit"}, first)
        overlay = self.store.write_json(self.overlay, {"generation": REV})
        self.assertEqual(updated[0], P.M.canonical({"phase": "commit"}))
        self.assertEqual(updated[1]["selinux"], self.labels[self.pending])
        self.assertNotEqual(updated[2], first[2])
        self.assertEqual(overlay[1]["selinux"], self.labels[self.overlay])
        self.assertEqual((self.root / self.pending).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.store.observe(self.pending), updated)

    def test_existing_target_and_stale_receipt_refused(self):
        first = self.store.write_json(self.pending, {"phase": "pending"})
        with self.assertRaises(P.Refused):
            self.store.write_json(self.pending, {"phase": "commit"})
        updated = self.store.write_json(self.pending, {"phase": "commit"}, first)
        with self.assertRaises(P.Refused):
            self.store.write_json(self.pending, {"phase": "rollback"}, first)
        self.assertEqual(self.store.observe(self.pending), updated)

    def test_policy_drift_and_foreign_xattr_refused(self):
        first = self.store.write_json(self.pending, {"phase": "pending"})
        self.labels[self.pending] = label("changed_journal_t")
        with self.assertRaises(P.Refused):
            self.store.write_json(self.pending, {"phase": "commit"}, first)
        self.labels[self.pending] = first[1]["selinux"]
        os.setxattr(str(self.root / self.pending), "user.foreign", b"foreign")
        with self.assertRaises(P.Refused):
            self.store.write_json(self.pending, {"phase": "commit"}, first)
        self.assertEqual((self.root / self.pending).read_bytes(), first[0])

    def test_directory_drift_and_symlink_refused(self):
        first = self.store.write_json(self.pending, {"phase": "pending"})
        directory = self.root / self.activation
        os.setxattr(str(directory), ATTRIBUTE, bytes.fromhex(label("changed_t")))
        with self.assertRaises(P.Refused):
            self.store.write_json(self.pending, {"phase": "commit"}, first)
        os.setxattr(str(directory), ATTRIBUTE, bytes.fromhex(self.labels[self.activation]))
        path = self.root / self.pending
        path.rename(directory / "foreign")
        path.symlink_to(directory / "foreign")
        with self.assertRaises(OSError):
            self.store.write_json(self.pending, {"phase": "commit"}, first)
        self.assertEqual((directory / "foreign").read_bytes(), first[0])

    def test_immutable_and_arbitrary_paths_refused(self):
        for name in (self.journal, "../foreign", self.activation + "/unknown"):
            with self.assertRaises(P.Refused):
                self.store.write_json(name, {"phase": "pending"})
        self.assertFalse((self.root / self.journal).exists())

    def test_relabel_failure_keeps_original(self):
        first = self.store.write_json(self.pending, {"phase": "pending"})
        with patch.object(P.T, "restore_file_metadata", side_effect=OSError("fixture")):
            with self.assertRaises(OSError):
                self.store.write_json(self.pending, {"phase": "commit"}, first)
        self.assertEqual(self.store.observe(self.pending), first)


if __name__ == "__main__":
    unittest.main()
