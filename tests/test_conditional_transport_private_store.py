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

    def snapshot_fixture(self):
        main = b"myhostname = fixture.example.org\n" + b"# fixture\n" * 4000
        master = b"smtp unix - - n - - smtp\n"
        rules, plan, after, names = P.R.proposal(
            main, master, self.info["rules"], "hash", P.X.C.CA_FILES[0])
        files = dict(zip(P.R.FILES, (main, master) + after))
        meta = {"mode": 0o644, "gid": self.gid, "selinux": label("postfix_etc_t")}
        info = dict(format=P.R.LABELED_FORMAT, plan=plan, rules=rules,
                    backend="hash", ca=P.X.C.CA_FILES[0], identity=[1, 2],
                    metadata=[dict(meta), dict(meta)], map_names=names,
                    directory_selinux=label("postfix_etc_t"),
                    map_selinux={name + ".db": label("postfix_map_t") for name in names},
                    files={name: P.M.digest(data) for name, data in files.items()})
        return info, files

    def remove_empty_snapshot(self):
        (self.root / self.activation).rmdir()
        (self.root / self.store.snapshot).rmdir()

    def test_create_directory_and_complete_snapshot(self):
        self.remove_empty_snapshot()
        (self.root / P.R.BASE).rmdir()
        info, files = self.snapshot_fixture()
        self.assertGreater(len(files["main.before"]), P.M.MAX_BYTES)
        self.assertEqual(self.store.create_snapshot(info, files), REV)
        self.assertEqual(self.store.read_snapshot(), (info, files))
        for relative in (P.R.BASE, self.store.snapshot):
            self.assertEqual(os.getxattr(str(self.root / relative), ATTRIBUTE).hex(),
                             self.labels[relative])
        for name in P.R.FILES + (P.R.MANIFEST,):
            relative = self.store.snapshot + "/" + name
            path = self.root / relative
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(os.getxattr(str(path), ATTRIBUTE).hex(), self.labels[relative])
        with self.assertRaises(P.Refused):
            self.store.create_snapshot(info, files)
        self.store.create_directory(self.activation)
        self.assertEqual(self.store.read_snapshot(allow_activation=True), (info, files))
        with self.assertRaises(P.Refused):
            self.store.read_snapshot()
        self.assertEqual(self.store.read_snapshot(allow_activation=True), (info, files))

    def test_invalid_snapshot_refused_before_directory_creation(self):
        self.remove_empty_snapshot()
        info, files = self.snapshot_fixture()
        files["main.before"] = b"changed"
        with self.assertRaises(P.Refused):
            self.store.create_snapshot(info, files)
        self.assertFalse((self.root / self.store.snapshot).exists())

    def test_interrupted_snapshot_cannot_be_loaded_or_overwritten(self):
        self.remove_empty_snapshot()
        info, files = self.snapshot_fixture()
        real = self.store._write

        def interrupt(relative, data, previous=None):
            if relative.endswith("/master.before"):
                raise KeyboardInterrupt()
            return real(relative, data, previous)

        with patch.object(self.store, "_write", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.store.create_snapshot(info, files)
        self.assertTrue((self.root / self.store.snapshot / "main.before").exists())
        self.assertFalse((self.root / self.store.snapshot / P.R.MANIFEST).exists())
        with self.assertRaises(P.Refused):
            self.store.read_snapshot()
        with self.assertRaises(P.Refused):
            self.store.create_snapshot(info, files)

    def test_directory_label_failure_does_not_modify_existing_store(self):
        self.remove_empty_snapshot()
        baseline = self.store.observe_directory(P.R.BASE)
        with patch.object(P.T, "restore_file_metadata", side_effect=OSError("fixture")):
            with self.assertRaises(OSError):
                self.store.create_directory(self.store.snapshot)
        self.assertEqual(self.store.observe_directory(P.R.BASE), baseline)
        with self.assertRaises(P.Refused):
            self.store.observe_directory(self.store.snapshot)

    def test_new_record_policy_drift_before_link_refuses_publication(self):
        original = P.T.restore_file_metadata

        def change(fd, meta):
            original(fd, meta)
            self.labels[self.pending] = label("changed_journal_t")

        with patch.object(P.T, "restore_file_metadata", side_effect=change):
            with self.assertRaisesRegex(P.Refused, "private_publication_context_changed"):
                self.store.write_json(self.pending, {"phase": "pending"})
        self.assertFalse((self.root / self.pending).exists())
        self.assertFalse(any(p.name.startswith(".lmr365-txn-")
                             for p in (self.root / self.activation).iterdir()))


if __name__ == "__main__":
    unittest.main()
