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
rotation_spec = importlib.util.spec_from_file_location(
    "scoped_rotation", str(ROOT / "linux/conditional-transport-scoped-rotation.py"))
SR = importlib.util.module_from_spec(rotation_spec)
rotation_spec.loader.exec_module(SR)
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

    def config_fixture(self):
        self.remove_empty_snapshot()
        info, files = self.snapshot_fixture()
        config = self.root / "postfix"
        config.mkdir(mode=0o700)
        os.setxattr(str(config), ATTRIBUTE, bytes.fromhex(info["directory_selinux"]))
        for name, meta in zip(P.X.CONFIGS, info["metadata"]):
            path = config / (name + ".cf")
            path.write_bytes(files[name + ".before"])
            path.chmod(meta["mode"])
            os.setxattr(str(path), ATTRIBUTE, bytes.fromhex(meta["selinux"]))
        fd = os.open(str(config), P.M.DIR_FLAGS)
        self.addCleanup(os.close, fd)
        info["identity"] = P.T.context(fd, self.uid)
        databases = {P.X.C.ROUTE_MAP: b"synthetic routing database",
                     P.X.C.profile_name(info["plan"], 1) + "-sasl":
                         b"synthetic private database"}
        return fd, config, info, files, databases

    def activation_fixture(self):
        fd, config, info, files, databases = self.config_fixture()
        self.store.create_snapshot(info, files)
        journal = self.store.create_activation(databases, self.gid)
        maps = P.X.native_database_set(info, databases)
        return fd, config, info, files, journal, maps

    def test_activation_journal_and_exclusive_map_receipts(self):
        fd, config, info, files, journal, maps = self.activation_fixture()
        record = self.store.read_activation()
        self.assertEqual(record, (info, files, journal, dict.fromkeys(maps)))
        for name, data in maps.items():
            identity = self.store.publish_map(fd, name, data, record)
            record = self.store.read_activation()
            self.assertEqual(record[3][name], identity)
            P.X.checked_map(fd, name, journal, identity, self.uid)
            receipt = self.activation + "/" + P.X.receipt_name(name)
            self.assertEqual(os.getxattr(str(self.root / receipt), ATTRIBUTE).hex(),
                             self.labels[receipt])
            with self.assertRaises(P.Refused):
                self.store.publish_map(fd, name, data, record)
        self.assertTrue(all(record[3].values()))
        self.assertEqual((config / "main.cf").read_bytes(), files["main.before"])
        self.assertEqual((config / "master.cf").read_bytes(), files["master.before"])
        for path in (self.root / self.store.snapshot).rglob("*"):
            if path.is_file():
                self.assertFalse(any(data in path.read_bytes() for data in maps.values()))

    def test_activation_rejects_foreign_equal_bytes_without_receipt(self):
        fd, config, info, files, journal, maps = self.activation_fixture()
        name, data = next(iter(maps.items()))
        record = self.store.read_activation()
        path = config / name
        path.write_bytes(data)
        path.chmod(0o640)
        os.setxattr(str(path), ATTRIBUTE, bytes.fromhex(info["map_selinux"][name]))
        before = P.T.file_identity(path.stat())
        with self.assertRaises(P.Refused):
            self.store.publish_map(fd, name, data, record)
        self.assertEqual(P.T.file_identity(path.stat()), before)
        self.assertIsNone(self.store.read_activation()[3][name])

    def test_activation_lost_receipt_requires_manual_review(self):
        fd, config, info, files, journal, maps = self.activation_fixture()
        name, data = next(iter(maps.items()))
        record = self.store.read_activation()
        real = self.store._write

        def interrupt(relative, raw, previous=None):
            if relative.endswith(".published.json"):
                raise KeyboardInterrupt()
            return real(relative, raw, previous)

        with patch.object(self.store, "_write", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.store.publish_map(fd, name, data, record)
        self.assertEqual((config / name).read_bytes(), data)
        self.assertIsNone(self.store.read_activation()[3][name])
        with self.assertRaises(P.Refused):
            self.store.publish_map(fd, name, data, self.store.read_activation())

    def test_activation_policy_drift_and_pending_marker_block_read(self):
        fd, config, info, files, journal, maps = self.activation_fixture()
        self.labels[self.journal] = label("changed_journal_t")
        with self.assertRaises(P.Refused):
            self.store.read_activation()
        self.labels[self.journal] = label("lmr365_journal_t")
        self.store.write_json(self.pending, {"phase": "pending"})
        with self.assertRaisesRegex(P.Refused, "credential_rotation_recovery_required"):
            self.store.read_activation()

    def test_activation_refuses_stale_review_before_second_map(self):
        fd, config, info, files, journal, maps = self.activation_fixture()
        original = self.store.read_activation()
        first, second = list(maps)
        self.store.publish_map(fd, first, maps[first], original)
        with self.assertRaisesRegex(P.Refused, "private_activation_review_changed"):
            self.store.publish_map(fd, second, maps[second], original)
        self.assertFalse((config / second).exists())

    def live_fixture(self):
        fd, config, info, files, databases = self.config_fixture()
        labels = dict(info["map_selinux"])
        labels["."] = info["directory_selinux"]
        for name, meta in zip(P.X.CONFIGS, info["metadata"]):
            labels[name + ".cf"] = meta["selinux"]
        maps = P.X.native_database_set(info, databases)
        verified = []

        def policy(rules, backend):
            self.assertEqual(rules, info["rules"])
            self.assertEqual(backend, info["backend"])
            return dict(labels)

        def fresh():
            return P.R.observe(fd, info["rules"], info["backend"], info["ca"],
                               self.uid, lambda: None, policy_labels=policy(
                                   info["rules"], info["backend"]))

        def verify(active, reviewed):
            self.assertEqual(reviewed, info)
            P.X.assert_pair(fd, info, files, ".after" if active else ".before", self.uid)
            verified.append(active)
            return True

        def apply(check=verify):
            return self.store.apply_reviewed(fd, (info, files), databases, self.gid,
                                            policy, check, fresh, P.X.APPLY)

        def restore(check=verify):
            return self.store.restore_reviewed(fd, self.store.read_activation(),
                                              policy, check, P.X.RESTORE)

        return fd, config, info, files, maps, labels, verified, apply, restore

    def test_scoped_labeled_apply_and_restore(self):
        fd, config, info, files, maps, labels, verified, apply, restore = self.live_fixture()
        self.assertEqual(apply(), REV)
        record = self.store.read_activation()
        self.assertTrue(all(record[3].values()))
        self.assertEqual(verified, [True])
        for name, data in maps.items():
            path = config / name
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(os.getxattr(str(path), ATTRIBUTE).hex(), labels[name])
            P.X.checked_map(fd, name, record[2], record[3][name], self.uid)
        self.assertEqual(restore(), REV)
        self.assertEqual(verified, [True, False, False])
        self.assertFalse(any((config / name).exists() for name in maps))
        for name in P.X.CONFIGS:
            path = config / (name + ".cf")
            self.assertEqual(path.read_bytes(), files[name + ".before"])
            self.assertEqual(os.getxattr(str(path), ATTRIBUTE).hex(), labels[name + ".cf"])

    def test_scoped_labeled_native_failure_rolls_back(self):
        fd, config, info, files, maps, labels, verified, apply, restore = self.live_fixture()

        def reject_active(active, reviewed):
            return not active

        with self.assertRaises(P.X.ApplyFailed) as result:
            apply(reject_active)
        self.assertTrue(result.exception.rolled_back)
        P.X.assert_pair(fd, info, files, ".before", self.uid)
        self.assertFalse(any((config / name).exists() for name in maps))

    def test_scoped_labeled_interrupted_switch_recovers(self):
        fd, config, info, files, maps, labels, verified, apply, restore = self.live_fixture()
        original = P.T.atomic_write

        def interrupt(target, name, *args, **kwargs):
            if target == fd and name == "main.cf":
                raise KeyboardInterrupt()
            return original(target, name, *args, **kwargs)

        with patch.object(P.T, "atomic_write", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                apply()
        self.assertEqual((config / "main.cf").read_bytes(), files["main.before"])
        self.assertEqual((config / "master.cf").read_bytes(), files["master.after"])
        self.assertEqual(restore(), REV)
        P.X.assert_pair(fd, info, files, ".before", self.uid)
        self.assertFalse(any((config / name).exists() for name in maps))

    def test_scoped_labeled_live_policy_drift_prevents_restore(self):
        fd, config, info, files, maps, labels, verified, apply, restore = self.live_fixture()
        apply()
        name = next(iter(maps))
        original = labels[name]
        labels[name] = label("other_map_t")
        with self.assertRaisesRegex(P.Refused, "live_selinux_policy_changed"):
            restore()
        P.X.assert_pair(fd, info, files, ".after", self.uid)
        self.assertTrue(all((config / n).exists() for n in maps))
        labels[name] = original
        self.assertEqual(restore(), REV)

    def test_scoped_labeled_lost_receipt_fails_closed(self):
        fd, config, info, files, maps, labels, verified, apply, restore = self.live_fixture()
        original = self.store._write

        def fail_receipt(relative, data, previous=None):
            if relative.endswith(".published.json"):
                raise OSError("fixture lost receipt")
            return original(relative, data, previous)

        with patch.object(self.store, "_write", side_effect=fail_receipt):
            with self.assertRaises(P.X.ApplyFailed) as result:
                apply()
        self.assertFalse(result.exception.rolled_back)
        P.X.assert_pair(fd, info, files, ".before", self.uid)
        remaining = [name for name in maps if (config / name).exists()]
        self.assertEqual(len(remaining), 1)
        self.assertIsNone(self.store.read_activation()[3][remaining[0]])
        with self.assertRaises(P.Refused):
            restore()
        self.assertTrue((config / remaining[0]).exists())

    def rotation_fixture(self):
        fd, config, info, files, maps, labels, verified, apply, restore = self.live_fixture()
        self.assertEqual(apply(), REV)
        record = self.store.read_activation()
        name = SR.Q.target_name(info, 1)
        candidate = b"synthetic replacement credential map"
        neighbors = {n: P.T.file_identity((config / n).stat())
                     for n in maps if n != name}

        def policy(rules, backend):
            self.assertEqual(rules, info["rules"])
            self.assertEqual(backend, info["backend"])
            return dict(labels)

        manager = SR.ScopedRotation(self.store, fd, policy)

        def verify(active, reviewed, target, data):
            self.assertEqual(reviewed, info)
            self.assertEqual(target, name)
            self.assertEqual((config / target).read_bytes(), data)
            self.assertEqual(os.getxattr(str(config / target), ATTRIBUTE).hex(), labels[target])
            for n, identity in neighbors.items():
                self.assertEqual(P.T.file_identity((config / n).stat()), identity)
            return True

        def rotate(check=verify):
            return manager.rotate(1, record, candidate, self.gid, SR.CONFIRM,
                                  check, self.store.read_activation)

        def recover(check=verify):
            return manager.recover(manager.pending_review(), self.gid, SR.RECOVER, check)

        return manager, record, config, name, candidate, maps, labels, rotate, recover, verify, restore

    def test_scoped_rotation_and_restore(self):
        manager, old, config, name, candidate, maps, labels, rotate, recover, verify, restore = self.rotation_fixture()
        self.assertTrue(P.R.valid_sha(rotate()))
        current = self.store.read_activation()
        self.assertEqual(current[2]["maps"][name], P.M.digest(candidate))
        self.assertNotEqual(current[3][name], old[3][name])
        self.assertEqual(current[2]["map_selinux"], old[2]["map_selinux"])
        self.assertEqual(os.getxattr(str(self.root / self.overlay), ATTRIBUTE).hex(),
                         self.labels[self.overlay])
        self.assertFalse((self.root / self.pending).exists())
        self.assertEqual(restore(), REV)

    def test_scoped_rotation_native_failure_rolls_back(self):
        manager, old, config, name, candidate, maps, labels, rotate, recover, verify, restore = self.rotation_fixture()

        def fail(active, info, target, data):
            verify(active, info, target, data)
            return not active

        with self.assertRaises(SR.Q.RotationFailed) as error:
            rotate(fail)
        self.assertTrue(error.exception.rolled_back)
        self.assertEqual((config / name).read_bytes(), maps[name])
        self.assertEqual(self.store.read_activation()[2]["maps"], old[2]["maps"])
        self.assertEqual(restore(), REV)

    def test_scoped_rotation_interrupted_overlay_recovery(self):
        manager, old, config, name, candidate, maps, labels, rotate, recover, verify, restore = self.rotation_fixture()
        with patch.object(manager, "overlay", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                rotate()
        with self.assertRaisesRegex(P.Refused, "credential_rotation_recovery_required"):
            self.store.read_activation()
        self.assertEqual(manager.pending_review()[3], "new_retained")
        self.assertEqual(recover(), "new_retained")
        self.assertEqual((config / name).read_bytes(), candidate)
        self.assertEqual(restore(), REV)

    def test_scoped_rotation_interrupted_before_replace(self):
        manager, old, config, name, candidate, maps, labels, rotate, recover, verify, restore = self.rotation_fixture()
        original = P.T.atomic_write

        def interrupt(fd, target, *args, **kwargs):
            if target == name:
                raise KeyboardInterrupt()
            return original(fd, target, *args, **kwargs)

        with patch.object(P.T, "atomic_write", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                rotate()
        self.assertEqual(manager.pending_review()[3], "old_retained")
        self.assertEqual(recover(), "old_retained")
        self.assertEqual(self.store.read_activation(), old)
        self.assertEqual(restore(), REV)

    def test_scoped_rotation_policy_drift_blocks_recovery(self):
        manager, old, config, name, candidate, maps, labels, rotate, recover, verify, restore = self.rotation_fixture()
        with patch.object(manager, "overlay", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                rotate()
        original = self.labels[self.pending]
        self.labels[self.pending] = label("different_journal_t")
        with self.assertRaises(P.Refused):
            recover()
        self.assertTrue((self.root / self.pending).exists())
        self.assertEqual((config / name).read_bytes(), candidate)
        self.labels[self.pending] = original
        self.assertEqual(recover(), "new_retained")
        self.assertEqual(restore(), REV)

    def test_scoped_rotation_refuses_equal_bytes_foreign_inode(self):
        manager, old, config, name, candidate, maps, labels, rotate, recover, verify, restore = self.rotation_fixture()
        with patch.object(manager, "overlay", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                rotate()
        path = config / name
        path.rename(config / "foreign-original")
        path.write_bytes(candidate)
        path.chmod(0o640)
        os.setxattr(str(path), ATTRIBUTE, bytes.fromhex(labels[name]))
        with self.assertRaisesRegex(P.Refused, "rotation_map_publication_unproven"):
            recover()
        self.assertTrue((self.root / self.pending).exists())
        self.assertEqual(path.read_bytes(), candidate)


if __name__ == "__main__":
    unittest.main()
