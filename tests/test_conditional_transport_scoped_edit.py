"""Scoped two-generation edit with real user xattrs and synthetic DB bytes."""
import importlib.util
import os
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


F = load("scoped_edit_fixture", "tests/test_conditional_transport_private_store.py")
S = load("scoped_edit", "linux/conditional-transport-scoped-edit.py")
P = F.P
NEW = "b" * 64


class ScopedEditTests(unittest.TestCase):
    def setUp(self):
        self.f = F.PrivateStoreTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        fd, config, info, files, maps, labels, _, apply, restore = self.f.live_fixture()
        self.fd, self.config, self.info, self.files = fd, config, info, files
        self.maps, self.labels, self.restore = maps, labels, restore
        apply()
        self.old = self.f.store
        self.original = self.old.read_activation()
        self.ids = {name: P.T.file_identity((config / name).stat()) for name in maps}
        rule = info["rules"][0]
        self.draft = [dict(rule, pattern="second@example.org", host="replacement.example.net",
                           port=2526, tls="implicit"), rule]
        _, plan, _, names = P.R.proposal(files["main.before"], files["master.before"],
                                         self.draft, info["backend"], info["ca"])
        self.new_labels = {k: labels[k] for k in (".", "main.cf", "master.cf")}
        self.new_labels.update({name + ".db": F.label("new_map_t") for name in names})
        self.policies = {info["plan"]: labels, plan: self.new_labels}
        self.manager = S.ScopedEdit(self.old, fd, self.policy)
        self.reviewed = self.manager.review(self.draft, self.f.gid, self.verify)
        self.new_info = self.reviewed[1]
        self.assertEqual(self.reviewed[3], (None, 1))
        paths = P.policy_paths(self.new_info, NEW)
        self.f.labels.update({k: F.label("var_lib_t" if mode == "dir" else "new_journal_t")
                              for k, mode in paths.items() if k not in self.f.labels})
        self.new = P.PrivateStore(self.f.parent, self.new_info, NEW, self.f.uid,
                                  self.f.gid, self.f.store.guard,
                                  lambda relative, mode: self.f.labels[relative])
        self.slots = [{"mode": "new", "credential": {"username": "fixture", "password": "synthetic"}},
                      {"mode": "retain"}]
        self.target_old = S.E.Q.target_name(info, 1)
        self.target_new = S.E.Q.target_name(self.new_info, 2)
        self.new_maps = P.X.native_database_set(self.new_info, {
            S.E.C.ROUTE_MAP: b"new synthetic route",
            S.E.C.profile_name(plan, 1) + "-sasl": b"new synthetic account",
            S.E.C.profile_name(plan, 2) + "-sasl": maps[self.target_old]})
        p = patch.object(S.E.T, "SELINUX_XATTR", F.ATTRIBUTE)
        p.start()
        self.addCleanup(p.stop)

    def policy(self, rules, backend):
        self.assertEqual(backend, self.info["backend"])
        return dict(self.policies[P.X.C.plan(rules)[1]])

    def verify(self, record):
        P.X.assert_pair(self.fd, record[0], record[1], ".after", self.f.uid)
        for name in P.X.map_names(record[0]):
            P.X.checked_map(self.fd, name, record[2], record[3][name], self.f.uid)
        return True

    def begin(self, verify=None):
        with patch.object(S.E, "compile_route", return_value=b"new synthetic route"), \
                patch.object(S.E.Q, "compile_rotation_candidate", return_value=b"new synthetic account"), \
                patch.object(S.E.Q, "verify_retained_native") as retained:
            result = self.manager.begin(self.new, self.reviewed, self.slots, str(self.config),
                                        (self.f.uid, self.f.gid), self.verify,
                                        lambda *args: None, verify or self.verify, S.BEGIN)
            self.assertEqual(retained.call_count, 1)
            self.assertEqual(retained.call_args[0][3:5],
                             (self.target_old, self.maps[self.target_old]))
            return result

    def observe(self):
        return self.manager.observe(self.new)

    def resolve(self, decision):
        return self.manager.resolve(self.new, self.observe(), self.verify, decision)

    def old_preserved(self):
        for name, data in self.maps.items():
            self.assertEqual((self.config / name).read_bytes(), data)
            self.assertEqual(P.T.file_identity((self.config / name).stat()), self.ids[name])
            self.assertEqual(os.getxattr(str(self.config / name), F.ATTRIBUTE).hex(), self.labels[name])

    def new_verified(self):
        for name, data in self.new_maps.items():
            self.assertEqual((self.config / name).read_bytes(), data)
            self.assertEqual(os.getxattr(str(self.config / name), F.ATTRIBUTE).hex(),
                             self.new_labels[name])

    def test_commit_and_restore_with_destination_labels(self):
        self.assertEqual(self.begin(), NEW)
        self.old_preserved()
        self.new_verified()
        self.assertEqual((self.config / self.target_new).read_bytes(), self.maps[self.target_old])
        for store in (self.old, self.new):
            with self.assertRaisesRegex(P.Refused, "transport_edit_recovery_required"):
                store.read_activation()
        self.assertEqual(self.resolve(S.COMMIT), NEW)
        self.assertFalse(any((self.config / name).exists() for name in self.maps))
        self.new_verified()
        def restore_verified(active, info):
            self.assertFalse(active)
            P.X.assert_pair(self.fd, info, self.files, ".before", self.f.uid)
            return True
        self.assertEqual(self.new.restore_reviewed(self.fd, self.new.read_activation(),
                                                  self.policy, restore_verified, P.X.RESTORE), NEW)
        self.assertFalse(any((self.config / name).exists() for name in self.new_maps))

    def test_rollback_preserves_old_receipts_and_bytes(self):
        self.begin()
        self.assertEqual(self.resolve(S.ROLLBACK), self.old.revision)
        self.old_preserved()
        self.assertEqual(self.old.read_activation(), self.original)
        self.assertFalse(any((self.config / name).exists() for name in self.new_maps))
        self.assertEqual(self.restore(), self.old.revision)

    def test_interrupted_switch_refuses_commit_and_can_rollback(self):
        original = P.T.atomic_write
        def interrupt(fd, name, *args, **kwargs):
            if fd == self.fd and name == "main.cf":
                raise KeyboardInterrupt()
            return original(fd, name, *args, **kwargs)
        with patch.object(P.T, "atomic_write", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.begin()
        with self.assertRaises(P.Refused):
            self.resolve(S.COMMIT)
        self.assertEqual(self.resolve(S.ROLLBACK), self.old.revision)
        self.old_preserved()

    def test_cleanup_direction_persists_after_interruption(self):
        self.begin()
        unlink = os.unlink
        removed = []
        def interrupt(name, *args, **kwargs):
            if name in self.maps and kwargs.get("dir_fd") == self.fd:
                if removed:
                    raise KeyboardInterrupt()
                removed.append(name)
            return unlink(name, *args, **kwargs)
        with patch.object(S.os, "unlink", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.resolve(S.COMMIT)
        state = self.observe()
        self.assertEqual(P.X.parse_edit_marker(state[0][1][0])["phase"], "commit")
        with self.assertRaisesRegex(P.Refused, "edit_resolution_direction_fixed"):
            self.resolve(S.ROLLBACK)
        self.assertEqual(self.resolve(S.COMMIT), NEW)
        self.new_verified()

    def test_private_policy_drift_and_foreign_map_fail_closed(self):
        self.begin()
        path = self.manager.marker_path
        previous = self.f.labels[path]
        self.f.labels[path] = F.label("foreign_journal_t")
        with self.assertRaises(P.Refused):
            self.resolve(S.ROLLBACK)
        self.f.labels[path] = previous
        name = next(iter(self.new_maps))
        target = self.config / name
        target.rename(self.config / "foreign-original")
        target.write_bytes(self.new_maps[name])
        target.chmod(0o640)
        os.setxattr(str(target), F.ATTRIBUTE, bytes.fromhex(self.new_labels[name]))
        with self.assertRaises(P.Refused):
            self.resolve(S.ROLLBACK)
        self.old_preserved()
        self.assertTrue(target.exists())

    def test_lost_receipt_never_adopts_unproven_map(self):
        real = self.new._write
        def interrupt(relative, data, previous=None):
            if relative.endswith(".published.json"):
                raise KeyboardInterrupt()
            return real(relative, data, previous)
        with patch.object(self.new, "_write", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.begin()
        self.assertTrue((self.f.root / self.manager.marker_path).exists())
        self.assertEqual(sum((self.config / n).exists() for n in self.new_maps), 1)
        with self.assertRaises(P.Refused):
            self.observe()
        self.old_preserved()

    def test_stale_review_and_changed_rule_credential_refused(self):
        bad = [{"mode": "retain"}, {"mode": "retain"}]
        with patch.object(S.E, "compile_route") as compile_route:
            with self.assertRaisesRegex(P.Refused, "edit_candidate_preparation_failed"):
                self.manager.prepare(self.reviewed, bad, str(self.config),
                                     (self.f.uid, self.f.gid), self.verify, lambda *args: None)
            compile_route.assert_not_called()
        self.assertFalse((self.f.root / self.new.snapshot).exists())
        self.old_preserved()


if __name__ == "__main__":
    unittest.main()
