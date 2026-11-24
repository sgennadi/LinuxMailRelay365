"""Two-generation edit transaction with fault injection; synthetic DB bytes."""
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


S = load("switch_edit", "linux/conditional-transport-edit-transaction.py")
F = load("switch_fixture", "tests/test_conditional_transport_transaction.py")


class MultiTransportSwitchTests(unittest.TestCase):
    def setUp(self):
        self.f = F.MultiTransportTransactionTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        self.old = self.f.apply()
        self.record = S.X.load(self.f.parent, self.old, self.f.uid)
        self.rules = [dict(self.f.rules[1], port=2526), self.f.rules[0]]
        self.reviewed = S.E.review(self.f.fd, self.f.parent, self.old, self.rules,
                                   self.f.uid, self.f.gid, self.f.guard,
                                   self.native)
        self.new = self.reviewed[1]
        self.dbs = {S.C.ROUTE_MAP: b"new synthetic route",
                    S.C.profile_name(self.new["plan"], 1) + "-sasl": b"new account",
                    S.C.profile_name(self.new["plan"], 2) + "-sasl":
                        self.f.maps[S.Q.target_name(self.record[0], 1)]}
        self.maps = S.X.native_database_set(self.new, self.dbs)

    def native(self, record):
        info, files, _, _ = record
        self.assertEqual(S.X.pair(self.f.fd, self.f.uid),
                         S.X.expected_pair(info, files, ".after"))
        return True

    def begin(self, verify=None):
        with patch.object(S.E, "prepare", return_value=self.dbs):
            return S.begin(self.f.fd, self.f.parent, str(self.f.config), self.old,
                           self.reviewed, [], self.f.uid, (self.f.uid, self.f.gid),
                           self.f.guard, self.native, lambda *args: None,
                           verify or self.native, S.BEGIN)

    def observe(self):
        return S.observe(self.f.fd, self.f.parent, self.f.uid, self.f.gid, self.f.guard)

    def resolve(self, decision, reviewed=None, verify=None):
        return S.resolve(self.f.fd, self.f.parent,
                         self.observe() if reviewed is None else reviewed,
                         self.f.uid, self.f.gid, self.f.guard,
                         verify or self.native, decision)

    def assert_maps(self, maps, absent):
        for name, data in maps.items():
            self.assertEqual((self.f.config / name).read_bytes(), data)
        self.assertFalse(any((self.f.config / name).exists() for name in absent))

    def test_commit_and_normal_restore(self):
        revision = self.begin()
        self.assert_maps(dict(self.f.maps, **self.maps), [])
        with self.assertRaisesRegex(S.Refused, "transport_edit_recovery_required"):
            S.X.load(self.f.parent, revision, self.f.uid)
        with self.assertRaisesRegex(S.Refused, "transport_edit_recovery_required"):
            self.f.restore(self.old)
        self.assertEqual(self.resolve(S.COMMIT), revision)
        self.assert_maps(self.maps, self.f.maps)
        record = S.X.load(self.f.parent, revision, self.f.uid)
        def verify_restore(active, info):
            self.assertFalse(active)
            self.assertEqual(info, record[0])
            self.assertEqual(S.X.pair(self.f.fd, self.f.uid),
                             S.X.expected_pair(record[0], record[1], ".before"))
        S.X.restore(self.f.fd, self.f.parent, revision, S.X.RESTORE,
                    self.f.uid, self.f.guard, verify_restore)
        self.f.assert_original()
        self.assert_maps({}, self.maps)

    def test_rollback_keeps_original_map_identities(self):
        self.begin()
        self.assertEqual(self.resolve(S.ROLLBACK), self.old)
        self.assert_maps(self.f.maps, self.maps)
        self.assertEqual(S.X.load(self.f.parent, self.old, self.f.uid), self.record)
        S.Q.assert_installed(self.f.fd, self.record, self.f.uid)

    def test_native_failure_leaves_recoverable_pending(self):
        with self.assertRaises(S.SwitchFailed):
            self.begin(verify=lambda _: False)
        with self.assertRaisesRegex(S.Refused, "edit_native_verification_failed"):
            self.resolve(S.COMMIT, verify=lambda _: False)
        self.assertEqual(self.observe()[0]["phase"], "pending")
        self.assertEqual(self.resolve(S.ROLLBACK), self.old)

    def test_interruption_between_master_and_main(self):
        original = S.T.atomic_write
        def interrupt(fd, name, data, *args, **kwargs):
            if name == "main.cf":
                raise KeyboardInterrupt()
            return original(fd, name, data, *args, **kwargs)
        with patch.object(S.T, "atomic_write", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.begin()
        with self.assertRaises(S.Refused):
            self.resolve(S.COMMIT)
        self.assertEqual(self.resolve(S.ROLLBACK), self.old)
        self.assert_maps(self.f.maps, self.maps)

    def test_partial_publication_can_rollback(self):
        original = S.X.publish
        calls = []
        def interrupt(*args):
            if calls:
                raise KeyboardInterrupt()
            original(*args)
            calls.append(True)
        with patch.object(S.X, "publish", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.begin()
        self.assertEqual(len(self.observe()[5]), 1)
        self.assertEqual(self.resolve(S.ROLLBACK), self.old)
        self.assert_maps(self.f.maps, self.maps)

    def test_interrupted_cleanup_is_directional_and_resumable(self):
        revision = self.begin()
        real = os.unlink
        count = []
        def interrupt(name, *args, **kwargs):
            if name in self.f.maps:
                if count:
                    raise KeyboardInterrupt()
                count.append(name)
            return real(name, *args, **kwargs)
        with patch.object(S.os, "unlink", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.resolve(S.COMMIT)
        self.assertEqual(self.observe()[0]["phase"], "commit")
        with self.assertRaisesRegex(S.Refused, "edit_resolution_direction_fixed"):
            self.resolve(S.ROLLBACK)
        self.assertEqual(self.resolve(S.COMMIT), revision)
        self.assert_maps(self.maps, self.f.maps)

    def test_foreign_map_and_configuration_drift_block_cleanup(self):
        self.begin()
        name = next(iter(self.maps))
        target = self.f.config / name
        target.rename(self.f.config / "foreign-old")
        target.write_bytes(self.maps[name])
        target.chmod(0o640)
        with self.assertRaises(S.Refused):
            self.resolve(S.ROLLBACK)
        self.assertEqual(target.read_bytes(), self.maps[name])

    def test_stale_recovery_approval_refused(self):
        self.begin()
        state = self.observe()
        with self.assertRaisesRegex(S.Refused, "edit_recovery_review_changed"):
            self.resolve(S.ROLLBACK, reviewed=state[:-1] + ((),))
        self.assertEqual(self.observe(), state)

    def test_no_extra_private_map_backup(self):
        self.begin()
        for path in (self.f.root / S.R.BASE).rglob("*"):
            if path.is_file():
                for data in self.f.maps.values():
                    self.assertNotIn(data, path.read_bytes())
        self.assertEqual(self.resolve(S.ROLLBACK), self.old)


if __name__ == "__main__":
    unittest.main()
