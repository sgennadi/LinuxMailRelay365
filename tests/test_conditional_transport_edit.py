"""Replacement planning and private candidate preparation, no active writes."""
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


E = load("replacement_preparation", "linux/conditional-transport-edit.py")
F = load("edit_transaction_fixture", "tests/test_conditional_transport_transaction.py")


class MultiTransportEditTests(unittest.TestCase):
    def setUp(self):
        self.f = F.MultiTransportTransactionTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        self.revision = self.f.apply()
        self.record = E.X.load(self.f.parent, self.revision, self.f.uid)
        self.original = self.snapshot()
        self.first, self.second = self.f.rules
        self.changed = dict(self.second, host="new.example.net", port=2526,
                            tls="starttls")
        self.credential = {"username": "fixture-new", "password": "synthetic-new"}

    def snapshot(self):
        return {p.name: (p.read_bytes(), E.T.file_identity(p.stat()))
                for p in self.f.config.iterdir() if p.is_file()}

    def unchanged(self):
        self.assertEqual(self.snapshot(), self.original)
        self.assertEqual(E.X.load(self.f.parent, self.revision, self.f.uid), self.record)

    def native_review(self, record):
        self.assertEqual(record, self.record)
        return True

    def review(self, draft, native=None):
        return E.review(self.f.fd, self.f.parent, self.revision, draft,
                        self.f.uid, self.f.gid, self.f.guard,
                        native or self.native_review)

    def prepare(self, reviewed, slots):
        return E.prepare(self.f.fd, self.f.parent, str(self.f.config), self.revision,
                         reviewed, slots, self.f.uid, (self.f.uid, self.f.gid),
                         self.f.guard, self.native_review, lambda *args: None)

    def test_reorder_and_exact_retention(self):
        old, new, files, retain = self.review([self.second, self.first])
        self.assertEqual(old, self.record)
        self.assertEqual(retain, (2, 1))
        self.assertNotEqual(new["plan"], old[0]["plan"])
        self.assertEqual(files["main.before"], self.f.original["main.cf"])
        self.assertEqual(files["master.before"], self.f.original["master.cf"])
        self.assertEqual(files["master.after"].count(b"# LinuxMailRelay365 transport set"), 1)
        self.assertNotIn(old[0]["plan"].encode("ascii"), files["main.after"])
        self.assertFalse(set(E.X.map_names(new)) & set(E.X.map_names(old[0])))
        self.unchanged()

    def test_changed_or_renamed_rule_needs_explicit_credential(self):
        for changed in (self.changed, dict(self.second, pattern="third@example.org"),
                        dict(self.second, port=587), dict(self.second, tls="starttls")):
            reviewed = self.review([self.first, changed])
            self.assertEqual(reviewed[3], (1, None))
            with self.assertRaisesRegex(E.Refused, "credential_reuse_not_permitted"):
                E.credential_choices(reviewed, [{"mode": "retain"}, {"mode": "retain"}])
        self.unchanged()

    def test_removal_and_no_auth(self):
        reviewed = self.review([dict(self.second, auth="none")])
        self.assertEqual(reviewed[3], (None,))
        self.assertEqual(E.credential_choices(reviewed, [None]), [("none", None)])
        with self.assertRaises(E.Refused):
            E.credential_choices(reviewed, [{"mode": "retain"}])
        self.unchanged()

    def test_no_op_empty_invalid_and_native_refusal(self):
        for rules in (self.f.rules, [], [self.first, self.first]):
            with self.assertRaises(E.Refused):
                self.review(rules)
        with self.assertRaisesRegex(E.Refused, "installed_native_policy_unverified"):
            self.review([self.changed], native=lambda _: False)
        self.unchanged()

    def test_destination_collision_before_preparation(self):
        reviewed = self.review([self.changed])
        name = E.X.map_names(reviewed[1])[0]
        target = self.f.config / name
        target.write_bytes(b"foreign map")
        with self.assertRaisesRegex(E.Refused, "replacement_destination_exists"):
            self.review([self.changed])
        self.assertEqual(target.read_bytes(), b"foreign map")
        target.unlink()
        self.unchanged()

    def test_private_candidate_retains_only_selected_original_map(self):
        reviewed = self.review([self.changed, self.first])
        old_name = E.Q.target_name(self.record[0], 1)
        expected = self.f.maps[old_name]
        calls = []

        def verify(fd, directory, info, name, data, uid, identity, lookup):
            self.assertEqual(name, old_name)
            self.assertEqual(data, expected)
            calls.append(name)

        with patch.object(E, "compile_route", return_value=b"new synthetic route"), \
                patch.object(E.Q, "compile_rotation_candidate",
                             return_value=b"new synthetic credential") as compiler, \
                patch.object(E.Q, "verify_retained_native", side_effect=verify):
            result = self.prepare(reviewed, [
                {"mode": "new", "credential": self.credential}, {"mode": "retain"}])
            compiler.assert_called_once_with(reviewed[1], 1, self.credential)
        plan = reviewed[1]["plan"]
        self.assertEqual(result, {E.C.ROUTE_MAP: b"new synthetic route",
                                  E.C.profile_name(plan, 1) + "-sasl": b"new synthetic credential",
                                  E.C.profile_name(plan, 2) + "-sasl": expected})
        self.assertEqual(calls, [old_name])
        self.unchanged()

    def test_all_slots_validated_before_compilation(self):
        reviewed = self.review([self.first, self.changed])
        with patch.object(E, "compile_route") as compiler:
            with self.assertRaisesRegex(E.Refused, "^edit_candidate_preparation_failed$"):
                self.prepare(reviewed, [{"mode": "retain"}, {"mode": "retain"}])
            compiler.assert_not_called()
        self.unchanged()

    def test_stale_review_and_foreign_replacement_refused(self):
        reviewed = self.review([self.first, self.changed])
        path = self.f.config / E.Q.target_name(self.record[0], 1)
        old = path.read_bytes()
        path.rename(self.f.config / "foreign-old")
        path.write_bytes(old)
        path.chmod(0o640)
        with patch.object(E, "compile_route") as compiler:
            with self.assertRaisesRegex(E.Refused, "^edit_candidate_preparation_failed$"):
                self.prepare(reviewed, [{"mode": "retain"},
                                       {"mode": "new", "credential": self.credential}])
            compiler.assert_not_called()
        self.assertEqual(path.read_bytes(), old)

    def test_native_failure_is_redacted_and_no_changes(self):
        reviewed = self.review([self.changed])
        with patch.object(E, "compile_route", side_effect=OSError("synthetic-private")):
            with self.assertRaisesRegex(E.Refused, "^edit_candidate_preparation_failed$") as error:
                self.prepare(reviewed, [{"mode": "new", "credential": self.credential}])
        self.assertTrue(error.exception.__suppress_context__)
        self.unchanged()


if __name__ == "__main__":
    unittest.main()
