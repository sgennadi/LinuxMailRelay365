"""Synthetic port-policy operations with real private filesystem journals."""
import copy
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "outbound_port_transaction", str(ROOT / "linux/manage-conditional-transport-selinux-port.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
REV = "a" * 64
PORT = 2526
HEADER = "SELinux Port Type Proto Port Number\n"
FULL = HEADER + ("smtp_port_t tcp 25, 465, 587\n"
                 "unreserved_port_t tcp 1024-65535\n"
                 "http_port_t tcp 8080\n")
LOCAL = HEADER + "http_port_t tcp 8080\n"


class FakeHost:
    def __init__(self):
        self.policy = {"mode": "enforcing", "full": P.rows(FULL), "local": P.rows(LOCAL, True)}
        self.calls = []
        self.in_use = False

    def snapshot(self):
        return copy.deepcopy(self.policy)

    def busy(self, port):
        return self.in_use

    def change(self, action, port):
        row = ["smtp_port_t", "tcp", port, port]
        self.calls.append((action, port))
        for name in ("full", "local"):
            if action == "add":
                self.policy[name].append(row)
                self.policy[name].sort()
            else:
                self.policy[name].remove(row)


class PortTransactionTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = pathlib.Path(work.name)
        self.parent = os.open(str(self.root), P.M.DIR_FLAGS)
        self.addCleanup(os.close, self.parent)
        self.host = FakeHost()
        self.uid = os.getuid()
        self.state, self.intent = P.review_add(self.host, PORT, REV)
        self.token = P.sha(self.intent)
        self.assertEqual(self.state, "candidate")

    def store(self):
        store = P.Store(self.parent, REV, self.uid, create=True)
        self.addCleanup(store.close)
        return store

    def install(self, store):
        return P.apply(self.host, store, self.intent, self.token)

    def test_strict_tables_and_no_existing_binding_adoption(self):
        self.assertEqual(P.classify(self.host.policy, 25), "existing_smtp")
        self.assertEqual(P.classify(self.host.policy, 8080), "conflict")
        self.assertEqual(P.classify(self.host.policy, 23), "restricted_port")
        self.assertEqual(P.rows("", True), [])
        for raw in ("", HEADER + "smtp_port_t tcp 0-99999\n",
                    FULL + "malformed\n", FULL + "smtp_port_t tcp 25\n"):
            with self.assertRaises(P.Refused):
                P.rows(raw)
        policy = self.host.snapshot()
        policy["local"].append(["unreserved_port_t", "tcp", 1024, 65535])
        policy["local"].sort()
        self.assertEqual(P.classify(policy, PORT), "conflict")

    def test_apply_and_rollback_exact_tables_and_immutable_backup(self):
        store = self.store()
        before = self.host.snapshot()
        original = self.host.change

        def change(action, port):
            self.assertIn(P.INTENT, store.entries())
            self.assertEqual(store.read(P.INTENT), self.intent)
            if action == "remove":
                self.assertIn(P.APPLIED, store.entries())
                self.assertIn(P.REMOVE, store.entries())
            original(action, port)

        with patch.object(self.host, "change", side_effect=change):
            self.assertEqual(self.install(store), REV)
            self.assertEqual(P.status(self.host, store)[0], "managed")
            _, token = P.review_rollback(self.host, store)
            self.assertEqual(P.rollback(self.host, store, token), REV)
        self.assertEqual(self.host.snapshot(), before)
        self.assertEqual(self.host.calls, [("add", PORT), ("remove", PORT)])
        self.assertEqual(P.status(self.host, store)[0], "restored")
        self.assertEqual(store.entries(), set(P.NAMES))
        for file in (self.root / P.BASE / REV).iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(P.Refused):
            P.review_rollback(self.host, store)

    def test_stale_approval_and_busy_port_do_not_change_policy(self):
        store = self.store()
        with self.assertRaises(P.Refused):
            P.apply(self.host, store, self.intent, "b" * 64)
        self.host.in_use = True
        with self.assertRaises(P.Refused):
            self.install(store)
        self.assertEqual(self.host.calls, [])
        self.assertEqual(store.entries(), set())

    def test_conflict_or_mode_drift_after_review(self):
        store = self.store()
        self.host.policy["mode"] = "permissive"
        with self.assertRaises(P.Refused):
            self.install(store)
        self.assertEqual(self.host.calls, [])

    def test_unrelated_policy_change_blocks_rollback(self):
        store = self.store()
        self.install(store)
        self.host.policy["full"].append(["foreign_port_t", "tcp", 8888, 8888])
        self.host.policy["full"].sort()
        self.assertEqual(P.status(self.host, store)[0], "managed_policy_changed")
        with self.assertRaises(P.Refused):
            P.review_rollback(self.host, store)
        self.assertEqual(self.host.calls, [("add", PORT)])

    def test_uncertain_add_is_never_adopted_or_deleted(self):
        store = self.store()
        original = store.write

        def interrupt(name, value):
            if name == P.APPLIED:
                raise KeyboardInterrupt()
            original(name, value)

        with patch.object(store, "write", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.install(store)
        self.assertEqual(self.host.snapshot(), P.expected_after(self.intent))
        self.assertEqual(P.status(self.host, store)[0], "add_outcome_unconfirmed")
        with self.assertRaises(P.Refused):
            P.review_rollback(self.host, store)
        self.assertEqual(self.host.calls, [("add", PORT)])

    def test_interrupted_rollback_retains_history_and_refuses_retry(self):
        store = self.store()
        self.install(store)
        _, token = P.review_rollback(self.host, store)
        original = store.write

        def interrupt(name, value):
            if name == P.RESTORED:
                raise KeyboardInterrupt()
            original(name, value)

        with patch.object(store, "write", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                P.rollback(self.host, store, token)
        self.assertEqual(self.host.snapshot(), self.intent["before"])
        self.assertEqual(P.status(self.host, store)[0], "rollback_outcome_unconfirmed")
        with self.assertRaises(P.Refused):
            P.rollback(self.host, store, token)
        self.assertEqual(self.host.calls, [("add", PORT), ("remove", PORT)])

    def test_add_that_changes_more_than_one_singleton_is_unverified(self):
        store = self.store()
        real = self.host.change

        def mutate(action, port):
            real(action, port)
            self.host.policy["full"].append(["foreign_port_t", "udp", 2526, 2526])
            self.host.policy["full"].sort()

        with patch.object(self.host, "change", side_effect=mutate):
            with self.assertRaisesRegex(P.Refused, "port_add_outcome_unverified"):
                self.install(store)
        self.assertNotIn(P.APPLIED, store.entries())
        self.assertEqual(self.host.calls, [("add", PORT)])

    def test_foreign_record_and_busy_rollback_block_mutation(self):
        store = self.store()
        self.install(store)
        _, token = P.review_rollback(self.host, store)
        self.host.in_use = True
        with self.assertRaises(P.Refused):
            P.rollback(self.host, store, token)
        self.host.in_use = False
        (self.root / P.BASE / REV / "foreign.json").write_text("fixture")
        with self.assertRaises(P.Refused):
            P.rollback(self.host, store, token)
        self.assertEqual(self.host.calls, [("add", PORT)])

    def test_cli_requires_separate_exact_approvals(self):
        common = ["--revision", REV, "--approve-review-sha256", self.token,
                  "--confirm", P.ADD, "--maintenance-confirmation", P.MAINTENANCE]
        self.assertTrue(P.validate_args(P.arguments(["--apply", str(PORT)] + common)))
        self.assertFalse(P.validate_args(P.arguments(["--review", str(PORT)])))
        for args in (["--apply", str(PORT)], ["--apply", "25"] + common,
                     ["--review", str(PORT)] + common,
                     ["--rollback", REV, "--approve-review-sha256", self.token,
                      "--confirm", P.ADD, "--maintenance-confirmation", P.MAINTENANCE]):
            with self.assertRaises(P.Refused):
                P.validate_args(P.arguments(args))


if __name__ == "__main__":
    unittest.main()
