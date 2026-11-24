"""Offline activation orchestration and native lookup contracts (no live MTA)."""
import importlib.util
import pathlib
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "offline_activation", str(ROOT / "linux/manage-conditional-postfix-offline.py"))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class OfflineActivationTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.compiled = "a"*64, "b"*64
        self.txn, self.evidence = "c"*64, "d"*64
        self.identity = (100, 101)
        self.rules = [dict(selector="exact-envelope-sender", pattern="user@example.org",
                           host="relay.example.net", port=46500, tls="starttls", auth="none")]
        self.policy = dict.fromkeys(C.P.KEYS, "")
        self.policy.update(C.P.FIXED_SETTINGS)
        self.policy.update(smtp_tls_CAfile="/etc/ssl/certs/ca-certificates.crt",
                           local_transport="local:localhost", virtual_transport="virtual")
        self.bundle = ((self.txn, {"fixture": True}, {"fixture": b"db"}),
                       self.evidence, 1, self.policy, self.rules)
        self.map = "hash:/etc/postfix/lmr365-conditional-" + self.plan + "-sender"

    def test_exact_review_rechecked_before_and_after_backup(self):
        reviewer = Mock(return_value=self.bundle)
        lookup, guard, master = Mock(), Mock(), Mock()
        observed = dict(self.policy, sender_dependent_relayhost_maps=self.map)
        def transaction(config, parent, reviewed, confirmation, uid, gid,
                        maintenance, verify, fresh):
            self.assertEqual(reviewed, self.txn)
            self.assertEqual(confirmation, C.T.CONFIRM)
            self.assertEqual(gid, self.identity[1])
            self.assertEqual(fresh(), self.bundle[0])
            self.assertEqual(fresh(), self.bundle[0])
            verify(self.map)
            return self.txn
        with patch.object(C.T, "apply", side_effect=transaction):
            self.assertEqual(C.apply_reviewed(1, 2, 3, self.plan, self.compiled,
                self.txn, self.evidence, self.identity, guard,
                reviewer, lookup, lambda: observed, master), self.txn)
        self.assertEqual(reviewer.call_count, 2)
        lookup.assert_called_once_with(self.map, self.rules, self.identity)
        master.assert_called_once()

    def test_changed_evidence_rejected_before_write(self):
        reviewer = Mock(return_value=(self.bundle[0], "e"*64, 1,
                                     self.policy, self.rules))
        def transaction(*args):
            args[-1]()
            self.fail("unexpected write")
        with patch.object(C.T, "apply", side_effect=transaction):
            with self.assertRaises(C.Refused):
                C.apply_reviewed(1, 2, 3, self.plan, self.compiled, self.txn,
                    self.evidence, self.identity, Mock(), reviewer)

    def test_active_lookup_checks_exact_map_all_rows_and_missing_key(self):
        calls = []
        expected = b"user@example.org\t[relay.example.net]:46500\n"
        def runner(args, identity, data=None):
            calls.append((args, identity, data))
            self.assertEqual(args[:2], ["-c", "/etc/postfix"])
            self.assertEqual(args[-1], self.map)
            if C.M.NEGATIVE_KEY in args:
                return 1, b""
            return 0, expected
        C.verify_active_map(self.map, self.rules, self.identity, runner)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1][2], b"user@example.org\n")
        with self.assertRaises(C.Refused):
            C.verify_active_map("hash:/etc/postfix/foreign", self.rules,
                                self.identity, runner)

    def test_active_lookup_detects_unexpected_values(self):
        for response in ((1, b""), (0, b"user@example.org\t[wrong.example.org]:25\n")):
            with self.assertRaises(C.Refused):
                C.verify_active_map(self.map, self.rules, self.identity,
                                    lambda *args: response)

    def test_group_identity_part_of_approval(self):
        self.assertNotEqual(C.review_digest(self.evidence, self.identity),
                            C.review_digest(self.evidence, (100, 102)))

    def test_restore_verifies_original_policy_without_start(self):
        guard, master = Mock(), Mock()
        def restore(config, parent, backup, confirmation, uid, gid,
                    maintenance, verify):
            self.assertEqual(confirmation, C.T.RESTORE)
            verify("")
            return backup
        with patch.object(C.T, "restore", side_effect=restore):
            self.assertEqual(C.restore_reviewed(1, 2, self.txn, self.identity,
                            guard, lambda: self.policy, master), self.txn)
        master.assert_called_once()


if __name__ == "__main__":
    unittest.main()
