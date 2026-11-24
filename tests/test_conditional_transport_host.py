"""Experimental multi-transport host orchestration; no daemon or SMTP network."""
import importlib.util
import ipaddress
import pathlib
import socket
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "multi_host", str(ROOT / "linux/manage-conditional-transports-offline.py"))
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


class HostTests(unittest.TestCase):
    def setUp(self):
        self.rules = [
            dict(selector="exact-envelope-sender", pattern="one@example.org",
                 host="relay.example.net", port=587, tls="starttls", auth="password"),
            dict(selector="exact-envelope-sender", pattern="two@example.org",
                 host="relay.example.net", port=465, tls="implicit", auth="password")]
        self.plan = H.C.plan(self.rules)[1]
        self.request = {"rules": self.rules, "credentials": [
            {"username": "one", "password": "syntheticA"},
            {"username": "two", "password": "syntheticB"}]}
        self.identity = (100, 101)
        self.approved = "a"*64
        self.info = {"rules": self.rules, "plan": self.plan, "backend": "hash",
                     "ca": H.C.CA_FILES[0]}
        self.snapshot = (self.info, {})
        self.baseline = ({}, {}, {}, {}, {})
        self.review = (self.snapshot, self.baseline, self.approved, 2)

    def test_network_distinguishes_ports_and_tls_modes_and_rejects_local(self):
        calls = []
        def resolve(host, port, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.0.2.5", port))]
        def check(host, port, mode, peer, context):
            calls.append((port, mode, str(peer)))
            return "b"*64
        ctx = Mock()
        with patch.object(H.P, "trust_store_digest", return_value="c"*64), \
                patch.object(H.ssl, "create_default_context", return_value=ctx):
            proof, count = H.network(self.rules, self.info["ca"], set(), resolve, check)
            self.assertTrue(H.R.valid_sha(proof))
            self.assertEqual(count, 2)
            self.assertEqual(calls, [(465, "implicit", "192.0.2.5"),
                                     (587, "starttls", "192.0.2.5")])
            with self.assertRaises(H.Refused):
                H.network(self.rules, self.info["ca"], {ipaddress.ip_address("192.0.2.5")},
                          resolve, check)
        self.assertEqual(len(calls), 2)

    def test_mismatched_review_never_compiles_credentials(self):
        with patch.object(H, "review", return_value=self.review), \
                patch.object(H.C, "compile_profiles") as compiler:
            with self.assertRaises(H.Refused):
                H.apply_reviewed(1, 2, self.request, self.plan, "d"*64,
                                 "hash", self.identity, Mock())
            compiler.assert_not_called()

    def test_changed_review_after_compile_never_applies(self):
        def compile(*args, **kwargs):
            kwargs["verified_consumer"](self.rules, self.plan, "hash", self.info["ca"], {})
        with patch.object(H, "review", side_effect=[self.review,
                          (self.snapshot, self.baseline, "e"*64, 2)]), \
                patch.object(H.C, "tmpfs_parent", return_value="/dev/shm"), \
                patch.object(H.C, "compile_profiles", side_effect=compile), \
                patch.object(H.X, "apply") as apply:
            with self.assertRaises(H.Refused):
                H.apply_reviewed(1, 2, self.request, self.plan, self.approved,
                                 "hash", self.identity, Mock())
            apply.assert_not_called()

    def test_native_verified_consumer_is_only_apply_path(self):
        dbs = {"private": b"synthetic"}
        def compile(*args, **kwargs):
            self.assertEqual(args[0], self.request)
            kwargs["verified_consumer"](self.rules, self.plan, "hash", self.info["ca"], dbs)
        with patch.object(H, "review", return_value=self.review) as review, \
                patch.object(H.C, "tmpfs_parent", return_value="/dev/shm"), \
                patch.object(H.C, "compile_profiles", side_effect=compile), \
                patch.object(H.X, "apply", return_value="f"*64) as apply:
            self.assertEqual(H.apply_reviewed(1, 2, self.request, self.plan, self.approved,
                                             "hash", self.identity, Mock()), "f"*64)
            self.assertEqual(review.call_count, 2)
            self.assertEqual(apply.call_args[0][:7],
                             (1, 2, self.snapshot, dbs, 101, H.X.APPLY, 0))

    def test_inherited_client_certificate_and_debug_settings_refused(self):
        values = dict.fromkeys(H.P.KEYS, "")
        extra = dict.fromkeys(H.EXTRA, "")
        extra.update(smtp_host_lookup="dns", disable_dns_lookups="no")
        with patch.object(H.P, "inspect_policy", return_value=self.info["ca"]), \
                patch.object(H.P, "inspect_master"):
            self.assertEqual(H.policy((values, extra, {}, {}, {})), self.info["ca"])
            for key in H.EMPTY_EXTRA:
                with self.assertRaises(H.Refused):
                    H.policy((values, dict(extra, **{key: "unexpected"}), {}, {}, {}))

    def test_restore_group_mismatch_refused_before_mutation(self):
        with patch.object(H.X, "load", return_value=(self.info, {}, {"gid": 999}, {})), \
                patch.object(H.X, "restore") as restore:
            with self.assertRaises(H.Refused):
                H.restore_reviewed(1, 2, "f"*64, self.identity, Mock())
            restore.assert_not_called()


if __name__ == "__main__":
    unittest.main()
