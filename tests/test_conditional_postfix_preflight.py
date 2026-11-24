"""Read-only sender activation preflight regression tests; no real SMTP."""
import importlib.util
import ipaddress
import os
import pathlib
import socket
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "conditional_preflight", str(ROOT / "linux/inspect-conditional-postfix-activation.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def policy():
    values = dict.fromkeys(P.KEYS, "")
    values.update(P.FIXED_SETTINGS)
    values.update(smtp_tls_CAfile="/etc/ssl/certs/ca-certificates.crt",
                  local_transport="local:localhost", virtual_transport="virtual")
    return values


class ConditionalPreflightTests(unittest.TestCase):
    def test_strict_policy_and_existing_settings(self):
        self.assertEqual(P.inspect_policy(policy()), "/etc/ssl/certs/ca-certificates.crt")
        for key, value in (
                ("transport_maps", "hash:/etc/postfix/transport"),
                ("sender_dependent_relayhost_maps", "hash:/etc/postfix/old"),
                ("default_transport", "smtp:other"),
                ("smtp_tls_security_level", "encrypt"),
                ("smtp_tls_wrappermode", "yes"),
                ("smtp_sasl_auth_enable", "yes"),
                ("smtp_tls_policy_maps", "hash:/etc/postfix/tls"),
                ("smtp_tls_secure_cert_match", "hostname"),
                ("multi_instance_directories", "/etc/postfix-other"),
                ("local_transport", "smtp:other"),
                ("smtp_tls_CApath", "/etc/ssl/certs")):
            with self.subTest(key=key), self.assertRaises(P.Refused):
                P.inspect_policy(dict(policy(), **{key: value}))

    def test_master_defaults_and_override_conflicts(self):
        def runner(tool, args):
            if "-M" in args:
                return 0, b"smtp unix - - n - - smtp\nrelay unix - - n - - smtp\n"
            return 0, b"relay/unix/syslog_name=postfix/relay\n"
        P.inspect_master(runner)
        for override in (b"smtp/unix/smtp_tls_security_level=none\n",
                         b"rewrite/unix/transport_maps=hash:/other\n"):
            def bad(tool, args):
                return runner(tool, args) if "-M" in args else (0, override)
            with self.assertRaises(P.Refused):
                P.inspect_master(bad)

    def test_service_stopped_only(self):
        def command(name, args):
            if args[0] == "list-units":
                return "postfix.service loaded inactive dead Postfix\n"
            if args[1] == "postfix@-.service":
                return "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            return "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
        P.stopped_units(command)
        for active in ("active", "activating", "failed"):
            def bad(name, args):
                return command(name, args).replace("ActiveState=inactive",
                                                  "ActiveState=" + active)
            with self.assertRaises(P.Refused):
                P.stopped_units(bad)

    def test_queue_directory_inventory_rejects_messages_and_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            for name in P.QUEUE_DIRS:
                (root / name).mkdir()
            (root / "deferred" / "A").mkdir()
            fd = os.open(temp, P.M.DIR_FLAGS)
            try:
                P.empty_queue(fd)
                path = root / "maildrop" / "queued"
                path.write_bytes(b"must never read")
                with self.assertRaises(P.Refused):
                    P.empty_queue(fd)
                path.unlink()
                path.symlink_to(root / "active")
                with self.assertRaises(P.Refused):
                    P.empty_queue(fd)
            finally:
                os.close(fd)

    def test_network_checks_all_resolved_addresses_and_preserves_ports(self):
        rules = [{"host": "relay.example.org", "port": 46500},
                 {"host": "other.example.org", "port": 25}]
        calls = []
        def resolve(host, port, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "",
                     ("192.0.2.10", port))]
        def check(host, port, ip, ctx):
            calls.append((host, port, str(ip)))
            return "a"*64
        with patch.object(P, "trust_store_digest", return_value="b"*64), \
                patch.object(P.ssl, "create_default_context", return_value=object()):
            proof, count = P.network_evidence(rules, "test", set(), resolve, check)
            self.assertEqual(len(proof), 64)
            self.assertEqual(count, 2)
            self.assertEqual(calls, [("other.example.org", 25, "192.0.2.10"),
                                     ("relay.example.org", 46500, "192.0.2.10")])
            with self.assertRaises(P.Refused):
                P.network_evidence(rules, "test", {ipaddress.ip_address("192.0.2.10")},
                                   resolve, check)
            self.assertEqual(len(calls), 2)

    def test_loopback_and_mapped_loopback_blocked(self):
        for value in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0",
                      "169.254.1.2", "224.0.0.1"):
            self.assertFalse(P.safe_destination(P.address(value), set()))

    def test_duplicate_and_missing_native_fields_refused(self):
        for data in ("a=x\na=y", "b=x", ""):
            with self.assertRaises(P.Refused):
                P.key_values(data, ("a",))


if __name__ == "__main__":
    unittest.main()
