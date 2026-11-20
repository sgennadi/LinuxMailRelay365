"""Read-only network/MTA bind regression; no network connections or mail."""
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "audit_bindings", str(ROOT / "linux" / "audit-mail-bindings.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def interfaces(oper="UP", admin=True):
    return audit.ip_interfaces(json.dumps([
        {"ifname": "eth0", "flags": ["UP"] if admin else [],
         "operstate": oper, "addr_info": [
             {"family": "inet", "local": "10.23.4.9",
              "prefixlen": 24, "scope": "global"}]},
        {"ifname": "lo", "flags": ["UP"], "operstate": "UNKNOWN",
         "addr_info": [{"family": "inet", "local": "127.0.0.1",
                        "prefixlen": 8, "scope": "host"}]}]))


def sockets(payload="LISTEN 0 128 10.23.4.9:2525 0.0.0.0:*\n"):
    return audit.scan_sockets(payload, 2525)


class MailBindingTests(unittest.TestCase):
    def test_ipv6_literal_is_not_mistaken_for_separator(self):
        for mta, raw, expected in (
            ("postfix", "[::1], 127.0.0.1", ["::1", "127.0.0.1"]),
            ("postfix", "::1", ["::1"]),
            ("exim", "127.0.0.1 : [::1]", ["127.0.0.1", "::1"]),
        ):
            with self.subTest(raw=raw):
                result = audit.configured_addresses(
                    mta, runner=lambda argv, cap=2048:
                    ("local_interfaces = " + raw if mta == "exim" else raw))
                self.assertEqual(result, ("explicit_addresses", expected))
        self.assertEqual(audit.configured_addresses(
            "postfix", runner=lambda argv, cap=2048: "localhost")[0],
            "complex_manual_review")
        self.assertEqual(audit.configured_addresses(
            "postfix", runner=lambda argv, cap=2048: " , , "),
            ("complex_manual_review", []))

    def test_down_and_uncertain_interfaces_are_distinct(self):
        cases = (({"admin": False}, "configured_ip_admin_down"),
                 ({"oper": "DOWN"}, "configured_ip_oper_down"),
                 ({"oper": "UNKNOWN"}, "configured_ip_oper_unverified"),
                 ({}, "selected_port_listening_owner_unverified"))
        for parameters, result in cases:
            with self.subTest(result=result):
                self.assertEqual(audit.bind_assessment(
                    "postfix", "explicit_addresses", ["10.23.4.9"],
                    interfaces(**parameters), sockets(), 2525), result)

    def test_unknown_bind_configuration_fails_closed(self):
        for kind in ("unavailable", "empty", "complex_manual_review"):
            self.assertEqual(audit.bind_assessment(
                "exim", kind, [], interfaces(), sockets(), 2525),
                "mta_bind_configuration_unverified")
        self.assertEqual(audit.bind_assessment(
            "sendmail", "not_applicable", [], interfaces(), sockets(), 2525),
            "mta_bind_configuration_not_applicable")
        self.assertEqual(audit.bind_assessment(
            "postfix", "explicit_addresses", ["10.23.4.10"],
            interfaces(), sockets(), 2525), "configured_ip_not_assigned")

    def test_truncated_inventory_cannot_prove_an_address_is_missing(self):
        many = [{"ifname": "eth" + str(i), "flags": ["UP"],
                 "operstate": "UP", "addr_info": [
                    {"family": "inet", "local": "10.1.0." + str(i + 1),
                     "prefixlen": 24, "scope": "global"}]}
                for i in range(audit.MAX_INTERFACES + 1)]
        inventory = audit.ip_interfaces(json.dumps(many))
        self.assertTrue(inventory[-1])
        self.assertEqual(audit.bind_assessment(
            "postfix", "explicit_addresses", ["10.23.4.9"],
            inventory, sockets(), 2525),
            "incomplete_network_or_socket_inventory")
        content = "".join(
            "LISTEN 0 128 127.0.0.{}:2525 0.0.0.0:*\n".format(i)
            for i in range(1, audit.MAX_SOCKETS + 2))
        clipped = audit.scan_sockets(content, 2525)
        self.assertTrue(clipped[-1])
        self.assertEqual(audit.bind_assessment(
            "postfix", "all", [], interfaces(), clipped, 2525),
            "incomplete_network_or_socket_inventory")

    def test_report_never_claims_socket_owner_or_internet_reachability(self):
        def runner(argv, cap=32768):
            if argv[:2] == ["ip", "-j"]:
                return json.dumps([{"ifname": "eth0", "flags": ["UP"],
                    "operstate": "UP", "addr_info": [
                    {"family": "inet", "local": "10.23.4.9",
                     "prefixlen": 24, "scope": "global"}]}])
            if argv[:2] == ["ss", "-H"]:
                return "LISTEN 0 128 10.23.4.9:2525 0.0.0.0:*\n"
            if argv[:2] == ["postconf", "-h"]:
                return "10.23.4.9\n"
            return None
        report = audit.inspect("postfix", 2525, runner=runner)
        self.assertEqual(report["MAIL_HOST_NET_BIND_RESULT"],
                         "selected_port_listening_owner_unverified")
        self.assertEqual(report["MAIL_HOST_SOCKET_OWNER"], "unverified")
        self.assertEqual(report["MAIL_HOST_EXTERNAL_REACHABILITY"], "not_tested")
        self.assertEqual(report["MAIL_HOST_NET_TRUNCATED"], "no")


if __name__ == "__main__":
    unittest.main()
