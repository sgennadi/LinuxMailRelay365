"""Dedicated transports: exact rules, independent AUTH and native compiler contracts."""
import importlib.util
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "transport_compiler", str(ROOT / "linux/compile-conditional-transports.py"))
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)


def rule(pattern, tls="starttls", auth="password", port=587,
         selector="exact-envelope-sender"):
    return dict(selector=selector, pattern=pattern, host="relay.example.net",
                port=port, tls=tls, auth=auth)


def fixture():
    return [rule("first@example.org"), rule("second@example.org"),
            rule("other.example.org", "implicit", "password", 465,
                 "envelope-sender-domain"),
            rule("fourth@example.org", "starttls", "none", 46500)]


class TransportTests(unittest.TestCase):
    def test_same_endpoint_different_accounts_have_distinct_services(self):
        rules, sha = T.plan(fixture())
        main, master, routes, services, auth = T.render(
            rules, sha, "/dev/shm/lmr365-fixture", "hash", T.CA_FILES[0])
        names = list(services)
        self.assertEqual(len(names), 4)
        self.assertEqual(len(set(auth.values())), 3)
        self.assertNotEqual(routes["first@example.org"], routes["second@example.org"])
        self.assertTrue(routes["@other.example.org"].endswith(":[relay.example.net]:465"))
        self.assertTrue(routes["fourth@example.org"].endswith(":[relay.example.net]:46500"))
        self.assertEqual(services[names[2]]["smtp_tls_wrappermode"], "yes")
        self.assertEqual(services[names[3]]["smtp_sasl_auth_enable"], "no")
        self.assertEqual(services[names[3]]["smtp_sasl_password_maps"], "")
        self.assertNotEqual(services[names[0]]["smtp_sasl_password_maps"],
                            services[names[1]]["smtp_sasl_password_maps"])
        for options in services.values():
            self.assertEqual(options["smtp_tls_security_level"], "secure")
            self.assertEqual(options["smtp_tls_secure_cert_match"], "nexthop")
            self.assertEqual(options["smtp_connection_cache_on_demand"], "no")
            self.assertEqual(options["smtp_connection_cache_destinations"], "")
            self.assertEqual(options["smtp_sasl_tls_security_options"], "noplaintext,noanonymous")
            self.assertEqual(options["smtp_sasl_tls_verified_security_options"], "noanonymous")
        self.assertNotIn(b" inet ", master)
        self.assertIn(b"sender_dependent_default_transport_maps = hash:", main)
        self.assertEqual(sha, T.M.plan_sha(rules))

    def test_unsupported_or_overlapping_rules_refused(self):
        for data in ([rule("first@example.org", "plain")],
                     [rule("first@example.org", auth="oauth2")],
                     [rule("example.org", selector="recipient-domain")],
                     [rule("first@example.org"), rule("example.org", selector="envelope-sender-domain")],
                     [rule("first@example.org")] * 9):
            with self.subTest(count=len(data)), self.assertRaises(T.Refused):
                T.plan(data)

    def test_credential_slots_and_formats(self):
        rules, _ = T.plan(fixture())
        good = [dict(username="first", password="secret1"),
                dict(username="second", password="secret2"),
                dict(username="third", password="secret3"), None]
        self.assertEqual(T.credentials(rules, good), [
            "first:secret1", "second:secret2", "third:secret3", None])
        for data in (good[:-1], good[:3] + [good[0]],
                     [dict(username="bad:separator", password="secret")] + good[1:],
                     [dict(username="first", password="bad\nsecret")] + good[1:],
                     [None] + good[1:]):
            with self.assertRaises(T.Refused):
                T.credentials(rules, data)

    def test_native_map_compiler_reads_credential_from_stdin_not_source(self):
        with tempfile.TemporaryDirectory() as work:
            fd = os.open(work, T.M.DIR_FLAGS)
            key, value = "[relay.example.net]:587", "synthetic:secret"
            expected = {key: value}
            calls = []
            def runner(tool, args, data):
                calls.append((tool, args, data))
                self.assertNotIn(value, " ".join(args))
                self.assertNotIn(value.encode(), (pathlib.Path(work) / "private").read_bytes())
                self.assertEqual(tool, "postmap")
                if "-i" in args:
                    self.assertEqual(data, T.rows(expected))
                    T.M.write_file(fd, "private.db", b"fake-db")
                    return 0, b""
                if "-s" in args or "-q" in args and "-" in args:
                    return 0, T.rows(expected)
                return 1, b""
            try:
                self.assertEqual(T.compile_map(fd, work, "hash", "private", expected,
                    os.getuid(), runner, secret=True), "private.db")
                self.assertEqual(len(calls), 4)
                self.assertTrue((pathlib.Path(work) / "private.db").is_file())
            finally:
                os.close(fd)

    def test_wrong_approval_no_native_commands(self):
        rules = fixture()
        with tempfile.TemporaryDirectory() as work:
            def forbidden(*args):
                self.fail("native command before approval")
            with self.assertRaises(T.Refused):
                T.compile_profiles({"rules": rules, "credentials": []}, "0"*64,
                    T.CONFIRM, os.getuid(), work, T.CA_FILES[0], forbidden)
            self.assertEqual(os.listdir(work), [])


if __name__ == "__main__":
    unittest.main()
