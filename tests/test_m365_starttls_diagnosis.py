import importlib.util
import pathlib
import socket
import ssl
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("probe", ROOT / "linux/inspect-m365-starttls.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
HOST = "example-org.mail.protection.outlook.com"
V4 = (socket.AF_INET, socket.SOCK_STREAM, 6, ("192.0.2.10", 25))
V6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, ("2001:db8::1", 25, 0, 0))


class StartTlsDiagnosisTests(unittest.TestCase):
    def client(self):
        c = Mock()
        c.connect.return_value = (220, b"private banner")
        c.ehlo.return_value = (250, b"private ehlo")
        c.has_extn.return_value = True
        c.starttls.return_value = (220, b"private response")
        c.sock.getpeercert.side_effect = lambda binary_form=False: b"synthetic DER" if binary_form else {
            "subjectAltName": [("DNS", HOST)], "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "Jan 01 00:00:00 2026 GMT", "notAfter": "Jan 01 00:00:00 2027 GMT"}
        c.sock.version.return_value = "TLSv1.3"
        c.sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        return c

    def test_success_no_envelope_auth_or_raw_responses(self):
        c = self.client()
        ctx = Mock()
        row = M.probe_one(HOST, V4, ctx, lambda *args: c)
        self.assertEqual(row["status"], "tls_verified")
        self.assertEqual(row["protocol"], "TLSv1.3")
        self.assertTrue(row["certificate_chain_and_hostname_verified"])
        self.assertEqual(len(row["certificate_sha256"]), 64)
        c.starttls.assert_called_once_with(context=ctx)
        c.close.assert_called_once()
        for command in ("login", "sendmail", "mail", "rcpt", "data", "auth"):
            getattr(c, command).assert_not_called()
        self.assertNotIn("private", str(row))

    def test_missing_starttls_and_bad_banner(self):
        c = self.client()
        c.has_extn.return_value = False
        self.assertEqual(M.probe_one(HOST, V4, Mock(), lambda *args: c)["status"], "starttls_missing")
        c.starttls.assert_not_called()
        c.connect.return_value = (421, b"private")
        self.assertEqual(M.probe_one(HOST, V4, Mock(), lambda *args: c)["banner_code"], 421)

    def test_certificate_failure_no_downgrade(self):
        c = self.client()
        c.starttls.side_effect = M.CERT_ERROR("private")
        row = M.probe_one(HOST, V4, Mock(), lambda *args: c)
        self.assertEqual(row["status"], "certificate_verification_failed")
        self.assertEqual(c.starttls.call_count, 1)
        self.assertNotIn("certificate_chain_and_hostname_verified", row)

    def test_resolver_rejects_private_addresses(self):
        with patch.object(M.socket, "getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 25))]):
            with self.assertRaises(ValueError):
                M.resolve(HOST)

    def test_bounded_family_sampling(self):
        probe = Mock(return_value={"status": "tls_verified"})
        result = M.inspect(HOST, lambda _: [V4, V4, V6], Mock(), probe)
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(result["resolved_count"], 3)
        self.assertFalse(result["mail_sent"])
        self.assertFalse(result["postfix_process_tested"])
        self.assertFalse(result["client_certificate_loaded"])

    def test_invalid_mx_never_resolved(self):
        resolver = Mock()
        for host in ("evil.example.org", HOST + ".evil.org", "-bad.mail.protection.outlook.com"):
            with self.assertRaises(ValueError):
                M.inspect(host, resolver)
        resolver.assert_not_called()

    def test_context_verification_enabled(self):
        ctx = M.context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_global_deadline_cannot_be_swallowed_by_socket_timeout(self):
        c = self.client()
        c.connect.side_effect = M.DeadlineExceeded("deadline")
        with self.assertRaises(M.DeadlineExceeded):
            M.probe_one(HOST, V4, Mock(), lambda *args: c)
        c.close.assert_called_once()

    def test_trust_environment_overrides_not_used(self):
        import os
        defaults = ssl.get_default_verify_paths()
        keys = [key for key in (defaults.openssl_cafile_env, defaults.openssl_capath_env) if key]
        with patch.dict(os.environ, {key: "/nonexistent-test-trust" for key in keys}):
            ctx = M.context()
            for key in keys:
                self.assertNotIn(key, os.environ)
            self.assertTrue(ctx.check_hostname)


class PublicMxTests(unittest.TestCase):
    def answer(self, records="", status="NOERROR"):
        runner = Mock(return_value=Mock(returncode=0, stdout=(
            ";; ->>HEADER<<- opcode: QUERY, status: "+status+", id: 42\n"
            ";; flags: qr rd ra; QUERY: 1, ANSWER: 1\n"+records).encode()))
        result = M.public_mx("example.org", runner)
        self.assertFalse(result["tenant_verified"])
        self.assertFalse(result["postfix_modified"])
        self.assertFalse(result["mail_sent"])
        return result

    def test_unique_preferred_direct_mx(self):
        result = self.answer("example.org. 300 IN MX 20 backup.mail.protection.outlook.com.\n"
                             "example.org. 300 IN MX 10 primary.mail.protection.outlook.com.\n")
        self.assertEqual(result["status"], "direct_m365")
        self.assertEqual(result["recommended_mx"], "primary.mail.protection.outlook.com")

    def test_gateway_mixed_and_tied_no_guess(self):
        for records, status in (
            ("example.org. 300 IN MX 1 gateway.example.net.\n", "mixed_or_gateway"),
            ("example.org. 300 IN MX 1 primary.mail.protection.outlook.com.\n"
             "example.org. 300 IN MX 10 gateway.example.net.\n", "mixed_or_gateway"),
            ("example.org. 300 IN MX 1 a.mail.protection.outlook.com.\n"
             "example.org. 300 IN MX 1 b.mail.protection.outlook.com.\n", "multiple_preferred"),
            ("example.org. 300 IN MX 0 .\n", "null_mx"),
            ("example.org. 300 IN CNAME elsewhere.example.net.\n", "dns_unverified"),
            ("other.example.org. 300 IN MX 0 a.mail.protection.outlook.com.\n", "dns_unverified"),
            ("example.org. 300 IN MX 65536 a.mail.protection.outlook.com.\n", "dns_unverified"),
            ("example.org. 300 IN MX 0 a.mail.protection.outlook.com.evil.net.\n", "mixed_or_gateway"),
            ("", "no_mx")):
            with self.subTest(status=status, records=records):
                result = self.answer(records)
                self.assertEqual(result["status"], status)
                self.assertIsNone(result["recommended_mx"])

    def test_nxdomain_and_missing_dig(self):
        self.assertEqual(self.answer(status="NXDOMAIN")["status"], "nxdomain")
        result = M.public_mx("example.org", Mock(side_effect=FileNotFoundError()))
        self.assertEqual(result["status"], "dig_missing")
        self.assertIsNone(result["recommended_mx"])

    def test_invalid_domain_never_queries(self):
        runner = Mock()
        with self.assertRaises(ValueError):
            M.public_mx("@evil.example.org", runner)
        runner.assert_not_called()

    def test_gui_wiring_preserves_configured_mx(self):
        src = ROOT / "src/LinuxMailRelay365"
        self.assertIn("BuildM365MxDiscovery", (src/"EmbeddedAssets.cs").read_text())
        self.assertIn('action == "mx-discovery"', (src/"MainForm.DeliveryMiniWizard.cs").read_text())
        ui = (src/"SmtpTlsRotationDialog.cs").read_text()
        self.assertIn("existing.Length == 0", ui)
        self.assertIn("Existing value preserved", ui)
