"""Read-only TLS identity checks against an isolated custom-port SMTP service.

Python 3.6+ compatibility. Does not send email or authenticate clients.
"""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "verify-sidecar-tls-identity.py"
spec = importlib.util.spec_from_file_location("lmr365_tls_identity", str(SCRIPT))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TlsIdentityTests(unittest.TestCase):
    def test_names_and_paths(self):
        for good in ("smtp.example.org", "smtp.internal.example.org",
                     "mail-01.example.org"):
            self.assertTrue(probe.validate_hostname(good), good)
        for bad in ("localhost", "0.0.0.0", "192.168.0.1",
                    "[::1]", "all", "mail;id.example.org",
                    "*.example.org", "example..org", "-x.example.org",
                    "x-.example.org", ""):
            self.assertFalse(probe.validate_hostname(bad), bad)
        self.assertTrue(probe.validate_ca_file(None))
        self.assertFalse(probe.validate_ca_file("relative-ca.pem"))
        self.assertFalse(probe.validate_ca_file("/tmp/../ca.pem"))
        self.assertFalse(probe.validate_ca_file("/tmp/missing-root-ca-test.pem"))

    def test_invariant_loopback_only_socket_even_if_host_is_public(self):
        # No real network operation; verifies socket arguments.
        obj = probe.LoopbackOnlySmtp()
        obj._host = "smtp.example.org"
        socket_marker = object()
        with patch.object(probe.socket, "create_connection",
                          return_value=socket_marker) as connect:
            result = obj._get_socket("smtp.example.org", 46500, 5)
            self.assertIs(result, socket_marker)
            self.assertEqual(connect.call_args[0][0], ("127.0.0.1", 46500))
            with self.assertRaises(OSError):
                obj._get_socket("evil.example.org", 46500, 5)
            self.assertEqual(connect.call_count, 1)

    def test_no_plaintext_auth_mail_data_or_unsafe_tls(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for unsafe in ("smtp.login(", ".sendmail(", ".send_message(",
                       "smtp.mail(", "smtp.rcpt(", "smtp.docmd('MAIL",
                       "ssl._create_unverified_context(", "CERT_NONE",
                       "check_hostname = False", "os.system(",
                       "systemctl ", "postconf -e", "setenforce "):
            self.assertNotIn(unsafe, source)
        for required in ("ssl.CERT_REQUIRED", "context.check_hostname = True",
                         "smtp.starttls(context=context)", "socket.create_connection",
                         "SMTP_TLS_EXTERNAL_CLIENT_TRUST",
                         "MICROSOFT365_DELIVERY_VERIFIED",
                         "CHANGES_APPLIED"):
            self.assertIn(required, source)

    def test_bad_port_does_not_connect(self):
        for port in (0, 25, 587, 1023, 65536):
            result = probe.probe_tls(port, "smtp.example.org")
            self.assertEqual(result["SMTP_TLS_PROBE_RESULT"], "invalid_port")
            self.assertEqual(result["CHANGES_APPLIED"], "no")

    def test_validate_only_accepts_arbitrary_custom_port(self):
        for port in ("1024", "2525", "2529", "46500", "65535"):
            with self.subTest(port=port):
                run = subprocess.run([sys.executable, str(SCRIPT),
                                      "--validate-only", "--smtp-port", port,
                                      "--server-name", "smtp.example.org"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True, timeout=8)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn("SMTP_TLS_PORT=" + port, run.stdout)
                self.assertIn("SMTP_TLS_ARGUMENTS=valid_no_network", run.stdout)
        for port in ("25", "587", "1023", "65536", "abc"):
            with self.subTest(bad_port=port):
                run = subprocess.run([sys.executable, str(SCRIPT),
                                      "--validate-only", "--smtp-port", port,
                                      "--server-name", "smtp.example.org"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True, timeout=8)
                self.assertNotEqual(run.returncode, 0)

    def test_wrong_dns_and_unknown_ca_block_early(self):
        for args in (["--server-name", "smtp.bad example.org"],
                     ["--server-name", "*.example.org"],
                     ["--server-name", "smtp.example.org", "--ca-file", "/nonexistent/ca.pem"]):
            with self.subTest(args=args):
                run = subprocess.run([sys.executable, str(SCRIPT),
                                      "--validate-only", "--smtp-port", "2529"] + args,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True, timeout=8)
                self.assertNotEqual(run.returncode, 0)


if __name__ == "__main__":
    unittest.main()
