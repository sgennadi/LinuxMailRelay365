"""Manual STARTTLS+SMTP AUTH verifier safety and input tests.

Python 3.6+ / RHEL 8-10 compatible. Never opens a real SMTP connection.
A separate ephemeral Ubuntu Postfix smoke tests an authenticated login.
"""
import base64
import importlib.util
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "verify-sidecar-auth-client.py"
spec = importlib.util.spec_from_file_location("lmr365_auth_client", str(SCRIPT))
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)


class SMTPAuthClientTests(unittest.TestCase):
    def test_validation_rejects_unsafe_inputs(self):
        auth.validate(46500, "relay.example.org", "smtp-app01", "")
        auth.validate(1024, "relay.example.org", "smtp-app01", "/tmp/ca.pem")
        auth.validate(25, "relay.example.org", "smtp-app01", "")
        for port in (0, 587, 1023, 65536):
            with self.subTest(port=port), self.assertRaises(auth.Refused):
                auth.validate(port, "relay.example.org", "smtp-app01", "")
        for name in ("", "evil", "bad;name", "foo..bar", "-bad.example.org"):
            with self.subTest(hostname=name), self.assertRaises(auth.Refused):
                auth.validate(46500, name, "smtp-app01", "")
        for login in ("", "x", "bad;name", "a" * 65):
            with self.subTest(login=login), self.assertRaises(auth.Refused):
                auth.validate(46500, "relay.example.org", login, "")
        for bad in ("relative.pem", "/tmp/../../etc/shadow", "/tmp/ca pem",
                    "/tmp/key;rm"):
            with self.subTest(ca=bad), self.assertRaises(auth.Refused):
                auth.validate(46500, "relay.example.org", "smtp-app01", bad)

    def test_plain_auth_frame_and_password_never_logged(self):
        frame = auth.make_auth_plain("smtp-app01", "Temporary-Secret_12345678")
        self.assertTrue(frame.startswith(b"AUTH PLAIN "))
        self.assertTrue(frame.endswith(b"\r\n"))
        decoded = base64.b64decode(frame[11:].strip())
        self.assertEqual(decoded, b"\x00smtp-app01\x00Temporary-Secret_12345678")
        for invalid in ("tiny", "\x00injected", "spaces not allowed", "\nmalicious"):
            with self.subTest(password=repr(invalid)), self.assertRaises(auth.Refused):
                auth.make_auth_plain("smtp-app01", invalid)
        self.assertRaises(auth.Refused, auth.make_auth_plain,
                          "bad;login", "Temporary-Secret_12345678")

    def test_cli_refuses_noninteractive_login_even_with_valid_arguments(self):
        p = subprocess.run([sys.executable, str(SCRIPT), "--smtp-port", "46500",
                            "--server-name", "relay.example.org",
                            "--login", "smtp-app01"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=8)
        self.assertEqual(p.returncode, 2)
        self.assertIn("SMTP_AUTH_CLIENT_RESULT=interactive_terminal_required", p.stdout)
        self.assertIn("SMTP_AUTH_CREDENTIALS_LOGGED=no", p.stdout)
        self.assertIn("SMTP_MAIL_FROM_RCPT_DATA_SENT=no", p.stdout)
        self.assertIn("MICROSOFT365_DELIVERY_VERIFIED=no", p.stdout)
        self.assertNotIn("SMTP app password", p.stdout)
        test = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=8)
        self.assertEqual(test.returncode, 0)
        self.assertIn("SMTP_AUTH_CLIENT_RESULT=self_test_passed", test.stdout)

    def test_input_fail_closed_without_password_or_network(self):
        p = subprocess.run([sys.executable, str(SCRIPT), "--smtp-port", "587",
                            "--server-name", "relay.example.org",
                            "--login", "smtp-app01"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=8)
        self.assertEqual(p.returncode, 2)
        self.assertIn("SMTP_AUTH_CLIENT_RESULT=invalid_smtp_port", p.stdout)

    def test_source_never_prints_secret_or_sends_mail(self):
        data = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("context.check_hostname = True", data)
        self.assertIn("context.verify_mode = ssl.CERT_REQUIRED", data)
        self.assertIn("socket.create_connection((\"127.0.0.1\", port)", data)
        self.assertIn("MICROSOFT365_DELIVERY_VERIFIED=no", data)
        self.assertIn("password_provider(", data)
        self.assertIn('sys.stdin.isatty() and sys.stderr.isatty()', data)
        for forbidden in ('sendall(b"MAIL', 'sendall(b"RCPT',
                          'sendall(b"DATA', ".sendmail(",
                          'print(password', 'print(request',
                          'print(username', 'smtp.office365.com'):
            self.assertNotIn(forbidden, data)


if __name__ == "__main__":
    unittest.main()
