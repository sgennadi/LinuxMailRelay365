"""Offline custom SMTP diagnostics: no external network, no mail delivery."""
import base64
import contextlib
import importlib.util
import io
import json
import pathlib
import unittest
from unittest import mock

FILE = pathlib.Path(__file__).resolve().parents[1] / "linux" / "check-custom-smtp.py"
SPEC = importlib.util.spec_from_file_location("lmr_custom_smtp_probe", FILE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class SmtpFake:
    def __init__(self, starttls=True):
        self.tls_offered = starttls
        self.auth_calls = 0
        self.closed = False
        self.esmtp_features = {"auth": "PLAIN LOGIN"}
    def ehlo(self):
        return (250, b"hello")
    def has_extn(self, name):
        return name == "starttls" and self.tls_offered
    def starttls(self, context):
        return (220, b"ready")
    def auth(self, mechanism, responder, initial_response_ok=False):
        self.auth_calls += 1
        assert mechanism == "PLAIN"
        assert responder() == "\0user@example.org\0testsecret"
        return (235, b"ok")
    def close(self):
        self.closed = True
    def mail(self, *args):
        raise AssertionError("MAIL FROM must never be issued")
    def rcpt(self, *args):
        raise AssertionError("RCPT TO must never be issued")
    def data(self, *args):
        raise AssertionError("DATA must never be issued")


class CustomSmtpProbeTests(unittest.TestCase):
    def request(self, **updates):
        result = {
            "host": "relay.example.org", "port": 587, "tls": "starttls",
            "authenticate": False, "username": "", "secret": "",
        }
        result.update(updates)
        return result

    def test_custom_port_and_host_validation(self):
        for port in (25, 465, 587, 2525, 10025, 65535):
            self.assertEqual(module.validate(self.request(port=port))["port"], port)
        for value in ("", "example..org", "-wrong.example", "999.999.999.999",
                      "127.0.0.1;id", "[::1]", "bad\nname", "bad/name", "a"*255):
            with self.subTest(host=value), self.assertRaises(ValueError):
                module.validate(self.request(host=value))
        self.assertEqual(module.validate(self.request(host="localhost"))["host"], "localhost")

    def test_no_secrets_without_explicit_tls_approval(self):
        for change in (
                {"tls": "plain", "authenticate": True,
                 "username": "user@example.org", "secret": "pw"},
                {"authenticate": True, "username": "", "secret": "pw"},
                {"authenticate": True, "username": "u", "secret": "secret\nline"},
                {"authenticate": False, "username": "u"},
                {"authenticate": False, "secret": "secret"},
                {"port": -1},
                {"port": "587"},
                {"tls": "bogus"},
                {"authenticate": "yes"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.validate(self.request(**change))

    def test_auth_once_after_certificate_validated(self):
        fake = SmtpFake()
        req = self.request(authenticate=True, username="user@example.org",
                           secret="testsecret")
        with mock.patch.object(module.socket, "getaddrinfo", return_value=[object()]), \
             mock.patch.object(module.ssl, "create_default_context", return_value=object()), \
             mock.patch.object(module.smtplib, "SMTP", return_value=fake):
            result = module.probe(module.validate(req))
        self.assertEqual(result["TLS"], "verified")
        self.assertEqual(result["AUTH_RESULT"], "accepted")
        self.assertEqual(fake.auth_calls, 1)
        self.assertTrue(fake.closed)

    def test_never_auth_when_starttls_not_offered(self):
        fake = SmtpFake(starttls=False)
        req = self.request(authenticate=True, username="user@example.org",
                           secret="testsecret")
        with mock.patch.object(module.socket, "getaddrinfo", return_value=[object()]), \
             mock.patch.object(module.ssl, "create_default_context", return_value=object()), \
             mock.patch.object(module.smtplib, "SMTP", return_value=fake):
            result = module.probe(module.validate(req))
        self.assertEqual(result["TLS"], "not_offered")
        self.assertEqual(result["AUTH_RESULT"], "not_requested")
        self.assertEqual(fake.auth_calls, 0)
        self.assertTrue(fake.closed)

    def test_plain_mode_does_not_authenticate(self):
        fake = SmtpFake()
        with mock.patch.object(module.socket, "getaddrinfo", return_value=[object()]), \
             mock.patch.object(module.ssl, "create_default_context", return_value=object()), \
             mock.patch.object(module.smtplib, "SMTP", return_value=fake):
            result = module.probe(module.validate(self.request(tls="plain", port=25)))
        self.assertEqual(result["TLS"], "not_used")
        self.assertEqual(result["AUTH_RESULT"], "not_requested")
        self.assertEqual(fake.auth_calls, 0)

    def test_sanitized_output_and_no_secret_echo(self):
        req = self.request(authenticate=True, username="user@example.org",
                           secret="private-test")
        with mock.patch.object(module, "probe", return_value={
                "DNS": "resolved", "TCP": "reachable", "TLS": "verified",
                "AUTH": "plain", "AUTH_RESULT": "accepted"}):
            log = io.StringIO()
            with contextlib.redirect_stdout(log):
                module.main(req)
        self.assertNotIn(req["secret"], log.getvalue())
        self.assertIn("CUSTOM_SMTP_AUDIT_MAIL_SENT=no", log.getvalue())
        self.assertIn("CUSTOM_SMTP_AUDIT_CONFIG_CHANGED=no", log.getvalue())


if __name__ == "__main__":
    unittest.main()
