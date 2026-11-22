"""No-network regression contracts for Gmail/Workspace SMTP port/auth auditing."""
import base64
import contextlib
import importlib.util
import io
import json
import pathlib
import smtplib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILE = ROOT / "linux" / "check-google-smtp.py"
SPEC = importlib.util.spec_from_file_location("lmr_google_smtp_probe", FILE)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class FakeClient:
    def __init__(self, authorized=True):
        self.esmtp_features = {"auth": "PLAIN LOGIN XOAUTH2"}
        self.auth_calls = 0
        self.closed = False
        self.authorized = authorized

    def auth(self, method, responder, initial_response_ok=False):
        assert method == "PLAIN"
        self.auth_calls += 1
        # Never print, persist or return credentials from an auth method.
        if self.authorized:
            return 235, b"Authentication succeeded"
        raise smtplib.SMTPAuthenticationError(535, b"Credentials rejected")

    def close(self):
        self.closed = True


class GoogleSmtpProbeTests(unittest.TestCase):
    def config(self, **changes):
        request = {
            "profile": "gmail", "authenticate": False,
            "auth_port": 587, "user": None, "secret": None
        }
        request.update(changes)
        raw = base64.b64encode(json.dumps(request).encode()).decode()
        return module.config_from_encoded(raw)

    def test_fixed_hosts_and_well_defined_ports(self):
        self.assertEqual(module.PROFILES["gmail"][0], "smtp.gmail.com")
        self.assertEqual(module.PROFILES["workspace"][0], "smtp-relay.gmail.com")
        self.assertEqual([n for n, _ in module.PROFILES["gmail"][1]], [587, 465])
        self.assertEqual([n for n, _ in module.PROFILES["workspace"][1]], [587, 465, 25])

    def test_bad_profile_and_command_injection_disallowed(self):
        for change in [
            {"profile": "evil.smtp.example.org"},
            {"auth_port": 2525},
            {"authenticate": True, "user": "bad;id", "secret": "secret"},
            {"authenticate": False, "user": "mail@example.org", "secret": "secret"},
            {"authenticate": True, "user": "x@example.org", "secret": "a\npass"},
        ]:
            with self.subTest(change=str(change)[:80]):
                with self.assertRaises(ValueError):
                    self.config(**change)

    def test_probe_no_credentials_no_smtp_mail_commands(self):
        created = []

        def factory(host, port, mode):
            client = FakeClient()
            created.append(client)
            return client, "reachable", "verified"

        with mock.patch.object(module.socket, "getaddrinfo", return_value=[("ok",)]), \
             mock.patch.object(module, "connect_checked", side_effect=factory):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                module.run(self.config())
        report = output.getvalue()
        self.assertIn("GOOGLE_SMTP_AUDIT_PORT_587_TLS=verified", report)
        self.assertIn("GOOGLE_SMTP_AUDIT_PORT_465_TCP=reachable", report)
        self.assertIn("GOOGLE_SMTP_AUDIT_AUTH_RESULT=not_requested", report)
        self.assertIn("GOOGLE_SMTP_AUDIT_MAIL_SENT=no", report)
        self.assertEqual(len(created), 2)
        self.assertTrue(all(x.closed and x.auth_calls == 0 for x in created))

    def test_credential_auth_once_and_never_prints_secret(self):
        created = []
        def factory(host, port, mode):
            client = FakeClient(authorized=False)
            created.append((port, client))
            return client, "reachable", "verified"
        config = self.config(authenticate=True, user="mail@example.org",
                             secret="SENSITIVE-UNIQUE-SECRET")
        with mock.patch.object(module.socket, "getaddrinfo", return_value=[("ok",)]), \
             mock.patch.object(module, "connect_checked", side_effect=factory):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                module.run(config)
        report = output.getvalue()
        self.assertIn("GOOGLE_SMTP_AUDIT_AUTH_RESULT=rejected_or_policy", report)
        self.assertNotIn(config["secret"], report)
        self.assertNotIn(config["user"], report)
        self.assertEqual(sum(client.auth_calls for _, client in created), 1)
        self.assertTrue(all(client.closed for _, client in created))

    def test_tls_failure_never_tries_smtp_auth(self):
        created = []
        def factory(host, port, mode):
            if port == 587:
                return None, "reachable", "certificate_invalid"
            client = FakeClient()
            created.append(client)
            return client, "reachable", "verified"
        config = self.config(authenticate=True, user="mail@example.org", secret="secret")
        with mock.patch.object(module.socket, "getaddrinfo", return_value=[("ok",)]), \
             mock.patch.object(module, "connect_checked", side_effect=factory):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                module.run(config)
        self.assertIn("GOOGLE_SMTP_AUDIT_AUTH_RESULT=tls_or_connect_unverified", output.getvalue())
        self.assertTrue(all(client.auth_calls == 0 for client in created))


if __name__ == "__main__":
    unittest.main()
