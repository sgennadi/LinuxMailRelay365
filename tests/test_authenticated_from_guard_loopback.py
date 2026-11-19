"""Offline contract tests for disposable real SMTP AUTH/From Guard smoke.

No Postfix or privileged operation is executed by these tests.
"""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PY = ROOT / "tests" / "smoke_authenticated_from_guard_loopback.py"
SH = ROOT / "tests" / "smoke_authenticated_from_guard_loopback.sh"

spec = importlib.util.spec_from_file_location("lmr365_real_fromguard_ci", str(PY))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class AuthFromGuardLoopbackFixtureTests(unittest.TestCase):
    def test_requires_disposable_actions_runner_and_exact_ca(self):
        with mock.patch.dict(fixture.os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                fixture.require_disposable_fixture(["2529", fixture.CA_PATH])
        with mock.patch.dict(fixture.os.environ,
                             {"GITHUB_ACTIONS": "true", "RUNNER_TEMP": "/tmp"},
                             clear=True), mock.patch.object(fixture.Path, "is_file", return_value=True):
            for args in ([], ["25", fixture.CA_PATH], ["0", fixture.CA_PATH],
                         ["46601", fixture.CA_PATH], ["2529", "/tmp/other-ca.pem"],
                         ["2529", fixture.CA_PATH, "extra"]):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    fixture.require_disposable_fixture(args)
            self.assertEqual(fixture.require_disposable_fixture(["2529", fixture.CA_PATH]), 2529)

    def test_positive_and_spoofed_headers_are_separate_smtp_data_trials(self):
        source = PY.read_text(encoding="utf-8")
        for header in ("From: billing@example.org", "duplicate_from",
                       "Sender: billing@example.org", "Return-Path:",
                       "Resent-From:", "group_from", "missing_from"):
            self.assertIn(header, source)
        self.assertIn("client.data(raw_message)", source)
        self.assertIn("client.login(LOGIN, password)", source)
        self.assertIn("client.starttls(context=ctx)", source)
        self.assertIn("SSL", source.replace("ssl", "SSL"))
        self.assertIn("if not should_accept and code < 500", source)
        self.assertIn("if len(receiver.messages) != 1", source)
        self.assertIn("MICROSOFT365_DELIVERY_VERIFIED=no", source)
        self.assertIn("XOAUTH2_MULTI_MAILBOX_ENABLED=no", source)
        self.assertNotIn("smtp.office365.com", source)

    def test_wrapper_guarantees_isolated_routing_and_queue_fail_closed(self):
        source = SH.read_text(encoding="utf-8")
        for expected in (
            "GITHUB_ACTIONS", "RUNNER_TEMP", "SINK=46601",
            'sudo systemctl stop "$UNIT"',
            '"default_transport = smtp:[127.0.0.1]:$SINK"',
            '"relay_transport = smtp:[127.0.0.1]:$SINK"',
            '"relayhost = [127.0.0.1]:$SINK"',
            '"smtp_fallback_relay ="',
            '"smtp_bind_address = 127.0.0.1"',
            "postqueue -c", "trap finish EXIT",
            "FAIL_CLOSED_QUEUED_MAIL_LOOPBACK_ROUTE_SERVICE_STOPPED",
            "sha256sum", "smtp_authenticated_from_guard_loopback.py",
            "MICROSOFT365_DELIVERY_VERIFIED=no",
        ):
            # Accepted spelling in the subprocess invocation.
            if expected == "smtp_authenticated_from_guard_loopback.py":
                expected = "smoke_authenticated_from_guard_loopback.py"
            with self.subTest(needle=expected):
                self.assertIn(expected, source)
        self.assertIn("require_setting fallback_relay", source)
        self.assertIn("unsafe_fallback_relay", source)
        self.assertIn("smtp_fallback_relay =", source)
        self.assertNotIn("sendmail -f", source)
        self.assertNotIn("smtp.office365.com", source)
        self.assertNotIn('sudo systemctl start "$GUARD_UNIT"', source)
        self.assertIn("missing_sidecar_guard_autostart_link", source)
        self.assertIn("SOCKET_RECREATED_AUTOMATICALLY_AFTER_SIDECAR_STOP=yes", source)
        self.assertNotIn("postconf -e", source.replace('postconf -c "$CONF" -e', ""))

    def test_systemd_guard_autorestarts_with_isolated_postfix(self):
        source = (ROOT / "linux" / "install-sidecar-from-guard.sh").read_text(encoding="utf-8")
        smoke = (ROOT / "tests" / "smoke_from_owner_milter.sh").read_text(encoding="utf-8")
        self.assertIn("Requires=linuxmailrelay365-sidecar.service", source)
        self.assertIn("After=linuxmailrelay365-sidecar.service", source)
        self.assertIn("WantedBy=multi-user.target linuxmailrelay365-sidecar.service", source)
        self.assertIn("systemctl enable --now", source)
        self.assertIn("missing_automatic_sidecar_start_dependency", smoke)
        self.assertIn("linuxmailrelay365-sidecar.service.wants/linuxmailrelay365-from-guard.service", smoke)

    def test_real_ubuntu_smoke_wires_the_guarded_fixture(self):
        primary = (ROOT / "tests" / "smoke_isolated_postfix.sh").read_text("utf-8")
        milter = (ROOT / "tests" / "smoke_from_owner_milter.sh").read_text("utf-8")
        self.assertIn('bash tests/smoke_from_owner_milter.sh "$PORT"', primary)
        self.assertIn('bash tests/smoke_authenticated_from_guard_loopback.sh "$PORT"', milter)
        self.assertIn("--confirm DEPLOY_PRIVATE_EOP_ROUTE", milter)
        self.assertLess(milter.index("bash tests/smoke_authenticated_from_guard_loopback.sh"),
                        milter.index("=== Verify independent root-only DR archive"))


if __name__ == "__main__":
    unittest.main()
