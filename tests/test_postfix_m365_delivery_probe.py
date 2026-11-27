import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("probe", ROOT / "linux/review-postfix-m365-delivery.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class PostfixDeliveryProbeTests(unittest.TestCase):
    def setUp(self):
        self.req = {"run_id": "a"*32, "sender": "relay@example.org", "internal": "test@example.org",
                    "external": "test@outside.net", "mx": "example-org.mail.protection.outlook.com",
                    "accepted_domain": "example.org"}
        self.sha = "b"*64

    def test_address_and_domain_checks(self):
        self.assertEqual(M.validate_request(self.req), self.req)
        for change in ({"external": "another@example.org"}, {"sender": "bad\n@foo.org"},
                       {"mx": "evil.example.org"}, {"internal": "-x@example.org"}):
            with self.assertRaises(ValueError):
                M.validate_request(dict(self.req, **change))

    def test_route_requires_exact_mx_and_mandatory_tls(self):
        settings = {"config_directory": "/etc/postfix", "relayhost": "["+self.req["mx"]+"]:25",
                    "default_transport": "smtp", "relay_transport": "relay",
                    "smtp_sasl_auth_enable": "no", "smtp_tls_security_level": "encrypt",
                    "mydestination": "localhost, localhost.localdomain"}
        read = lambda key: settings.get(key, "")
        self.assertEqual(M.route_settings(read, "", self.req)["relayhost"], self.req["mx"])
        for key, value in (("transport_maps", "hash:/etc/postfix/transport"),
                           ("smtp_tls_security_level", "may"), ("mydestination", "example.org"),
                           ("relayhost", "[evil.example.org]:25")):
            changed = dict(settings, **{key: value})
            with self.assertRaises(ValueError):
                M.route_settings(lambda name: changed.get(name, ""), "", self.req)
        with self.assertRaises(ValueError):
            M.route_settings(read, "smtp/unix/smtp_tls_security_level=none", self.req)

    def test_stale_review_does_not_reserve_or_send(self):
        with patch.object(M, "reserve") as reserve:
            runner = Mock()
            with self.assertRaises(ValueError):
                M.submit(self.req, self.sha, lambda _: {"plan_sha256": "c"*64}, runner)
            reserve.assert_not_called()
            runner.assert_not_called()

    def test_reserved_attempt_before_send_and_no_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(M, "ROOT", pathlib.Path(temp)/"ledger"), patch.object(M, "directory"):
                plan = lambda _: {"plan_sha256": self.sha, "_binary": "/usr/sbin/sendmail.postfix"}
                def run(args, **kwargs):
                    raw = M.ledger_file(self.req).read_text()
                    self.assertIn('"event":"attempted","role":"internal"', raw)
                    self.assertEqual(args[-1], self.req["internal"])
                    self.assertIn(M.message_id(self.req, "internal").encode(), kwargs["input"])
                    return Mock(returncode=1)
                runner = Mock(side_effect=run)
                outcome = M.submit(self.req, self.sha, plan, runner)
                self.assertEqual(outcome["outcomes"], {"internal": "submission_uncertain"})
                with self.assertRaises(FileExistsError):
                    M.submit(self.req, self.sha, plan, runner)
                self.assertEqual(runner.call_count, 1)

    def test_trace_requires_exact_id_recipient_and_relay(self):
        marker = M.message_id(self.req, "internal")
        lines = ["ABC123: message-id="+marker,
                 "OTHER1: to=<test@example.org>, relay="+self.req["mx"]+"[192.0.2.1]:25, dsn=2.0.0, status=sent (ok)",
                 "ABC123: to=<test@example.org>, relay="+self.req["mx"]+"[192.0.2.1]:25, dsn=2.0.0, status=sent (ok)"]
        result = M.correlate(self.req, "internal", lines, [], "local_submission_accepted")
        self.assertEqual(result["transport"], "exchange_relay_accepted")
        self.assertEqual(result["queue"], "not_observed")
        self.assertEqual(result["dsn"], "2.0.0")
        self.assertNotIn(self.req["internal"], str(result))
        self.assertEqual(M.correlate(self.req, "internal", lines[:2], [], "attempted")["transport"], "unknown")
        self.assertEqual(M.correlate(self.req, "internal", lines+["OTHER2: message-id="+marker], [], "attempted")["transport"], "correlation_unavailable")

    def test_queue_state_not_delivery(self):
        lines = ["ABC123: message-id="+M.message_id(self.req, "external"),
                 "ABC123: to=<test@outside.net>, relay=none, dsn=4.4.1, status=deferred (private detail)"]
        queue = [{"queue_id": "ABC123", "queue_name": "deferred", "recipients": [{"address": self.req["external"]}]}]
        result = M.correlate(self.req, "external", lines, queue, "local_submission_accepted")
        self.assertEqual(result["transport"], "deferred")
        self.assertEqual(result["queue"], "deferred")
        self.assertNotIn("private detail", str(result))

    def test_package_ownership_requires_native_postfix(self):
        import subprocess
        adapter = Mock()
        adapter.trusted_binary.side_effect = lambda path: path
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, b"postfix: /usr/sbin/sendmail\n"))
        M.verify_postfix_package("/usr/sbin/sendmail", adapter, runner)
        runner.return_value = subprocess.CompletedProcess([], 0, b"exim4-daemon-light: /usr/sbin/sendmail\n")
        with self.assertRaises(ValueError):
            M.verify_postfix_package("/usr/sbin/sendmail", adapter, runner)

    def test_remote_response_text_cannot_supply_missing_relay(self):
        lines = ["ABC123: message-id="+M.message_id(self.req, "internal"),
                 "ABC123: to=<test@example.org>, relay=none, dsn=4.4.1, status=deferred (relay="+
                 self.req["mx"]+"[192.0.2.1]:25, dsn=2.0.0, status=sent)"]
        result = M.correlate(self.req, "internal", lines, [], "local_submission_accepted")
        self.assertEqual(result["transport"], "deferred")
        self.assertEqual(result["dsn"], "4.4.1")
