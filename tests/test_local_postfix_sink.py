"""Offline tests of the disposable loopback-only Postfix SMTP sink.

No Postfix root access, Microsoft 365 account, Internet socket or SMTP
credential is required. Only localhost on an ephemeral port is contacted.
"""
import email.policy
from email.parser import BytesParser
import importlib.util
from pathlib import Path
import smtplib
import threading
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parent / "smoke_local_postfix_sink.py"
SPEC = importlib.util.spec_from_file_location("smoke_local_postfix_sink", str(SCRIPT))
SINK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SINK)


class LocalPostfixSinkTests(unittest.TestCase):
    def test_refuses_real_hosts_and_wrong_sink_port(self):
        with mock.patch.dict(SINK.os.environ, {"GITHUB_ACTIONS": "false",
                                               "RUNNER_TEMP": "/tmp"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "ephemeral_github_actions"):
                SINK.main(["2525", "46601"])
        with mock.patch.dict(SINK.os.environ, {"GITHUB_ACTIONS": "true",
                                               "RUNNER_TEMP": "/tmp"}, clear=True):
            for values in (["2525", "25"], ["2525", "46500"],
                           ["46601", "46601"], ["-1", "46601"]):
                with self.assertRaises(ValueError):
                    SINK.main(values)

    def test_exact_envelope_smtp_data_and_dot_unstuff(self):
        with SINK.Sink(("127.0.0.1", 0)) as server:
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={"poll_interval": .05}, daemon=True)
            thread.start()
            try:
                with smtplib.SMTP("127.0.0.1", server.server_address[1],
                                 timeout=5) as client:
                    self.assertEqual(client.ehlo()[0], 250)
                    self.assertEqual(client.mail("spoof@evil.example")[0], 550)
                    self.assertEqual(client.mail(SINK.SENDER)[0], 250)
                    self.assertEqual(client.rcpt("external@example.net")[0], 550)
                    self.assertEqual(client.rcpt(SINK.RECIPIENT)[0], 250)
                    self.assertEqual(client.data(
                        "From: alerts@example.org\r\n"
                        "To: ingress@example.org\r\n"
                        "Subject: test\r\n"
                        "\r\n"
                        "First line\r\n"
                        ".dot-prefix\r\n"
                        "Last line\r\n")[0], 250)
                self.assertTrue(server.delivered.wait(3))
                self.assertEqual(len(server.messages), 1)
                sender, recipient, data = server.messages[0]
                self.assertEqual((sender, recipient), (SINK.SENDER, SINK.RECIPIENT))
                parsed = BytesParser(policy=email.policy.default).parsebytes(data)
                self.assertEqual(parsed["From"], SINK.SENDER)
                self.assertEqual(parsed["To"], SINK.RECIPIENT)
                self.assertIn(".dot-prefix", parsed.get_content())
                self.assertNotIn("..dot-prefix", parsed.get_content())
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_pause_for_sampling_is_explicit_and_releasable(self):
        with SINK.Sink(("127.0.0.1", 0), pause_for_sample=True) as server:
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={"poll_interval": .05}, daemon=True)
            thread.start()
            failures = []
            def submit():
                try:
                    with smtplib.SMTP("127.0.0.1", server.server_address[1], timeout=5) as client:
                        client.sendmail(SINK.SENDER, [SINK.RECIPIENT], "Subject: test\r\n\r\nbody")
                except Exception as error:
                    failures.append(error)
            worker = threading.Thread(target=submit, daemon=True)
            worker.start()
            try:
                self.assertTrue(server.pending_sample.wait(3))
                self.assertFalse(server.delivered.is_set())
                server.allow_accept.set()
                self.assertTrue(server.delivered.wait(3))
                worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(failures, [])
            finally:
                server.allow_accept.set()
                server.shutdown()
                thread.join(timeout=5)
                worker.join(timeout=5)

    def test_temporary_failure_fixture_never_accepts_mail(self):
        with SINK.Sink(("127.0.0.1", 0), defer_delivery=True) as server:
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={"poll_interval": .05}, daemon=True)
            thread.start()
            try:
                with smtplib.SMTP("127.0.0.1", server.server_address[1], timeout=5) as client:
                    client.ehlo()
                    client.mail(SINK.SENDER)
                    client.rcpt(SINK.RECIPIENT)
                    self.assertEqual(client.data("Subject: fixture\r\n\r\nsynthetic")[0], 451)
                self.assertTrue(server.pending_sample.is_set())
                self.assertFalse(server.delivered.is_set())
                self.assertEqual(len(server.messages), 1)
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_ci_shell_guards_and_transport_only_loopback(self):
        src = (Path(__file__).parent / "smoke_local_postfix_delivery.sh"
               ).read_text(encoding="utf-8")
        self.assertIn("GITHUB_ACTIONS", src)
        self.assertIn("RUNNER_TEMP", src)
        self.assertIn('SINK=46601', src)
        self.assertIn('"smtp_bind_address = 127.0.0.1"', src)
        self.assertIn('"smtp_fallback_relay ="', src)
        self.assertIn("postqueue -c", src)
        self.assertIn("trap safe_cleanup EXIT", src)
        self.assertIn("LEAVING_LOOPBACK_ROUTE_AND_SERVICE_STOPPED", src)
        self.assertNotIn("sendmail -f", src)
        self.assertNotIn("smtp.office365.com", src)


if __name__ == "__main__":
    unittest.main()
