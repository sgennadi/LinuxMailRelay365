"""Offline tests of isolated Postfix pre-DATA SMTP envelope checking."""
import importlib.util
import io
import pathlib
import subprocess
import sys
import unittest
from unittest import mock
from types import SimpleNamespace
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "verify-sidecar-envelope.py"
SPEC = importlib.util.spec_from_file_location("sidecar_envelope", str(SCRIPT))
E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E)


class FakeReader:
    def __init__(self, responses):
        self.responses = iter(responses)

    def readline(self, _limit):
        return next(self.responses, b"")

    def close(self):
        pass


class FakeSock:
    def __init__(self, replies, tls=False):
        self.reader = FakeReader(replies)
        self.sent = []
        self.tls = tls

    def settimeout(self, _value):
        pass

    def makefile(self, _mode):
        return self.reader

    def sendall(self, packet):
        self.sent.append(packet)

    def version(self):
        return "TLSv1.3"

    def close(self):
        pass


def simulated_probe(rcpt_code=250, expect_reject=False):
    plain = FakeSock([b"220 local SMTP ready\r\n",
                      b"250-local\r\n", b"250 STARTTLS\r\n",
                      b"220 start tls\r\n"])
    tls = FakeSock([b"250-local\r\n", b"250 AUTH PLAIN\r\n",
                    b"235 auth accepted\r\n",
                    b"250 sender ok\r\n",
                    ("%d recipient decision\r\n" % rcpt_code).encode("ascii"),
                    b"250 reset ok\r\n", b"221 bye\r\n"], tls=True)
    ctx = SimpleNamespace(verify_mode=None, check_hostname=False,
                          minimum_version=None,
                          wrap_socket=lambda _sock, server_hostname: tls)
    with mock.patch.object(E.socket, "create_connection", return_value=plain) as connect, \
         mock.patch.object(E.ssl, "create_default_context", return_value=ctx):
        status = E.probe(46500, "relay.example.org", "smtp-app01", "",
                         "alerts@example.org", "internal@example.org",
                         expect_reject=expect_reject,
                         password_provider=lambda _prompt: "Temporary-Secret_123456")
    assert connect.call_args[0] == (("127.0.0.1", 46500),)
    return status, plain, tls


class SidecarEnvelopeTests(unittest.TestCase):
    def test_validated_tls_auth_and_positive_rcpt_no_data(self):
        status, plain, tls = simulated_probe()
        self.assertEqual(status, "rcpt_accepted_without_data")
        self.assertEqual(plain.sent, [b"EHLO lmr365-envelope-check.invalid\r\n",
                                      b"STARTTLS\r\n"])
        self.assertTrue(tls.sent[0].startswith(b"EHLO "))
        self.assertTrue(tls.sent[1].startswith(b"AUTH PLAIN "))
        self.assertEqual(tls.sent[2], b"MAIL FROM:<alerts@example.org>\r\n")
        self.assertEqual(tls.sent[3], b"RCPT TO:<internal@example.org>\r\n")
        self.assertEqual(tls.sent[4:], [b"RSET\r\n", b"QUIT\r\n"])
        self.assertFalse(any(x.startswith(b"DATA") for x in tls.sent))

    def test_expected_permanent_rcpt_deny(self):
        status, _plain, tls = simulated_probe(554, expect_reject=True)
        self.assertEqual(status, "rcpt_rejected_as_expected")
        self.assertIn(b"RSET\r\n", tls.sent)
        with self.assertRaises(E.Refused):
            simulated_probe(450, expect_reject=True)
        with self.assertRaises(E.Refused):
            simulated_probe(250, expect_reject=True)

    def test_unexpected_rcpt_rejection_is_failure(self):
        with self.assertRaises(E.Refused):
            simulated_probe(554, expect_reject=False)

    def test_address_header_and_port_injection_refused_before_network(self):
        E.validate(46500, "relay.example.org", "smtp-app01", "",
                   "alerts@example.org", "recipient@outside.example")
        for sender, recipient in (
            ("foo\nRCPT TO:<evil@example.net>@example.org", "ok@example.org"),
            ("bad@example.org\r\nDATA", "ok@example.org"),
            ("bad..dot@example.org", "ok@example.org"),
            ("foo@example.org", "<postmaster@example.org>"),
            ("foo@example.org", "foo@@example.org"),
            ("foo@example.org", "recipient@localhost"),
            ("", "ok@example.org"),
        ):
            with self.subTest(sender=repr(sender), recipient=repr(recipient)):
                with self.assertRaises(E.Refused):
                    E.validate(46500, "relay.example.org", "smtp-app01", "",
                               sender, recipient)
        for port in (0, 25, 587, 1023, 65536):
            with self.assertRaises(E.Refused):
                E.validate(port, "relay.example.org", "smtp-app01", "",
                           "a@example.org", "b@example.org")
        for ca in ("relative.pem", "/tmp/../shadow", "/bad file.pem"):
            with self.assertRaises(E.Refused):
                E.validate(46500, "relay.example.org", "smtp-app01", ca,
                           "a@example.org", "b@example.org")

    def test_noninteractive_never_prompts_or_connects(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--smtp-port", "46500",
                                 "--server-name", "relay.example.org",
                                 "--login", "smtp-app01"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True,
                                timeout=8)
        self.assertEqual(result.returncode, 2)
        self.assertIn("SMTP_ENVELOPE_PREFLIGHT_RESULT=interactive_terminal_required",
                      result.stdout)
        self.assertIn("SMTP_ENVELOPE_PREFLIGHT_DATA_SENT=no", result.stdout)
        self.assertNotIn("Test MAIL", result.stdout)
        self.assertNotIn("Temporary-Secret", result.stdout)
        result = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=8)
        self.assertEqual(result.returncode, 0)
        self.assertIn("SMTP_ENVELOPE_PREFLIGHT_RESULT=self_test_passed",
                      result.stdout)

    def test_fixed_output_never_exposes_credentials(self):
        out = io.StringIO()
        with redirect_stdout(out):
            E.output("rcpt_accepted_without_data")
        data = out.getvalue()
        self.assertIn("SMTP_ENVELOPE_PREFLIGHT_DATA_SENT=no", data)
        self.assertIn("SMTP_ENVELOPE_PREFLIGHT_TENANT_DELIVERY_VERIFIED=no", data)
        self.assertNotIn("@example.org", data)
        self.assertNotIn("Temporary-Secret", data)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('sendall(b"DATA', source)
        self.assertNotIn(".sendmail(", source)
        self.assertNotIn(".send_message(", source)


if __name__ == "__main__":
    unittest.main()
