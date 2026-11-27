"""Local integration test of the disposable Rocky SMTP sink, not SELinux proof."""
import importlib.util
import pathlib
import smtplib
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vm_fixture", ROOT / "tests/rocky_vm_smtp_client_tls_enforcing.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for the synthetic TLS fixture")
class RockyClientTlsFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = pathlib.Path(cls.temp.name)
        cls.patch_work = patch.object(M, "WORK", cls.work)
        cls.patch_work.start()
        cls.addClassCleanup(cls.patch_work.stop)
        M.certificates()

    def exchange(self, identity, expected="first"):
        # Real local TLS handshake. Only the unrelated OS-specific process
        # label assertion is mocked; actual SELinux is verified in Rocky VM.
        real_run = M.run
        def run(*args, **kwargs):
            if args == ("ps", "-eZ"):
                return b"system_u:system_r:postfix_smtp_t:s0 123 smtp\n"
            return real_run(*args, **kwargs)
        token = "LMR365-SYNTHETIC-FIXTURE"
        result = []
        context = ssl.create_default_context(cafile=str(self.work / "ca.pem"))
        if identity is not None:
            context.load_cert_chain(str(self.work / (identity + ".pem")),
                                    str(self.work / (identity + ".key")))
        with patch.object(M, "run", side_effect=run):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.2", 0))
                listener.listen(1)
                listener.settimeout(5)
                address, port = listener.getsockname()
                worker = threading.Thread(target=M.sink,
                    args=(listener, M.fingerprint(expected), token, result), daemon=True)
                worker.start()
                try:
                    with smtplib.SMTP(address, port, timeout=5, local_hostname="test.lab.invalid") as client:
                        client.ehlo()
                        client.starttls(context=context)
                        client.ehlo()
                        client.sendmail(M.SENDER, M.RECIPIENT,
                            "From: " + M.SENDER + "\r\nTo: " + M.RECIPIENT +
                            "\r\nSubject: fixture\r\n\r\n" + token + "\r\n")
                except (OSError, smtplib.SMTPException):
                    if identity == expected:
                        raise
                finally:
                    worker.join(6)
                self.assertFalse(worker.is_alive(), "fixture must terminate")
        return result

    def test_expected_client_certificate_accepted(self):
        self.assertEqual(self.exchange("first"), ["verified"])

    def test_other_trusted_certificate_is_not_expected_identity(self):
        self.assertEqual(self.exchange("second"), ["ValueError"])

    def test_missing_certificate_is_refused(self):
        result = self.exchange(None)
        self.assertEqual(len(result), 1)
        self.assertNotEqual(result, ["verified"])
