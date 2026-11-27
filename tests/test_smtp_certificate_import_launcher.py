import base64
import contextlib
import importlib.util
import io
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("launcher", ROOT / "linux/run-smtp-certificate-import.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


def encode(source):
    return base64.b64encode(source.encode("utf-8")).decode("ascii")


class SmtpCertificateImportLauncherTests(unittest.TestCase):
    def args(self, receiver):
        return ["--domain=relay.example.org", encode("CHECKER = True"),
                encode("STAGER = True"), encode(receiver)]

    def test_bundle_stdin_and_cleanup(self):
        receiver = """
import pathlib, sys, stat
parent = pathlib.Path(__file__).parent
assert stat.S_IMODE(parent.stat().st_mode) == 0o700
for name in ("check-smtp-relay-certificate.py", "stage-smtp-relay-certificate.py"):
    assert stat.S_IMODE((parent / name).stat().st_mode) == 0o600
assert sys.argv[1:] == ["--domain=relay.example.org"]
assert sys.stdin.buffer.read() == b"synthetic-secret"
print("received")
"""
        old_argv = sys.argv
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"synthetic-secret"))):
                with contextlib.redirect_stdout(output):
                    M.run_bundle(self.args(receiver), directory)
            self.assertEqual(output.getvalue(), "received\n")
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])
        self.assertIs(sys.argv, old_argv)

    def test_cleanup_on_receiver_failure(self):
        old_argv = sys.argv
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit):
                M.run_bundle(self.args("raise SystemExit(1)"), directory)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])
        self.assertIs(sys.argv, old_argv)

    def test_bad_arguments_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            for args in ([], ["--domain=x;id", "a", "b", "c"],
                         ["--domain=x", "!!!!", "b", "c"],
                         ["--domain=x", "A" * 65537, "b", "c"]):
                with self.assertRaises(ValueError):
                    M.run_bundle(args, directory)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_nonroot_refused(self):
        with patch.object(M.os, "geteuid", return_value=1000):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(M.main(), 1)
        self.assertIn('"status": "refused"', output.getvalue())

    def test_windows_import_embeds_all_dependencies(self):
        source = ROOT / "src/LinuxMailRelay365"
        project = (source / "LinuxMailRelay365.csproj").read_text()
        assets = (source / "EmbeddedAssets.cs").read_text()
        transfer = (source / "SmtpCertificateTransfer.cs").read_text()
        for name in M.FILES + ("run-smtp-certificate-import.py",):
            self.assertIn("../../linux/" + name, project)
        self.assertIn("BuildSmtpCertificateImportCommand(domain)", transfer)
        self.assertIn("payload, TimeSpan.FromSeconds(120)", transfer)
        self.assertNotIn("/usr/local/libexec/linuxmailrelay365/receive-smtp-certificate-import.py", transfer)
        self.assertIn("/usr/bin/python3 -I -B -c", assets)
