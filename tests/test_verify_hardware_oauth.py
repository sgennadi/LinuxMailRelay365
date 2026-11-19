"""Offline hardware OAuth diagnostics: no real TPM or Exchange is used."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "linux" / "verify-hardware-oauth.py"
SPEC = importlib.util.spec_from_file_location("verify_hardware_oauth", str(SOURCE))
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


class HardwareOAuthDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "identity"
        self.directory.mkdir()
        self.directory.chmod(0o750)
        self.path = self.directory / "app.json"
        self.group = self.directory.stat().st_gid
        self.transport = Path("/usr/local/libexec/linuxmailrelay365-sidecar-transport.py")
        self.identity = {"certificate": "/root/never-expose.pem",
                         "signer": {"type": "openssl-provider", "provider": "tpm2",
                                    "key_ref": "handle:0x81000000",
                                    "provider_config": "/root/never-expose.cnf"}}

    def write(self, data=None):
        self.path.write_text(json.dumps(self.identity if data is None else data))
        self.path.chmod(0o640)

    def test_offline_inventory_and_unsafe_permissions(self):
        self.write()
        with mock.patch.object(V, "secure_path", return_value=True):
            self.assertEqual(V.read_configuration(self.path, self.group)[0],
                             "hardware_configured_unverified")
        # Validate the actual path gate using representative metadata so
        # these tests pass without root on GitHub Actions runners.
        from types import SimpleNamespace
        import stat
        def meta(mode, owner=0, gid=None, links=1):
            return SimpleNamespace(st_mode=mode, st_uid=owner,
                                   st_gid=self.group if gid is None else gid,
                                   st_nlink=links)
        with mock.patch.object(V.Path, "lstat", return_value=meta(stat.S_IFREG | 0o640)):
            self.assertTrue(V.secure_path(self.path, group=self.group, mode=0o640))
        with mock.patch.object(V.Path, "lstat", return_value=meta(stat.S_IFREG | 0o666)):
            self.assertFalse(V.secure_path(self.path, group=self.group, mode=0o640))
        with mock.patch.object(V.Path, "lstat", return_value=meta(stat.S_IFLNK | 0o777)):
            self.assertFalse(V.secure_path(self.path, group=self.group, mode=0o640))
        with mock.patch.object(V.Path, "lstat", return_value=meta(stat.S_IFREG | 0o640, links=2)):
            self.assertFalse(V.secure_path(self.path, group=self.group, mode=0o640))
        with mock.patch.object(V.Path, "lstat", return_value=meta(stat.S_IFREG | 0o640, owner=1000)):
            self.assertFalse(V.secure_path(self.path, group=self.group, mode=0o640))

    def test_software_or_invalid_hardware_identity(self):
        with mock.patch.object(V, "secure_path", return_value=True):
            self.write({"private_key": "/root/key.pem", "certificate": "/root/cert.pem"})
            self.assertEqual(V.read_configuration(self.path, self.group)[0],
                             "software_signer_or_unconfigured")
            self.write(dict(self.identity, private_key="/root/key.pem"))
            self.assertEqual(V.read_configuration(self.path, self.group)[0],
                             "invalid_hardware_identity")
            self.write({"signer": {"provider": "invalid", "type": "openssl-provider"}})
            self.assertEqual(V.read_configuration(self.path, self.group)[0],
                             "invalid_hardware_identity")
            self.path.write_text("{invalid")
            self.assertEqual(V.read_configuration(self.path, self.group)[0],
                             "invalid_identity_json")

    def test_fixed_command_suppresses_assertions_and_secrets(self):
        self.write()
        calls = []
        def pretend(argv, **kw):
            calls.append((argv, kw))
            return SimpleNamespace(returncode=0)
        with mock.patch.object(V, "secure_path", return_value=True):
            status = V.check_target("SIDECAR_ACTIVE", self.path, self.transport,
                                    "--config", self.group, runner=pretend,
                                    find_executable=lambda _: "/usr/sbin/runuser")
        self.assertEqual(status, "provider_ps256_certificate_match_verified")
        self.assertEqual(len(calls), 1)
        argv, kw = calls[0]
        self.assertEqual(argv[:7], ["/usr/sbin/runuser", "-u", "m365mailer", "--",
                                     "/usr/bin/python3", str(self.transport), "--signing-check"])
        self.assertEqual(argv[-2:], ["--config", str(self.path)])
        self.assertIs(kw["stdout"], V.subprocess.DEVNULL)
        self.assertIs(kw["stderr"], V.subprocess.DEVNULL)
        self.assertEqual(kw["timeout"], 90)
        self.assertNotIn("never-expose", " ".join(argv))

    def test_failed_signing_is_not_reported_as_success(self):
        self.write()
        with mock.patch.object(V, "secure_path", return_value=True):
            status = V.check_target("SIDECAR_ACTIVE", self.path, self.transport,
                                    "--config", self.group,
                                    runner=lambda *_a, **_k: SimpleNamespace(returncode=75),
                                    find_executable=lambda _: "/usr/sbin/runuser")
            self.assertEqual(status, "hardware_signature_unavailable")
            state = V.check_target("SIDECAR_ACTIVE", self.path, self.transport,
                                   "--config", self.group, verify=False)
            self.assertEqual(state, "hardware_configured_unverified")

    def test_missing_user_and_no_root(self):
        data = []
        with mock.patch.object(V.os, "geteuid", return_value=1000):
            self.assertEqual(V.inspect(targets=(), output=data.append), 2)
        self.assertEqual(data, ["HARDWARE_OAUTH_ERROR=root_required"])

    def test_report_never_claims_provenance_or_delivery(self):
        self.write()
        data = []
        target = ("SIDECAR_ACTIVE", self.path, self.transport, "--config")
        with mock.patch.object(V.os, "geteuid", return_value=0), \
             mock.patch.object(V.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=self.group)), \
             mock.patch.object(V, "check_target", return_value="provider_ps256_certificate_match_verified"):
            self.assertEqual(V.inspect(targets=(target,), output=data.append), 0)
        report = "\n".join(data)
        self.assertIn("HARDWARE_OAUTH_INSTALLED_VERIFIED=yes", report)
        self.assertIn("HARDWARE_OAUTH_HARDWARE_PROVENANCE_VERIFIED=no", report)
        self.assertIn("HARDWARE_OAUTH_ENTRA_CONTACTED=no", report)
        self.assertIn("HARDWARE_OAUTH_TENANT_DELIVERY_VERIFIED=no", report)
        self.assertIn("HARDWARE_OAUTH_MAIL_CONFIG_CHANGED=no", report)
        self.assertNotIn("never-expose", report)


if __name__ == "__main__":
    unittest.main()
