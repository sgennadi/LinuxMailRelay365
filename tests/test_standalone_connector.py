"""Standalone isolated Microsoft 365 Connector deployment contracts.

Live Azure/Exchange authorization and external recipient delivery are NOT
claimed. The primary Postfix must be preserved and RHEL Enforcing is refused.
Python 3.6-compatible; no mail is submitted.
"""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "install-connector-sidecar.sh"


class FreshConnectorContracts(unittest.TestCase):
    def run_cmd(self, *args):
        return subprocess.run(["bash", str(SCRIPT)] + list(args),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=12)

    def base(self, port="46500"):
        return ("--smtp-port", port,
                "--mx-host", "example-org.mail.protection.outlook.com",
                "--accepted-domain", "example.org",
                "--fixed-sender", "alerts@example.org",
                "--public-ip", "8.8.8.8")

    def test_fresh_sidecar_detection_does_not_require_oauth_identity(self):
        source = (ROOT / "src/LinuxMailRelay365/SshRemote.cs").read_text(encoding="utf-8")
        body = source.split("internal static async Task<bool> HasIsolatedSidecarAsync(", 1)[1].split(
            "internal static async Task<int> GetIsolatedSidecarPortAsync", 1)[0]
        self.assertIn('"/smtp-port"', body)
        self.assertIn('"/main.cf"', body)
        self.assertNotIn("SidecarIdentity", body)

    def test_bash_syntax_and_selftest(self):
        shell = subprocess.run(["bash", "-n", str(SCRIPT)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=10)
        self.assertEqual(shell.returncode, 0, shell.stderr)
        result = self.run_cmd("--self-test")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CONNECTOR_SIDECAR_PARSER=ready", result.stdout)

    def test_safe_input_preflight_and_custom_port(self):
        for port in ("1024", "2525", "2529", "46500", "65535"):
            with self.subTest(port=port):
                result = self.run_cmd("--check-only", *self.base(port))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("CONNECTOR_PREFLIGHT=inputs_valid_only", result.stdout)
                self.assertIn("external_recipients_need_verified_tenant_connector", result.stdout)
                self.assertIn("CHANGES_APPLIED=no", result.stdout)
                self.assertIn("CONNECTOR_TENANT_CONNECTOR_VERIFIED=no", result.stdout)

    def test_invalid_ports_and_unknown_tenant_identity_fail_closed(self):
        for port in ("25", "587", "1023", "65536", "0", "x"):
            with self.subTest(port=port):
                result = self.run_cmd("--check-only", *self.base(port))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid_custom_port", result.stderr)
        missing_ip = list(self.base())
        missing_ip[-2:] = []
        result = self.run_cmd("--check-only", *missing_ip)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("connector_public_ipv4_or_certificate_required", result.stderr)
        for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.20", "0.0.0.0"):
            with self.subTest(ip=ip):
                args = list(self.base())
                args[-1] = ip
                result = self.run_cmd("--check-only", *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid_public_egress_ipv4", result.stderr)

    def test_apply_requires_two_independent_tenant_approvals(self):
        result = self.run_cmd("--apply", *self.base())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tenant_domain_confirmation_required", result.stderr)
        result = self.run_cmd("--apply", *self.base(),
                              "--confirm-accepted-domain", "TENANT_DOMAIN_CHECKED")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tenant_connector_confirmation_required", result.stderr)

    def test_primary_server_isolation_and_sasl_scope(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for expected in (
            "PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes",
            "CONNECTOR_SIDECAR_INSTALLED=yes",
            "CONNECTOR_TENANT_CONNECTOR_VERIFIED=operator_attestation_only",
            "CONNECTOR_RECIPIENT_SCOPE=external_recipients_need_verified_tenant_connector",
            "smtp_tls_security_level = secure", "smtp_tls_secure_cert_match = nexthop",
            "smtpd_client_restrictions = permit_mynetworks, reject",
            "smtpd_relay_restrictions = permit_mynetworks, reject",
            "eop-recipients.regexp", "smtp_tls_cert_file = $CERT",
            "selinux_enforcing_not_integration_verified"):
            self.assertIn(expected, source)
        for blocked in ("setenforce 0", "ufw allow", "systemctl restart postfix",
                        "New-InboundConnector", "New-MgApplication", "postconf -e",
                        "smtp.login(", "sendmail("):
            self.assertNotIn(blocked, source)

    def test_wizard_and_resource_contracts(self):
        project = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        assets = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text(encoding="utf-8")
        ui = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        for term in ("install-connector-sidecar.sh", "LinuxMailRelay365.linux.connector-sidecar.sh"):
            self.assertIn(term, project)
        for term in ("BuildFreshConnectorBundle", "TENANT_CONNECTOR_CHECKED"):
            self.assertIn(term, assets)
        for term in ("PreviewFreshConnectorAsync", "InstallFreshConnectorAsync",
                     "INSTALL PRIVATE CONNECTOR", "CONNECTOR_SIDECAR_INSTALLED=yes"):
            self.assertIn(term, ui)


if __name__ == "__main__":
    unittest.main()
