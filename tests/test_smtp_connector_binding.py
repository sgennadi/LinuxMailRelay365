import importlib.util
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("binding", ROOT / "linux/review-smtp-tls-rotation.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class ConnectorBindingTests(unittest.TestCase):
    def test_exact_san_only(self):
        self.assertTrue(M.exact_dns_san("X509v3 Subject Alternative Name:\n    DNS:Relay.example.org, DNS:example.org\nX509v3 Extended Key Usage:\n    TLS Web Client Authentication", "relay.example.org"))
        for value in ("DNS:relay.example.org", "X509v3 Subject Alternative Name:\n    DNS:*.example.org",
                      "X509v3 Subject Alternative Name:\n    DNS:evil-relay.example.org",
                      "X509v3 Extended Key Usage:\n    DNS:relay.example.org"):
            self.assertFalse(M.exact_dns_san(value, "relay.example.org"))

    def test_invalid_name_refused_before_files(self):
        with patch.object(M, "directory") as directory:
            for name in ("*.example.org", "--bad.example.org", "relay;id.example.org"):
                with self.assertRaises(ValueError):
                    M.connector_binding(name)
            directory.assert_not_called()

    def test_gui_inspection_is_not_apply(self):
        source = ROOT / "src/LinuxMailRelay365"
        dialog = (source / "MainForm.SmtpConnectorBinding.cs").read_text()
        self.assertIn('BuildSmtpTlsRotation("binding-preview"', dialog)
        self.assertIn('RunTenantConnectorManagerAsync(options, "Inspect")', dialog)
        self.assertIn('(await LocalAsync()).Sha != local.Sha', dialog)
        self.assertNotIn('connectorApproved.Checked = true', dialog)
        self.assertNotIn('RunTenantConnectorManagerAsync(options, "Apply")', dialog)

    def test_tenant_script_contract(self):
        script = (ROOT / "windows/Manage-LinuxMailRelay365Connector.ps1").read_text()
        self.assertIn("Certificate DNS identity must itself be an exact accepted domain", script)
        self.assertIn("Get-CertificateOverlap", script)
        self.assertIn("EXO_CONNECTOR_BINDING=$binding", script)
        self.assertIn("$options['RequireTls'] = $true", script)
        inspect = script.split("if ($Action -eq 'Inspect')", 1)[1].split("    foreach ($item in $connectors) {", 2)
        self.assertNotIn("New-InboundConnector", inspect[0])

    def test_workflow_navigation_does_not_authorize_changes(self):
        source = ROOT / "src/LinuxMailRelay365"
        plan = (source/"SmtpCertificateWizardPlan.cs").read_text()
        self.assertIn("[SmtpWorkflowStage.Identity, SmtpWorkflowStage.Delivery]", plan)
        self.assertIn("SmtpWorkflowStage.Binding, SmtpWorkflowStage.Delivery, SmtpWorkflowStage.Maintenance", plan)
        ui = (source/"SmtpCertificateWizardDialog.cs").read_text()
        self.assertIn("Navigation is not approval", ui)
        self.assertIn("sessionMx = dialog.SessionMx", ui)
        self.assertIn("deliveryProbe(this, sessionMx)", ui)
        self.assertIn("if (working) e.Cancel = true", ui)
        self.assertNotIn("connectorApproved.Checked = true", ui)
        main = (source/"MainForm.DeliveryMiniWizard.cs").read_text()
        self.assertIn("outboundFixedSender.Text.Trim(), sessionMx,", main)
