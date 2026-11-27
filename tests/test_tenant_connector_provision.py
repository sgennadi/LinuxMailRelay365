"""New Exchange Connector creation requires reviewed exact-tenant plan."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "windows" / "Manage-LinuxMailRelay365Connector.ps1"


class ConnectorProvisionContracts(unittest.TestCase):
    def test_no_implicit_tenant_mutation(self):
        s = SCRIPT.read_text(encoding="utf-8")
        for item in ("CREATE_REVIEWED_M365_CONNECTOR", "Get-ConnectionInformation",
                     "[guid]$sessions[0].TenantID -ne $TenantId",
                     "Get-AcceptedDomain", "Get-InboundConnector",
                     "New-InboundConnector @options",
                     "EXO_CONNECTOR_REVIEW_SHA256=",
                     "EXO_CONNECTOR_DELIVERY_VERIFIED=no",
                     "CloudServicesMailEnabled = $false",
                     "ConnectorType = 'OnPremises'"):
            self.assertIn(item, s)
        for item in ("Set-InboundConnector ", "Remove-InboundConnector ",
                     "New-MgApplication", "Set-AcceptedDomain", "Invoke-Expression"):
            self.assertNotIn(item, s)

    def test_wizard_embeds_script_and_requires_preview_confirmation(self):
        ui = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        project = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        assets = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text(encoding="utf-8")
        for item in ("PreviewTenantConnectorAsync", "CreateTenantConnectorAsync",
                     "EXO_CONNECTOR_REVIEW_SHA256", "CREATE M365 CONNECTOR",
                     "RunTenantConnectorManagerAsync", "EXO_CONNECTOR_CREATED=yes"):
            self.assertIn(item, ui)
        self.assertIn("Manage-LinuxMailRelay365Connector.ps1", project)
        self.assertIn("TenantConnectorManager", assets)


if __name__ == "__main__":
    unittest.main()


class PublicIpConnectorInspectionContracts(unittest.TestCase):
    def test_public_ipv4_inspection_and_conflict_guard(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("function Get-IPv4Overlap", source)
        self.assertIn("$Action -eq 'Inspect' -and $PublicIpv4", source)
        self.assertIn("EXO_CONNECTOR_PUBLIC_IPV4=$PublicIpv4", source)
        self.assertIn("$overlap=Get-IPv4Overlap $value $PublicIpv4", source)
        section = source.split("if ($Action -eq 'Inspect' -and $PublicIpv4)",1)[1].split("if ($Action -eq 'Inspect')",1)[0]
        self.assertIn("CHANGES_APPLIED=no", section)
        self.assertNotIn("New-InboundConnector", section)

    def test_public_ip_wizard_requires_separate_confirmation(self):
        src = ROOT / "src/LinuxMailRelay365"
        main = (src/"MainForm.SmtpPublicIpConnector.cs").read_text()
        ui = (src/"SmtpPublicIpConnectorDialog.cs").read_text()
        self.assertIn('RunTenantConnectorManagerAsync(options, "Inspect")', main)
        self.assertIn('RunTenantConnectorManagerAsync(options, "Preview")', main)
        self.assertLess(main.index("ConfirmDestructive("), main.index('RunTenantConnectorManagerAsync(options, "Apply", sha)'))
        self.assertIn("acceptedDomainApproved.Checked", main)
        self.assertIn("Confirm external IP observation", ui)
        self.assertIn("smtp_egress_verified", ui)
        self.assertIn("ipv4Verified", ui)
        self.assertIn("ip.Text.Trim().Length == 0", ui)
        self.assertIn("OpenPublicIpConnectorAsync(owner, context, mx)", (src/"MainForm.DeliveryMiniWizard.cs").read_text())
        self.assertIn("sessionMx = await publicIpConnector", (src/"SmtpCertificateWizardDialog.cs").read_text())
