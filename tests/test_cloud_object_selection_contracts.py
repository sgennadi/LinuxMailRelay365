"""Cloud object read-only inventory must bind the original UI selection.

The actual 365 request requires interactive authentication; these are source
contract checks, NOT a live tenant test. Do not claim Cloud acceptance from CI.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
FORM = ROOT / "src" / "LinuxMailRelay365" / "MainForm.CloudObjects.cs"
SHELL = ROOT / "windows" / "Inspect-LinuxMailRelay365Objects.ps1"


class CloudObjectsIdentityContracts(unittest.TestCase):
    def test_ssh_and_m365_identity_do_not_cross_tenants_or_apps(self):
        source = FORM.read_text(encoding="utf-8")
        self.assertIn("string requestedClientField = existingAppId.Text.Trim();", source)
        self.assertIn("string requestedConnectorName = outboundConnectorName.Text.Trim();", source)
        self.assertEqual(source.count("ValidateCloudInventorySelection("), 4)
        self.assertIn("Guid? expectedClient", source)
        self.assertIn("chosenClient != expectedClient.Value", source)
        self.assertIn("option.Id != expectedTenant", source)
        self.assertIn("selectedTenant != expectedTenant", source)
        self.assertIn("discoveredTenants.Count > 1", source)
        self.assertIn("existingAppId.Text.Trim(), requestedClientField", source)
        self.assertIn("outboundConnectorName.Text.Trim(), requestedConnectorName", source)
        self.assertIn("psi.ArgumentList.Add(requestedConnectorName);", source)
        self.assertNotIn("Guid nowClient", source)

    def test_smtp_mailbox_audit_exact_identity_and_no_mutation(self):
        source = FORM.read_text(encoding="utf-8")
        shell = SHELL.read_text(encoding="utf-8")
        model = (ROOT / "src/LinuxMailRelay365/CloudObjectsInventory.cs").read_text(encoding="utf-8")
        for marker in ("requestedTransport == 0", "EnterpriseObjectId: Guid enterprise",
                       'psi.ArgumentList.Add("-EnterpriseObjectId")',
                       'psi.ArgumentList.Add("-Mailbox")',
                       "tenantId, clientId, auditMailbox, auditEnterprise",
                       "ValidateMailboxSelection();", "Live authentication not tested"):
            self.assertIn(marker, source)
        for marker in ("Get-TransportConfig -ErrorAction Stop", "Get-Mailbox -Identity $exactMailbox",
                       "Get-CASMailbox -Identity $exactMailbox",
                       "Get-ServicePrincipal -Identity $exactEnterprise.ToString('D')",
                       "Test-ServicePrincipalAuthorization -Identity $exactEnterprise.ToString('D') -Resource $exactMailbox",
                       "([guid]$principal[0].AppId) -eq $exactClient",
                       "([guid]$principal[0].ObjectId) -eq $exactEnterprise",
                       "M365_SMTP_MAILBOX_POLICY_SELF_TEST=pass"):
            self.assertIn(marker, shell)
        self.assertIn("Inconsistent SMTP mailbox audit evidence", model)
        self.assertIn("Missing or unexpected SMTP mailbox audit", model)
        for forbidden in ("Set-CASMailbox ", "Set-TransportConfig ", "New-ServicePrincipal ",
                          "New-ManagementRoleAssignment ", "Remove-ManagementRoleAssignment "):
            self.assertNotIn(forbidden, shell)

    def test_live_cloud_inventory_is_read_only_and_exact_tenant_bound(self):
        source = SHELL.read_text(encoding="utf-8")
        for required in ("Get-InboundConnector", "TenantID",
                         "Connect-ExchangeOnline", "CHANGES_APPLIED=no"):
            self.assertIn(required, source)
        self.assertNotIn("Connect-MgGraph", source)
        self.assertNotIn("Microsoft.Graph.Authentication", source)
        native = (ROOT / "src" / "Microsoft365Auth" / "EntraGraphInventoryClient.cs").read_text(encoding="utf-8")
        self.assertIn("https://graph.microsoft.com/Application.Read.All", (ROOT / "src" / "Microsoft365Auth" / "EntraTenantDiscoveryClient.cs").read_text(encoding="utf-8"))
        self.assertIn("EntraTenantDiscoveryClient.AcquireGraphReadTokenAsync(", native)
        self.assertIn("GuidProperty(root, \"appId\") != appId", native)
        self.assertIn("new CloudCredentialObject(", FORM.read_text(encoding="utf-8"))
        for forbidden in ("New-MgApplication ", "Remove-MgApplication ",
                          "Remove-InboundConnector ", "Set-InboundConnector "):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
