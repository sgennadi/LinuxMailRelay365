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
