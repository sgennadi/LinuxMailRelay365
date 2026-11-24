"""Cloud inventory must never precede its exact tenant selection controls."""
from pathlib import Path
import unittest

CS = Path(__file__).resolve().parents[1] / "src/LinuxMailRelay365"
FORM = (CS / "MainForm.cs").read_text(encoding="utf-8")
CLOUD = (CS / "MainForm.CloudObjects.cs").read_text(encoding="utf-8")
FLOW = (CS / "MainForm.MailFlow.cs").read_text(encoding="utf-8")


class CloudTenantNavigation(unittest.TestCase):
    def test_all_three_m365_modes_show_tenant_before_cloud_inventory(self):
        step = FORM.split("            case 2:\n", 1)[1].split("            case 3:\n", 1)[0]
        self.assertLess(step.index("if (selectedMailTarget != MailFlowIntent.TargetM365)"),
                        step.index("ShowCloudTenantSelection(page);"))
        self.assertLess(step.index("ShowCloudTenantSelection(page);"),
                        step.index("AddCloudInventoryAction(page);"))
        self.assertLess(step.index("AddCloudInventoryAction(page);"),
                        step.index("if (mailTransport.SelectedIndex is 1 or 2)"))
        self.assertIn("No Microsoft 365 Tenant ID or Entra sign-in is required", step)
        step3 = FORM.split("            case 3:\n", 1)[1].split("            case 4:\n", 1)[0]
        self.assertLess(step3.index("ShowCloudTenantSelection(page);"),
                        step3.index("PreviewTenantConnectorAsync,"))
        self.assertLess(step3.index("ShowCloudTenantSelection(page);"),
                        step3.index("AddCloudInventoryAction(page);"))

    def test_tenant_selection_remains_exact_and_optional_for_linux_only(self):
        picker = FORM.split("private void ShowCloudTenantSelection(", 1)[1].split(
            "private Button? cloudInventoryAction;", 1)[0]
        for value in ("DiscoverTenantsAsync", "UseManualTenantAsync", "tenantSelector",
                      "tenant);", "existingAppId);", "XOAUTH2 requires a Tenant ID"):
            self.assertIn(value, picker)
        gate = FORM.split("private bool CanInspectCloudInventory()", 1)[1].split(
            "private void RefreshCloudInventoryAction()", 1)[0]
        for value in ("TargetM365", "MailScenarioPlanner.Choose", "MailScenarioPlanner.Keep",
                      "HasMailDiscovery()", "Guid.TryParse", "Guid.Empty",
                      "selected.Id == tenantId", "discoveredTenants.Count <= 1"):
            self.assertIn(value, gate)
        self.assertIn("action.Enabled = !busy && CanInspectCloudInventory();", FORM)
        self.assertIn("tenant.TextChanged += (_, _) => RefreshCloudInventoryAction();", FORM)
        self.assertIn("cloudInventoryAction = null;", FORM)
        self.assertIn("Gmail and Custom SMTP do not require a Tenant ID.", CLOUD)
        self.assertIn("ValidateCloudInventorySelection(", CLOUD)
        self.assertIn("The detected current relay and the intended provider are separate", FLOW)


if __name__ == "__main__":
    unittest.main()
