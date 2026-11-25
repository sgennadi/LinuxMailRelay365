"""Selected mailbox Graph/Exchange read-only boundaries (not live tenant acceptance)."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src/LinuxMailRelay365"
UI = (CS / "MainForm.MultiMailboxIdentities.cs").read_text(encoding="utf-8")
CLOUD = (CS / "MainForm.MultiMailboxCloud.cs").read_text(encoding="utf-8")
MODEL = (CS / "MultiMailboxCloudObservation.cs").read_text(encoding="utf-8")
PS = (ROOT / "windows/Inspect-LinuxMailRelay365Objects.ps1").read_text(encoding="utf-8")


class MultiMailboxLiveCloud(unittest.TestCase):
    def test_exact_selection_read_before_and_after_cloud(self):
        handler = UI.split("verify.Click += async", 1)[1].split("refresh.Click += async", 1)[0]
        self.assertLess(handler.index("selection.RequireUnchanged(await ReadAsync())"),
                        handler.index("await QueryMultiMailboxCloudAsync("))
        self.assertLess(handler.index("await QueryMultiMailboxCloudAsync("),
                        handler.index("var latest = await ReadAsync();"))
        self.assertLess(handler.index("selection.RequireUnchanged(latest);"),
                        handler.index("observations[selection] = observation;"))
        self.assertIn("RequireSameArchiveConnection(endpoint);", handler)
        self.assertIn("selection.Matches(inventory, SelectedScope(), Selected())", handler)
        self.assertIn('Invalidate("Mailbox audit failed or became stale.")', handler)
        self.assertIn("observations.Clear();", UI)
        self.assertIn("inventoryValid = false;", UI)

    def test_only_exact_mailbox_cloud_query(self):
        for marker in ("EntraGraphInventoryClient.InspectAsync(tenantId, clientId, bootstrap",
                       'signInOwner: owner', '"-MailboxOnly"', '"-Mailbox", row.Mailbox',
                       '"-EnterpriseObjectId", enterprise.ToString("D")',
                       "tenantId, clientId, row.Mailbox, enterprise",
                       "graph.ClientId != clientId", "exchange.MailboxAudit ??"):
            self.assertIn(marker, CLOUD)
        for forbidden in ("tenant.Text =", "existingAppId.Text =", "mailbox.Text =",
                          "lastReadOnlyCloudInventory =", "SendMail", "Set-CASMailbox"):
            self.assertNotIn(forbidden, CLOUD)
        self.assertIn("[switch]$MailboxOnly", PS)
        self.assertIn("mailbox_only_requires_exact_identity", PS)
        broad = PS.split("  if (-not $MailboxOnly) {", 1)[1].split(
            "  if ($mailboxRequested) {", 1)[0]
        for command in ("Get-InboundConnector", "Get-ManagementScope", "Get-ManagementRoleAssignment"):
            self.assertIn(command, broad)
        self.assertIn("ReadSmtpMailboxAudit $TenantId $ClientId $EnterpriseObjectId $Mailbox", PS)

    def test_observation_bound_to_scope_map_row_and_app(self):
        for marker in ("string Scope, string MapSha", "MultiMailboxIdentityRow Row",
                       "this == Capture(inventory, scope, row)",
                       "selection.Row.Tenant != cloud.Tenant", "selection.Row.Client != cloud.Client",
                       "audit.EnterpriseObjectId != sp", "audit.Mailbox != selection.Row.Mailbox",
                       "cloud.Connectors.Count != 0", "SMTP authentication and delivery are NOT verified"):
            self.assertIn(marker, MODEL)
        self.assertIn("MultiMailboxCloudObservation.SelfTest",
                      (CS / "Program.cs").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
