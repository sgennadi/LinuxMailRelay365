"""Contract for a compact host-scoped Advanced SMTP section in Windows Wizard."""
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class AdvancedWizardTests(unittest.TestCase):
    def test_advanced_group_is_closed_by_default_and_host_scoped(self):
        routing=(ROOT/"src/LinuxMailRelay365/MailRoutingPlan.cs").read_text(encoding="utf-8")
        gui=(ROOT/"src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        self.assertIn("ShowAdvancedSmtpTools { get; set; } = false",routing)
        self.assertIn("advancedSmtpTools.Checked = routingPlan.ShowAdvancedSmtpTools",gui)
        self.assertIn("routingPlan.ShowAdvancedSmtpTools = advancedSmtpTools.Checked",gui)
        self.assertIn("advancedSmtpTools.CheckedChanged",gui)
        self.assertIn("if (advancedSmtpTools.Checked)",gui)
        self.assertIn("Show advanced SMTP operations and diagnostics",gui)
        self.assertIn("ShowAdvancedSmtpTools",routing)
        self.assertIn("BuildHealthAlertsBundle",gui)
        self.assertIn("EnableHealthAlertsAsync",gui)
        self.assertIn("DisableHealthAlertsAsync",gui)
        self.assertIn("BuildM365DnsAuditBundle",gui)
        self.assertIn("InspectM365DnsAsync",gui)

    def test_primary_install_and_preserve_diagram_are_not_hidden(self):
        gui=(ROOT/"src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        self.assertIn("AddLine(page, preserveFlowPreview);",gui)
        self.assertIn("AddLine(page, preserveMailInstructions);",gui)
        self.assertIn("PreflightAsync, false",gui)
        self.assertIn("ApplyAsync, true",gui)
        self.assertIn("CheckNetworkFirewallAsync, false",gui)

    def test_no_hardcoded_2525_for_existing_hebrew_postfix_summary(self):
        gui=(ROOT/"src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        self.assertNotIn("בפורט 2525 ללא שינוי בתצורה הקיימת",gui)
        self.assertIn("ביציאת SMTP שנבחרה",gui)


if __name__=="__main__":
    unittest.main()
