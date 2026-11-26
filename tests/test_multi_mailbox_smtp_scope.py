"""Offline contract for exact scoped Exchange SMTP setup."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PS = (ROOT/"windows/Manage-LinuxMailRelay365MailboxScope.ps1").read_text(encoding="utf-8")
UI = (ROOT/"src/LinuxMailRelay365/MainForm.MultiMailboxIdentities.cs").read_text(encoding="utf-8")
CS = (ROOT/"src/LinuxMailRelay365/MainForm.MultiMailboxSmtpScope.cs").read_text(encoding="utf-8")


class ScopeContracts(unittest.TestCase):
    def test_narrow_create_only(self):
        for text in ("Guid -eq", "scope_not_exact_single_mailbox", "-CustomResourceScope $scopeGuid",
                     "if ($plan.enableMailboxSmtp)", "assignment_assignee_unverified", "assignment_scope_unverified"):
            self.assertIn(text, PS)
        for forbidden in ("Set-TransportConfig", "Set-Mailbox ", "Remove-Management", "Set-Management",
                          "New-Mg", "Connect-MgGraph", "Add-MailboxPermission"):
            self.assertNotIn(forbidden, PS)
        preview = PS.split("function ReadPlan",1)[1].split("function PlanHash",1)[0]
        for forbidden in ("New-ServicePrincipal","New-ManagementScope","New-ManagementRoleAssignment","Set-CASMailbox"):
            self.assertNotIn(forbidden, preview)

    def test_approval_and_identity_recheck(self):
        flow = UI.split("configureScope.Click +=",1)[1].split("verify.Click +=",1)[0]
        self.assertLess(flow.index("RunMailboxSmtpScopeAsync(req,null"),flow.index("ConfirmDestructive("))
        self.assertLess(flow.index("ConfirmDestructive("),flow.index("RunMailboxSmtpScopeAsync(req,preview"))
        self.assertGreaterEqual(flow.count("ReadScopeEnterpriseAsync("),2)
        self.assertIn("selection.RequireUnchanged(await ReadAsync())",flow)
        self.assertIn("if (attempted) saveUncertain=true",flow)
        self.assertIn("EntraGraphInventoryClient.InspectAsync",CS)
        self.assertIn("CertificateSha256 == row.CertificateSha",CS)


if __name__ == "__main__":
    unittest.main()
