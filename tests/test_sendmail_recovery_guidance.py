"""Read-only guidance must not become write approval or bypass a refusal."""
from pathlib import Path
import unittest

CS = Path(__file__).resolve().parents[1] / "src/LinuxMailRelay365"


class SendmailRecoveryGuidanceContract(unittest.TestCase):
    def test_guidance_is_presentation_only_and_uses_existing_gate(self):
        source = (CS / "SendmailRecoveryGuidance.cs").read_text(encoding="utf-8")
        for marker in ("SendmailV2RecoveryReceipt.CanRestore(plan)",
                       "SeparateApprovalRequired", "NoChanges", "Blocked",
                       '"queue_unknown"', '"queue_nonempty"', '"write_scope"',
                       '"file_set"', '"offline_unknown"'):
            self.assertIn(marker, source)
        for forbidden in ("RunRootScriptAsync", "ConfirmDestructive", "BuildSendmailV2RestoreApplyBundle"):
            self.assertNotIn(forbidden, source)
        self.assertIn("SendmailRecoveryGuidance.SelfTest",
                      (CS / "Program.cs").read_text(encoding="utf-8"))

    def test_failed_apply_reports_and_returns_before_confirmation(self):
        source = (CS / "MainForm.SendmailV2Recovery.cs").read_text(encoding="utf-8")
        body = source.split("private async Task ApplySendmailV2RestoreAsync()", 1)[1].split(
            "private async Task ReviewSendmailV2RollbackAsync", 1)[0]
        blocked = body.split("if (!SendmailV2RecoveryReceipt.CanRestore(plan))", 1)[1].split(
            "string details", 1)[0]
        self.assertIn("ShowSendmailV2ReviewReport(reviewed, id, plan)", blocked)
        self.assertIn("return;", blocked)
        self.assertNotIn("RunRootScriptAsync", blocked)
        self.assertLess(body.index("ShowSendmailV2ReviewReport"), body.index("ConfirmDestructive"))
        self.assertLess(body.index("ConfirmDestructive"), body.index("BuildSendmailV2RestoreApplyBundle"))

    def test_report_is_shared_read_only_and_resizable(self):
        source = (CS / "MainForm.SendmailV2.cs").read_text(encoding="utf-8")
        self.assertIn("ShowSendmailV2ReviewReport(current, id, plan)", source)
        report = source.split("private void ShowSendmailV2ReviewReport", 1)[1]
        for marker in ("SendmailRecoveryGuidance.From(plan)", "PreferredDialogSize",
                       "ReadOnly = true", "ScrollBars = ScrollBars.Vertical",
                       "FormBorderStyle.Sizable", "RowStyle(SizeType.Percent, 100)",
                       "dialog.ClientSizeChanged", "A timeout is not an empty queue",
                       "never delete mail", "does not authorize starting the MTA"):
            self.assertIn(marker, report)
        for forbidden in ("RunRootScriptAsync", "ConfirmDestructive", "BuildSendmailV2RestoreApplyBundle"):
            self.assertNotIn(forbidden, report)


if __name__ == "__main__":
    unittest.main()
