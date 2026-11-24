"""Source-level GUI recovery guards; actual C# receipt tests run in Windows CI."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src/LinuxMailRelay365"


class SendmailV2RecoveryGui(unittest.TestCase):
    def test_review_before_confirmation_before_write(self):
        ui = (CS / "MainForm.SendmailV2Recovery.cs").read_text(encoding="utf-8")
        restore = ui.split("private async Task ApplySendmailV2RestoreAsync()", 1)[1].split(
            "private async Task ReviewSendmailV2RollbackAsync", 1)[0]
        rollback = ui.split("private async Task ReviewSendmailV2RollbackAsync", 1)[1].split(
            "private async Task VerifySendmailRecoveryCompletedAsync", 1)[0]
        for body, parser, bundle, receipt in (
            (restore, "SendmailV2Review.Parse(", "BuildSendmailV2RestoreApplyBundle(", "VerifyRestore("),
            (rollback, "ParseRollbackPlan(", "BuildSendmailV2RollbackApplyBundle(", "VerifyRollback("),
        ):
            self.assertLess(body.index(parser), body.index("ConfirmDestructive("))
            self.assertLess(body.index("ConfirmDestructive("), body.index(bundle))
            self.assertLess(body.index(bundle), body.index(receipt))
            self.assertLess(body.index(receipt), body.index("VerifySendmailRecoveryCompletedAsync("))
            self.assertIn("finally { InvalidateAfterSendmailV2Write(); }", body)
        self.assertIn("if (!apply)", rollback)
        self.assertIn("VerifyArchive(archive.StdOut)", restore)
        self.assertIn("RequireStoppedSendmailV2Selection", restore)
        self.assertIn("SendmailV2RecoveryReceipt.CanRestore(plan)", restore)
        self.assertNotIn("foreignBackupSelector", rollback)
        self.assertIn("RequireSendmailRecoveryConnection(confirmed)", ui)
        self.assertIn("ForeignPendingInspection.Parse(inspection.StdOut).IsClear", ui)

    def test_actions_and_strict_receipts_are_wired(self):
        form = (CS / "MainForm.cs").read_text(encoding="utf-8")
        self.assertIn("ApplySendmailV2RestoreAsync, false", form)
        self.assertIn("ReviewSendmailV2RollbackAsync(false)", form)
        self.assertIn("ReviewSendmailV2RollbackAsync(true)", form)
        self.assertIn("SendmailV2RecoveryReceipt.SelfTest", (CS / "Program.cs").read_text(encoding="utf-8"))
        script = (ROOT / "linux/restore-foreign-mta-config.py").read_text(encoding="utf-8")
        self.assertIn('print("SENDMAIL_V2_EVIDENCE_VERSION=4")', script)
        self.assertIn('print("SENDMAIL_V2_EVIDENCE_MTA=sendmail")', script)
        receipt = (CS / "SendmailV2RecoveryReceipt.cs").read_text(encoding="utf-8")
        for field in ("SENDMAIL_V2_EVIDENCE_TARGET_MANIFEST_SHA256", "SENDMAIL_V2_EVIDENCE_SAFETY_MANIFEST_SHA256",
                      "SENDMAIL_V2_ROLLBACK_APPROVED_SHA256", "SENDMAIL_V2_RECOVERY_MARKER_CLEARED",
                      "SENDMAIL_V2_QUEUE_CHANGED", "SENDMAIL_V2_SERVICE_CHANGED"):
            self.assertIn(field, receipt)


if __name__ == "__main__":
    unittest.main()
