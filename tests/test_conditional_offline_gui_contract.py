from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src" / "LinuxMailRelay365"

class OfflineGuiContract(unittest.TestCase):
    def test_separate_review_and_write_confirmations(self):
        ui = (CS / "MainForm.ConditionalOffline.cs").read_text(encoding="utf-8")
        client = (CS / "ConditionalOfflineClient.cs").read_text(encoding="utf-8")
        for marker in ('MtaState: "installed_inactive"', 'Status: "compiled_verified_read_only"',
                       "ConfirmDestructive(", "OfflineHostContext() != hostContext",
                       "OfflineCandidateContext() != context", "offlineReviewContext != context",
                       "ConditionalOfflineClient.ParseReview", "ConditionalOfflineClient.VerifyMutation",
                       "discoveredMailIdentity = null", "offlineBackupSha.Text = recovery!"):
            self.assertIn(marker, ui)
        for marker in ("I_HAVE_PREVENTED_CONCURRENT_MAIL_AND_CONFIG_CHANGES",
                       "APPLY_STOPPED_POSTFIX_SENDER_MAP", "RESTORE_STOPPED_POSTFIX_SENDER_MAP",
                       "--approve-transaction-sha256", "--approve-evidence-sha256",
                       'GetValueOrDefault("MAIL_SENT") != "no"'):
            self.assertIn(marker, client)
        for marker in ("systemctl stop", "systemctl start", "postfix reload", "postconf -e"):
            self.assertNotIn(marker, client)
            self.assertNotIn(marker, ui)
        self.assertIn("ShowConditionalOfflineActions(page, width, languageIndex)",
                      (CS / "MainForm.MailFlow.cs").read_text(encoding="utf-8"))
        self.assertIn("ConditionalOfflineClient.SelfTest",
                      (CS / "Program.cs").read_text(encoding="utf-8"))
        self.assertNotIn("RunConditionalOfflineAsync(",
                         (CS / "MainForm.AdvancedRoutes.cs").read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
