from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src" / "LinuxMailRelay365"

class MultiTransportGuiContract(unittest.TestCase):
    def test_guarded_separate_workflow(self):
        ui = (CS / "MainForm.MultiTransport.cs").read_text(encoding="utf-8")
        client = (CS / "MultiTransportClient.cs").read_text(encoding="utf-8")
        for marker in ("OfflineHostContext()", "MultiCandidateContext() != context",
                       "multiReviewContext != context", "ConfirmDestructive(",
                       "PromptRouteCredential(rules[i], forApply: true)",
                       "Array.Clear(credentials)", "discoveredMailIdentity = null",
                       "MultiTransportClient.ParseInventory", "MultiTransportClient.ParseMutation"):
            self.assertIn(marker, ui)
        for marker in ("--approve-plan-sha256", "--approve-review-sha256",
                       "APPLY_NEW_STOPPED_POSTFIX_TRANSPORTS",
                       "RESTORE_STOPPED_POSTFIX_TRANSPORTS", "builtin printf",
                       'GetValueOrDefault("MAIL_SENT") != "no"'):
            self.assertIn(marker, client)
        for marker in ("result.StdErr", "systemctl start", "systemctl stop", "postfix reload"):
            self.assertNotIn(marker, ui)
            self.assertNotIn(marker, client)
        self.assertIn("ShowMultiTransportActions(page, width, languageIndex)",
                      (CS / "MainForm.MailFlow.cs").read_text(encoding="utf-8"))
        self.assertIn("MultiTransportClient.SelfTest",
                      (CS / "Program.cs").read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
