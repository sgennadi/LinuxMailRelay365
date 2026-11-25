"""Adaptive native recovery display: presentation only; no hidden approval."""
from pathlib import Path
import unittest

CS = Path(__file__).resolve().parents[1] / "src/LinuxMailRelay365"


class NativeRecoveryVisibilityContract(unittest.TestCase):
    def test_unknown_and_clear_keep_global_inspection_and_full_tools(self):
        form = (CS / "MainForm.cs").read_text(encoding="utf-8")
        page = form.split("private void ShowBackupMaintenance(", 1)[1].split(
            "private void ClearNativeRecoverySample(", 1)[0]
        self.assertLess(page.index("InspectForeignPendingRestoreAsync"), page.index("NativeRecoveryVisibility.From("))
        self.assertIn("Show all interrupted recovery tools", page)
        self.assertIn("nativeRecoveryToolsExpanded = !nativeRecoveryToolsExpanded", page)
        self.assertIn("if (visibility.ShowExim)", page)
        self.assertIn("if (visibility.ShowSendmail)", page)
        for action in ("ReviewEximPendingRollbackAsync(false)", "ReviewEximPendingRollbackAsync(true)",
                       "ReviewSendmailV2RollbackAsync(false)", "ReviewSendmailV2RollbackAsync(true)",
                       "RestoreBackupAsync", "RestoreSidecarConfigAsync", "ApplyEximNativeRestoreAsync",
                       "ApplySendmailV2RestoreAsync"):
            self.assertIn(action, page)
        self.assertIn("Not service-start approval.", page)

    def test_sample_is_invalidated_and_never_authorizes_writes(self):
        form = (CS / "MainForm.cs").read_text(encoding="utf-8")
        runner = form.split("private async Task RunBusyAsync(", 1)[1].split(
            "private Task CopySafeReportAsync(", 1)[0]
        self.assertLess(runner.index("ClearNativeRecoverySample();"), runner.index("await work();"))
        inspect = form.split("private async Task InspectForeignPendingRestoreAsync()", 1)[1].split(
            "private async Task PreviewExactForeignRestorePlanAsync()", 1)[0]
        self.assertLess(inspect.index("ForeignPendingInspection.Parse"), inspect.index("nativeRecoverySample = report"))
        self.assertLess(inspect.index("SameRollbackConnection"), inspect.index("nativeRecoverySample = report"))
        self.assertIn("HostKeySha256", inspect)
        self.assertIn("connectionField.TextChanged += (_, _) => ClearNativeRecoverySample(collapseTools: true)", form)
        model = (CS / "NativeRecoveryVisibility.cs").read_text(encoding="utf-8")
        for token in ('{ Mta: "exim", Counts: not null }', '{ Mta: "sendmail", Counts: not null }',
                      "expanded || state == NativeRecoverySampleState.Exim",
                      "expanded || state == NativeRecoverySampleState.Sendmail"):
            self.assertIn(token, model)
        for forbidden in ("RunRootScriptAsync", "ConfirmDestructive", "BuildEximPendingRollbackApplyBundle",
                          "BuildSendmailV2RollbackApplyBundle"):
            self.assertNotIn(forbidden, model)
        self.assertIn("NativeRecoveryVisibility.SelfTest", (CS / "Program.cs").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
