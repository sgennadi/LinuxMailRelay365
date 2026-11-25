"""Explicit host-scoped archive selection and unchanged recovery guards."""
from pathlib import Path
import unittest

CS = Path(__file__).resolve().parents[1] / "src/LinuxMailRelay365"
FORM = (CS / "MainForm.cs").read_text(encoding="utf-8")
HELPER = (CS / "MainForm.ArchiveSelection.cs").read_text(encoding="utf-8")


class ArchiveSelectionContract(unittest.TestCase):
    def test_all_lists_are_explicit_and_bound_to_host(self):
        for name, context in (("ListBackupsAsync", "postfixBackupListIdentity"),
                              ("ListSidecarConfigBackupsAsync", "sidecarBackupListIdentity"),
                              ("ListForeignMtaBackupsAsync", "foreignBackupListContext")):
            body = FORM.split("private async Task " + name + "()", 1)[1].split("\n    private ", 1)[0]
            self.assertIn("SelectedIndex = -1", body)
            self.assertIn("RequireSameArchiveConnection", body)
            self.assertIn(context + " = null", body)
            self.assertNotIn("SelectedIndex = 0", body)
        self.assertIn("connectionField.TextChanged += (_, _) => ClearArchiveSelections()", FORM)
        self.assertIn("ClearSidecarRestoreReview();", HELPER)
        self.assertIn("listIdentity != SecurityOptionsStore.Identity(endpoint)", HELPER)

    def test_postfix_and_sidecar_writes_recheck_selected_archive(self):
        for name, command in (("RestoreBackupAsync", 'BuildRecoveryBundle("--restore"'),
                              ("RestoreSidecarConfigAsync", 'BuildSidecarConfigRecoveryBundle("--restore"')):
            body = FORM.split("private async Task " + name + "()", 1)[1].split("\n    private ", 1)[0]
            self.assertLess(body.index("RequireArchiveSelection"), body.index("ConfirmDestructive"))
            self.assertLess(body.index("ConfirmDestructive"), body.index("var confirmed = RequireSameArchiveConnection"))
            self.assertLess(body.index("var confirmed = RequireSameArchiveConnection"), body.index(command))
            self.assertIn("finally { InvalidateAfterArchiveWrite(); }", body)
        self.assertIn("await VerifySelectedPostfixArchiveAsync();", FORM)
        self.assertIn('BuildRecoveryBundle("--verify", id)', HELPER)
        self.assertIn("reviewedSidecarRestoreSha != expected", FORM)

    def test_maintenance_keeps_all_tools_and_stages_selection(self):
        body = FORM.split("private void ShowBackupMaintenance(", 1)[1].split(
            "private void ClearNativeRecoverySample(", 1)[0]
        self.assertEqual(body.count("ShowArchiveChoice("), 3)
        for marker in ("backupSelector.SelectedItem is string",
                       "foreignBackupSelector.SelectedItem is string",
                       "sidecarBackupSelector.SelectedItem is string selectedSidecar",
                       "reviewedSidecarRestoreId == selectedSidecar",
                       "Show additional archive checks",
                       "PreviewForeignMtaRecoveryAsync", "PreflightForeignMtaRecoveryAsync",
                       "ExportForeignMtaOfflineAsync", "PreviewExactForeignRestorePlanAsync",
                       "ApplyEximNativeRestoreAsync", "ApplySendmailV2RestoreAsync"):
            self.assertIn(marker, body)
        self.assertIn("VerifiedArchiveListing.SelfTest", (CS / "Program.cs").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
