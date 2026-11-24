"""Native restore planning stays read-only and independent of the chosen provider."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src/LinuxMailRelay365"
FORM = (CS / "MainForm.cs").read_text(encoding="utf-8")
ASSETS = (CS / "EmbeddedAssets.cs").read_text(encoding="utf-8")

class NativeRestorePlanGui(unittest.TestCase):
    def test_provider_independent_maintenance(self):
        section = FORM.split("            case 4:", 1)[1]
        self.assertLess(section.index("OpenBackupStepAsync"), section.index("if (!HasMailDiscovery())"))
        self.assertIn("ShowBackupMaintenance(page", section)
        self.assertIn("renderedBackupMaintenanceOpen == backupMaintenanceOpen", FORM)

    def test_global_pending_inspection_is_read_only(self):
        section = FORM.split("private void ShowBackupMaintenance(", 1)[1]
        self.assertLess(section.index("InspectForeignPendingRestoreAsync"), section.index("bool verifiedPrimary"))
        method = FORM.split("private async Task InspectForeignPendingRestoreAsync()", 1)[1].split(
            "private async Task PreviewExactForeignRestorePlanAsync()", 1)[0]
        for item in ("BuildForeignMtaPendingInspectBundle()", "ForeignPendingInspection.Parse(result.StdOut)",
                     "identity != TryCurrentIdentity()", "Resume is unavailable",
                     "counts.Original", "counts.Target", "counts.Missing", "counts.Extra"):
            self.assertIn(item, method)
        self.assertNotIn("ConfirmedForeignBackupMta(", method)
        bundle = ASSETS.split("internal static string BuildForeignMtaPendingInspectBundle()", 1)[1].split(
            "internal static string BuildForeignMtaRestorePlanBundle", 1)[0]
        self.assertIn(" --pending-inspect", bundle)
        for item in (" --apply ", " --confirm ", " --approve-sha256 "):
            self.assertNotIn(item, bundle)
        self.assertIn("ForeignPendingInspection.SelfTest", (CS / "Program.cs").read_text(encoding="utf-8"))

    def test_stopped_mta_and_exact_plan(self):
        preflight = FORM.split("private async Task PreflightForeignMtaRecoveryAsync()", 1)[1].split(
            "private async Task PreviewExactForeignRestorePlanAsync()", 1)[0]
        self.assertEqual(preflight.count("ConfirmedForeignBackupMta(allowStopped: true)"), 2)
        plan = FORM.split("private async Task PreviewExactForeignRestorePlanAsync()", 1)[1].split(
            "private async Task ExportForeignMtaOfflineAsync()", 1)[0]
        for text in ("ForeignRestorePlan.Parse(result.StdOut, mta, id)", "identity != TryCurrentIdentity()",
                     "foreignBackupListContext != identity", "current != id", "Apply unavailable"):
            self.assertIn(text, plan)
        bundle = ASSETS.split("internal static string BuildForeignMtaRestorePlanBundle", 1)[1].split(
            "internal static string BuildRecoveryBundle", 1)[0]
        self.assertIn(" --plan ", bundle)
        for token in (" --apply ", " --approve-sha256 ", " --confirm "):
            self.assertNotIn(token, bundle)
        self.assertIn("ForeignRestorePlan.SelfTest", (CS / "Program.cs").read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
