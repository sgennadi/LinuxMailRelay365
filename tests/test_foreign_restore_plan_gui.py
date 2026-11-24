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
