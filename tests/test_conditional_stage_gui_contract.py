from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src/LinuxMailRelay365"

class ConditionalGuiContract(unittest.TestCase):
    def test_embedded_backend_and_strict_receipts(self):
        project = (CS / "LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        source = (CS / "ConditionalStageClient.cs").read_text(encoding="utf-8")
        ui = (CS / "MainForm.ConditionalStage.cs").read_text(encoding="utf-8")
        self.assertIn("stage-conditional-postfix-maps.py", project)
        for marker in ("STAGE_CONDITIONAL_MAPS_ONLY", "COMPILE_CONDITIONAL_MAPS_ONLY",
                       'Get("ACTIVE") != "no"', 'Get("POSTFIX_CHANGED") != "no"',
                       "expectedRules", "manifestSha"):
            self.assertIn(marker, source)
        for marker in ("ConfirmDestructive(", "CurrentConditionalStageContext() != context",
                       "HasMailDiscovery()", "ConfigSha256", "InventorySha256",
                       "ConditionalStageClient.Parse("):
            self.assertIn(marker, ui)
        self.assertNotIn("postconf -e", source)
        self.assertNotIn('"apply" =>', source)
        self.assertNotIn("result.StdOut);", ui)

if __name__ == "__main__":
    unittest.main()
