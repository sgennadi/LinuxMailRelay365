from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src" / "LinuxMailRelay365"

class RecoveryGuiContract(unittest.TestCase):
    def test_recovery_panel_is_read_only(self):
        client = (CS / "ConditionalRecoveryClient.cs").read_text(encoding="utf-8")
        ui = (CS / "MainForm.ConditionalRecovery.cs").read_text(encoding="utf-8")
        for marker in ('--list', '"WRITE_ALLOWED") != "no"', '"POSTFIX_CHANGED") != "no"',
                       'entries.Count >= 64', 'seen.Add'):
            self.assertIn(marker, client)
        for marker in ("HasMailDiscovery()", "RecoveryInventoryContext() != context",
                       "ConditionalRecoveryClient.Parse", "ReadOnly = true"):
            self.assertIn(marker, ui)
        for marker in ('--apply', '--restore', 'systemctl start', 'postfix reload'):
            self.assertNotIn(marker, client)
            self.assertNotIn(marker, ui)
        self.assertIn("ConditionalRecoveryClient.SelfTest",
                      (CS / "Program.cs").read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
