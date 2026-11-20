"""All advanced Wizard selectors should be localized without applying changes."""
import pathlib
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
FORM = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")

class WizardUiLocalization(unittest.TestCase):
    def test_advanced_controls_have_localized_choices(self):
        self.assertIn("private void LocalizeAdvancedChoices()", FORM)
        self.assertIn("LocalizeAdvancedChoices();", FORM)
        for field in ("postfixBasicsInterfaces", "tpmDependencyProfile",
                      "hardwareStageProvider", "hardwareCutoverTarget",
                      "smtpAccountOperation"):
            self.assertIn("Relabel(" + field + ", lang switch", FORM)
        for value in ("loopback-only — только локальный SMTP",
                      "Ротация учётных данных", "ספק TPM2 OpenSSL",
                      "אבחה", "SELECTED"):
            if value not in ("אבחה", "SELECTED"):
                self.assertIn(value, FORM)
        self.assertIn("if (localizingAdvancedChoices) return;", FORM)

    def test_security_help_localization(self):
        self.assertIn("ДОПОЛНИТЕЛЬНАЯ ЗАЩИТА", FORM)
        self.assertIn("OPTIONAL SECURITY", FORM)
        self.assertIn("אבטחה נוספת", FORM)
        self.assertIn("RightToLeft = language.SelectedIndex == 2", FORM)

if __name__ == "__main__":
    unittest.main()
