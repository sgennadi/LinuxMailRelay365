from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
MAIN=(ROOT/'src/LinuxMailRelay365/MainForm.cs').read_text()
SCRIPT=(ROOT/'linux/install-postfix-m365-xoauth2.sh').read_text()

class ForceReplaceWizardTests(unittest.TestCase):
    def test_force_only_after_existing_postfix_inspection(self):
        self.assertIn('inspectedMail.Mta == "postfix"',MAIN)
        self.assertIn('inspectedServerIdentity == TryCurrentIdentity()',MAIN)
        self.assertIn('inspectedMail != inventory',MAIN)
        self.assertIn('Preserve Existing Mail',MAIN)
        self.assertIn('Force Replace',MAIN)
        self.assertIn('REPLACE POSTFIX',MAIN)
        self.assertIn('REPLACE_POSTFIX_CONFIG',MAIN)

    def test_restore_requires_selected_backup_and_typed_confirmation(self):
        self.assertIn('backupSelector.SelectedItem is not string backupId',MAIN)
        self.assertIn('BuildRecoveryBundle("--restore", backupId)',MAIN)
        self.assertIn('BuildRecoveryBundle("--list")',MAIN)
        self.assertIn('BuildRecoveryBundle("--backup")',MAIN)
        self.assertIn('RESTORE POSTFIX',MAIN)
        self.assertIn('result.EnsureSuccess()',MAIN)
        self.assertIn('inspectedMail = null',MAIN)
        self.assertIn('"backup" or "restore"',(ROOT/'src/LinuxMailRelay365/DiagnosticJournal.cs').read_text())

    def test_undetected_postfix_fails_closed(self):
        script=(ROOT/'linux/probe-linux.sh').read_text()
        self.assertIn('elif [ -e /etc/postfix ]; then',script)
        self.assertIn('val MTA unknown',script)
        self.assertIn('Existing Postfix detected.',SCRIPT)
if __name__ == '__main__': unittest.main()
