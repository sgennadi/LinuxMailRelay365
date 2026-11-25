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
        body = MAIN.split("private async Task RestoreBackupAsync()", 1)[1].split("\n    private ", 1)[0]
        helper = (ROOT/'src/LinuxMailRelay365/MainForm.ArchiveSelection.cs').read_text()
        self.assertIn('RequireArchiveSelection(backupSelector, postfixBackupListIdentity, endpoint)', body)
        self.assertIn('selector.SelectedItem is not string id', helper)
        self.assertIn('listIdentity != SecurityOptionsStore.Identity(endpoint)', helper)
        self.assertIn('BuildRecoveryBundle("--restore", backupId)', body)
        self.assertIn('BuildRecoveryBundle("--list")', MAIN)
        self.assertIn('BuildRecoveryBundle("--backup")', MAIN)
        self.assertIn('RESTORE POSTFIX', body)
        self.assertLess(body.index('await VerifySelectedPostfixArchiveAsync()'), body.index('ConfirmDestructive('))
        self.assertLess(body.index('ConfirmDestructive('), body.index('BuildRecoveryBundle("--restore"'))
        self.assertIn('result.EnsureSuccess()', body)
        self.assertIn('finally { InvalidateAfterArchiveWrite(); }', body)
        self.assertIn('InvalidateAfterSendmailV2Write();', helper)
        self.assertIn('inspectedMail = null', (ROOT/'src/LinuxMailRelay365/MainForm.SendmailV2Recovery.cs').read_text())
        self.assertIn('"backup" or "restore"',(ROOT/'src/LinuxMailRelay365/DiagnosticJournal.cs').read_text())

    def test_undetected_postfix_fails_closed(self):
        script=(ROOT/'linux/probe-linux.sh').read_text()
        self.assertIn('elif [ -e /etc/postfix ]; then',script)
        self.assertIn('val MTA unknown',script)
        self.assertIn('Existing Postfix detected.',SCRIPT)
if __name__ == '__main__': unittest.main()
