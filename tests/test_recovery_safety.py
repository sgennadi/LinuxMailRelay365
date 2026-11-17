from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[1]
RECOVERY=ROOT/'linux/mail-config-recovery.sh'
INSTALLER=ROOT/'linux/install-postfix-m365-xoauth2.sh'

class RecoverySafetyTests(unittest.TestCase):
    def test_shell_syntax_and_backup_id_selftest(self):
        for script in (RECOVERY,INSTALLER):
            result=subprocess.run(['bash','-n',str(script)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
        check=subprocess.run(['bash',str(RECOVERY),'--self-test'],
                             capture_output=True,text=True,timeout=10)
        self.assertEqual(check.returncode,0,check.stderr)

    def test_backup_before_packages_and_changes(self):
        text=INSTALLER.read_text(encoding='utf-8')
        self.assertLess(text.index('snapshot="$(bash'),text.index('apt-get update'))
        self.assertLess(text.index('snapshot="$(bash'),text.index('useradd --system'))
        self.assertIn("trap rollback_if_failed EXIT",text)
        self.assertIn('REPLACE_POSTFIX_CONFIG',text)
        self.assertIn('VERIFIED_PRE_CHANGE_BACKUP_ID=',text)

    def test_private_verified_recovery(self):
        source=RECOVERY.read_text(encoding='utf-8')
        self.assertIn('BASE=/var/backups/linuxmailrelay365',source)
        self.assertIn('sha256sum --status -c SHA256SUMS',source)
        self.assertIn('Pre-restore safety snapshot',source)
        self.assertIn('Files and service state restored',source)
        embedded=(ROOT/'src/LinuxMailRelay365/EmbeddedAssets.cs').read_text(encoding='utf-8')
        self.assertIn('BuildRecoveryBundle',embedded)
        self.assertIn('LMR365_RECOVERY',embedded)
if __name__ == '__main__':
    unittest.main()
