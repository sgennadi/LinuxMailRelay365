from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class PostfixFingerprintContract(unittest.TestCase):
    def test_probe_reports_only_digest(self):
        source=(ROOT/'linux/probe-linux.sh').read_text(encoding='utf-8')
        self.assertIn('val POSTFIX_CONFIG_SHA256 "$digest"',source)
        self.assertIn('sha256sum /etc/postfix/main.cf /etc/postfix/master.cf',source)
        self.assertNotIn('cat /etc/postfix/main.cf',source)
    def test_installer_double_checks_before_modification(self):
        source=(ROOT/'linux/install-postfix-m365-xoauth2.sh').read_text(encoding='utf-8')
        self.assertIn('check_postfix_fingerprint || exit 1',source)
        self.assertIn('if [ "$FORCE_REPLACE" -eq 1 ]; then check_postfix_fingerprint || exit 1; fi',source)
        self.assertLess(source.index('check_postfix_fingerprint || exit 1'),source.index('snapshot="$(bash'))
        self.assertLess(source.index('if [ "$FORCE_REPLACE" -eq 1 ]; then check_postfix_fingerprint || exit 1; fi'),source.index('apt-get update'))
    def test_wizard_blocks_race_and_passes_fingerprint(self):
        gui=(ROOT/'src/LinuxMailRelay365/MainForm.cs').read_text(encoding='utf-8')
        self.assertIn('inspectedMail != inventory',gui)
        self.assertIn('arguments.Add("--expect-postfix-sha256")',gui)
        self.assertIn('Postfix configuration changed since inspection',gui)
        model=(ROOT/'src/LinuxMailRelay365/MailRoutingPlan.cs').read_text(encoding='utf-8')
        self.assertIn('string ConfigSha256',model)
if __name__=='__main__':unittest.main()
