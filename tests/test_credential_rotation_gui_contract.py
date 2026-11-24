"""Static GUI integration contracts; the registered C# SelfTest requires Windows build/CI."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / 'src/LinuxMailRelay365'


class RotationGuiContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = (CS/'CredentialRotationClient.cs').read_text(encoding='utf-8')
        cls.ui = (CS/'MainForm.CredentialRotation.cs').read_text(encoding='utf-8')
        cls.panel = (CS/'MainForm.MultiTransport.cs').read_text(encoding='utf-8')

    def test_all_modules_embedded(self):
        project = ET.parse(CS/'LinuxMailRelay365.csproj')
        embedded = {e.attrib.get('Include') for e in project.iter('EmbeddedResource')}
        for file in ('conditional-transport-rotation.py','manage-conditional-transport-rotation.py'):
            self.assertIn('../../linux/'+file,embedded)
            self.assertIn('LinuxMailRelay365.linux.'+file,(CS/'EmbeddedAssets.cs').read_text(encoding='utf-8'))
            self.assertTrue((ROOT/'linux'/file).is_file())
            self.assertIn(file,self.client)

    def test_exact_review_bound_to_current_owned_transport(self):
        for marker in ('OfflineHostContext() == context','ReferenceEquals(multiInstalled, installed)',
                       'installed.Status == "installed_owned"','installed.Rules[index - 1].AuthMode == "password"',
                       'ReferenceEquals(credentialRotationReview, review)','installed.Plan == review.Plan',
                       'multiRevision.Text.Trim().ToLowerInvariant() == review.Revision'):
            self.assertIn(marker,self.ui)
        self.assertIn('ShowCredentialRotationActions(page, width, l);',self.panel)
        self.assertGreaterEqual(self.panel.count('ResetCredentialRotationReview();'),5)

    def test_password_only_requested_for_rotate(self):
        self.assertEqual(self.ui.count('PromptRouteCredential('),1)
        self.assertIn('if (!review.IsRecovery)\n            {\n                credential = PromptRouteCredential(',self.ui)
        self.assertIn('Recovery never accepts credentials or an index override.',self.client)
        self.assertIn('new { username = value.User, password = value.Secret }',self.client)
        self.assertIn('builtin printf',self.client)
        self.assertIn('credential = null;',self.ui)
        self.assertIn('script = null;',self.ui)

    def test_separate_typed_approval_and_strict_receipts(self):
        for marker in ('ROTATE_ONE_STOPPED_POSTFIX_CREDENTIAL','RECOVER_ONE_STOPPED_POSTFIX_CREDENTIAL',
                       '--approve-plan-sha256','--approve-review-sha256','SMTP_AUTH_ATTEMPTED',
                       'fields.SetEquals(f.Keys)','!result.TryAdd','exitCode != 0',
                       'f["RETAINED"] != review.Retained'):
            self.assertIn(marker,self.client)
        self.assertIn('ConfirmRotationMaintenance(l)',self.ui)
        self.assertIn('ConfirmDestructive(',self.ui)
        self.assertIn('CredentialRotationClient.ParseReview',self.ui)
        self.assertIn('CredentialRotationClient.ParseResult',self.ui)
        self.assertIn('CredentialRotationClient.SelfTest',(CS/'Program.cs').read_text(encoding='utf-8'))

    def test_uncertain_write_invalidates_evidence_and_no_service_control(self):
        for marker in ('if (attempted) InvalidateAfterCredentialRotation();','discoveredMailIdentity = null',
                       'inspectedHostIdentity = null','multiInstalled = null','conditionalRouteAudits.Clear()',
                       'Keep Postfix stopped'):
            self.assertIn(marker,self.ui)
        for forbidden in ('result.StdErr','systemctl start','systemctl stop','postfix reload','postconf -e',
                          'File.WriteAllText','credential.Value.Secret','ex.Message'):
            self.assertNotIn(forbidden,self.ui)
            self.assertNotIn(forbidden,self.client)


if __name__ == '__main__': unittest.main()
