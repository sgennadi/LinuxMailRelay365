from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / 'src/LinuxMailRelay365/MainForm.cs'
FLOW = ROOT / 'src/LinuxMailRelay365/PreserveMailFlowPreview.cs'

class PreserveMailLiveDiagramContract(unittest.TestCase):
    def test_two_separate_mail_routes(self):
        source = FLOW.read_text(encoding='utf-8')
        for marker in ('EXISTING APPLICATIONS', 'NEW APPLICATIONS',
                       'PRIMARY MAIL SERVER', 'ISOLATED POSTFIX', 'MICROSOFT 365',
                       'Existing SMTP settings'):
            self.assertIn(marker, source)
        self.assertIn('UpdateData(PreserveFlowSnapshot snapshot', source)
        self.assertIn('publicInternetRequested', GUI.read_text())

    def test_actual_inputs_and_no_example_data_used_as_real(self):
        gui = GUI.read_text()
        for name in ('host.Text.Trim()', 'smtpListenIp.Text.Trim()',
                     'isolatedSmtpPort.Text.Trim()', 'mailbox.Text.Trim()',
                     'tenant.Text.Trim()', 'smtpTrustedCidrs.Text.Trim()'):
            self.assertIn(name, gui)
        self.assertIn('UpdatePreserveFlowPreview()', gui)
        self.assertIn('preserveFlowPreview.UpdateData(snapshot, language.SelectedIndex)',
                      gui)
        self.assertIn('CopyPreserveInstructions()', gui)
        flow = FLOW.read_text()
        self.assertIn('LinuxMailRelay365 | Preserve Existing Mail', flow)
        self.assertIn('not confirmed installed', flow)
        self.assertIn('127.0.0.1 on a different machine', flow)
        self.assertIn('SMTP AUTH: not enabled by default', flow)
        self.assertIn('SMTP TLS to Linux: not enabled by default', flow)

    def test_secret_material_not_in_client_instructions(self):
        source = FLOW.read_text()
        for secret in ('SSH password', 'sudo password', 'private_key', 'client_secret',
                       'password=', 'Bearer '):
            self.assertNotIn(secret, source)
        self.assertIn('recipient', source.lower())
        self.assertIn('Sender (From/envelope): rewritten', source)

if __name__ == '__main__':
    unittest.main()
