from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class SourceContracts(unittest.TestCase):
    def test_default_off_per_host_plan(self):
        text = (ROOT / 'src/LinuxMailRelay365/SecurityOptions.cs').read_text(encoding='utf8')
        for name in ['RequestHardwareBackedKey', 'RequestIpConditionalAccess',
                     'RequestEntraSignInMonitoring']:
            self.assertIn(f'{name} {{ get; set; }} = false;', text)
        self.assertIn('SHA256.HashData', text)
        self.assertIn('server-b.example', text)

    def test_ssh_password_is_not_written_to_process_args(self):
        text = (ROOT / 'src/LinuxMailRelay365/SshRemote.cs').read_text(encoding='utf8')
        self.assertIn('new SshClient(', text)
        self.assertIn('HostKeyReceived', text)
        self.assertIn('FingerPrintSHA256', text)
        self.assertIn('StrictHostKeyChecking=yes', text)
        self.assertNotIn('sshpass', text.lower())
        self.assertNotIn('ArgumentList.Add(endpoint.Password)', text)
        self.assertIn('QuoteShell(mailbox)', text)

if __name__ == '__main__':
    unittest.main()
