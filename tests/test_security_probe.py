import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / 'linux' / 'probe-linux.sh'

class SecurityProbeTests(unittest.TestCase):
    def test_probe_read_only_and_explicit_disabled(self):
        result = subprocess.run(['bash', str(PROBE)], capture_output=True,
                                text=True, timeout=20, check=True)
        self.assertIn('PROBE_VERSION=2\n', result.stdout)
        self.assertIn('SECURITY_CHANGES_APPLIED=no\n', result.stdout)
        self.assertIn('HARDWARE_SIGNING_AUTOMATICALLY_ENABLED=no\n', result.stdout)
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        self.assertIn(values['TPM_VERSION'], {'unknown', '1', '2'})
        self.assertIn(values['MTA'], {'postfix', 'sendmail', 'exim', 'none'})
        self.assertIn('PKCS11_TOKENS', values)
        self.assertIn(values['OPENSSL_TPM2_PROVIDER'], {'loadable_unverified', 'not_available'})
        self.assertIn(values['OPENSSL_PKCS11_PROVIDER'], {'loadable_unverified', 'not_available'})
        self.assertIn(values['TPM2_ABRMD_SERVICE'], {'not_verified', 'active', 'inactive_or_unavailable'})

    def test_probe_contains_no_mutating_commands(self):
        text = PROBE.read_text(encoding='utf8')
        for bad in ['apt-get install', 'dnf install', 'useradd ', 'postconf -e',
                    'systemctl enable', 'chmod ', 'chown ', 'openssl req']:
            self.assertNotIn(bad, text)

    def test_cloud_probe_explicitly_read_only(self):
        text = (ROOT / 'windows' / 'Test-LinuxMailRelay365Security.ps1').read_text(encoding='utf8')
        self.assertIn('$false', text)
        self.assertIn('Policy.Read.All', text)
        self.assertIn('AuditLog.Read.All', text)
        for bad in ['New-MgIdentityConditionalAccessPolicy', 'Update-MgIdentityConditionalAccessPolicy',
                    'Set-ConditionalAccessPolicy', 'Method PATCH', 'Method POST']:
            self.assertNotIn(bad, text)

if __name__ == '__main__':
    unittest.main()
