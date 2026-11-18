from pathlib import Path
import subprocess
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'linux' / 'install-preserve-postfix-sidecar.sh'

class IsolatedSidecarTests(unittest.TestCase):
    def run_check(self, *args):
        return subprocess.run(['bash', str(SCRIPT), '--check-only', *args],
                              capture_output=True, text=True, timeout=10)

    def test_no_change_default(self):
        r = self.run_check()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('SIDECAR_APPLIED=no', r.stdout)

    def test_explicit_private_relay(self):
        r = self.run_check('--listen-ip', '192.168.20.5',
                           '--trusted-network', '192.168.20.0/24',
                           '--trusted-network', '10.30.0.0/16')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_reject_wildcard_public_and_remote_untrusted(self):
        for args in [
            ('--listen-ip','0.0.0.0','--trusted-network','192.168.20.0/24'),
            ('--listen-ip','192.168.20.5','--trusted-network','0.0.0.0/0'),
            ('--listen-ip','192.168.20.5','--trusted-network','8.8.8.0/24'),
            ('--listen-ip','192.168.20.5'),
            ('--trusted-network','10.0.0.0/8'),
            ('--listen-ip','127.0.0.1','--trusted-network','10.0.0.0/8'),
            ('--listen-ip','192.168.20.5','--trusted-network','192.168.20.3/24')
        ]:
            with self.subTest(args=args):
                self.assertNotEqual(self.run_check(*args).returncode,0)

    def test_isolated_paths_and_no_primary_modifications(self):
        s = SCRIPT.read_text(encoding='utf-8')
        self.assertIn('QUEUE=/var/spool/linuxmailrelay365-sidecar', s)
        self.assertIn('CONF=/etc/linuxmailrelay365/sidecar-postfix', s)
        self.assertIn('linuxmailrelay365-sidecar.service', s)
        self.assertIn("postfix -c \"$CONF\" check", s)
        self.assertIn('SIDECAR_PORT=2525', s)
        self.assertIn('PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes', s)
        for blocked in (
            "postconf -e ", "systemctl reload postfix", "systemctl restart postfix",
            "systemctl stop postfix.service", "systemctl start postfix.service",
            "postmulti -e init", "apt-get install", "dnf install"
        ):
            self.assertNotIn(blocked, s)

    def test_transport_allowlisted_identity_per_instance(self):
        t = (ROOT/'linux/m365_xoauth2_transport.py').read_text()
        self.assertIn('SIDECAR_CONF_FILE',t)
        self.assertIn('if path not in (CONF_FILE, SIDECAR_CONF_FILE):',t)
        self.assertIn("ap.add_argument('--config', choices=", t)
        m = (ROOT/'src/LinuxMailRelay365/MainForm.cs').read_text()
        for token in ('BuildSidecarBundle', 'HasIsolatedSidecarAsync',
                      'SendIsolatedSidecarTestAsync', 'SidecarDiagnosticsAsync'):
            self.assertIn(token, m)

    def test_shell_syntax_and_validation_selftest(self):
        result = subprocess.run(['bash','-n',str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        result = subprocess.run(['bash',str(SCRIPT),'--self-test'],
                                capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

if __name__ == '__main__':
    unittest.main()
