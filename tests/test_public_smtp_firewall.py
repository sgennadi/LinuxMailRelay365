from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'linux' / 'network-firewall.sh'

class FirewallAndPublicSmtpTests(unittest.TestCase):
    def invoke(self, *argv):
        return subprocess.run(['bash', str(SCRIPT), *argv], text=True,
                              capture_output=True, timeout=10)

    def test_readonly_private_policy(self):
        proc = self.invoke('--validate-only', '--smtp-port', '2526',
                           '--listen-ip', '192.168.30.20',
                           '--trusted-network', '192.168.30.0/24')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('FIREWALL_CHANGES=no', proc.stdout)

    def test_public_option_is_a_plan_only(self):
        result = self.invoke('--validate-only', '--public-internet',
                             '--smtp-port', '2525')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PUBLIC_SMTP_PLAN=selected_not_active', result.stdout)
        self.assertIn('PUBLIC_SMTP_APPLY_ALLOWED=no', result.stdout)
        self.assertIn('SMTP_AUTH_TLS_rate_limits_monitoring', result.stdout)

    def test_public_apply_blocked_even_with_root_or_confirmation(self):
        result = self.invoke('--apply', '--public-internet',
                             '--confirm', 'OPEN_TRUSTED_SMTP_PORT',
                             '--smtp-port', '2525', '--listen-ip', '192.168.30.20',
                             '--trusted-network', '192.168.30.0/24')
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn('PUBLIC_SMTP_APPLY_BLOCKED=', result.stderr)

    def test_rejects_invalid_networks_and_ports(self):
        for args in (
            ('--smtp-port', '25'),
            ('--smtp-port', '0'),
            ('--smtp-port', '65536'),
            ('--smtp-port', 'abc'),
            ('--smtp-port', '2525', '--listen-ip', '0.0.0.0',
             '--trusted-network', '10.0.0.0/8'),
            ('--smtp-port', '2525', '--listen-ip', '192.168.30.20',
             '--trusted-network', '0.0.0.0/0'),
            ('--smtp-port', '2525', '--listen-ip', '192.168.30.20',
             '--trusted-network', '8.8.8.0/24'),
            ('--smtp-port', '2525', '--trusted-network', '192.168.30.0/24')
        ):
            with self.subTest(args=args):
                result = self.invoke('--validate-only', *args)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_linux_firewall_changes_require_narrow_scoped_rules(self):
        source = SCRIPT.read_text(encoding='utf-8')
        self.assertIn('OPEN_TRUSTED_SMTP_PORT', source)
        self.assertIn('PUBLIC_SMTP_APPLY_BLOCKED=', source)
        self.assertIn('postconf -c "$CONF" -h mynetworks', source)
        self.assertIn('destination address=', source)
        self.assertIn('ufw --dry-run allow in proto tcp from', source)
        self.assertNotIn('\nufw enable', source)  # comments about prohibiting enable are allowed
        self.assertNotIn('--add-port=', source)

    def test_wizard_exposes_public_risks_but_blocks_activation(self):
        gui = (ROOT / 'src/LinuxMailRelay365/MainForm.cs').read_text(encoding='utf-8')
        for needle in ('publicInternetRequested', 'BuildNetworkFirewallBundle',
                       'CheckNetworkFirewallAsync', 'OpenTrustedFirewallAsync',
                       'Public Internet SMTP is planning-only and blocked.',
                       'OPEN TRUSTED SMTP'):
            self.assertIn(needle, gui)
        routing = (ROOT / 'src/LinuxMailRelay365/MailRoutingPlan.cs').read_text(encoding='utf-8')
        self.assertIn('public bool PublicInternetRequested { get; set; } = false', routing)
        resources = (ROOT / 'src/LinuxMailRelay365/LinuxMailRelay365.csproj').read_text()
        self.assertIn('LinuxMailRelay365.linux.network-firewall.sh', resources)

if __name__ == '__main__':
    unittest.main()
