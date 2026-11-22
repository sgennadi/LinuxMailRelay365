import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / 'linux' / 'audit-existing-smtp.py'
SPEC = importlib.util.spec_from_file_location('existing_smtp_audit', AUDIT)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

class ExistingPublicSmtpAuditTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            'relayhost': '[smtp.partner.example]:587',
            'mynetworks': '127.0.0.0/8,192.168.10.0/24',
            'smtpd_relay_restrictions': 'permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination',
            'smtpd_recipient_restrictions': 'reject_unauth_destination',
            'smtpd_sasl_auth_enable': 'yes',
            'smtpd_tls_security_level': 'may',
        }
        self.services = {'smtp/inet': 25, 'submission/inet': 587}

    def test_public_smtp_is_not_equated_to_open_relay(self):
        result = MOD.analyze(self.config, self.services, {},
                             [('0.0.0.0', 25), ('127.0.0.1', 587)])
        self.assertEqual(result['SMTP_PUBLIC_BIND'], 'potentially_public')
        self.assertEqual(result['SMTP_RELAY_POLICY_RISK'], 'relay_guard_present')
        self.assertEqual(result['SMTP_OPEN_RELAY_PROVEN'], 'no_active_probe_performed')
        self.assertEqual(result['SMTP_EXTERNAL_REACHABILITY'], 'not_tested_from_internet')
        self.assertEqual(result['SMTP_RELAYHOST_CONFIGURED'], 'yes')

    def test_wide_trust_or_unconditional_permit_is_flagged(self):
        for cfg in (
            {**self.config, 'mynetworks': '0.0.0.0/0'},
            {**self.config, 'smtpd_relay_restrictions': 'permit,reject_unauth_destination'},
        ):
            with self.subTest(cfg=cfg):
                result = MOD.analyze(cfg, {'smtp/inet': 25}, {},
                                     [('0.0.0.0', 25)])
                self.assertEqual(result['SMTP_RELAY_POLICY_RISK'], 'suspected_unsafe_relay')
                self.assertEqual(result['SMTP_AUDIT_REQUIRES_MANUAL_REVIEW'],
                                 'high_priority')

    def test_loopback_only_and_firewall_unknown(self):
        result = MOD.analyze(self.config, {'smtp/inet': 25}, {},
                             [('127.0.0.1', 25)])
        self.assertEqual(result['SMTP_PUBLIC_BIND'], 'loopback_only')
        self.assertEqual(result['SMTP_EXTERNAL_REACHABILITY'], 'not_tested_from_internet')

    def test_service_overrides_are_effective(self):
        result = MOD.analyze(self.config, {'submission/inet': 587},
                             {'submission/inet': {'mynetworks': '0.0.0.0/0'}},
                             [('0.0.0.0', 587)])
        self.assertEqual(result['SMTP_RELAY_POLICY_RISK'], 'suspected_unsafe_relay')

    def test_unknown_is_never_silently_safe(self):
        a = MOD.analyze(None, None, {}, None, 'postfix')
        b = MOD.analyze(None, None, {}, [], 'exim_manual_review')
        self.assertEqual(a['SMTP_PUBLIC_BIND'], 'unknown')
        self.assertEqual(b['SMTP_PUBLIC_BIND'], 'unknown')
        self.assertEqual(a['SMTP_AUDIT_REQUIRES_MANUAL_REVIEW'], 'yes')

    def test_parse_postconf_and_ss_service(self):
        master = ('smtp/inet= n - n - - smtpd\n'
                  'submission/inet= n - n - - smtpd\n'
                  'localhost/unix= - - n - - local\n')
        self.assertEqual(MOD.services(master), self.services)
        binds = MOD.listeners('LISTEN 0 100 0.0.0.0:25 0.0.0.0:*\n'
                              'LISTEN 0 50 [::1]:587 [::]:*\n')
        self.assertEqual(binds, [('0.0.0.0', 25), ('::1', 587)])

    def test_selftest_and_readonly_policy(self):
        r = subprocess.run(['python3', str(AUDIT), '--self-test'],
                           capture_output=True, text=True, timeout=15)
        self.assertEqual(r.returncode, 0, r.stderr)
        source = AUDIT.read_text(encoding='utf-8')
        self.assertIn('postconf', source)
        self.assertIn('ss', source)
        self.assertNotIn('smtplib', source)
        self.assertNotIn('sendmail -', source)
        self.assertNotIn('postconf -e', source)

    def test_custom_inbound_port_socket_evidence(self):
        busy = MOD.analyze(None, None, {}, [("0.0.0.0", 25),
            ("127.0.0.1", 2525)], mta="no_active_mta_verified",
            selected_port=2525)
        self.assertEqual(busy["SMTP_SELECTED_PORT"], "2525")
        self.assertEqual(busy["SMTP_SELECTED_PORT_SOCKET"], "occupied_loopback")
        self.assertEqual(busy["SMTP_STANDARD_PORT_SOCKETS"],
                         "potentially_public_unattributed")
        free = MOD.analyze(None, None, {}, [("127.0.0.1", 2526)],
                           mta="no_active_mta_verified", selected_port=2525)
        self.assertEqual(free["SMTP_SELECTED_PORT_SOCKET"], "no_listener_observed")
        unknown = MOD.analyze(None, None, {}, None,
                              mta="no_active_mta_verified", selected_port=2525)
        self.assertEqual(unknown["SMTP_SELECTED_PORT_SOCKET"], "scan_unavailable")
        self.assertEqual(MOD.selected_port_socket_status(
            [("127.0.0.1", 2525), ("0.0.0.0", 2525)], 2525),
            "occupied_potentially_public")

    def test_invalid_custom_port_fails_before_host_scan(self):
        for port in ("25", "587", "0", "65536", "-1"):
            proc = subprocess.run(
                ["python3", str(AUDIT), "--smtp-port", port],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=10)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("--smtp-port must be 1024..65535", proc.stderr)

    def test_wizard_audit_embedded_and_displayed(self):
        gui = (ROOT / 'src/LinuxMailRelay365/MainForm.cs').read_text()
        for token in ('InspectExistingPublicSmtpAsync', 'BuildExistingSmtpAuditBundle',
                      'existingSmtpAudit.Summary(language.SelectedIndex)',
                      'SuspectedUnsafeRelay'):
            self.assertIn(token, gui)
        project = (ROOT / 'src/LinuxMailRelay365/LinuxMailRelay365.csproj').read_text()
        self.assertIn('LinuxMailRelay365.linux.existing-smtp-audit.py', project)

if __name__ == '__main__':
    unittest.main()
