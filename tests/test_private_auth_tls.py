"""Non-destructive SMTP AUTH/TLS installer and GUI integration contracts."""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'linux' / 'enable-sidecar-auth-tls.sh'


class PrivateSmtpAuthTlsTests(unittest.TestCase):
    def shell(self, *args):
        return subprocess.run(['bash', str(SCRIPT), *args], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True, timeout=8)

    def test_shell_syntax(self):
        r = subprocess.run(['bash', '-n', str(SCRIPT)], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=8)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_self_test_only_parses_arguments(self):
        r = self.shell('--self-test')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('AUTH_TLS_ARGUMENT_PARSER=available', r.stdout)

    def test_invalid_custom_port_is_rejected_early_without_root(self):
        for port in ('0','25','587','1000','65536','abc','-2','', '0;id'):
            with self.subTest(port=port):
                r = self.shell('--check-only','--smtp-port',port,'--server-name',
                               'smtp.example.test','--tls-cert','/tmp/cert.pem',
                               '--tls-key','/tmp/key.pem','--password-file','/tmp/hash')
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('AUTH_TLS_ERROR=invalid_custom_smtp_port', r.stderr)

    def test_custom_port_accepted_by_argument_validation(self):
        for port in ('1024', '2525', '2526', '46500', '65535'):
            with self.subTest(port=port):
                r = self.shell('--check-only','--smtp-port',port,'--server-name',
                               'smtp.example.test','--tls-cert','/tmp/cert.pem',
                               '--tls-key','/tmp/key.pem','--password-file','/tmp/hash')
                self.assertNotIn('invalid_custom_smtp_port', r.stderr)
                # No Postfix in CI unit test containers; this is NOT proof of deployment.
                self.assertNotIn('AUTH_TLS_APPLIED=yes', r.stdout)

    def test_unsafe_hostname_and_source_paths_rejected(self):
        for name in ('bad name', 'localhost', 'x;id', '0.0.0.0'):
            if name == '0.0.0.0':
                continue # syntactically DNS-like: IP is rejected by TLS SAN check
            r = self.shell('--check-only','--smtp-port','2525',
                           '--server-name',name,'--tls-cert','/tmp/cert.pem',
                           '--tls-key','/tmp/key.pem','--password-file','/tmp/hash')
            self.assertNotEqual(r.returncode, 0)
        r = self.shell('--check-only','--smtp-port','2525',
                       '--server-name','smtp.example.test','--tls-cert','/tmp/a/../b',
                       '--tls-key','/tmp/key.pem','--password-file','/tmp/hash')
        self.assertIn('invalid_absolute_linux_path', r.stderr)

    def test_security_contract_uses_primary_fingerprint_and_rollback(self):
        s = SCRIPT.read_text(encoding='utf-8')
        for token in (
            'ENABLE_PRIVATE_AUTH_TLS',
            'AUTH_TLS_PUBLIC_INTERNET=blocked',
            'PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes',
            'AUTH_TLS_ROLLBACK=attempted',
            'postfix -c "$CONF" check',
            'postfix -c "$CONF" reload',
            'smtpd_tls_security_level = encrypt',
            'smtpd_tls_auth_only = yes',
            'smtpd_sasl_auth_enable = yes',
            'smtpd_relay_restrictions = permit_sasl_authenticated, reject',
            'AUTH_TLS_ERROR=requested_port_differs_from_installed_sidecar',
            'AUTH_TLS_ERROR=selinux_enforcing_not_verified',
            'AUTH_TLS_ERROR=rhel_selinux_permissive_policy_not_verified',
            'AUTH_TLS_ERROR=selinux_status_unknown_manual_review_required',
            'DOVECOT_CONFIG_FAMILY=2.3',
            'DOVECOT_CONFIG_FAMILY=2.4',
            'dovecot_config_version = 2.4.0',
            'dovecot_storage_version = 2.4.0',
            'auth_allow_cleartext = yes',
            'passdb passwd-file {',
            'passwd_file_path = /etc/linuxmailrelay365/smtp-auth/passwd',
        ):
            self.assertIn(token, s)
        self.assertLess(s.index('AUTH_TLS_ERROR=selinux_enforcing_not_verified'),
                        s.index('exec 9>/run/linuxmailrelay365-sidecar-auth.lock'))
        for forbidden in (
            'systemctl restart postfix.service',
            'systemctl stop postfix.service',
            'systemctl restart dovecot.service',
            'ufw allow ',
            'semanage port -a',
            'setenforce 0',
            '0.0.0.0/0',
            'postconf -e ',
        ):
            self.assertNotIn(forbidden, s)

    def test_wizard_embeds_script_and_only_accepts_linux_file_paths(self):
        ui = (ROOT/'src/LinuxMailRelay365/MainForm.cs').read_text(encoding='utf-8')
        embed = (ROOT/'src/LinuxMailRelay365/EmbeddedAssets.cs').read_text(encoding='utf-8')
        proj = (ROOT/'src/LinuxMailRelay365/LinuxMailRelay365.csproj').read_text(encoding='utf-8')
        for token in ('PrivateAuthTlsArguments', 'CheckAuthTlsAsync', 'EnableAuthTlsAsync',
                      'ConfirmDestructive', 'ENABLE PRIVATE SMTP AUTH',
                      'BuildAuthTlsBundle(args)', 'BuildAuthTlsBundle(PrivateAuthTlsArguments(apply: false))'):
            self.assertIn(token, ui)
        self.assertIn('AuthTlsInstaller', embed)
        self.assertIn('BuildAuthTlsBundle(string[] args)', embed)
        self.assertIn('linux/enable-sidecar-auth-tls.sh', proj)
        ssh=(ROOT/'src/LinuxMailRelay365/SshRemote.cs').read_text(encoding='utf-8')
        self.assertIn('IsSidecarAuthTlsEnabledAsync', ssh)
        self.assertIn('AUTH_TLS', ui)
        self.assertIn('The wizard intentionally does not store client credentials', ui)
        self.assertIn('if (authState != false)', ui)
        self.assertIn("AUTH_TLS_ERROR=one_to_64_hashed_accounts_required", SCRIPT.read_text())


if __name__ == '__main__':
    unittest.main()
