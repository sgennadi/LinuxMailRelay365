"""Fail-closed SMTP AUTH/STARTTLS restore contracts (Python 3.6+)."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESTORE = ROOT / "linux" / "restore-sidecar-auth-tls.sh"
ACTIVATE = ROOT / "linux" / "enable-sidecar-auth-tls.sh"


class SidecarAuthTlsRestoreTests(unittest.TestCase):
    def run_restore(self, *args):
        return subprocess.run(["bash", str(RESTORE)] + list(args),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=8)

    def test_shell_syntax_and_selftest(self):
        r = subprocess.run(["bash", "-n", str(RESTORE)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=8)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.run_restore("--self-test").returncode, 0)

    def test_invalid_custom_ports_rejected_before_root_or_files(self):
        for p in ("25", "587", "0", "1023", "65536", "bad", "", "0;id"):
            with self.subTest(port=p):
                r = self.run_restore("--check-only", "--smtp-port", p)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("AUTH_TLS_RESTORE_ERROR=invalid_custom_smtp_port", r.stderr)

    def test_valid_custom_ports_are_not_hardcoded_2525(self):
        for p in ("1024", "2525", "2529", "46500", "65535"):
            with self.subTest(port=p):
                r = self.run_restore("--check-only", "--smtp-port", p)
                self.assertNotIn("invalid_custom_smtp_port", r.stderr)
                self.assertNotIn("AUTH_TLS_RESTORED=yes", r.stdout)

    def test_apply_requires_specific_expected_sha_and_confirmation(self):
        expected = "a" * 64
        r = self.run_restore("--restore", "--smtp-port", "2529",
                             "--expect-main-sha256", expected)
        self.assertIn("explicit_security_downgrade_confirmation_required", r.stderr)
        r = self.run_restore("--restore", "--smtp-port", "2529",
                             "--confirm", "RESTORE_TRUSTED_NETWORK_SMTP")
        self.assertIn("expected_main_sha256_required", r.stderr)
        r = self.run_restore("--restore", "--smtp-port", "2529",
                             "--expect-main-sha256", "z" * 64,
                             "--confirm", "RESTORE_TRUSTED_NETWORK_SMTP")
        self.assertIn("expected_main_sha256_required", r.stderr)

    def test_scripts_have_one_terminal_success_without_orphan_tail(self):
        # An earlier code edit left a second partial SELinux block AFTER the
        # final success output. Bash -n caught it, but guard the file layout.
        for script in (ACTIVATE, RESTORE):
            with self.subTest(script=script.name):
                text = script.read_text(encoding="utf-8")
                terminal = "echo 'MICROSOFT365_DELIVERY_VERIFIED=no'"
                self.assertEqual(text.count(terminal), 1)
                self.assertEqual(text.split(terminal, 1)[1].strip(), "")
                self.assertEqual(text.count('selinux_status="$(getenforce'), 1)
                self.assertIn("selinux_status_unknown_manual_review_required", text)

    def test_safe_restore_policy_is_only_private_and_never_public(self):
        text = RESTORE.read_text(encoding="utf-8")
        for required in (
            "AUTH_TLS_RESTORE_SECURITY_DOWNGRADE=yes",
            "AUTH_TLS_RESTORE_PUBLIC_INTERNET=blocked",
            "AUTH_TLS_RESTORE_TARGET=private_trusted_network_without_auth",
            "AUTH_TLS_RESTORE_CURRENT_MAIN_SHA256=",
            "AUTH_TLS_RESTORE_ERROR=isolated_configuration_changed_since_activation",
            "AUTH_TLS_RESTORE_ERROR=operator_reviewed_sha256_no_longer_matches",
            "AUTH_TLS_RESTORE_ROLLBACK=verified_auth_restored",
            "AUTH_TLS_RESTORE_ROLLBACK=MANUAL_RECOVERY_REQUIRED",
            "PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes",
            "RESTORE_TRUSTED_NETWORK_SMTP",
            "flock -n 9",
            "main.cf.auth.sha256",
            "master.cf.auth.sha256",
            "main.cf.before-auth",
            "AUTH_TLS_RESTORE_ERROR=backup_copy_verification_failed_no_settings_changed",
            'cmp -s "$AUTH/passwd" "$ARCHIVE/smtp-auth/passwd"',
            'cmp -s "$AUTH/privkey.pem" "$ARCHIVE/smtp-auth/privkey.pem"',
            "AUTH_TLS_RESTORE_ERROR=rhel_selinux_permissive_policy_not_verified",
            "AUTH_TLS_RESTORE_ERROR=selinux_status_unknown_manual_review_required",
            "chmod 0700",
            "systemctl disable --now linuxmailrelay365-smtp-auth.service",
            "postfix -c \"$CONF\" check",
            "postfix -c \"$CONF\" reload",
        ):
            self.assertIn(required, text)
        for forbidden in (
            "systemctl restart postfix",
            "systemctl stop postfix",
            "postconf -e",
            "ufw allow ",
            "semanage port -a",
            "setenforce 0",
            "0.0.0.0/0",
        ):
            self.assertNotIn(forbidden, text)

    def test_current_auth_installer_writes_manifest_and_same_lock(self):
        text = ACTIVATE.read_text(encoding="utf-8")
        for expected in ("main.cf.auth.sha256", "master.cf.auth.sha256",
                         "flock -n 9", "AUTH_TLS_APPLIED=yes"):
            self.assertIn(expected, text)

    def test_wizard_embeds_exact_sha_guard_and_asks_for_confirmation(self):
        main = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        embed = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text(encoding="utf-8")
        project = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        for pattern in (
            "RestoreAuthTlsAsync", "BuildAuthTlsRestoreBundle(installedPort, fingerprint)",
            "AUTH_TLS_RESTORE_CURRENT_MAIN_SHA256=", "RESTORE TRUSTED SMTP",
            "ConfirmDestructive(", "GetIsolatedSidecarPortAsync(",
            "publicInternetRequested.Checked",
        ):
            self.assertIn(pattern, main)
        self.assertIn("BuildAuthTlsRestoreBundle", embed)
        self.assertIn("restore-sidecar-auth-tls.sh", project)
        self.assertRegex(embed, r"Regex\.IsMatch\(expectedMainSha")


if __name__ == "__main__":
    unittest.main()
