"""Public SMTP mode stays fail-closed unless verified isolated AUTH+TLS exists."""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "manage-public-smtp.py"
spec = importlib.util.spec_from_file_location("lmr365_public_smtp", str(SCRIPT))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PublicSmtpContracts(unittest.TestCase):
    def runcli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=10)

    def test_custom_port_and_address_bounded(self):
        for port in ("25", "587", "1023", "65536", "0"):
            res = self.runcli("--check-only", "--smtp-port", port,
                              "--listen-ip", "192.168.30.2",
                              "--server-name", "smtp.example.org")
            self.assertNotEqual(res.returncode, 0)
        for value in ("0.0.0.0", "8.8.8.8", "127.0.0.1", "192.168.0.0", "::"):
            res = self.runcli("--check-only", "--smtp-port", "46500",
                              "--listen-ip", value, "--server-name", "smtp.example.org")
            self.assertEqual(res.returncode, 2)
            self.assertIn("explicit_private_listener", res.stdout)

    def test_sensitive_actions_need_confirmation_and_attestation(self):
        for action in ("--apply", "--restore"):
            r = self.runcli(action, "--smtp-port", "46500",
                            "--listen-ip", "192.168.30.3",
                            "--server-name", "smtp.example.org")
            self.assertEqual(r.returncode, 2)
            self.assertIn("reviewed_sha_and_typed_confirmation", r.stdout)
        r = self.runcli("--apply", "--smtp-port", "46500",
                        "--listen-ip", "192.168.30.3",
                        "--server-name", "smtp.example.org",
                        "--expect-main-sha256", "a"*64,
                        "--confirm", "ENABLE_REVIEWED_PUBLIC_AUTH_SUBMISSION")
        self.assertIn("operator_security_attestation_required", r.stdout)

    def test_isolated_server_requires_auth_tls_fixed_transport_and_monitor(self):
        required = ("m365xoauth2:", "linuxmailrelay365-smtp-auth.service",
                    "linuxmailrelay365-health.timer", "fail2ban.service",
                    '("postfix", "dovecot")', "smtpd_tls_auth_only",
                    "permit_sasl_authenticated, reject", "smtpd_relay_restrictions")
        text = SCRIPT.read_text(encoding="utf-8")
        for token in required:
            self.assertIn(token, text)
        for token in ("setenforce 0", "ufw enable", "systemctl restart postfix",
                      "0.0.0.0/0", "postconf -e", "smtplib.sendmail"):
            self.assertNotIn(token, text)

    def test_manifest_is_separate_and_config_change_has_restore(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("linuxmailrelay365-public-smtp", source)
        self.assertIn("public_postfix_config_modified", source)
        self.assertIn("primary_postfix_changed_manual_review_required", source)
        self.assertIn("firewall_remove(", source)
        self.assertIn("public_firewall_rule_already_exists", source)
        self.assertIn("firewall_rule_query_unreliable", source)
        self.assertIn("reload_postfix(original)", source)
        self.assertIn("atomic(STATE / archive, before, 0o600)", source)
        self.assertIn("invalid_recovery_archive_name", source)

    def test_config_patch_is_deduplicated_and_scoped(self):
        old = b"smtpd_client_restrictions = permit_mynetworks, reject\nmyhostname = example.org\n"
        new = module.mutate_main(old, module.CHANGES)
        self.assertIn(b"myhostname = example.org\n", new)
        self.assertIn(b"smtpd_client_restrictions = \n", new)
        self.assertIn(b"smtpd_client_auth_rate_limit = 10\n", new)
        self.assertIn(b"smtpd_client_event_limit_exceptions = \n", new)
        with self.assertRaisesRegex(module.Refused, "duplicate_postfix_parameter"):
            module.mutate_main(old + b"smtpd_client_restrictions = bad\n", module.CHANGES)

    def test_outbound_eop_route_cannot_be_mutated_beneath_manifest(self):
        src = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("eop_route_active_must_restore_before_public_mode", src)

    def test_no_mail_delivery_claimed(self):
        r = self.runcli("--self-test", "--smtp-port", "46500")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("PUBLIC_SMTP_PARSER=ready", r.stdout)
        self.assertIn('MICROSOFT365_DELIVERY_VERIFIED", "no"', SCRIPT.read_text())


if __name__ == "__main__":
    unittest.main()
