"""Unit contracts for private EOP Direct Send / Connector Postfix routing.

Python 3.6 compatible. No actual Microsoft 365 send occurs. Live Postfix
RCPT rejection and sidecar restore are separately covered by Ubuntu smoke.
"""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "manage-sidecar-eop-route.py"
spec = importlib.util.spec_from_file_location("lmr365_eop_route", str(SCRIPT))
eop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eop)


def opts(mode="direct-send", port=46500, sender="alerts@example.org",
         recipients=None, public_ip="", cert="", key="", apply=False,
         restore=False, expected="", confirm="", attestation=""):
    return SimpleNamespace(
        check_only=not apply and not restore, apply=apply, restore=restore,
        smtp_port=port, mode=mode, mx_host="example-org.mail.protection.outlook.com",
        sender=sender, recipient_domain=recipients or ["example.org"],
        public_ip=public_ip, tls_cert=cert, tls_key=key,
        expect_main_sha256=expected, confirm=confirm,
        connector_attestation=attestation)


class EopRouteContracts(unittest.TestCase):
    def test_direct_send_enforces_internal_recipient_domain(self):
        args = opts()
        eop.validate(args)
        sender, canonical, rcpt = eop.policy_maps(args)
        self.assertIn("example[.]org", sender)
        self.assertIn("alerts@example.org", canonical)
        self.assertIn("example[.]org", rcpt)
        self.assertNotIn("gmail", rcpt)
        changes = eop.policy_changes(args, "/etc/ssl/certs/ca-certificates.crt", False)
        self.assertEqual(changes["smtpd_relay_restrictions"], "permit_mynetworks, reject")
        self.assertIn("check_recipient_access regexp:", changes["smtpd_recipient_restrictions"])
        self.assertTrue(changes["smtpd_recipient_restrictions"].endswith(", reject"))
        self.assertEqual(changes["smtp_tls_security_level"], "secure")
        self.assertEqual(changes["smtp_tls_secure_cert_match"], "nexthop")
        self.assertEqual(changes["relayhost"], "[example-org.mail.protection.outlook.com]:25")

    def test_authenticated_clients_keep_auth_required(self):
        changes = eop.policy_changes(opts(), "/etc/ssl/certs/ca-certificates.crt", True)
        self.assertEqual(changes["smtpd_relay_restrictions"],
                         "permit_sasl_authenticated, reject")
        self.assertNotIn("permit_mynetworks", changes["smtpd_relay_restrictions"])

    def test_connector_external_rcpt_requires_explicit_attestation(self):
        args = opts(mode="connector", public_ip="8.8.8.8", apply=True,
                    expected="a"*64, confirm="DEPLOY_PRIVATE_EOP_ROUTE")
        with self.assertRaisesRegex(eop.Refused, "operator_must_confirm"):
            eop.validate(args)
        args.connector_attestation = "TENANT_CONNECTOR_CHECKED"
        eop.validate(args)
        self.assertIn("[^@[:space:]]+", eop.policy_maps(args)[2])
        self.assertEqual(eop.policy_changes(args, "/etc/ssl/testca.pem", True)
                         ["smtp_tls_security_level"], "secure")

    def test_public_inbound_and_unverified_rhel_never_implicitly_allowed(self):
        for bad in ("0.0.0.0", "192.168.5.1", "127.0.0.1", "10.0.0.1"):
            with self.subTest(ip=bad):
                with self.assertRaises(eop.Refused):
                    eop.validate(opts(mode="connector", public_ip=bad))
        for port in (25, 587, 1023, 65536):
            with self.subTest(port=port):
                with self.assertRaisesRegex(eop.Refused, "invalid_custom_port"):
                    eop.validate(opts(port=port))
        with self.assertRaises(eop.Refused):
            eop.validate(opts(sender="bad@evil.example"))
        with self.assertRaises(eop.Refused):
            eop.validate(opts(recipients=["example.org", "example.org"]))
        with self.assertRaises(eop.Refused):
            eop.validate(opts(mode="direct-send", cert="/tmp/cert.pem"))
        with self.assertRaises(eop.Refused):
            eop.validate(opts(mode="connector", public_ip=""))

    def test_postfix_policy_render_and_duplicate_refusal(self):
        original = b"default_transport = m365xoauth2:\nrelay_transport = m365xoauth2:\nmyhostname = node.example.org\n"
        args = opts()
        updates = eop.policy_changes(args, "/etc/ssl/certs/ca-certificates.crt", False)
        changed = eop.rewrite_main(original, updates)
        self.assertIn(b"myhostname = node.example.org", changed)
        self.assertIn(b"default_transport = smtp:[example-org.mail.protection.outlook.com]:25", changed)
        self.assertNotIn(b"m365xoauth2:", changed)
        self.assertIn(b"smtpd_relay_restrictions = permit_mynetworks, reject", changed)
        self.assertIn(b"sender_canonical_classes = envelope_sender, header_sender", changed)
        with self.assertRaisesRegex(eop.Refused, "duplicate_configuration_key"):
            eop.rewrite_main(original + b"relay_transport = bad:\n", updates)
        master = b"2529 inet n - n - - smtpd\nm365xoauth2 unix - n n - 2 pipe\n"
        self.assertIn(b"smtp unix - - n - 5 smtp", eop.rewrite_master(master))
        with self.assertRaisesRegex(eop.Refused, "unexpected_existing_smtp_transport"):
            eop.rewrite_master(master + b"smtp unix - - n - - smtp\n")

    def test_explicit_sha_and_typed_confirmation_for_apply_and_restore(self):
        a = opts(apply=True)
        with self.assertRaisesRegex(eop.Refused, "reviewed_sha256_required"):
            eop.validate(a)
        a.expect_main_sha256 = "b"*64
        with self.assertRaisesRegex(eop.Refused, "typed_confirmation_required"):
            eop.validate(a)
        b = opts(restore=True, mode=None, recipients=[], sender="")
        b.mx_host = ""
        with self.assertRaises(eop.Refused):
            eop.validate(b)
        b.expect_main_sha256 = "b"*64
        b.confirm = "RESTORE_PRIVATE_EOP_ROUTE"
        eop.validate(b)

    def test_cli_invalid_port_and_no_credentials_or_mail_submission(self):
        for port in ("25", "587", "1023", "65536", "0"):
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--check-only", "--smtp-port", port,
                 "--mode", "direct-send",
                 "--mx-host", "example-org.mail.protection.outlook.com",
                 "--sender", "alerts@example.org", "--recipient-domain", "example.org"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=8)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("EOP_ROUTE_RESULT=refused", proc.stdout)
        src = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("setenforce 0", "ufw allow", "sendmail(", "smtp.login(",
                          "systemctl restart postfix", "New-InboundConnector",
                          "/etc/postfix/main.cf", "smtpd_relay_restrictions = permit"):
            self.assertNotIn(forbidden, src)
        for required in ("active.json", "EOP_ROUTE_PREFLIGHT",
                         "EOP_ROUTE_ROLLBACK", "EOP_ROUTE_RESTORED",
                         "MICROSOFT365_DELIVERY_VERIFIED", "check_recipient_access",
                         "smtpd_client_restrictions", "smtp_tls_secure_cert_match"):
            self.assertIn(required, src)


if __name__ == "__main__":
    unittest.main()
