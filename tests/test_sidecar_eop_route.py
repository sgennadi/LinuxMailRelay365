"""Unit contracts for private EOP Direct Send / Connector Postfix routing.

Python 3.6 compatible. No actual Microsoft 365 send occurs. Live Postfix
RCPT rejection and sidecar restore are separately covered by Ubuntu smoke.
"""
import io
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "manage-sidecar-eop-route.py"
spec = importlib.util.spec_from_file_location("lmr365_eop_route", str(SCRIPT))
eop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eop)


def opts(mode="direct-send", port=46500, sender="alerts@example.org",
         recipients=None, public_ip="", cert="", key="", apply=False,
         restore=False, status=False, expected="", confirm="", attestation=""):
    return SimpleNamespace(
        check_only=not apply and not restore and not status, apply=apply, restore=restore,
        status=status,
        smtp_port=port, mode=mode, mx_host="example-org.mail.protection.outlook.com",
        sender=sender, recipient_domain=recipients if recipients is not None else ["example.org"],
        public_ip=public_ip, tls_cert=cert, tls_key=key,
        expect_main_sha256=expected, expect_owner_sha256="", confirm=confirm,
        connector_attestation=attestation,
        sender_policy="fixed-mailbox", sender_owner_file="")


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

    def test_connector_sender_policy_is_explicit_and_domain_scoped(self):
        a = opts(mode="connector", public_ip="8.8.8.8")
        a.sender_policy = "preserve-domain"
        with self.assertRaisesRegex(eop.Refused, "connector_sender_ownership_file_required"):
            eop.validate(a)
        a.sender_owner_file = "/root/reviewed-owners.txt"
        eop.validate(a)
        sender, canonical, _ = eop.policy_maps(a)
        self.assertIn("example[.]org", sender)
        self.assertNotIn("A-Za-z0-9-", sender)
        self.assertTrue(canonical.startswith("# Preserve"))
        policy = eop.policy_changes(a, "/etc/ssl/testca.pem", True)
        self.assertEqual(policy["sender_canonical_maps"], "")
        self.assertIn("reject_authenticated_sender_login_mismatch", policy["smtpd_sender_restrictions"])
        self.assertIn("eop-sender-owners.regexp", policy["smtpd_sender_login_maps"])
        apply_args = opts(mode="connector", public_ip="8.8.8.8", apply=True,
                          expected="a"*64, confirm="DEPLOY_PRIVATE_EOP_ROUTE",
                          attestation="TENANT_CONNECTOR_CHECKED")
        apply_args.sender_policy = "preserve-domain"
        apply_args.sender_owner_file = "/root/owners.txt"
        with self.assertRaisesRegex(eop.Refused, "reviewed_sender_owner_sha256_required"):
            eop.validate(apply_args)
        apply_args.expect_owner_sha256 = "c"*64
        eop.validate(apply_args)
        a.sender_policy = "masquerade"
        eop.validate(a)
        sender, canonical, _ = eop.policy_maps(a)
        self.assertIn("A-Za-z0-9-", sender)
        self.assertIn("\${1}@example.org".replace("\\", ""), canonical)
        self.assertEqual(
            eop.policy_changes(a, "/etc/ssl/testca.pem", True)["sender_canonical_classes"],
            "envelope_sender, header_sender")
        a.mode = "direct-send"
        a.public_ip = ""
        a.sender_owner_file = ""
        with self.assertRaisesRegex(eop.Refused, "direct_send_requires_fixed_sender"):
            eop.validate(a)
        a.sender_policy = "unknown"
        with self.assertRaisesRegex(eop.Refused, "invalid_sender_policy"):
            eop.validate(a)

    def test_sender_owner_map_validates_active_login_and_domain(self):
        import tempfile
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "owners"
            passwd = Path(folder) / "passwd"
            source.write_text("alice@example.org smtp-app01\n")
            passwd.write_text("smtp-app01:{SHA512-CRYPT}fake\n")
            args = opts(mode="connector", public_ip="8.8.8.8")
            args.sender_policy = "preserve-domain"
            args.sender_owner_file = str(source)
            fake_st = SimpleNamespace(st_mode=0o100600, st_size=500, st_uid=0)
            with patch.object(eop, "AUTH_USERS", passwd), \
                 patch.object(eop, "owned_file", return_value=fake_st), \
                 patch.object(eop, "postconf",
                    side_effect=lambda key: "encrypt" if key == "smtpd_tls_security_level" else "yes"), \
                 patch.object(eop, "run", return_value=SimpleNamespace(returncode=0)):
                rules = eop.sender_owner_map(args)
                self.assertIn("/^alice@example[.]org$/ smtp-app01", rules)
                source.write_text("alice@other.example smtp-app01\n")
                with self.assertRaisesRegex(eop.Refused, "outside_accepted_domain"):
                    eop.sender_owner_map(args)
                source.write_text("alice@example.org other-login\n")
                with self.assertRaisesRegex(eop.Refused, "not_active_smtp_account"):
                    eop.sender_owner_map(args)

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

    def test_read_only_status_has_no_route_configuration_arguments(self):
        args = opts(mode=None, sender="", recipients=[], status=True)
        args.mx_host = ""
        eop.validate(args)
        self.assertEqual(args.check_only, False)
        self.assertTrue(args.status)
        self.assertIn("--status", SCRIPT.read_text(encoding="utf-8"))
        self.assertIn("EOP_ROUTE_CURRENT_MAIN_SHA256", SCRIPT.read_text(encoding="utf-8"))

    def test_wizard_has_explicit_preview_apply_restore_and_root_only_asset(self):
        embedded = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text(encoding="utf-8")
        project = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        ui = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        self.assertIn("BuildEopRouteBundle", embedded)
        self.assertIn("--sender-policy", embedded)
        self.assertIn("sender-owner-file", SCRIPT.read_text(encoding="utf-8"))
        self.assertIn("expectedOwnerSha: senderOwnerSha", ui)
        self.assertIn("reject_authenticated_sender_login_mismatch", SCRIPT.read_text(encoding="utf-8"))
        self.assertIn("senderPolicy: opt.SenderPolicy", ui)
        self.assertIn("preserve-domain", ui)
        self.assertIn("manage-sidecar-eop-route.py", project)
        self.assertIn("PreviewEopRouteAsync", ui)
        self.assertIn("ApplyEopRouteAsync", ui)
        self.assertIn("RestoreEopRouteAsync", ui)
        self.assertIn("acceptedDomainApproved", ui)
        self.assertIn("connectorApproved", ui)
        self.assertIn("EOP_TLS_CONNECTIVITY=tls_12_plus_hostname_verified", ui)
        self.assertIn("DEPLOY PRIVATE EOP ROUTE", ui)

    def test_refuse_pending_queue_before_changing_or_restoring_route(self):
        class FakePostqueue:
            def __init__(self, lines):
                self.stdout = io.StringIO(lines)
            def poll(self):
                return 0
            def wait(self, timeout=None):
                return 0
            def kill(self):
                pass

        for output, blocked in (("", False),
                                ('{"queue_name":"deferred","sender":"redacted"}\\n', True)):
            with self.subTest(blocked=blocked), \
                 patch.object(eop.shutil, "which", return_value="/usr/sbin/postqueue"), \
                 patch.object(eop.subprocess, "Popen", return_value=FakePostqueue(output)), \
                 patch("select.select", side_effect=lambda rd, wr, ex, t: (rd, [], [])):
                if blocked:
                    with self.assertRaisesRegex(eop.Refused, "sidecar_queue_not_empty"):
                        eop.require_empty_sidecar_queue()
                else:
                    eop.require_empty_sidecar_queue()

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
