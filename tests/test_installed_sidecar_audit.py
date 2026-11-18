"""Read-only installed sidecar security audit: custom port, TLS and SELinux.

Runs with Python 3.6+ (including system Python in RHEL/Oracle Linux 8).
No real credentials, mail submission, firewall or SELinux changes.
"""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "installed-sidecar-audit.py"
spec = importlib.util.spec_from_file_location("lmr365_installed_audit", str(SCRIPT))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class InstalledSidecarAuditUnitTests(unittest.TestCase):
    def test_reject_invalid_custom_port_early(self):
        for port in ("0", "25", "587", "1023", "65536", "not-a-port"):
            with self.subTest(port=port):
                p = subprocess.run([sys.executable, str(SCRIPT), "--smtp-port", port],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, timeout=8)
                self.assertNotEqual(p.returncode, 0)

    def test_read_only_cli_without_sidecar(self):
        p = subprocess.run([sys.executable, str(SCRIPT), "--smtp-port", "46500",
                            "--no-live-probe"], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=8)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("CUSTOM_SMTP_PORT=46500", p.stdout)
        self.assertIn("CHANGES_APPLIED=no", p.stdout)
        self.assertIn("MICROSOFT365_DELIVERY_VERIFIED=no", p.stdout)
        self.assertIn("PUBLIC_INTERNET_ACCESS_VERIFIED=no", p.stdout)
        self.assertNotIn("AUTH_TLS_APPLIED=yes", p.stdout)

    def test_private_ranges_and_wildcards(self):
        self.assertEqual(audit.private_listener("127.0.0.1, 10.20.30.40"),
                         "private_ipv4")
        self.assertEqual(audit.private_listener("127.0.0.1"),
                         "loopback_only")
        for unsafe in ("0.0.0.0", "127.0.0.1, 8.8.8.8",
                       "127.0.0.1, ::1", "all", "127.0.0.1, 192.0.2.40"):
            self.assertEqual(audit.private_listener(unsafe), "unsafe")

    def test_trusted_subnets_python36_compatible(self):
        self.assertEqual(
            audit.trusted_networks("127.0.0.0/8, 10.20.0.0/16"),
            "private_only")
        self.assertEqual(
            audit.trusted_networks("127.0.0.0/8 192.168.20.0/24"),
            "private_only")
        for unsafe in ("0.0.0.0/0", "8.8.8.0/24",
                       "10.0.0.0/7", "192.168.0.0/15",
                       "127.0.0.0/7", "::/0", "all"):
            self.assertEqual(audit.trusted_networks(unsafe), "unsafe")

    def test_selinux_port_type_checks_requested_custom_port(self):
        data = ("smtp_port_t tcp 25, 587, 465, 2525-2527\n"
                "http_port_t tcp 80, 8080, 8443\n")
        self.assertEqual(audit.selinux_port_type(data, 2526), "smtp_port_t")
        self.assertEqual(audit.selinux_port_type(data, 2529), "unmapped")
        self.assertEqual(audit.selinux_port_type(data, 8443), "conflicting_type")
        self.assertEqual(audit.selinux_port_type(None, 46500), "unverified")

    def test_no_credentials_and_no_mutations_in_audit_source(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for banned in ("smtp.login(", "sendmail(", ".send_message(", ".sendmail(",
                       "semanage port -a", "setenforce 0", "systemctl restart ",
                       "postconf -e ", "ufw allow "):
            self.assertNotIn(banned, text)
        self.assertIn("ssl._create_unverified_context()", text)
        self.assertIn("TLS_CLIENT_CERT_TRUST", text)
        self.assertIn("not_verified", text)
        embedded = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text()
        gui = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text()
        project = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text()
        self.assertIn("BuildInstalledSidecarAuditBundle", embedded)
        self.assertIn("installed-sidecar-audit.py", project)
        self.assertIn("AuditInstalledPrivateSmtpAsync", gui)
        self.assertIn("GetIsolatedSidecarPortAsync", gui)

    def test_selinux_file_labels_are_hints_not_authorization(self):
        label = b"system_u:object_r:postfix_spool_t:s0\x00"
        with patch.object(audit.os, "getxattr", return_value=label):
            self.assertEqual(
                audit.selinux_file_label_hints(auth_enabled=True),
                "labels_present_requires_policy_review")
        with patch.object(audit.os, "getxattr",
                          return_value=b"system_u:object_r:default_t:s0"):
            self.assertEqual(
                audit.selinux_file_label_hints(auth_enabled=False),
                "unlabeled_or_default_type")
        with patch.object(audit.os, "getxattr", side_effect=FileNotFoundError):
            self.assertEqual(
                audit.selinux_file_label_hints(auth_enabled=True), "missing_files")

    def test_unauthorized_relay_policy_never_gets_green(self):
        values = {
            "inet_interfaces": "127.0.0.1, 192.168.10.7",
            "mynetworks": "127.0.0.0/8, 192.168.10.0/24",
            "smtpd_client_restrictions": "permit_mynetworks, reject",
            "smtpd_relay_restrictions": "permit_sasl_authenticated, reject",
            "smtpd_recipient_restrictions": "permit_sasl_authenticated, reject",
            "smtpd_tls_security_level": "encrypt",
            "smtpd_sasl_auth_enable": "yes",
            "smtpd_tls_auth_only": "yes",
            "smtpd_sasl_type": "dovecot",
            "smtpd_sasl_path": "private/auth",
        }
        for unsafe_key, unsafe_value in [
            ("smtpd_relay_restrictions", "permit_mynetworks, permit"),
            ("smtpd_client_restrictions", "permit"),
            ("smtpd_tls_security_level", "may"),
            ("smtpd_tls_auth_only", "no")
        ]:
            with self.subTest(setting=unsafe_key):
                config = dict(values)
                config[unsafe_key] = unsafe_value
                with patch.object(audit, "postconf", side_effect=lambda k: config.get(k)), \
                     patch.object(audit, "run", return_value="active"), \
                     patch.object(audit, "port_configuration", return_value="matched"), \
                     patch.object(audit, "auth_file_status", return_value="restricted"), \
                     patch.object(audit, "auth_socket_status", return_value="present"), \
                     patch.object(audit, "smtp_handshake", return_value=dict(
                         SMTP_EHLO="responding", SMTP_STARTTLS="offered",
                         SMTP_AUTH_BEFORE_TLS="no", SMTP_AUTH_AFTER_TLS="yes")), \
                     patch.object(Path, "is_file", return_value=True), \
                     patch.object(Path, "exists", return_value=False), \
                     patch.object(Path, "read_text", return_value='ID=ubuntu\n'):
                    result = audit.audit(2526)
                self.assertNotEqual(result["SMTP_SECURITY_RESULT"],
                                    "local_auth_tls_verified_external_unverified")


if __name__ == "__main__":
    unittest.main()
