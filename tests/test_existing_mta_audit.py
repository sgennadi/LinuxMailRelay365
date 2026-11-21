"""Existing MTA public SMTP audit stays read-only and identifies active services.

No SMTP transaction, credentials, messages or tenant interaction are performed.
This module runs with Python 3.6+ on RHEL-compatible hosts.
"""
import importlib.util
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "audit-existing-smtp.py"
spec = importlib.util.spec_from_file_location("lmr365_existing_mta", str(SCRIPT))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class ActiveMtaAuditTests(unittest.TestCase):
    @staticmethod
    def choose(*active, postfix_cli=True):
        running = set(active)
        return audit.detect_mta(
            unit_runner=lambda name: name in running,
            finder=lambda name: "/usr/sbin/postconf" if postfix_cli and name == "postconf" else None)

    def test_exim_active_is_not_masked_by_installed_postfix_cli(self):
        self.assertEqual(self.choose("exim4.service"), "exim_manual_review")
        self.assertEqual(self.choose("exim.service"), "exim_manual_review")

    def test_sendmail_active_is_not_masked_by_installed_postfix_cli(self):
        self.assertEqual(self.choose("sendmail.service"), "sendmail_manual_review")

    def test_primary_postfix_requires_active_service_and_cli(self):
        self.assertEqual(self.choose("postfix.service"), "postfix")
        self.assertEqual(self.choose("postfix.service", postfix_cli=False),
                         "postfix_cli_missing_manual_review")
        self.assertEqual(self.choose(), "no_active_mta_verified")

    def test_multiple_mta_and_unknown_service_state_fail_closed(self):
        self.assertEqual(self.choose("postfix.service", "exim4.service"),
                         "multiple_active_mta_manual_review")
        self.assertEqual(self.choose("sendmail.service", "exim.service"),
                         "multiple_active_mta_manual_review")
        self.assertEqual(audit.detect_mta(
            unit_runner=lambda name: None if name == "sendmail.service" else False),
            "mta_service_state_unverified_manual_review")

    def test_standard_smtp_ports_are_socket_only_not_owner_evidence(self):
        cases = (
            (None, "unknown"),
            ([], "no_standard_smtp_listeners_observed"),
            ([("0.0.0.0", 25)], "potentially_public_unattributed"),
            ([("::", 587)], "potentially_public_unattributed"),
            ([("192.168.40.2", 465)], "private_or_other_unattributed"),
            ([("127.0.0.1", 25)], "loopback_only_unattributed"),
            ([("0.0.0.0", 443)], "no_standard_smtp_listeners_observed"),
        )
        for sockets, expected in cases:
            with self.subTest(sockets=sockets):
                self.assertEqual(audit.observed_smtp_ports(sockets), expected)
                result = audit.analyze(
                    None, None, {}, sockets, mta="exim_manual_review")
                self.assertEqual(result["SMTP_STANDARD_PORT_SOCKETS"], expected)
                self.assertEqual(result["SMTP_PUBLIC_BIND"], "unknown")
                self.assertEqual(result["SMTP_OPEN_RELAY_PROVEN"],
                                 "no_active_probe_performed")

    def test_systemctl_command_status_not_assumed_on_errors(self):
        with patch.object(audit.shutil, "which", return_value="/bin/systemctl"):
            with patch.object(audit.subprocess, "run",
                              return_value=Mock(returncode=0, stdout="active\n")):
                self.assertTrue(audit.unit_active("postfix.service"))
            with patch.object(audit.subprocess, "run",
                              return_value=Mock(returncode=3, stdout="inactive\n")):
                self.assertFalse(audit.unit_active("postfix.service"))
            with patch.object(audit.subprocess, "run",
                              return_value=Mock(returncode=1, stdout="not-known\n")):
                self.assertIsNone(audit.unit_active("postfix.service"))
        with patch.object(audit.shutil, "which", return_value=None):
            self.assertIsNone(audit.unit_active("postfix.service"))

    def test_cli_self_test_and_no_mta_mutations(self):
        res = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=10)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("SMTP_AUDIT_SELFTEST=pass", res.stdout)
        src = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("systemctl stop ", "systemctl restart ", "postconf -e",
                          "setenforce 0", "sendmail(", "smtp.login(",
                          "smtplib.sendmail", "apt-get install", "dnf install"):
            self.assertNotIn(forbidden, src)


if __name__ == "__main__":
    unittest.main()
