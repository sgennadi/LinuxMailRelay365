"""RHEL SELinux Enforcing live SMTP acceptance must never submit mail."""
import importlib.util
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "rhel-enforcing-live-smoke.py"
spec = importlib.util.spec_from_file_location("lmr_enforcing_smoke", str(SCRIPT))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class EnforcingProbeContracts(unittest.TestCase):
    def test_port_policy_parser_requires_exact_smtp_port_type(self):
        mapping = "smtp_port_t    tcp    25, 465, 2525, 10000-10100\n" \
                  "http_port_t    tcp    80, 443\n"
        self.assertEqual(smoke.port_type(2525, mapping), "smtp_port_t")
        self.assertEqual(smoke.port_type(10050, mapping), "smtp_port_t")
        self.assertEqual(smoke.port_type(80, mapping), "other_or_unmapped")
        self.assertEqual(smoke.port_type(2526, mapping), "other_or_unmapped")
        self.assertEqual(smoke.port_type(2525, mapping+"http_port_t tcp 2525\n"),
                         "other_or_unmapped")

    def test_selftest_on_older_python_and_invalid_ports(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=8)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for port in ("25", "0", "65536", "no"):
            with self.subTest(port=port):
                p = subprocess.run([sys.executable, str(SCRIPT), "--smtp-port", port,
                                    "--server-name", "smtp.example.org"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, timeout=8)
                self.assertNotEqual(p.returncode, 0)

    def test_no_smtp_mail_from_rcpt_or_data(self):
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('socket.create_connection(("127.0.0.1", port)', script)
        self.assertIn('server_hostname=hostname', script)
        self.assertIn('smtp_auth_exposed_before_tls', script)
        self.assertIn('smtp_auth_not_advertised_after_tls', script)
        self.assertIn('SMTP_MAIL_FROM_RCPT_DATA_SENT", "no"', script)
        self.assertIn('"TLSv1.2", "TLSv1.3"', script)
        for prohibited in ("smtplib.SMTP.sendmail", "mail from:", "rcpt to:",
                           "b'DATA", 'b"DATA', "setenforce 0",
                           "semanage port -a", "restorecon -R", "systemctl restart"):
            self.assertNotIn(prohibited.lower(), script.lower())

    def test_status_disclosure_and_fail_closed(self):
        with patch.object(smoke, "os_mode", side_effect=smoke.Refused("enforcing_required")):
            with self.assertRaisesRegex(smoke.Refused, "enforcing_required"):
                smoke.run(46500, "smtp.example.org", None)


if __name__ == "__main__":
    unittest.main()
