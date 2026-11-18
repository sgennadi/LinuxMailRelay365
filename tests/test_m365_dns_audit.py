"""Read-only DNS record assessment; do not expose TXT or tenant identifiers."""
import importlib.util
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "audit-m365-dns.py"
spec = importlib.util.spec_from_file_location("lmr_dns", str(SCRIPT))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class DnsEvidenceContracts(unittest.TestCase):
    def test_spf_dmarc_and_exact_eop_mx(self):
        entries = {
            ("example.org", "MX"): ["0 example-org.mail.protection.outlook.com."],
            ("example.org", "TXT"): [
                '"v=spf1 include:spf.protection.outlook.com -all"',
                '"public-token=not-to-leak"'],
            ("_dmarc.example.org", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:private@example.org"'],
            ("selector1._domainkey.example.org", "CNAME"): [
                "selector1-example-org._domainkey.example.onmicrosoft.com."],
            ("selector2._domainkey.example.org", "CNAME"): []
        }
        result = audit.evaluate("example.org", "example-org.mail.protection.outlook.com",
                                resolver=lambda q, t: entries[(q, t)])
        self.assertEqual(result["DNS_MX"], "microsoft365_candidate")
        self.assertEqual(result["DNS_SELECTED_EOP_MX"], "public_mx_matches_selection")
        self.assertEqual(result["DNS_SPF"], "m365_include_present")
        self.assertEqual(result["DNS_DMARC"], "reject")
        self.assertEqual(result["DNS_DKIM_SELECTOR2"], "not_found")
        text = str(result)
        for secret in ("private@example.org", "public-token", "selector1-example"):
            self.assertNotIn(secret, text)
        self.assertEqual(result["M365_ACCEPTED_DOMAIN_VERIFIED"], "no")
        self.assertEqual(result["MICROSOFT365_DELIVERY_VERIFIED"], "no")

    def test_missing_multiple_and_unavailable_records(self):
        result = audit.evaluate("example.org", resolver=lambda q, t: None)
        self.assertEqual(result["DNS_EVIDENCE"], "partial_no_dns_records_changed")
        result = audit.evaluate("example.org", resolver=lambda q, t:
                                ['"v=spf1 -all"', '"v=spf1 ~all"'] if t == "TXT" and q == "example.org"
                                else [])
        self.assertEqual(result["DNS_SPF"], "multiple_spf_records_invalid")

    def test_domain_validation_and_no_shell_injection(self):
        for d in ("example.org;cat /etc/passwd", "example..org", "-bad.example.org", "a", "xn--"):
            proc = subprocess.run([sys.executable, str(SCRIPT), "--domain", d],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True, timeout=5)
            self.assertNotEqual(proc.returncode, 0, d)
        src = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", src)
        self.assertNotIn("subprocess.Popen('", src)
        self.assertNotIn("nsupdate", src)
        self.assertIn("CHANGES_APPLIED", src)
        self.assertEqual(subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=5).returncode, 0)


if __name__ == "__main__":
    unittest.main()
