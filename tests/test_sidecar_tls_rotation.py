"""Private-sidecar TLS rotation contracts, Python 3.6 compatible."""
import subprocess
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"linux"/"rotate-sidecar-tls.sh"


class SidecarTlsRotationTests(unittest.TestCase):
    def run_cmd(self,*args):
        return subprocess.run(["bash",str(SCRIPT)]+list(args),
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              universal_newlines=True,timeout=8)

    def test_shell_syntax_and_self_test(self):
        lint=subprocess.run(["bash","-n",str(SCRIPT)],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            universal_newlines=True,timeout=8)
        self.assertEqual(lint.returncode,0,lint.stderr)
        self.assertEqual(self.run_cmd("--self-test").returncode,0)

    def test_arbitrary_port_and_canonical_paths(self):
        for port in ("25","1024","2525","2529","46500","65535"):
            with self.subTest(port=port):
                r=self.run_cmd("--check-only","--smtp-port",port,
                      "--server-name","smtp.example.org","--tls-cert","/tmp/newcert.pem",
                      "--tls-key","/tmp/newkey.pem")
                self.assertNotIn("invalid_custom_port",r.stderr)
                self.assertNotIn("TLS_ROTATE_APPLIED=yes",r.stdout)
        for bad in ("587","1023","65536","n/a"):
            with self.subTest(bad=bad):
                r=self.run_cmd("--check-only","--smtp-port",bad,
                      "--server-name","smtp.example.org","--tls-cert","/tmp/newcert.pem",
                      "--tls-key","/tmp/newkey.pem")
                self.assertIn("invalid_custom_port",r.stderr)

    def test_self_signed_cert_can_also_be_explicit_trust_anchor(self):
        args=("--check-only","--smtp-port","2529",
              "--server-name","smtp.example.org",
              "--tls-cert","/tmp/newcert.pem","--tls-key","/tmp/newkey.pem",
              "--ca-file","/tmp/newcert.pem")
        r=self.run_cmd(*args)
        self.assertNotIn("source_paths_must_differ",r.stderr)
        self.assertNotIn("TLS_ROTATE_APPLIED=yes",r.stdout)

    def test_apply_requires_fingerprint_and_confirmation(self):
        base=("--apply","--smtp-port","2529","--server-name","smtp.example.org",
              "--tls-cert","/tmp/newcert.pem","--tls-key","/tmp/newkey.pem")
        r=self.run_cmd(*base,"--confirm","ROTATE_PRIVATE_SMTP_TLS")
        self.assertIn("expected_sha256_required",r.stderr)
        r=self.run_cmd(*base,"--expect-cert-sha256","a"*64)
        self.assertIn("explicit_confirmation_required",r.stderr)

    def test_safety_constraints(self):
        s=SCRIPT.read_text(encoding="utf-8")
        for expected in ("TLS_ROTATE_PREFLIGHT=ready",
                         "TLS_ROTATE_ROLLBACK=attempted_original_cert_restored",
                         "TLS_ROTATE_ROLLBACK=MANUAL_RECOVERY_REQUIRED",
                         "ROTATE_PRIVATE_SMTP_TLS","flock -n 9",
                         "certificate_changed_since_preflight",
                         "PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes",
                         "verified_local_chain_dns_and_starttls",
                         "rhel_selinux_policy_unknown",
                         "MICROSOFT365_DELIVERY_VERIFIED=no"):
            self.assertIn(expected,s)
        for forbidden in ("systemctl restart postfix","systemctl stop postfix",
                          "setenforce 0","semanage port -a","ufw allow ",
                          "smtp.login(","sendmail(","New-InboundConnector"):
            self.assertNotIn(forbidden,s)

if __name__=="__main__":
    unittest.main()
