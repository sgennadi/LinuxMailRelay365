"""Fresh Direct Send isolated Postfix safety contracts. Python 3.6 friendly."""
import subprocess
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"linux"/"install-direct-send-sidecar.sh"


class StandaloneDirectSendTests(unittest.TestCase):
    def cli(self,*args):
        return subprocess.run(["bash",str(SCRIPT)]+list(args),
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              universal_newlines=True,timeout=8)

    def valid(self,port="46500"):
        return ["--check-only","--smtp-port",port,
                "--mx-host","example-org.mail.protection.outlook.com",
                "--accepted-domain","example.org",
                "--fixed-sender","alerts@example.org"]

    def test_fresh_direct_send_detected_without_oauth_identity(self):
        source = (ROOT / "src/LinuxMailRelay365/SshRemote.cs").read_text(encoding="utf-8")
        body = source.split("internal static async Task<bool> HasIsolatedSidecarAsync(", 1)[1].split(
            "internal static async Task<int> GetIsolatedSidecarPortAsync", 1)[0]
        self.assertIn('"/smtp-port"', body)
        self.assertNotIn("SidecarIdentity", body)

    def test_bash_syntax_and_selftest(self):
        proc=subprocess.run(["bash","-n",str(SCRIPT)],stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,universal_newlines=True,timeout=8)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertEqual(self.cli("--self-test").returncode,0)

    def test_private_custom_port_range(self):
        for port in ("1024","2525","2529","46500","65535"):
            with self.subTest(port=port):
                result=self.cli(*self.valid(port))
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn("CHANGES_APPLIED=no",result.stdout)
                self.assertIn("DIRECT_SEND_CUSTOM_PORT="+port,result.stdout)
        for port in ("25","587","1023","65536","oops"):
            with self.subTest(port=port):
                self.assertIn("invalid_custom_port",self.cli(*self.valid(port)).stderr)

    def test_public_listener_or_trusted_network_refusal(self):
        for address in ("0.0.0.0","8.8.8.8","203.0.113.10","127.0.0.1"):
            result=self.cli(*(self.valid()+["--listen-ip",address,
                                    "--trusted-network","10.0.0.0/8"]))
            self.assertNotEqual(result.returncode,0,address)
        args=self.valid()+["--listen-ip","192.168.5.10",
                           "--trusted-network","0.0.0.0/0"]
        self.assertNotEqual(self.cli(*args).returncode,0)
        args=self.valid()+["--listen-ip","192.168.5.10",
                           "--trusted-network","192.168.5.0/24"]
        self.assertEqual(self.cli(*args).returncode,0)

    def test_reject_bad_domain_sender_and_mx(self):
        for modified in (
            ["--mx-host","evil.example.org"],
            ["--accepted-domain","gmail.com"],
            ["--fixed-sender","spoof@elsewhere.example"],
        ):
            src=self.valid()
            src[src.index(modified[0])+1]=modified[1]
            with self.subTest(args=modified):
                result=self.cli(*src)
                self.assertNotEqual(result.returncode,0)

    def test_apply_needs_confirmation_without_touching_linux(self):
        args=self.valid()
        args[0]="--apply"
        result=self.cli(*args)
        self.assertIn("tenant_domain_confirmation_required",result.stderr)

    def test_exact_fixed_sender_map_does_not_allow_other_local_parts(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("':^{}$: OK", source)
        self.assertIn("special=r'\.^$*+?{}[]()|'", source)
        self.assertIn("literal=''.join", source)
        fixed_map = source.split("(root/'eop-fixed-sender.regexp').write_text(", 1)[1].split(
            "(root/'eop-sender-canonical.regexp').write_text(", 1)[0]
        self.assertNotIn("'/^[^@[:space:]]+@{}$/ OK", fixed_map)

    def test_canonical_map_escapes_dollar_substitutions(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("sender.replace('$','$$')", source)

    def test_direct_send_safety(self):
        src=SCRIPT.read_text(encoding="utf-8")
        for required in (
            "smtpd_recipient_restrictions = check_recipient_access",
            "smtpd_relay_restrictions = permit_mynetworks, reject",
            "smtpd_sender_restrictions = check_sender_access",
            "sender_canonical_classes = envelope_sender, header_sender",
            "local_header_rewrite_clients = static:all",
            "smtp_tls_security_level = secure",
            "smtp_tls_secure_cert_match = nexthop",
            "default_transport = smtp:",
            "mydestination =",
            "relay_domains =",
            "MICROSOFT365_DELIVERY_VERIFIED=no",
            "PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes",
            "selinux_enforcing_not_integration_verified",
            "TENANT_DOMAIN_CHECKED",
            "DIRECT_SEND_ROLLBACK=attempted_isolated_only",
        ):
            self.assertIn(required,src)
        for forbidden in (
            "smtp.office365.com:587", "m365xoauth2", "sudo postfix",
            "postconf -e ", "setenforce 0", "ufw allow ",
            "New-InboundConnector", "sendmail(", "smtp.login("
        ):
            self.assertNotIn(forbidden,src)

if __name__=="__main__":
    unittest.main()
