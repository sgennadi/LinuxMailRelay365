"""RC12 protects Postfix routing inventory and UI as strictly read-only.

These Linux-running contracts complement the real Windows C# SelfTest.
No test asserts that map lookups or SMTP delivery were performed.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src" / "LinuxMailRelay365"
LINUX = ROOT / "linux" / "inspect-mail-host.py"


class PostfixRoutePolicyContractTests(unittest.TestCase):
    def test_linux_probe_only_queries_effective_parameter_status(self):
        source = LINUX.read_text(encoding="utf-8")
        expected = (
            "transport_maps", "relayhost",
            "sender_dependent_relayhost_maps",
            "sender_dependent_default_transport_maps",
            "smtp_sasl_password_maps",
            "smtp_sender_dependent_authentication",
            "smtp_sasl_auth_enable",
            "smtp_tls_policy_maps",
        )
        for name in expected:
            with self.subTest(key=name):
                self.assertIn('"' + name + '"', source)
        self.assertIn('runner(["postconf", "-h", key])', source)
        self.assertIn('postfix_role_state(key, raw)', source)
        self.assertIn('"declared"', source)
        self.assertIn('"not_declared"', source)
        self.assertIn('"unverified"', source)
        self.assertNotIn('runner(["postmap"', source)
        self.assertNotIn('postconf -e', source)

    def test_parser_accepts_only_known_declaration_statuses(self):
        source = (CS / "MailHostInspection.cs").read_text(encoding="utf-8")
        for name in (
            "RELAYHOST", "SENDER_DEPENDENT_DEFAULT_TRANSPORT_MAPS",
            "SMTP_SASL_PASSWORD_MAPS", "SMTP_SENDER_DEPENDENT_AUTHENTICATION",
            "SMTP_SASL_AUTH_ENABLE", "SMTP_TLS_POLICY_MAPS",
        ):
            with self.subTest(name=name):
                self.assertIn('"' + name + '"', source)
        self.assertIn('"declared" or "not_declared" or "unverified"', source)

    def test_policy_advisor_fails_closed_and_flags_conflicts(self):
        source = (CS / "PostfixRoutePolicyAudit.cs").read_text(encoding="utf-8")
        self.assertIn("internal bool CanApply => false;", source)
        self.assertIn("MailHostInspection? host", source)
        self.assertIn("AdvancedRoutePlanner.ValidatePlan", source)
        for marker in (
            "TRANSPORT_MAPS", "RELAYHOST",
            "SENDER_DEPENDENT_RELAYHOST_MAPS",
            "SENDER_DEPENDENT_DEFAULT_TRANSPORT_MAPS",
            "SMTP_SASL_PASSWORD_MAPS", "SMTP_TLS_POLICY_MAPS",
            "SMTP_SENDER_DEPENDENT_AUTHENTICATION",
            "VIRTUAL_MAILBOX_DOMAINS", "VIRTUAL_ALIAS_DOMAINS",
            "literal-local-domain", "dynamic-local-domains", "overlap",
            "apply-gate", "unsupported-mta",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        self.assertNotIn("postmap -q", source)
        self.assertNotIn("SshRemote.", source)
        self.assertNotIn("File.Write", source)

    def test_native_gui_does_not_add_apply_or_remote_actions(self):
        ui = (CS / "MainForm.AdvancedRoutes.cs").read_text(encoding="utf-8")
        self.assertIn("PostfixRoutePolicyAudit.Review(", ui)
        self.assertIn("routePolicyReview.Describe(l)", ui)
        self.assertIn("HasMailDiscovery()", ui)
        self.assertNotIn("ApplyConditionalRoutingAsync", ui)
        self.assertNotIn("postconf -e", ui)

    def test_rc12_release_only_after_full_acceptance(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        csproj = (CS / "LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        self.assertIn("<Version>0.1.1-rc.12</Version>", csproj)
        for path in ("UpdateCheck.cs", "UpdateCheck.Fallback.cs"):
            self.assertIn('internal const string Version = "0.1.1-rc.12";',
                          (CS / path).read_text(encoding="utf-8"))
        self.assertIn("-ExpectedCandidateVersion '0.1.1-rc.12'", ci)
        job = ci.split("  rc12-prerelease-publish:", 1)[1]
        self.assertIn("github.event_name == 'push'", job)
        self.assertIn("refs/heads/feature/rc12-postfix-route-policy-audit", job)
        for requirement in ("- linux-tests", "- windows-build",
                            "- ubuntu-postfix-smoke", "- rhel-native-foreign-mta-smoke",
                            "- rhel-selinux-offline-policy-smoke"):
            self.assertIn(requirement, job)
        self.assertIn("UNSIGNED_RC12_RELEASE_SHA256_AND_ZIP=PASS", job)
        self.assertIn("tag='v0.1.1-rc.12'", job)
        self.assertIn("--prerelease", job)
        self.assertNotIn("--latest", job)

    def test_csharp_selftest_is_registered_in_windows_ci(self):
        program = (CS / "Program.cs").read_text(encoding="utf-8")
        self.assertIn("PostfixRoutePolicyAudit.SelfTest", program)
        self.assertIn("AdvancedRoutePlanner.SelfTest", program)


if __name__ == "__main__":
    unittest.main()
