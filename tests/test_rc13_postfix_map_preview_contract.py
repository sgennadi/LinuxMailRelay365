"""RC13 source safety gates for read-only Postfix candidate preview."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src" / "LinuxMailRelay365"


class PostfixCandidatePreviewTests(unittest.TestCase):
    def test_map_preview_is_local_only_and_fail_closed(self):
        code = (CS / "PostfixConditionalMapPreview.cs").read_text(encoding="utf-8")
        for marker in ("internal bool CanApply => false",
                       "AdvancedRoutePlanner.ValidatePlan",
                       "PostfixRoutePolicyAudit.Review",
                       "NeedsDedicatedTransport",
                       "sender_dependent_relayhost_maps",
                       "transport_maps"):
            self.assertIn(marker, code)
        for forbidden in ("SshRemote.", "RunRootScriptAsync",
                          "File.Write", "FileStream(", "postmap -q",
                          "postconf -e", "postfix reload", "Process.Start"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, code)

    def test_preview_reports_not_deployable_security(self):
        code = (CS / "PostfixConditionalMapPreview.cs").read_text(encoding="utf-8")
        for marker in ("wrapper-mode", "tls-not-bound", "credentials",
                       "endpoint-policy-conflict", "plaintext", "subdomain-rule",
                       "InventorySha256", "PlanSha256", "NOT an Apply script",
                       "PostfixDetected"):
            with self.subTest(marker=marker):
                self.assertIn(marker, code)
        self.assertNotIn("parent_domain_matches_subdomains", code)
        self.assertNotIn("TRANSPORT_SUBDOMAIN_POLICY", code)

    def test_native_readonly_gui_and_selftest_exist(self):
        ui = (CS / "MainForm.AdvancedRoutes.cs").read_text(encoding="utf-8")
        self.assertIn("PostfixConditionalMapPreview.Build(", ui)
        self.assertIn("candidate.Render(l)", ui)
        self.assertIn("ReadOnly = true", ui)
        self.assertIn("ScrollBars = ScrollBars.Both", ui)
        program = (CS / "Program.cs").read_text(encoding="utf-8")
        self.assertIn("PostfixConditionalMapPreview.SelfTest", program)

    def test_exact_version_and_release_gates(self):
        for file in ("LinuxMailRelay365.csproj", "UpdateCheck.cs",
                     "UpdateCheck.Fallback.cs"):
            self.assertIn("0.1.1-rc.13",
                          (CS / file).read_text(encoding="utf-8"))
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("-ExpectedCandidateVersion '0.1.1-rc.13'", ci)
        job = ci.split("  rc13-prerelease-publish:", 1)[1]
        for requirement in ("- linux-tests", "- ubuntu-real-proof-timer-systemd",
                            "- windows-build", "- rhel-family-readonly-smoke",
                            "- rhel-selinux-offline-policy-smoke",
                            "refs/heads/feature/rc13-postfix-managed-map-review",
                            "UNSIGNED_RC13_RELEASE_SHA256_AND_ZIP=PASS",
                            "tag='v0.1.1-rc.13'", "--prerelease",
                            '--target "$GITHUB_SHA"'):
            self.assertIn(requirement, job)
        self.assertNotIn("--latest", job)


if __name__ == "__main__":
    unittest.main()
