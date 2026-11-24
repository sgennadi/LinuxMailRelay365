"""RC16 publication is immutable and inherits the complete RC15 CI gate."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RC16ReleaseContract(unittest.TestCase):
    def test_full_exact_branch_gate(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        before, job = ci.split("\n  rc16-prerelease-publish:\n", 1)
        prior = before.split("\n  rc15-prerelease-publish:\n", 1)[1]
        def dependencies(value):
            return value.split("    needs:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertEqual(dependencies(prior), dependencies(job))
        for marker in (
            "github.event_name == 'push'",
            "github.ref == 'refs/heads/feature/post-rc15-wizard-refinement'",
            "test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"",
            "tag='v0.1.1-rc.16'",
            "STATUS=preview_unsigned_not_for_production",
            "UNSIGNED_RC16_RELEASE_SHA256_AND_ZIP=PASS",
            'gh release view "$tag"', 'git ls-remote --exit-code --tags',
            '--target "$GITHUB_SHA"', "--prerelease", "NOT Stable",
            "Physical 200% DPI", "Active SELinux writes"):
            self.assertIn(marker, job)
        self.assertNotIn("--clobber", job)
        self.assertNotIn("--latest", job)
        native = before.split("\n  rc14-native-transaction-fast:\n", 1)[1].split(
            "\n  ubuntu-postfix-smoke:\n", 1)[0]
        self.assertIn("github.ref == 'refs/heads/feature/post-rc15-wizard-refinement'", native)
        self.assertIn("github.event.pull_request.head.ref == 'feature/post-rc15-wizard-refinement'", native)
        self.assertIn("tag='v0.1.1-rc.15'", prior)

    def test_version_and_navigation_test_wired(self):
        src = ROOT / "src/LinuxMailRelay365"
        self.assertIn("<Version>0.1.1-rc.16</Version>",
                      (src / "LinuxMailRelay365.csproj").read_text(encoding="utf-8"))
        for name in ("UpdateCheck.cs", "UpdateCheck.Fallback.cs"):
            self.assertIn('internal const string Version = "0.1.1-rc.16";',
                          (src / name).read_text(encoding="utf-8"))
        self.assertIn("MainForm.DeliveryNavigationSelfTest",
                      (src / "Program.cs").read_text(encoding="utf-8"))
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("-ExpectedCandidateVersion '0.1.1-rc.16'", ci)


if __name__ == "__main__":
    unittest.main()
