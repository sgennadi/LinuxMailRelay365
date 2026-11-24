"""RC15 release gate: exact commit, immutable preview, all existing CI."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RC15ReleaseContract(unittest.TestCase):
    def test_release_inherits_full_rc14_acceptance(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        before, after = ci.split("\n  rc15-prerelease-publish:\n", 1)
        prior = before.split("\n  rc14-prerelease-publish:\n", 1)[1]
        def dependencies(job):
            return job.split("    needs:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertEqual(dependencies(prior), dependencies(after))
        self.assertIn("      - rc14-native-transaction-fast\n", after)
        self.assertIn("github.event_name == 'push'", after)
        self.assertIn("github.ref == 'refs/heads/feature/rc15-ui-test-release'", after)
        native = before.split("\n  rc14-native-transaction-fast:\n", 1)[1].split(
            "\n  ubuntu-postfix-smoke:\n", 1)[0]
        self.assertIn("github.ref == 'refs/heads/feature/rc15-ui-test-release'", native)
        self.assertIn("github.event.pull_request.head.ref == 'feature/rc15-ui-test-release'", native)
        for marker in ("v0.1.1-rc.15", "STATUS=preview_unsigned_not_for_production",
                       "UNSIGNED_RC15_RELEASE_SHA256_AND_ZIP=PASS",
                       'gh release view "$tag"', 'git ls-remote --exit-code --tags',
                       '--target "$GITHUB_SHA"', "--prerelease", "NOT Stable",
                       "active SELinux writes", "Physical 200% DPI"):
            self.assertIn(marker, after)
        self.assertNotIn("--clobber", after)
        self.assertNotIn("--latest", after)
        self.assertIn("tag='v0.1.1-rc.14'", prior)
        self.assertIn("feature/rc14-transport-transaction", prior)

    def test_version_is_consistent(self):
        cs = ROOT / "src/LinuxMailRelay365"
        self.assertIn("<Version>0.1.1-rc.15</Version>",
                      (cs / "LinuxMailRelay365.csproj").read_text(encoding="utf-8"))
        for name in ("UpdateCheck.cs", "UpdateCheck.Fallback.cs"):
            self.assertIn('internal const string Version = "0.1.1-rc.15";',
                          (cs / name).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
