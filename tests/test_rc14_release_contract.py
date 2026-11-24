"""RC14 test-only publication contract, without mutating GitHub."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RC14ReleaseContract(unittest.TestCase):
    def test_exact_branch_and_native_acceptance(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        job = ci.split("\n  rc14-prerelease-publish:\n", 1)[1]
        self.assertIn("github.event_name == 'push'", job)
        self.assertIn("github.ref == 'refs/heads/feature/rc14-transport-transaction'", job)
        for dependency in (
            "linux-tests", "rc14-native-transaction-fast", "ubuntu-postfix-smoke",
            "ubuntu-native-foreign-mta-smoke", "rhel-native-foreign-mta-smoke",
            "rhel-selinux-offline-policy-smoke", "windows-build",
            "ubuntu-fresh-direct-send-smoke", "ubuntu-fresh-connector-smoke",
            "ubuntu-real-proof-timer-systemd", "ubuntu-clean-postfix-bootstrap",
            "rhel-family-readonly-smoke"):
            self.assertIn("      - " + dependency + "\n", job)
        for marker in ("v0.1.1-rc.14", "STATUS=preview_unsigned_not_for_production",
                       "UNSIGNED_RC14_RELEASE_SHA256_AND_ZIP=PASS",
                       'gh release view "$tag"', 'git ls-remote --exit-code --tags',
                       '--target "$GITHUB_SHA"', "--prerelease", "NOT Stable",
                       "active SELinux writes remain blocked"):
            self.assertIn(marker, job)
        self.assertNotIn("--clobber", job)
        self.assertNotIn("--latest", job)

    def test_required_native_job_runs_on_release_branch(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        job = ci.split("\n  rc14-native-transaction-fast:\n", 1)[1].split(
            "\n  ubuntu-postfix-smoke:\n", 1)[0]
        self.assertIn("github.ref == 'refs/heads/feature/rc14-transport-transaction'", job)
        self.assertIn("github.event.pull_request.head.ref == 'feature/rc14-transport-transaction'", job)
        self.assertIn("feature/rc14-postfix-map-inventory", job)
        self.assertIn("tests/smoke_native_conditional_transaction.py", job)
        self.assertNotIn("continue-on-error", job)

    def test_existing_release_job_preserved(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        old = ci.split("\n  rc13-prerelease-publish:\n", 1)[1].split(
            "\n  rc14-prerelease-publish:\n", 1)[0]
        self.assertIn("tag='v0.1.1-rc.13'", old)
        self.assertIn("feature/rc13-postfix-managed-map-review", old)


if __name__ == "__main__":
    unittest.main()
