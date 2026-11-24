"""RC18 release contract: same-commit real KVM gate and immutable test packages."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src/LinuxMailRelay365"
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
VM = (ROOT / ".github/workflows/rocky-enforcing-vm.yml").read_text(encoding="utf-8")


class RC18ReleaseContract(unittest.TestCase):
    def test_inherits_all_rc17_checks_and_requires_real_vm(self):
        prior = CI.split("\n  rc17-prerelease-publish:\n", 1)[1].split(
            "\n  rc18-prerelease-publish:\n", 1)[0]
        release = CI.split("\n  rc18-prerelease-publish:\n", 1)[1]
        def deps(job):
            return job.split("    needs:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertEqual(deps(release), deps(prior) + "      - rc18-rocky-enforcing-vm\n")
        self.assertNotIn("always()", release)
        self.assertNotIn("continue-on-error", release)
        vm_job = CI.split("\n  rc18-rocky-enforcing-vm:\n", 1)[1].split(
            "\n  rc17-prerelease-publish:\n", 1)[0]
        self.assertIn("uses: ./.github/workflows/rocky-enforcing-vm.yml", vm_job)
        self.assertIn("github.ref == 'refs/heads/feature/post-rc17-sendmail-v2'", vm_job)
        self.assertNotIn("continue-on-error", vm_job)
        for marker in ("workflow_call:", "workflow_dispatch:",
                       "feature/private-smtp-auth-tls", "actions/checkout@v5",
                       "persist-credentials: false", "tests/rocky_vm_kvm_probe.sh",
                       "tests/rocky_vm_boot_enforcing.sh"):
            self.assertIn(marker, VM)
        self.assertNotIn("continue-on-error", VM)

    def test_exact_version_and_immutable_unsigned_publication(self):
        release = CI.split("\n  rc18-prerelease-publish:\n", 1)[1]
        for marker in ("github.event_name == 'push'",
                       "github.ref == 'refs/heads/feature/post-rc17-sendmail-v2'",
                       'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
                       "tag='v0.1.1-rc.18'", "STATUS=preview_unsigned_not_for_production",
                       "UNSIGNED_RC18_RELEASE_SHA256_AND_ZIP=PASS",
                       'gh release view "$tag"', "git ls-remote --exit-code --tags",
                       '--target "$GITHUB_SHA"', "--prerelease",
                       "NOT Stable", "Active SELinux writes", "independent verified backup"):
            self.assertIn(marker, release)
        for marker in ("--clobber", "--latest", "continue-on-error"):
            self.assertNotIn(marker, release)
        self.assertIn("<Version>0.1.1-rc.18</Version>", (CS / "LinuxMailRelay365.csproj").read_text())
        for path in ("UpdateCheck.cs", "UpdateCheck.Fallback.cs"):
            self.assertIn('internal const string Version = "0.1.1-rc.18";',
                          (CS / path).read_text())
        self.assertIn("-ExpectedCandidateVersion '0.1.1-rc.18'", CI)
        self.assertIn("STABLE_UNSIGNED_RELEASE_GATE=refused_expected", CI)
        self.assertIn("tag='v0.1.1-rc.17'", CI)
        self.assertIn('z.namelist() == ["LinuxMailRelay365.exe"]', release)


if __name__ == "__main__":
    unittest.main()
