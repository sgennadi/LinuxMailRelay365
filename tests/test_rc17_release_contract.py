"""RC17 immutable unsigned prerelease and recovery center acceptance."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src/LinuxMailRelay365"
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")


class RC17ReleaseContract(unittest.TestCase):
    def test_full_exact_branch_release_gate(self):
        before, job = CI.split("\n  rc17-prerelease-publish:\n", 1)
        job = job.split("\n  rc18-prerelease-publish:\n", 1)[0]
        prior = before.split("\n  rc16-prerelease-publish:\n", 1)[1]
        def dependencies(value):
            return value.split("    needs:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertEqual(dependencies(prior), dependencies(job))
        for marker in (
            "github.event_name == 'push'",
            "github.ref == 'refs/heads/feature/post-rc16-native-recovery'",
            'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
            "tag='v0.1.1-rc.17'", "STATUS=preview_unsigned_not_for_production",
            "UNSIGNED_RC17_RELEASE_SHA256_AND_ZIP=PASS",
            'gh release view "$tag"', 'git ls-remote --exit-code --tags',
            '--target "$GITHUB_SHA"', "--prerelease", "NOT Stable",
            "Physical 200% DPI", "Active SELinux writes",
            "Sendmail v2 Apply", "disposable nonproduction host"):
            self.assertIn(marker, job)
        self.assertNotIn("--clobber", job)
        self.assertNotIn("--latest", job)
        self.assertIn("tag='v0.1.1-rc.16'", prior)
        self.assertIn("github.ref == 'refs/heads/feature/post-rc16-native-recovery'", before)
        self.assertIn("bash tests/smoke_native_exim_offline_restore.sh", before)

    def test_version_and_recovery_acceptance_are_wired(self):
        # Historical publication requirements stay frozen after version bumps.
        job = CI.split("\n  rc17-prerelease-publish:\n", 1)[1].split(
            "\n  rc18-prerelease-publish:\n", 1)[0]
        self.assertIn("<Version>0.1.1-rc.17</Version>", job)
        self.assertEqual(job.count('internal const string Version = "0.1.1-rc.17";'), 2)
        self.assertIn("tag='v0.1.1-rc.17'", job)
        self.assertNotIn("tag='v0.1.1-rc.18'", job)
        program = (CS / "Program.cs").read_text(encoding="utf-8")
        for marker in ("ForeignRestorePlan.SelfTest", "EximNativeRestoreReceipt.SelfTest",
                       "ForeignPendingInspection.SelfTest", "EximPendingRollbackPlan.SelfTest",
                       "CaptureWizardScreens(args[1]) != 37", "CaptureWizardScreens(null)"):
            self.assertIn(marker, program)
        form = (CS / "MainForm.cs").read_text(encoding="utf-8")
        for name in ("05-native-recovery-center.png", "05-native-recovery-center-bottom.png",
                     "compact-05-native-recovery-center.png", "compact-05-native-recovery-center-bottom.png"):
            self.assertIn(name, form)
        self.assertIn("Recovery center Back did not restore diagnostics.", form)
        self.assertIn("ACTUAL_WINDOWS_WIZARD_LAYOUT_CHECKS=37", CI)
        self.assertIn("--validate-wizard-layout", CI)
        smoke = (ROOT / "tests/smoke_native_exim_offline_restore.sh").read_text(encoding="utf-8")
        self.assertIn("os._exit(91)", smoke)
        self.assertIn("EXIM_RESTORE_LAB_INTERRUPTED_ROLLBACK=verified_original_bytes_stopped_empty_queue", smoke)


if __name__ == "__main__":
    unittest.main()
