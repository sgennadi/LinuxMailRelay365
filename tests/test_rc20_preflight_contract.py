"""RC20 preflight must never substitute a previous commit's VM results."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
VM = (ROOT / ".github/workflows/rocky-enforcing-vm.yml").read_text(encoding="utf-8")


def job(source, name):
    body = source.split("\n  " + name + ":\n", 1)[1]
    return re.split(r"\n  [a-zA-Z0-9_-]+:\n", body, maxsplit=1)[0]


def deps(body):
    return set(re.findall(r"^      - ([a-zA-Z0-9_-]+)$",
                          body.split("    needs:\n", 1)[1].split("    runs-on:", 1)[0], re.M))


class RC20PreflightContract(unittest.TestCase):
    def test_inherits_all_rc19_release_dependencies(self):
        expected = deps(job(CI, "rc19-prerelease-publish"))
        expected.remove("rc19-queue-enforcing-vm")
        expected.add("rc20-full-native-vm")
        result = job(CI, "rc20-preflight-result")
        self.assertEqual(deps(result), expected)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', result)
        self.assertIn("contents: read", result)
        self.assertIn("RC20_PREFLIGHT_PUBLISHED=no", result)
        self.assertNotIn("gh release", result)
        self.assertNotIn("contents: write", result)
        self.assertNotIn("always()", result)
        self.assertNotIn("continue-on-error", result)

    def test_pinned_rc19_upgrade_step_is_mandatory_for_new_candidate(self):
        windows = job(CI, "windows-build")
        step = windows.split("- name: Test pinned published RC19 to candidate binary replacement and rollback (disposable)", 1)[1].split("      - name:", 1)[0]
        for branch in ("feature/primary-rc20-updater-preflight", "feature/primary-rc20-combined", "feature/primary-rc20-native-readiness", "feature/primary-rc20-sandbox-guard", "feature/primary-rc20-release-package", "release/v0.1.1-rc.20"):
            self.assertIn("github.ref == 'refs/heads/" + branch + "'", step)
            self.assertIn("github.event.pull_request.head.ref == '" + branch + "'", step)
        self.assertIn("-SourceTag 'v0.1.1-rc.19'", step)
        self.assertNotIn("continue-on-error", step)
        self.assertIn("windows-build", deps(job(CI, "rc20-preflight-result")))

    def test_read_only_package_gate_requires_same_commit_upgrade_and_preflight(self):
        review = job(CI, "rc20-package-review")
        self.assertEqual(deps(review), {"rc20-preflight-result", "windows-build"})
        self.assertIn("contents: read", review)
        self.assertIn("github.event_name == 'push'", review)
        self.assertIn("github.ref == 'refs/heads/feature/primary-rc20-release-package'", review)
        self.assertIn("github.ref == 'refs/heads/release/v0.1.1-rc.20'", review)
        self.assertIn("LinuxMailRelay365-preview-builds", review)
        self.assertIn("LinuxMailRelay365-rc20-upgrade-receipt", review)
        self.assertIn("scripts/verify-rc20-package.py", review)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', review)
        for forbidden in ("contents: write", "gh release", "always()", "continue-on-error"):
            self.assertNotIn(forbidden, review)
        windows = job(CI, "windows-build")
        for marker in ("-ExpectedCandidateVersion '0.1.1-rc.20' -SourceTag 'v0.1.1-rc.19'",
                       "0.1.1-rc.19->0.1.1-rc.20", "candidate_sha256 = $before",
                       "commit = $env:GITHUB_SHA", "RC20 updater evidence for package review"):
            self.assertIn(marker, windows)

    def test_exact_branch_requires_both_native_guests(self):
        gate = job(CI, "rc20-full-native-vm")
        for branch in ("feature/primary-rc20-preflight", "feature/primary-rc20-updater-preflight", "feature/primary-rc20-combined", "feature/primary-rc20-native-readiness", "feature/primary-rc20-sandbox-guard", "feature/primary-rc20-release-package", "release/v0.1.1-rc.20"):
            for name in ("rc20-full-native-vm", "rc14-native-transaction-fast"):
                body = job(CI, name)
                self.assertIn("github.ref == 'refs/heads/" + branch + "'", body)
                self.assertIn("github.event.pull_request.head.ref == '" + branch + "'", body)
                self.assertNotIn("continue-on-error", body)
        self.assertIn("uses: ./.github/workflows/rocky-enforcing-vm.yml", gate)
        for key in ("queue-acceptance", "client-tls-acceptance",
                    "primary-mailbox-acceptance", "native-tpm-provider-acceptance"):
            self.assertIn(key + ": true", gate)
        rocky9 = job(VM, "kvm-host-capability")
        rocky10 = job(VM, "kvm-native-tpm-provider")
        for env, key in (("LMR365_KVM_QUEUE_ACCEPTANCE", "queue-acceptance"),
                         ("LMR365_KVM_CLIENT_TLS_ACCEPTANCE", "client-tls-acceptance"),
                         ("LMR365_KVM_PRIMARY_MAILBOX_ACCEPTANCE", "primary-mailbox-acceptance")):
            self.assertIn(env + ": ${{ inputs." + key, rocky9)
        self.assertIn("if: inputs.native-tpm-provider-acceptance ||", rocky10)
        for marker in ("LMR365_KVM_ROCKY_MAJOR: '10'", "LMR365_KVM_VTPM_ACCEPTANCE: 'true'",
                       "LMR365_KVM_VTPM_PROVIDER_REQUIRED: 'true'"):
            self.assertIn(marker, rocky10)
        for guest in (rocky9, rocky10):
            self.assertIn("actions/checkout@v5", guest)
            self.assertIn("bash tests/rocky_vm_boot_enforcing.sh", guest)
            self.assertNotIn("continue-on-error", guest)


if __name__ == "__main__":
    unittest.main()
