"""RC19 must inherit the complete native recovery and queue acceptance gates."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src/LinuxMailRelay365"
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
BRANCH = "release/v0.1.1-rc.19"


def job(name):
    source = CI.split("\n  " + name + ":\n", 1)[1]
    return re.split(r"\n  [a-zA-Z0-9_-]+:\n", source, maxsplit=1)[0]


def dependencies(source):
    return set(re.findall(r"^      - ([a-zA-Z0-9_-]+)$",
        source.split("    needs:\n", 1)[1].split("    runs-on:", 1)[0], re.M))


class RC19ReleaseContract(unittest.TestCase):
    def test_exact_branch_inherits_all_gates(self):
        release = job("rc19-prerelease-publish")
        expected = dependencies(job("rc18-prerelease-publish"))
        expected.remove("rc18-rocky-enforcing-vm")
        expected.update(("rc19-queue-enforcing-vm", "rhel-native-sendmail-queues"))
        self.assertEqual(dependencies(release), expected)
        for name in ("rc14-native-transaction-fast", "rc19-queue-enforcing-vm"):
            gate = job(name)
            self.assertIn("github.ref == 'refs/heads/" + BRANCH + "'", gate)
            self.assertIn("github.event.pull_request.head.ref == '" + BRANCH + "'", gate)
            self.assertNotIn("continue-on-error", gate)
        self.assertIn("queue-acceptance: true", job("rc19-queue-enforcing-vm"))
        self.assertIn("uses: ./.github/workflows/rocky-enforcing-vm.yml",
                      job("rc19-queue-enforcing-vm"))
        for marker in ("github.event_name == 'push'", "github.ref == 'refs/heads/" + BRANCH + "'",
                       'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
                       "tag='v0.1.1-rc.19'", "STATUS=preview_unsigned_not_for_production",
                       "UNSIGNED_RC19_RELEASE_SHA256_AND_ZIP=PASS",
                       'gh release view "$tag"', 'git ls-remote --exit-code --tags',
                       '--target "$GITHUB_SHA"', "--prerelease", "NOT Stable",
                       "independent verified backup", "Sendmail online Delete is NOT supported",
                       'z.namelist() == ["LinuxMailRelay365.exe"]',
                       'assert (arch, name) not in expected', "0xaa64"):
            self.assertIn(marker, release)
        for marker in ("always()", "continue-on-error", "--clobber", "--latest"):
            self.assertNotIn(marker, release)

    def test_version_and_actual_upgrade_baseline(self):
        # The historic RC19 publishing job must retain its exact version;
        # a reviewed RC20 development version may advance independently.
        release = job("rc19-prerelease-publish")
        self.assertIn("<Version>0.1.1-rc.19</Version>", release)
        self.assertEqual(release.count('internal const string Version = "0.1.1-rc.19";'), 2)
        current = re.findall(r"<Version>(0\.1\.1-rc\.(?:19|20))</Version>",
                             (CS / "LinuxMailRelay365.csproj").read_text(encoding="utf-8"))
        self.assertEqual(len(current), 1)
        for name in ("UpdateCheck.cs", "UpdateCheck.Fallback.cs"):
            self.assertIn('internal const string Version = "' + current[0] + '";',
                          (CS / name).read_text(encoding="utf-8"))
        windows = job("windows-build")
        self.assertIn("-ExpectedCandidateVersion '0.1.1-rc.19' -SourceTag 'v0.1.1-rc.18'", windows)
        self.assertIn("STABLE_UNSIGNED_RELEASE_GATE=refused_expected", windows)
        self.assertIn("ACTUAL_WINDOWS_WIZARD_SCREENS=37", windows)
        self.assertIn("ACTUAL_WINDOWS_QUEUE_SCREENS=42", windows)
        self.assertIn("Test-LinuxMailRelay365PreviewUpgrade.ps1", windows)
        self.assertIn("docker run --rm --network none", job("rhel-native-sendmail-queues"))


if __name__ == "__main__":
    unittest.main()
