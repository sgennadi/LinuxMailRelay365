"""Immutable RC7 prerelease contract; offline, no GitHub mutation or signing."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RC7ReleaseContractTests(unittest.TestCase):
    def test_exact_version_in_all_windows_build_paths(self):
        expected = "0.1.1-rc.8"
        csproj = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        self.assertIn("<Version>" + expected + "</Version>", csproj)
        for path in ("UpdateCheck.cs", "UpdateCheck.Fallback.cs"):
            text = (ROOT / "src/LinuxMailRelay365" / path).read_text(encoding="utf-8")
            self.assertIn('internal const string Version = "' + expected + '";', text)
        fallback = (ROOT / "src/LinuxMailRelay365/UpdateCheck.Fallback.cs").read_text(encoding="utf-8")
        self.assertIn('Compare("0.1.1-rc.7", "0.1.1-rc.6") > 0', fallback)
        self.assertIn('Compare("0.1.1", "0.1.1-rc.7") > 0', fallback)
        updater = (ROOT / "src/LinuxMailRelay365/SignedPortableUpdater.cs").read_text(encoding="utf-8")
        self.assertIn('bool sameVersionRejected = SelectRelease(', updater)
        self.assertIn('true, "0.1.1-rc.9", asset) is null', updater)
        self.assertIn('Parse(Fixture(asset, hash, true), true)?.Version == "0.1.1-rc.9"', updater)

    def test_rc7_publication_is_exact_branch_only_and_immutable(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        rc = ci.split("  release-candidate-publish:", 1)[1]
        self.assertIn("github.event_name == 'push'", rc)
        self.assertIn("github.ref == 'refs/heads/release/v0.1.0-stable-candidate'", rc)
        for requirement in ("- linux-tests", "- windows-build",
                            "- ubuntu-postfix-smoke", "- rhel-native-foreign-mta-smoke"):
            self.assertIn(requirement, rc)
        self.assertIn("tag='v0.1.1-rc.7'", rc)
        self.assertIn('gh release view "$tag"', rc)
        self.assertIn('git ls-remote --exit-code --tags origin "refs/tags/$tag"', rc)
        self.assertIn('gh release create "$tag"', rc)
        self.assertIn('--target "$GITHUB_SHA"', rc)
        self.assertIn("--prerelease", rc)
        self.assertIn("STATUS=preview_unsigned_not_for_production", rc)
        self.assertIn("UNSIGNED_RC7_RELEASE_SHA256_AND_ZIP=PASS", rc)
        self.assertIn("Previously published RC6 remains immutable.", rc)
        self.assertIn("Signed Stable is NOT published.", rc)
        self.assertNotIn("0.1.1-rc.6", rc)
        self.assertNotIn("--latest", rc)

    def test_unsigned_preview_is_not_treated_as_stable(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("ExpectedCandidateVersion '0.1.1-rc.8'", ci)
        self.assertIn("STABLE_UNSIGNED_RELEASE_GATE=refused_expected", ci)
        signed_gate = (ROOT / "scripts/Test-LinuxMailRelay365SignedRelease.ps1").read_text(encoding="utf-8")
        self.assertIn("Get-AuthenticodeSignature", signed_gate)


if __name__ == "__main__":
    unittest.main()
