"""Guard GUI updater entry, release versions and publisher restrictions."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
UPDATER = (ROOT / "src/LinuxMailRelay365/SignedPortableUpdater.cs").read_text(encoding="utf-8")
PROJECT = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
CHECK = (ROOT / "src/LinuxMailRelay365/UpdateCheck.Fallback.cs").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")


class UpdaterPreview25Contracts(unittest.TestCase):
    def test_first_page_updater_needs_no_ssh(self):
        self.assertIn("case 0:\n                AddUpdateAccess(page);\n                RenderConnectionStep(page);", MAIN)
        self.assertEqual(MAIN.count("AddUpdateAccess(page);"), 2)
        self.assertIn("SignedPortableUpdater.LastUpdateStatus()", MAIN)

    def test_release_and_updater_version_are_consistent(self):
        self.assertIn("<Version>0.1.1-rc.3</Version>", PROJECT)
        self.assertIn('internal const string Version = "0.1.1-rc.3";', CHECK)
        shared = (ROOT / "src/LinuxMailRelay365/UpdateCheck.cs").read_text(encoding="utf-8")
        self.assertIn('internal const string Version = "0.1.1-rc.3";', shared)
        self.assertIn("tag='v0.1.0-preview.25'", WORKFLOW)
        self.assertIn("Test-LinuxMailRelay365PreviewUpgrade.ps1", WORKFLOW)

    def test_preview_does_not_bypass_stable_signature_requirement(self):
        for marker in ("CanInstallPreview", "IsNonElevatedWindowsProcess",
                       "TrustedCandidate", "VerifiedPublisher",
                       "unsignedPreview ? PreviewPublisherMarker : publisher",
                       "MANUAL_REVIEW_REQUIRED", "RejectLinks"):
            self.assertIn(marker, UPDATER)
        self.assertIn("!IsNonElevatedWindowsProcess()", UPDATER)
        # Both install and rollback must use the same verified, bounded retry.
        self.assertIn("ReplaceWithVerifiedSharingRetry(next, target, backup,", UPDATER)
        self.assertIn("ReplaceWithVerifiedSharingRetry(backup, target, next,", UPDATER)
        self.assertIn("File.Replace(source, destination, backup, ignoreMetadataErrors: false)", UPDATER)
        self.assertIn("ex.HResult & 0xffff) is 32 or 33", UPDATER)
        self.assertIn("string.Equals(FileSha256(source), sourceDigest", UPDATER)
        self.assertIn("string.Equals(FileSha256(destination), destinationDigest", UPDATER)
        self.assertNotIn("File.Replace(backup, target, next, ignoreMetadataErrors: false)", UPDATER)
        self.assertNotIn("File.Replace(backup, target, null", UPDATER)


if __name__ == "__main__":
    unittest.main()
