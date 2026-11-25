"""Guard GUI updater entry, release versions and publisher restrictions."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
UPDATER = (ROOT / "src/LinuxMailRelay365/SignedPortableUpdater.cs").read_text(encoding="utf-8")
PROJECT = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
CHECK = (ROOT / "src/LinuxMailRelay365/UpdateCheck.Fallback.cs").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")


class UpdaterPreview25Contracts(unittest.TestCase):
    def test_first_page_updater_needs_no_ssh(self):
        # RC7: clear header control replaces the crowded update card on SSH page.
        # The original diagnostics page retains its full update controls.
        self.assertIn("case 0:\n                RenderConnectionStep(page);", MAIN)
        self.assertEqual(MAIN.count("AddUpdateAccess(page);"), 1)
        self.assertIn("headerUpdateButton.Click += (_, _) => ShowHeaderUpdateMenu();", MAIN)
        self.assertIn('headerUpdateButton.Text = T("Проверить обновления', MAIN)
        self.assertIn("previewUpdates.Checked = false;", MAIN)
        self.assertIn("previewUpdates.Checked = true;", MAIN)
        self.assertIn('RunBusyAsync("update", CheckUpdatesAsync)', MAIN)
        self.assertIn("SignedPortableUpdater.LastUpdateStatus()", MAIN)

    def test_release_and_updater_version_are_consistent(self):
        match = re.search(r"<Version>(0\.1\.1-rc\.[1-9][0-9]*)</Version>", PROJECT)
        self.assertIsNotNone(match)
        expected = match.group(1)
        self.assertIn('internal const string Version = "' + expected + '";', CHECK)
        shared = (ROOT / "src/LinuxMailRelay365/UpdateCheck.cs").read_text(encoding="utf-8")
        self.assertIn('internal const string Version = "' + expected + '";', shared)
        self.assertIn("ExpectedCandidateVersion '" + expected + "'", WORKFLOW)
        # Immutable published RC8 test asset must remain an explicit branch gate.
        self.assertIn("tag='v0.1.1-rc.8'", WORKFLOW)
        self.assertIn("tag='v0.1.0-preview.25'", WORKFLOW)
        self.assertIn("Test-LinuxMailRelay365PreviewUpgrade.ps1", WORKFLOW)

    def test_published_rc18_baseline_rehearsal(self):
        smoke = (ROOT / "scripts/Test-LinuxMailRelay365PreviewUpgrade.ps1").read_text(encoding="utf-8")
        self.assertIn("-SourceTag 'v0.1.1-rc.18'", WORKFLOW)
        self.assertIn("[ValidateSet('v0.1.0-preview.24', 'v0.1.1-rc.18')]", smoke)
        self.assertIn("d778c2107c88eb5dadfb1b2a105be09bd034843e8f7b9c9bae21c0ad9669ae67", smoke)
        self.assertIn("equal_version_file_replacement_rehearsal_only", smoke)
        self.assertIn("REAL_GUI_AND_HELPER_ACCEPTANCE=NOT_TESTED", smoke)

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
