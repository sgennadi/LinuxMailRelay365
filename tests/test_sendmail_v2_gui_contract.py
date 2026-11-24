"""The Sendmail v2 review is routed by verified format and cannot authorize writes."""
from pathlib import Path
import unittest

CS = Path(__file__).resolve().parents[1] / "src/LinuxMailRelay365"


class SendmailV2GuiContract(unittest.TestCase):
    def test_format_dispatched_from_existing_button(self):
        form = (CS / "MainForm.cs").read_text(encoding="utf-8")
        method = form.split("private async Task PreviewExactForeignRestorePlanAsync()", 1)[1].split(
            "private async Task ExportForeignMtaOfflineAsync()", 1)[0]
        self.assertLess(method.index("TryPreviewSendmailV2Async"), method.index("BuildForeignMtaRestorePlanBundle"))
        self.assertIn("PreviewExactForeignRestorePlanAsync, false", form)
        ui = (CS / "MainForm.SendmailV2.cs").read_text(encoding="utf-8")
        for token in ("BuildForeignMtaBackupBundle(\"sendmail\", \"verify\", id)",
                      "ParseForeignBackupFormat", 'format == "v1_regular_files"',
                      "BuildSendmailV2ReviewBundle(id)", "SendmailV2Review.Parse",
                      "hashes[0].Groups[1].Value", "SameRollbackConnection", "HostKeySha256",
                      "foreignBackupListContext", "foreignBackupSelector.SelectedItem",
                      "ReadOnly = true", "ScrollBars = ScrollBars.Vertical"):
            self.assertIn(token, ui)
        self.assertLess(ui.index("ParseForeignBackupFormat"), ui.index("BuildSendmailV2ReviewBundle"))
        self.assertEqual(ui.count("RequireSameSendmailReviewContext("), 3)
        for forbidden in ("ConfirmDestructive(", "ApplyExim", " --apply ", " --confirm ", " --approve-sha256 "):
            self.assertNotIn(forbidden, ui)

    def test_fixed_bundle_and_parser(self):
        assets = (CS / "EmbeddedAssets.cs").read_text(encoding="utf-8")
        bundle = assets.split("internal static string BuildSendmailV2ReviewBundle(", 1)[1].split(
            "internal static string BuildEximNativeRestoreApplyBundle(", 1)[0]
        self.assertIn(" --mta sendmail --sendmail-v2-plan ", bundle)
        for token in (" --apply ", " --approve-sha256 ", " --confirm "):
            self.assertNotIn(token, bundle)
        parser = (CS / "SendmailV2Review.cs").read_text(encoding="utf-8")
        for token in ('Exact("ARCHIVE_SHA256", verifiedArchiveSha)', '"APPLY_AUTHORIZED"',
                      'Exact(field, "no")', "fields.Count != 0", "metadata > shared", "drift !="):
            self.assertIn(token, parser)
        self.assertIn("SendmailV2Review.SelfTest", (CS / "Program.cs").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
