"""GUI source-map mutation boundaries; Windows self-test validates receipts."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src/LinuxMailRelay365"
UI = (CS / "MainForm.MultiMailboxIdentities.cs").read_text(encoding="utf-8")
MODEL = (CS / "MultiMailboxSourceEdit.cs").read_text(encoding="utf-8")
HELPER = (ROOT / "linux/edit-multi-mailbox-source.py").read_text(encoding="utf-8")


class SourceEditorGui(unittest.TestCase):
    def test_preview_confirmation_save_readback(self):
        flow = UI.split("async Task EditSourceAsync", 1)[1].split("addMailbox.Click", 1)[0]
        for marker in ('SelectedScope() != "source"', "fresh.Source.Rows.SequenceEqual(oldMap.Rows)",
                       "Execute(null)", "ConfirmDestructive(", "ResetMultiMailboxRouteReview();",
                       "saveAttempted = true;", "Execute(preview)", "latest.Source.Sha256 != preview.NewSha"):
            self.assertIn(marker, flow)
        self.assertLess(flow.index("Execute(null)"), flow.index("ConfirmDestructive("))
        self.assertLess(flow.index("ConfirmDestructive("), flow.index("Execute(preview)"))
        self.assertLess(flow.index("Execute(preview)"), flow.index("latest.Source.Sha256 != preview.NewSha"))
        self.assertIn("if (saveAttempted) saveUncertain = true;", flow)
        self.assertIn("!saveUncertain", UI)
        self.assertNotIn("InstallMultiMailbox", flow)
        self.assertNotIn("ApplyMultiMailbox", flow)

    def test_backup_catalog_is_read_only_and_still_requires_preview(self):
        flow = UI.split("async Task EditSourceAsync", 1)[1].split("addMailbox.Click", 1)[0]
        self.assertLess(flow.index("MultiMailboxSourceBackupCatalog.Parse"), flow.index("PromptMultiMailboxSourceEdit"))
        self.assertLess(flow.index("PromptMultiMailboxSourceEdit"), flow.index("Execute(null)"))
        catalog = HELPER.split("def backup_catalog(", 1)[1].split("def restore_plan(", 1)[0]
        self.assertIn("restore_backup(", catalog)
        self.assertNotIn("identity_row(", catalog)
        self.assertNotIn("write_new(", catalog)
        self.assertNotIn("os.replace(", catalog)
        self.assertIn('req["action"] == "list_backups"', HELPER)

    def test_receipt_requires_exact_plan_and_no_runtime_change(self):
        for marker in ("plan != approved", '"runtime_changed", "mail_sent", "cloud_changed"',
                       'Read("nonce") != req.Nonce', 'Read("base_sha") != req.BaseSha',
                       'row.Mailbox != req.Mailbox', 'root.GetProperty("old_count").GetInt32() != req.BaseCount'):
            self.assertIn(marker, MODEL)
        self.assertIn("MultiMailboxSourceEditPlan.SelfTest", (CS / "Program.cs").read_text(encoding="utf-8"))
        self.assertIn('LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")', HELPER)
        self.assertIn("backup_id = backup(old, result)", HELPER)
        self.assertLess(HELPER.index("backup_id = backup(old, result)"), HELPER.index("os.replace(str(stage), str(SOURCE))"))


if __name__ == "__main__":
    unittest.main()
