from pathlib import Path
import unittest

class CopyActivityContract(unittest.TestCase):
    def test_copy_uses_visible_log_only(self):
        source = (Path(__file__).resolve().parents[1] / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        method = source.split("private void CopyActivityWindow()", 1)[1].split("private static void ClearVisibleActivityText", 1)[0]
        self.assertIn("string snapshot = activity.Text;", method)
        self.assertIn("Clipboard.SetText(snapshot);", method)
        self.assertNotIn("journal.ExportJson", method)
        self.assertIn("activity.TextChanged += (_, _) => copyActivityButton.Enabled = activity.TextLength > 0;", source)
        self.assertIn("activityActions.Controls.Add(copyActivityButton);", source)
