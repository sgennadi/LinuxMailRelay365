from pathlib import Path
import unittest

FORM = (Path(__file__).resolve().parents[1] / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")

class WizardScrollContract(unittest.TestCase):
    def test_single_render_owner(self):
        self.assertEqual(FORM.count("pageHost.SuspendLayout();"), 1)
        self.assertIn("if (IsDisposed || Disposing || renderingPage) return;", FORM)
        self.assertIn("pageHost.ResumeLayout(true);", FORM)
        self.assertIn("pageHost.Rebuilding = true;", FORM)
        self.assertIn("pageHost.Rebuilding = false;", FORM)
        self.assertIn("Math.Clamp(requested, 0, Math.Min(contentMax, barMax))", FORM)
        self.assertNotIn("pageHost.AutoScrollPosition = new Point(0, previousScroll)", FORM)
        self.assertIn("QueueWizardRefresh();", FORM)
        self.assertIn("HasFocusedWizardInput(pageHost)", FORM)
        self.assertIn("Wizard viewport is blank.", FORM)
        self.assertIn("pageHost.ControlRemoved += nested;", FORM)
        self.assertIn("if (pageRenderFailed)", FORM)
