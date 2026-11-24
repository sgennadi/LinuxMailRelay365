"""Mini wizard separates planning decisions from configuration actions."""
from pathlib import Path
import unittest

CS = Path(__file__).resolve().parents[1] / "src/LinuxMailRelay365"
FORM = (CS / "MainForm.cs").read_text(encoding="utf-8")
FLOW = (CS / "MainForm.MailFlow.cs").read_text(encoding="utf-8")
PLAN = (CS / "MailScenarioPlanner.cs").read_text(encoding="utf-8")


class MiniWizardContract(unittest.TestCase):
    def test_second_step_is_phased(self):
        block = FORM.split("            case 1:\n                EnsureSecurityLoaded();", 1)[1].split(
            "            case 2:\n                EnsureRoutingLoaded();", 1)[0]
        for text in ("ShowMailPlanProgress(page)", "ShowMailDiscovery(page, true)",
                     "ShowMailFlowPlanner(page, mailPlanPhase)", "ShowRecipientAdvice(page)",
                     "ShowMailPlanSummary(page)", "ShowMailFlowPlanner(page, MailPlanReviewPhase)"):
            self.assertIn(text, block)
        self.assertNotIn("CheckLinuxSecurityAsync", block)
        self.assertNotIn("TPM/HSM", block)
        self.assertIn("private void ShowCertificateSecurityTools", FORM)
        self.assertIn("mailPlanProviderConfirmed", FORM)
        self.assertIn("option.Code == selectedMailScenario && option.Enabled", FLOW)

    def test_no_mutating_tools_in_planning_pages(self):
        for phase in ("phase == 1", "phase == 2", "phase == 4"):
            self.assertIn("if (" + phase + ") return;", FLOW)
        self.assertIn("if (phase == -1 && IsGoogleTarget && !advancedOnly)", FLOW)
        self.assertIn("if (phase == -1 && selectedMailTarget == MailFlowIntent.TargetCustom && !advancedOnly)", FLOW)
        self.assertIn("if (phase == -1)\n        {\n            // All existing technical tools", FLOW)
        self.assertIn('planOnly => "m365-pending"', FLOW)
        self.assertIn('\"m365-pending\" =>', PLAN)
        self.assertIn("BuildLiveMailFlowDiagram(planOnly: phase == MailPlanReviewPhase)", FLOW)

    def test_scroll_resets_on_subpage_and_checks_actual_viewport(self):
        self.assertIn("renderedMailPlanPhase == mailPlanPhase", FORM)
        self.assertIn("queuedMailPlanPhase != mailPlanPhase", FORM)
        self.assertIn("phase <= MailPlanReviewPhase", FORM)
        self.assertIn("phase <= DeliveryCertificateToolsPhase", FORM)
        self.assertIn("Mini wizard did not reset scroll.", FORM)
        self.assertIn("Continue without a plan (diagnostics)", FORM)


if __name__ == "__main__":
    unittest.main()
