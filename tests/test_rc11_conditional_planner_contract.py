"""RC11 local conditional-routing GUI safety contract.

The Python suite cannot execute WinForms on Linux. Its purpose here is to
prevent accidental wiring of an Apply, SSH, file persistence, or live MTA
mutation into a read-only Windows what-if panel. The C# executable self-test
exercises actual parsing/normalization, duplicate/overlap behavior and hashes.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src" / "LinuxMailRelay365"


class ConditionalRouteUiContractTests(unittest.TestCase):
    def test_what_if_planner_is_loaded_only_after_discovery(self):
        flow = (CS / "MainForm.MailFlow.cs").read_text(encoding="utf-8")
        guard = flow.index("if (!HasMailDiscovery())")
        cards = flow.index("ShowAdvancedConditionalRoutingPlanner(")
        self.assertLess(guard, cards)
        self.assertIn("selectedMailScenario", flow)
        self.assertIn("BuildMailFlowCards(choices", flow)

    def test_gui_is_local_only_without_hidden_mutation_or_persistence(self):
        ui = (CS / "MainForm.AdvancedRoutes.cs").read_text(encoding="utf-8")
        for disallowed in (
                "SshRemote.", "RunRootScriptAsync", "ExecuteAsync",
                "postconf -e", "postmap", "postfix reload", "SaveRoutingChoices(",
                "File.Write", "FileStream(", "Registry.",
                "ApplyAdvancedRoutingAsync", "ApplyConditionalRoutingAsync"):
            with self.subTest(disallowed=disallowed):
                self.assertNotIn(disallowed, ui)
        self.assertIn("private readonly List<AdvancedRouteRule>", ui)
        self.assertIn("HasMailDiscovery()", ui)
        self.assertIn("AdvancedRoutePlanner.Simulate", ui)
        self.assertIn("advancedRoutingRules.Clear()", ui)
        self.assertIn("NO Apply button", ui)

    def test_staged_simulation_denies_fake_precedence(self):
        engine = (CS / "AdvancedRoutePlanner.cs").read_text(encoding="utf-8")
        self.assertIn("overlap-requires-review", engine)
        self.assertIn("NO assumed precedence", (
            (CS / "MainForm.AdvancedRoutes.cs").read_text(encoding="utf-8")))
        self.assertIn("do not Apply", engine)
        self.assertIn("ExactEnvelopeSender", engine)
        self.assertIn("EnvelopeSenderDomain", engine)
        self.assertIn("RecipientDomain", engine)
        self.assertIn("MaximumRules = 24", engine)
        self.assertIn("TLS/AUTH combination", engine)
        self.assertIn("string PlanSha256", engine)

    def test_rule_cards_are_editable_without_postfix_changes(self):
        ui = (CS / "MainForm.AdvancedRoutes.cs").read_text(encoding="utf-8")
        self.assertIn("BeginAdvancedRouteEdit(", ui)
        self.assertIn("advancedRoutingEditIndex = -1", ui)
        self.assertIn("candidates[advancedRoutingEditIndex] = proposed", ui)
        self.assertIn("AdvancedRoutePlanner.ValidatePlan(candidates)", ui)
        self.assertIn("Cancel rule edit", ui)
        self.assertIn("simulation.SampleSender", ui)
        self.assertIn("simulation.SampleRecipient", ui)
        planner = (CS / "AdvancedRoutePlanner.cs").read_text(encoding="utf-8")
        self.assertIn("string SampleSender, string SampleRecipient", planner)

    def test_csharp_executable_self_test_is_registered(self):
        source = (CS / "Program.cs").read_text(encoding="utf-8")
        self.assertIn("AdvancedRoutePlanner.SelfTest", source)
        self.assertIn("CustomPostfixRoute.SelfTest", source)
        self.assertIn("MailScenarioPlanner.SelfTest", source)


if __name__ == "__main__":
    unittest.main()
