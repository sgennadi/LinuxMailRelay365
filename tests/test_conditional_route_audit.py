"""Per-rule SMTP audits are independent and do not authorize configuration writes."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src" / "LinuxMailRelay365"


class ConditionalRouteAuditContract(unittest.TestCase):
    def test_each_rule_uses_its_own_endpoint_and_exact_plan_context(self):
        ui = (CS / "MainForm.ConditionalRouteAudit.cs").read_text(encoding="utf-8")
        planner = (CS / "MainForm.AdvancedRoutes.cs").read_text(encoding="utf-8")
        for marker in ("AdvancedRoutePlanner.PlanSha256(advancedRoutingRules)",
                       "inspectedMail!.ConfigSha256", "TryCurrentIdentity()",
                       "advancedRoutingRules[index] == rule",
                       "rule.Host, rule.Port, rule.TlsMode",
                       "ConditionalRouteAudit.Parse(rule, result.StdOut, withAuth)",
                       "conditionalRouteAudits[index] = report", "secret.Clear()",
                       "UseSystemPasswordChar = true", "SshRemote.ExecuteAsync"):
            self.assertIn(marker, ui)
        self.assertIn("ShowConditionalRouteDiagnostics(line, width - 75, l, at, rule)", planner)
        self.assertNotIn("RunRootScriptAsync", ui)
        self.assertNotIn("result.StdErr", ui)
        self.assertNotIn("File.Write", ui)
        self.assertNotIn("postconf -e", ui)
        self.assertNotIn("ApplyReviewed", ui)
        self.assertIn("ConditionalRouteAudit.SelfTest",
                      (CS / "Program.cs").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
