"""Static wiring checks; Windows CI separately runs the C# self-test."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src/LinuxMailRelay365"


class TransportEditGuiContract(unittest.TestCase):
    def test_matching_embedded_modules_and_self_test(self):
        client = (CS / "TransportEditClient.cs").read_text(encoding="utf-8")
        assets = (CS / "EmbeddedAssets.cs").read_text(encoding="utf-8")
        names = {e.attrib.get("Include") for e in
                 ET.parse(CS / "LinuxMailRelay365.csproj").iter("EmbeddedResource")}
        for name in ("conditional-transport-edit.py", "conditional-transport-edit-transaction.py",
                     "manage-conditional-transport-edit.py"):
            self.assertIn("../../linux/" + name, names)
            self.assertIn("LinuxMailRelay365.linux." + name, assets)
            self.assertIn(name, client)
        self.assertIn("TransportEditClient.SelfTest", (CS / "Program.cs").read_text(encoding="utf-8"))

    def test_separate_approvals_and_no_service_or_secret_logging(self):
        client = (CS / "TransportEditClient.cs").read_text(encoding="utf-8")
        ui = (CS / "MainForm.TransportEdit.cs").read_text(encoding="utf-8")
        panel = (CS / "MainForm.MultiTransport.cs").read_text(encoding="utf-8")
        for marker in ("SWITCH_STOPPED_POSTFIX_TRANSPORTS", "COMMIT_STOPPED_POSTFIX_TRANSPORT_EDIT",
                       "ROLLBACK_STOPPED_POSTFIX_TRANSPORT_EDIT", "fields.SetEquals(f.Keys)",
                       "!result.TryAdd", "exitCode != 0", "SMTP_AUTH_ATTEMPTED",
                       "--approve-review-sha256", "--approve-plan-sha256"):
            self.assertIn(marker, client)
        for marker in ("ConfirmRotationMaintenance(", "ConfirmDestructive(",
                       "ReferenceEquals(transportEditReview, review)",
                       "ReferenceEquals(transportEditRecovery, review)",
                       "review.RetainIndices[i] > 0", "PromptRouteCredential(",
                       "Array.Clear(slots)", "if (attempted) InvalidateAfterCredentialRotation();",
                       "TransportEditClient.ParseResolution", "TransportEditClient.ParseRecovery"):
            self.assertIn(marker, ui)
        self.assertIn("if (ShowTransportEditActions(page, width, l)) return;", panel)
        for forbidden in ("result.StdErr", "systemctl start", "systemctl stop",
                          "postfix reload", "File.WriteAllText", "ex.Message"):
            self.assertNotIn(forbidden, client)
            self.assertNotIn(forbidden, ui)


if __name__ == "__main__":
    unittest.main()
