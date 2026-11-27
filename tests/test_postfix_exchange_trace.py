import importlib.util
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("probe", ROOT / "linux/review-postfix-m365-delivery.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class ExchangeTraceContracts(unittest.TestCase):
    def test_ledger_proof_in_trace(self):
        req = {"run_id": "a"*32, "accepted_domain": "example.org", "internal": "test@example.org"}
        with patch.object(M, "ledger", return_value=(123, {"internal": "attempted", "external": "not_attempted"})), \
             patch.object(M, "load_adapter"), patch.object(M, "log_lines", return_value=([], "journal_unavailable")), \
             patch.object(M, "queue_rows", return_value=None):
            result = M.trace(req)
        self.assertEqual(result["started_unix"], 123)
        self.assertEqual(result["outcomes"]["internal"]["submission"], "attempted")
        self.assertEqual(result["outcomes"]["external"]["transport"], "not_attempted")
        self.assertEqual(result["request_sha256"], M.digest(M.canonical(req)))
        self.assertFalse(result["inbox_verified"])

    def test_cloud_reads_only_exact_trace(self):
        source = (ROOT / "windows/Inspect-LinuxMailRelay365MessageTrace.ps1").read_text()
        self.assertIn("Get-MessageTraceV2 @query", source)
        self.assertIn("MessageId=$id; SenderAddress=$request.sender; RecipientAddress=$request[$role]", source)
        self.assertGreaterEqual(source.count("Assert-Tenant $TenantId"), 4)
        self.assertIn("if ($role -cnotin $attempted)", source)
        self.assertIn("EXO_MESSAGE_TRACE_SELF_TEST=pass", source)
        for forbidden in ("Send-MailMessage", "New-InboundConnector", "Set-InboundConnector", "Remove-InboundConnector", "Invoke-Expression", "New-MgServicePrincipal"):
            self.assertNotIn(forbidden, source)

    def test_wired_into_gui_and_ci(self):
        src = ROOT / "src/LinuxMailRelay365"
        self.assertIn("ReadPostfixExchangeTraceAsync", (src / "MainForm.DeliveryMiniWizard.cs").read_text())
        ui = (src / "MainForm.PostfixExchangeTrace.cs").read_text()
        self.assertIn("WriteRestrictedGraphPayload(input, payload)", ui)
        self.assertIn('proof.GetProperty("request_sha256").GetString() != requestSha', ui)
        self.assertIn('proof.GetProperty("started_unix")', ui)
        self.assertIn("CheckCloudTenant(id)", ui)
        self.assertIn('remote("trace", request, null)', (src / "PostfixM365DeliveryDialog.cs").read_text())
        self.assertIn("Inspect-LinuxMailRelay365MessageTrace.ps1", (src / "LinuxMailRelay365.csproj").read_text())
        self.assertIn("./windows/Inspect-LinuxMailRelay365MessageTrace.ps1 -SelfTest", (ROOT / ".github/workflows/ci.yml").read_text())
