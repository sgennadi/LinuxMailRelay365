"""Read-only Entra policy/license/sign-in migration: static no-tenant regression."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "src/Microsoft365Auth/EntraTenantDiscoveryClient.cs"
AUDIT = ROOT / "src/Microsoft365Auth/EntraGraphSecurityReadClient.cs"
GUI = ROOT / "src/LinuxMailRelay365/MainForm.cs"
PS1 = ROOT / "windows/Test-LinuxMailRelay365Security.ps1"


class NativeSecurityReadContracts(unittest.TestCase):
    def test_exact_3_delegated_read_scopes_and_tenant_bound_token(self):
        source = AUTH.read_text(encoding="utf-8")
        for scope in ("Policy.Read.All", "AuditLog.Read.All", "Organization.Read.All"):
            self.assertIn("https://graph.microsoft.com/" + scope, source)
        self.assertIn("AcquireGraphSecurityReadTokenAsync", source)
        self.assertIn('graph_wrong_tenant', source)
        self.assertIn('.WithTenantId(exactTenant.ToString("D"))', source)

    def test_fixed_paths_do_not_mutate_or_export_tenant_logs(self):
        code = AUDIT.read_text(encoding="utf-8")
        for path in (
            "identity/conditionalAccess/policies?$top=1",
            "auditLogs/signIns?$top=1",
            "subscribedSkus?$select=skuPartNumber,capabilityStatus",
        ):
            self.assertIn(path, code)
        self.assertIn("HttpMethod.Get", code)
        self.assertIn("AllowAutoRedirect = false", code)
        self.assertIn("ChangesApplied: false", code)
        for forbidden in ("HttpMethod.Post", "HttpMethod.Delete", "HttpMethod.Patch",
                          "WriteAllText(", "Set-ConditionalAccessPolicy",
                          "Console.WriteLine(token)", "Microsoft.Graph.Authentication"):
            self.assertNotIn(forbidden, code)

    def test_native_first_and_existing_ps1_manual_fallback(self):
        gui = GUI.read_text(encoding="utf-8")
        self.assertIn("if (!useLegacyEntraSecurityPowerShell.Checked)", gui)
        self.assertIn("EntraGraphSecurityReadClient.InspectAsync", gui)
        self.assertIn("Test-LinuxMailRelay365Security.ps1", gui)
        self.assertIn("Legacy Graph PowerShell 7 security check selected explicitly.", gui)
        self.assertIn("useLegacyEntraSecurityPowerShell.Enabled = !busy", gui)
        self.assertTrue(PS1.is_file())


if __name__ == "__main__":
    unittest.main()
