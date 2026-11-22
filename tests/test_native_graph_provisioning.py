"""Offline contracts for C#-native Entra provisioning and Exchange-only PowerShell.

No live tenant, SMTP send, certificate enrollment, or Graph mutation occurs.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CS = ROOT / "src" / "LinuxMailRelay365"
AUTH = ROOT / "src" / "Microsoft365Auth"
EXO = ROOT / "windows" / "Initialize-LinuxMailRelay365.ps1"

class NativeEntraProvisioning(unittest.TestCase):
    def test_native_graph_uses_only_delegated_app_write_and_postchecks(self):
        code = (AUTH / "EntraGraphProvisioner.cs").read_text(encoding="utf-8")
        token = (AUTH / "EntraTenantDiscoveryClient.cs").read_text(encoding="utf-8")
        for phrase in (
            "AcquireGraphWriteTokenAsync", "Application.ReadWrite.All",
            "WithTenantId(exactTenant.ToString(\"D\"))",
        ):
            self.assertIn(phrase, token)
        for phrase in (
            "ParsePublicCertificate(publicCertificatePem)",
            "if (certificate.HasPrivateKey",
            "rsa_public_certificate_required",
            "GetAppAsync(http, token, exactApp",
            "SameKeySet(existing, latest)",
            "app_credentials_changed_review_again",
            "keyCredentials = combined",
            "VerifyKeySetAsync(http, token, clientId",
            "created_enterprise_app_mismatch",
            "enterprise_app_postcheck_mismatch",
            "Sha256",
        ):
            self.assertIn(phrase, code)
        for forbidden in (
            "Graph Mail.Send", "Directory.ReadWrite.All",
            "Connect-MgGraph", "Connect-AzAccount", "client_secret",
            "Set-CASMailbox", "Set-ManagementScope",
            "File.WriteAllText", "Save-AzContext",
        ):
            self.assertNotIn(forbidden, code)
        self.assertIn('JsonPropertyName("key")', code)
        self.assertIn('JsonPropertyName("startDateTime")', code)
        self.assertIn("JsonIgnoreCondition.WhenWritingNull", code)

    def test_exchange_only_script_has_exact_tenant_gate(self):
        script = EXO.read_text(encoding="utf-8")
        self.assertIn("Get-ConnectionInformation -ErrorAction Stop", script)
        self.assertIn("[guid]$connections[0].TenantID -ne $TenantId", script)
        self.assertLess(script.index("Get-ConnectionInformation -ErrorAction Stop"),
                        script.index("New-ServicePrincipal"))
        self.assertLess(script.index("Get-ConnectionInformation -ErrorAction Stop"),
                        script.index("Set-CASMailbox"))
        self.assertIn("Application SMTP.SendAsApp", script)
        self.assertIn("Test-ServicePrincipalAuthorization", script)
        self.assertIn("EXO_BOOTSTRAP_PREFLIGHT=exchange_module_available_no_changes", script)
        for forbidden in ("Connect-MgGraph", "Get-MgContext", "Invoke-MgGraphRequest",
                          "Microsoft.Graph.Authentication", "Save-AzContext", "Install-Module"):
            self.assertNotIn(forbidden, script)
        for hint in ("appRegistration", "enterpriseApplication", "smtpRoleAssignment",
                     "mailboxTag", "addedCertificate", "createdObjectEvidence"):
            self.assertIn(hint, script)

    def test_wizard_checks_powershell_before_entra_write(self):
        main = (CS / "MainForm.cs").read_text(encoding="utf-8")
        section = main.split("private async Task SetupM365Async()", 1)[1].split(
            "private async Task VerifyM365Async()", 1)[0]
        self.assertLess(section.index("ExchangeOnlineManagement"),
                        section.index("MessageBox.Show(this"))
        self.assertLess(section.index("MessageBox.Show(this"),
                        section.index("EntraGraphProvisioner.ProvisionAsync"))
        self.assertLess(section.index("EntraGraphProvisioner.ProvisionAsync"),
                        section.index("Process.Start(psi)"))
        self.assertIn("WithNativeMicrosoftSignInAsync", section)
        self.assertIn("CloudInputs() != selected", section)
        self.assertIn("No automatic Graph deletion was attempted", section)
        self.assertIn('ArgumentList.Add("-AddedCertificate")', section)
        self.assertIn('ArgumentList.Add("-EnterpriseAppCreated")', section)
        self.assertIn('ArgumentList.Add("-AppCreated")', section)
        self.assertIn("await VerifyM365Async()", section)

if __name__ == "__main__":
    unittest.main()
