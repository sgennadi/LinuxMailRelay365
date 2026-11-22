from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src/LinuxMailRelay365'
AUTH = ROOT / 'src/Microsoft365Auth'

class TenantDiscoveryContracts(unittest.TestCase):
    def test_tenant_selection_requires_manual_choice_when_multiple(self):
        main = (SRC / 'MainForm.cs').read_text(encoding='utf8')
        self.assertIn('Sign in to Microsoft Entra (C# / MSAL)', main)
        self.assertIn('tenantSelector.SelectedIndex = choices.Count == 1 ? 0 : -1;', main)
        self.assertIn('discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption', main)
        self.assertIn('Tenant ID does not match the selected Microsoft Entra organization.', main)
        self.assertIn('Use manual Tenant ID instead', main)
        self.assertIn('discoveredTenants = Array.Empty<TenantOption>();', main)

    def test_native_graph_and_arm_tenant_read_only(self):
        csharp = (AUTH / 'EntraTenantDiscoveryClient.cs').read_text(encoding='utf8')
        self.assertIn('PublicClientApplicationBuilder.Create', csharp)
        self.assertIn('AcquireTokenWithDeviceCode', csharp)
        self.assertIn('AcquireTokenSilent', csharp)
        self.assertIn('https://graph.microsoft.com/v1.0/organization?', csharp)
        self.assertIn('https://management.azure.com/tenants?api-version=2022-12-01', csharp)
        self.assertIn('https://graph.microsoft.com/User.Read', csharp)
        self.assertIn('https://management.azure.com/user_impersonation', csharp)
        self.assertIn('approved_public_client_id_required', csharp)
        self.assertIn('loggedIn', csharp)
        self.assertIn('tenant_mismatch', csharp)
        self.assertIn('IsExpectedArmUrl(next)', csharp)
        for forbidden in ('Save-AzContext', 'Connect-AzAccount', 'Get-AzTenant',
                          'client_secret', 'tenantPass', 'password='):
            self.assertNotIn(forbidden, csharp)
        self.assertNotIn('File.WriteAllText', csharp)
        self.assertNotIn('File.WriteAllBytes', csharp)

    def test_device_code_has_visible_native_gui_and_cancellation(self):
        code = (SRC / 'NativeDeviceCodeDialog.cs').read_text(encoding='utf8')
        main = (SRC / 'MainForm.cs').read_text(encoding='utf8')
        self.assertIn('AutoScaleMode = AutoScaleMode.Dpi', code)
        self.assertIn('Copy code', code)
        self.assertIn('Open Microsoft sign-in', code)
        self.assertIn('if (!completed) cancel();', code)
        self.assertIn('IsTrustedMicrosoftVerificationUrl', code)
        self.assertIn('WithNativeMicrosoftSignInAsync(', main)
        helper = (SRC / 'MainForm.NativeCloud.cs').read_text(encoding='utf8')
        self.assertIn('new NativeDeviceCodeDialog(cancellation.Cancel)', helper)
        self.assertIn('DiscoverAsync(', main)
        self.assertIn('dialog.Finish()', helper)
        self.assertNotIn('TenantDiscovery.FailureCode(', main)
        self.assertNotIn('EmbeddedAssets.TenantDiscoveryScript', main)

    def test_no_tenant_powershell_is_in_portable_exe(self):
        project = (SRC / 'LinuxMailRelay365.csproj').read_text(encoding='utf8')
        assets = (SRC / 'EmbeddedAssets.cs').read_text(encoding='utf8')
        self.assertIn('Microsoft365Auth.csproj', project)
        self.assertNotIn('Discover-LinuxMailRelay365Tenants.ps1', project)
        self.assertNotIn('TenantDiscoveryScript', assets)
        self.assertFalse((ROOT / 'windows/Discover-LinuxMailRelay365Tenants.ps1').exists())
        self.assertIn('EntraTenantDiscoveryClient.SelfTest', (SRC / 'Program.cs').read_text('utf8'))

    def test_exchange_stays_fail_closed_if_another_tenant(self):
        script = (ROOT / 'windows/Initialize-LinuxMailRelay365.ps1').read_text(encoding='utf8')
        conn = script.index('Get-ConnectionInformation -ErrorAction Stop')
        first_mutation = script.index('Set-CASMailbox')
        self.assertLess(conn, first_mutation)
        self.assertIn('[guid]$connections[0].TenantID -ne $TenantId', script)
        self.assertIn('No Exchange settings were changed.', script)

if __name__ == '__main__':
    unittest.main()
