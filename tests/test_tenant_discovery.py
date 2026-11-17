from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class TenantDiscoveryContracts(unittest.TestCase):
    def test_tenant_selection_requires_manual_choice_when_multiple(self):
        main = (ROOT / 'src/LinuxMailRelay365/MainForm.cs').read_text(encoding='utf8')
        self.assertIn('Connect to Microsoft 365 and discover tenants', main)
        self.assertIn('tenantSelector.SelectedIndex = choices.Count == 1 ? 0 : -1;', main)
        self.assertIn('discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption', main)
        self.assertIn('Tenant ID does not match the selected Microsoft Entra organization.', main)
        self.assertIn('Use manual Tenant ID instead', main)
        self.assertIn('discoveredTenants = Array.Empty<TenantOption>();', main)

    def test_azure_tenants_query_read_only_and_no_secrets(self):
        script = (ROOT / 'windows/Discover-LinuxMailRelay365Tenants.ps1').read_text(encoding='utf8')
        self.assertIn('Get-AzTenant', script)
        self.assertIn('Disable-AzContextAutosave -Scope Process', script)
        self.assertIn('Connect-AzAccount -UseDeviceAuthentication -Scope Process', script)
        self.assertIn("schema = 'linux-mail-relay-tenant-discovery/v1'", script)
        self.assertNotIn('Save-AzContext', script)
        self.assertNotIn('client_secret', script)
        self.assertIn('Move-Item -LiteralPath $tmp -Destination $ResultPath -Force', script)

    def test_exchange_fails_closed_if_another_tenant(self):
        script = (ROOT / 'windows/Initialize-LinuxMailRelay365.ps1').read_text(encoding='utf8')
        conn = script.index('Get-ConnectionInformation -ErrorAction Stop')
        first_mutation = script.index('Set-CASMailbox')
        self.assertLess(conn, first_mutation)
        self.assertIn('[guid]$connections[0].TenantID -ne $TenantId', script)
        self.assertIn('No Exchange settings were changed.', script)

    def test_tenant_discovery_script_embedded(self):
        proj = (ROOT/'src/LinuxMailRelay365/LinuxMailRelay365.csproj').read_text(encoding='utf8')
        assets = (ROOT/'src/LinuxMailRelay365/EmbeddedAssets.cs').read_text(encoding='utf8')
        self.assertIn('Discover-LinuxMailRelay365Tenants.ps1', proj)
        self.assertIn('TenantDiscoveryScript', assets)
        self.assertIn('TenantDiscovery.SelfTest', (ROOT/'src/LinuxMailRelay365/Program.cs').read_text())

if __name__ == '__main__':
    unittest.main()
