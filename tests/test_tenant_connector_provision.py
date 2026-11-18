"""New Exchange Connector creation requires reviewed exact-tenant plan."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "windows" / "Manage-LinuxMailRelay365Connector.ps1"


class ConnectorProvisionContracts(unittest.TestCase):
    def test_no_implicit_tenant_mutation(self):
        s = SCRIPT.read_text(encoding="utf-8")
        for item in ("CREATE_REVIEWED_M365_CONNECTOR", "Get-ConnectionInformation",
                     "[guid]$sessions[0].TenantID -ne $TenantId",
                     "Get-AcceptedDomain", "Get-InboundConnector",
                     "New-InboundConnector @options",
                     "EXO_CONNECTOR_REVIEW_SHA256=",
                     "EXO_CONNECTOR_DELIVERY_VERIFIED=no",
                     "CloudServicesMailEnabled = $false",
                     "ConnectorType = 'OnPremises'"):
            self.assertIn(item, s)
        for item in ("Set-InboundConnector ", "Remove-InboundConnector ",
                     "New-MgApplication", "Set-AcceptedDomain", "Invoke-Expression"):
            self.assertNotIn(item, s)


if __name__ == "__main__":
    unittest.main()
