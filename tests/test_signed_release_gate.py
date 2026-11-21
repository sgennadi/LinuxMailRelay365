"""Production signing requires exact publisher and real trusted signatures."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "Test-LinuxMailRelay365SignedRelease.ps1"


class SignedReleaseContracts(unittest.TestCase):
    def test_no_unsigned_or_unpinned_stable_release(self):
        src = SCRIPT.read_text(encoding="utf-8")
        for token in ("Get-AuthenticodeSignature", "SignatureStatus]::Valid",
                      "PublisherThumbprint", "Get-PeMachine", "0x8664", "0xAA64",
                      "Get-FileHash", "SHA256", "CreateNew",
                      "RELEASE_PRODUCTION_ACCEPTED=no",
                      "not preview", "Exact publisher"):
            self.assertIn(token.lower(), src.lower())
        for forbidden in ("Set-AuthenticodeSignature", "Start-Process",
                          "Invoke-WebRequest", "gh release create",
                          "New-Item -Path Env:"):
            self.assertNotIn(forbidden, src)

    def test_readonly_selftest_contract(self):
        src = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("RELEASE_SIGNATURE_GATE_SELF_TEST=pass", src)
        self.assertIn("RELEASE_PUBLISHED=no", src)
        self.assertIn("requires_test_tenant_acceptance", src)


if __name__ == "__main__":
    unittest.main()
