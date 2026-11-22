"""Native Graph addKey migration contract: offline, no tenant or mail access."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "src/Microsoft365Auth/EntraGraphCertificateAddKeyClient.cs"
GUI = ROOT / "src/LinuxMailRelay365/MainForm.cs"
NATIVE = ROOT / "src/LinuxMailRelay365/MainForm.NativeCloud.cs"
LEGACY = ROOT / "windows/Manage-LinuxMailRelay365EntraCertificate.ps1"
EXE = ROOT / "src/LinuxMailRelay365/Program.cs"


class NativeGraphAddKeyTests(unittest.TestCase):
    def test_native_default_and_manual_legacy_preserved(self):
        gui = GUI.read_text(encoding="utf-8")
        self.assertIn("if (!useLegacyEntraCertPowerShell.Checked)", gui)
        self.assertIn("EntraGraphCertificateAddKeyClient.PreviewAsync", gui)
        self.assertIn("EntraGraphCertificateAddKeyClient.AddAsync", gui)
        self.assertIn("EntraGraphCertificateAddKeyClient.PrepareWriteSignInAsync", gui)
        self.assertIn("Legacy Microsoft.Graph PowerShell 7 selected explicitly", gui)
        self.assertIn("Manage-LinuxMailRelay365EntraCertificate.ps1", gui)
        self.assertIn("ADD_REVIEWED_ENTRA_OAUTH_CERT", gui)
        self.assertTrue(LEGACY.is_file(), "Legacy path is preserved, not removed")

    def test_native_graph_requires_current_proof_and_no_secret_exports(self):
        code = LIB.read_text(encoding="utf-8")
        for text in (
            "AcquireGraphReadTokenAsync", "AcquireGraphWriteTokenAsync",
            "VerifyProof(ephemeralProof, objectId, oldCert)",
            "RSASignaturePadding.Pkcs1", "SHA1.HashData(active.RawData)",
            "graph_inventory_changed_since_preview",
            "applications/", "/addKey",
            "AllowAutoRedirect = false",
            "existing_certificate", "ENTRA_CERT_EXISTING_KEYS_PRESERVED=yes",
            "graph_addkey_may_have_succeeded_verify_manually",
            "CHANGES_APPLIED=entra_addkey_only",
        ):
            with self.subTest(text=text):
                self.assertIn(text, code)
        self.assertNotIn("/removeKey", code)
        self.assertNotIn("HttpMethod.Patch", code)
        self.assertNotIn("WriteAllText(", code)
        self.assertNotIn("Save-AzContext", code)
        self.assertNotIn("Console.WriteLine(ephemeralProof)", code)
        self.assertNotIn("MessageBox.Show(ephemeralProof)", code)

    def test_sign_in_is_in_process_and_uses_the_same_native_ui(self):
        code = NATIVE.read_text(encoding="utf-8")
        self.assertIn("ApprovedGraphPublicClientId", code)
        self.assertIn("WithNativeMicrosoftSignInAsync", code)
        self.assertIn("DefaultGraphClientId", code)
        exe = EXE.read_text(encoding="utf-8")
        self.assertIn("EntraGraphCertificateAddKeyClient.SelfTest", exe)

    def test_legacy_script_continues_to_require_proof(self):
        source = LEGACY.read_text(encoding="utf-8")
        self.assertIn("Verify-Pop", source)
        self.assertIn("addKey", source)
        self.assertIn("ADD_REVIEWED_ENTRA_OAUTH_CERT", source)


if __name__ == "__main__":
    unittest.main()
