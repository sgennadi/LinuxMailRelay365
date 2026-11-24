from pathlib import Path
import unittest

CS = Path(__file__).resolve().parents[1] / "src/LinuxMailRelay365"
FORM = (CS / "MainForm.cs").read_text(encoding="utf-8")
DELIVERY = (CS / "MainForm.DeliveryMiniWizard.cs").read_text(encoding="utf-8")
FLOW = (CS / "MainForm.MailFlow.cs").read_text(encoding="utf-8")

class DeliveryMiniWizardTests(unittest.TestCase):
    def test_certificate_tools_moved_not_deleted(self):
        plan = FORM.split("            case 1:\n                EnsureSecurityLoaded();", 1)[1].split(
            "            case 2:\n                EnsureRoutingLoaded();", 1)[0]
        self.assertNotIn("TPM", plan)
        self.assertNotIn("CheckLinuxSecurityAsync", plan)
        section = FORM.split("private void ShowCertificateSecurityTools", 1)[1].split(
                "private void ShowDeliveryCloudSecurityTools", 1)[0]
        for action in ("PreviewPrimaryOAuthRotationAsync", "PreviewTpmDependenciesAsync",
                       "InstallTpmDependenciesAsync", "PreviewTpmKeyAsync", "ApplyTpmKeyAsync",
                       "VerifyOfflineHardwareOAuthAsync"):
            self.assertIn(action, section)
        self.assertIn("ShowCertificateProtection(page);", FORM)
        self.assertIn("Create software PEM certificate on Linux", FORM)
        self.assertIn("await RunBusyAsync(\"linux-security\", AutoProbeCertificateHardwareAsync)", FORM)
        self.assertIn("await CheckLinuxSecurityAsync();", DELIVERY)
        self.assertIn("await InspectTpmProviderAsync();", DELIVERY)
        self.assertIn("await PreviewTpmDependenciesAsync();", DELIVERY)
        self.assertIn("RequiresOAuthCertificate() ? 2 : DeliveryReviewPhase", DELIVERY)

    def test_provider_and_advanced_paths_stay_available(self):
        self.assertIn("ShowMailFlowPlanner(page, providerChecksOnly: true)", FORM)
        self.assertIn("ShowMailFlowPlanner(page, advancedOnly: true)", FORM)
        self.assertIn("ShowMailFlowPlanner(page, DeliveryReviewDiagramPhase)", FORM)
        self.assertIn("if (providerChecksOnly) return;", FLOW)
        self.assertIn("ShowGoogleSmtpChecks(page)", FLOW)
        self.assertIn("ShowCustomSmtpChecks(page, width, languageIndex)", FLOW)
        self.assertIn("ShowMultiTransportActions(page, width, languageIndex)", FLOW)
        self.assertIn("renderedDeliveryPhase == deliveryPhase", FORM)
        self.assertIn("Delivery mini wizard did not reset scroll.", FORM)

    def test_semantic_highlights(self):
        theme = (CS / "UiTheme.cs").read_text(encoding="utf-8")
        for name in ("InfoSurface", "WarningSurface", "SuccessSurface", "SystemInformation.HighContrast"):
            self.assertIn(name, theme)
        self.assertIn("UiTheme.HighlightInput(input);", FORM)
        self.assertIn("UiTheme.Emphasis(", DELIVERY)
