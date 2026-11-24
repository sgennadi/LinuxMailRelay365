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
        # Both directions now call the same guarded certificate-entry helper.
        # Preserve the requirement that no TPM check runs on unrelated pages.
        entry = FORM.split("private Task ProbeOnCertificateEntryAsync()", 1)[1].split(
            "private bool CanAdvanceWizard()", 1)[0]
        self.assertIn("!pageRenderFailed && step == 2 && deliveryPhase == 2", entry)
        self.assertIn("RequiresOAuthCertificate() && !CertificateHardwareProbeCurrent()", entry)
        self.assertIn("return RunBusyAsync(\"linux-security\", AutoProbeCertificateHardwareAsync);", entry)
        for signature, end in (
            ("private async Task MoveWizardBackAsync()", "private Task ProbeOnCertificateEntryAsync()"),
            ("private async Task MoveWizardNextAsync()", "private void RenderPageCore()")):
            navigation = FORM.split(signature, 1)[1].split(end, 1)[0]
            self.assertIn("await ProbeOnCertificateEntryAsync();", navigation)
        self.assertIn("await CheckLinuxSecurityAsync();", DELIVERY)
        self.assertIn("await InspectTpmProviderAsync();", DELIVERY)
        self.assertIn("await PreviewTpmDependenciesAsync();", DELIVERY)
        # Navigation was consolidated into explicit route-specific sequences.
        self.assertIn("keep ? [0, DeliveryReviewPhase]", DELIVERY)
        self.assertIn("oauth ? [0, 1, 2, 3, DeliveryReviewPhase]", DELIVERY)
        self.assertIn("[0, 1, DeliveryReviewPhase]", DELIVERY)
        for name in ("NextDeliveryPhase()", "PreviousDeliveryPhase()"):
            self.assertIn(name + " => AdjacentDeliveryPhase", DELIVERY)
        self.assertIn("DeliveryNavigationSelfTest()", DELIVERY)

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
