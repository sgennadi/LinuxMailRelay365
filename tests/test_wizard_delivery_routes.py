"""GUI contract: one universal explainable wizard, three separate outbound routes.

The user may save a multi-mailbox XOAUTH2 *plan* but may not treat it as a
working transport until server-side ownership + Exchange permissions exist.
These tests verify the GUI-source contract without launching a GUI or sending.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class WizardDeliveryRoutesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = ROOT / "src" / "LinuxMailRelay365"
        cls.form = (root / "MainForm.cs").read_text(encoding="utf-8")
        cls.plan = (root / "MailRoutingPlan.cs").read_text(encoding="utf-8")
        cls.guide = (root / "MailRoutingGuidance.cs").read_text(encoding="utf-8")
        cls.flow = (root / "PreserveMailFlowPreview.cs").read_text(encoding="utf-8")
        cls.program = (root / "Program.cs").read_text(encoding="utf-8")

    def test_distinct_transport_and_sender_modes(self):
        for needle in ('"oauth2"', '"connector"', '"direct-send"',
                       'oauthSenderMode', 'senderPolicy',
                       'LocalizeDeliveryChoices();',
                       'XOAUTH2 sender policy',
                       'Connector sender policy',
                       'senderPolicy.SelectedIndex != 0'):
            self.assertIn(needle, self.form)

    def test_live_diagram_and_help_from_entered_values(self):
        self.assertIn('MailRoutingGuidance.Explain(', self.form)
        self.assertIn('AddLine(page, deliveryModeExplanation);', self.form)
        self.assertIn('AddLine(page, preserveFlowPreview);', self.form)
        self.assertIn('deliveryModeExplanation.Width = width;', self.form)
        self.assertIn('PreserveFlowSnapshot(', self.form)
        self.assertIn('mailTransport.SelectedIndex switch', self.form)
        self.assertIn('outboundMxHost.Text.Trim(), outboundFixedSender.Text.Trim()', self.form)
        for transport in ['"connector"', '"direct-send"', '"oauth2"']:
            self.assertIn(transport, self.guide)
        self.assertIn('return "smtp.office365.com:587', self.guide)
        self.assertIn('":25 · STARTTLS/EOP"', self.guide)
        self.assertIn('MailRouteTitle', self.flow)
        self.assertIn('MailRouteHint', self.flow)
        self.assertIn('Outgoing', self.guide.replace('Outbound', 'Outgoing'))

    def test_multi_mailbox_is_plan_only_and_apply_and_test_refuse(self):
        self.assertIn('OAuthSenderMode { get; set; }', self.plan)
        self.assertIn('OAuthSenderMapPath { get; set; }', self.plan)
        self.assertIn('authorized-multiple-mailboxes', self.plan)
        self.assertIn('"/etc/linuxmailrelay365/"', self.plan)
        self.assertIn('if (mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 1)',
                      self.form)
        self.assertGreaterEqual(
            self.form.count('if (mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 1)'), 2)
        self.assertIn('Multi-mailbox XOAUTH2 is an unimplemented', self.form)
        self.assertIn('current transport uses one fixed mailbox', self.form)
        self.assertIn('NotDeployablePlan', self.flow)
        self.assertIn('MailRoutingGuidance.IsUnimplementedOAuthMultiSender', self.flow)
        self.assertIn('MULTI-MAILBOX XOAUTH2 IS NOT DEPLOYABLE YET', self.guide)

    def test_ru_en_he_selected_controls_and_selftests(self):
        self.assertIn('int lang = language.SelectedIndex;', self.form)
        self.assertIn('XOAUTH2 — ящик Microsoft 365', self.form)
        self.assertIn('XOAUTH2 — תיבת דואר Microsoft 365', self.form)
        self.assertIn('XOAUTH2 — authorized Microsoft 365', self.form)
        self.assertIn('Live delivery route explanations', self.program)
        self.assertIn('MailRoutingGuidance.SelfTest', self.program)
        self.assertIn('PreserveFlowSnapshot.SelfTest', self.program)
        self.assertIn('MailRoutingPlanStore.SelfTest', self.program)

    def test_delivery_choice_before_necessary_entra_setup(self):
        section = self.form.split("            case 2:", 1)[1].split("            case 3:", 1)[0]
        self.assertIn("First select HOW Linux will deliver mail through Microsoft 365", section)
        self.assertIn("AddLine(page, BuildDeliveryModeChoices());", section)
        self.assertLess(section.index("AddLine(page, BuildDeliveryModeChoices());"),
                        section.index("if (mailTransport.SelectedIndex is 1 or 2)"))
        # One source of truth: changing a tile updates the mode ComboBox and
        # its existing plan-only event, without creating a delivery route.
        self.assertIn("mailTransport.SelectedIndex = index;", self.form)
        self.assertIn("selected ? UiTheme.Accent : Color.White", self.form)
        self.assertIn("UseWideDeliveryChoices(", self.form)
        self.assertIn("DeliveryModeOverview.Describe(mode,", self.form)
        self.assertNotIn("AddLine(page, mailTransport);", section)
        self.assertIn("Connector and Direct Send do NOT require an Entra application", section)
        self.assertIn("Certificate", self.form)
        self.assertIn("step is 2 or 3", self.form)

    def test_multi_mailbox_audit_is_exposed_without_enabling_transport(self):
        project = (ROOT/"src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        assets = (ROOT/"src/LinuxMailRelay365/EmbeddedAssets.cs").read_text(encoding="utf-8")
        self.assertIn("Audit SMTP login → sender → M365 mailbox map (read-only)", self.form)
        self.assertIn("InspectOAuthSenderMapAsync, false", self.form)
        self.assertIn("private async Task InspectOAuthSenderMapAsync()", self.form)
        self.assertIn("BuildOAuthSenderMapAuditBundle(", self.form)
        self.assertIn("BuildOAuthSenderMapAuditBundle(string mapPath)", assets)
        self.assertIn("OAUTH_SENDER_MAP_EXCHANGE_SENDAS_VERIFIED", self.form)
        self.assertIn("OAUTH_SENDER_MAP_MESSAGES_SENT", self.form)
        self.assertIn("No route was enabled.", self.form)
        self.assertIn('OAUTH_SENDER_MAP_POLICY_SIMULATION=passed_offline_only', 
                      (ROOT/"linux/audit-oauth-sender-map.py").read_text(encoding="utf-8"))
        self.assertIn("oauthSenderAuditSummary", self.form)
        self.assertIn("synthetic policy cases. PLAN ONLY.", self.form)
        self.assertIn("sender map, or delivery mode changed during audit", self.form)
        self.assertIn('oauthSenderMapPath.Text.Trim() != auditedPath', self.form)

        self.assertIn("LinuxMailRelay365.linux.oauth-sender-map-audit.py", project)
        self.assertIn("LMR365_OAUTH_MAP_AUDIT", assets)
        self.assertIn("Only an absolute /etc/linuxmailrelay365/", assets)

    def test_oauth_ingress_inspection_is_read_only_and_stays_non_deployable(self):
        project = (ROOT/"src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        assets = (ROOT/"src/LinuxMailRelay365/EmbeddedAssets.cs").read_text(encoding="utf-8")
        self.assertIn("Compare sender map with installed SMTP AUTH and From Guard (read-only)", self.form)
        self.assertIn("InspectOAuthIngressAsync, false", self.form)
        self.assertIn("private async Task InspectOAuthIngressAsync()", self.form)
        self.assertIn("BuildOAuthIngressAuditBundle(auditedPath)", self.form)
        self.assertIn('["OAUTH_INGRESS_MULTI_MAILBOX_ENABLED"] = @"\\Ano\\z"', self.form)
        self.assertIn('["OAUTH_INGRESS_REAL_SMTP_LOGIN_VERIFIED"] = @"\\Ano\\z"', self.form)
        self.assertIn('["OAUTH_INGRESS_M365_SENDAS_VERIFIED"] = @"\\Ano\\z"', self.form)
        self.assertIn("SMTP host, sender policy or map changed while inspecting", self.form)
        self.assertIn("ingress_config_consistent_not_live_verified", self.form)
        self.assertIn("oauthIngressAuditSummary", self.form)
        self.assertIn('private string oauthIngressAuditSummary = "";', self.form)
        self.assertIn("BuildOAuthIngressAuditBundle(string mapPath)", assets)
        self.assertIn("LMR365_OAUTH_INGRESS_AUDIT", assets)
        self.assertIn("LMR365_OAUTH_SENDER_MAP_LIB", assets)
        self.assertIn("LinuxMailRelay365.linux.oauth-ingress-audit.py", project)
        self.assertIn("Read-only XOAUTH2 ingress comparison bundle", self.program)

    def test_mode_specific_final_step_and_installer_do_not_offer_wrong_route(self):
        section = self.form.split("            case 4:", 1)[1].split(
            "        pageHost.ResumeLayout();", 1)[0]
        self.assertIn("EnsureRoutingLoaded();", section)
        self.assertIn("mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 0", section)
        self.assertIn("InspectRelayHealthAsync, true", section)
        self.assertIn("CheckOutboundModeAsync, false", section)
        self.assertIn("SendTestAsync, false", section)
        self.assertIn("Multi-mailbox XOAUTH2 is PLAN ONLY", section)
        self.assertIn("a valid token does NOT prove message delivery", section)
        self.assertIn("For real delivery acceptance", section)
        self.assertIn("OAuth token diagnostics require the active single-mailbox XOAUTH2 route.", self.form)
        self.assertIn("Install and configure XOAUTH2 Postfix", self.form)
        self.assertIn("The XOAUTH2 installer is not offered", self.form)
        self.assertIn("05-connector-diagnostics.png", self.form)
        self.assertIn("05-direct-send-diagnostics.png", self.form)
        self.assertIn("05-xoauth2-multi-plan-only.png", self.form)

    def test_automatic_mta_discovery_after_verified_ssh(self):
        project = ROOT / "src" / "LinuxMailRelay365"
        advisor = (project / "MailServerDiscoveryDecision.cs").read_text(encoding="utf-8")
        connect = self.form.split("private async Task CheckSshAndContinueAsync()", 1)[1].split(
            "internal static bool UseWideDeliveryChoices", 1)[0]
        self.assertLess(connect.index("await CheckSshAsync();"),
                        connect.index("await InspectMailRoutingAsync();"))
        self.assertIn("ShowMailDiscovery(page, true);", self.form)
        self.assertGreaterEqual(self.form.count("ShowMailDiscovery(page, false);"), 2)
        self.assertIn("Read-only MTA discovery:", self.form)
        self.assertIn("HasIsolatedSidecarAsync(", self.form)
        self.assertIn("no Microsoft 365 delivery mode selected automatically", self.form)
        self.assertIn("MailServerDiscoveryDecision.Assess(", self.form)
        for status in ("postfix_active", "foreign_mta_active", "installed_but_not_active",
                       "suspected_unsafe_relay", "no_standard_mta_detected",
                       "existing_isolated_relay", "conflicting_or_unknown_mta"):
            self.assertIn(status, advisor)
        self.assertIn("MailServerDiscoveryDecision.SelfTest", self.program)
        self.assertIn("Do not assume an empty mail server", advisor)
        self.assertIn("No changes were made", advisor)
        self.assertIn("ConfirmCurrentActiveMtaForInstallationAsync", self.form)
        self.assertGreaterEqual(
            self.form.count("await ConfirmCurrentActiveMtaForInstallationAsync(endpoint, inventory);"), 3)
        self.assertIn("Postconf binary presence is NOT evidence", self.form)
        self.assertIn("InstallationSafetyStatus(", advisor)
        self.assertIn("unattributed_smtp_listener_or_unknown", advisor)
        audit = (project / "ExistingSmtpAudit.cs").read_text(encoding="utf-8")
        self.assertIn("StandardPortSockets =>", audit)
        probe = (ROOT / "linux" / "probe-linux.sh").read_text(encoding="utf-8")
        self.assertIn("active_exim", probe)
        self.assertIn("active_sendmail", probe)
        self.assertLess(probe.index("elif (( active_exim == 1 ))"), probe.index("elif has postconf; then"))

    def test_previous_mail_not_silently_reconfigured(self):
        self.assertIn('KeepExisting', self.flow)
        self.assertIn('mailTransport.SelectedIndex != 1', self.form)
        self.assertIn('The active transport rewrites all From addresses to one mailbox', self.form)
        self.assertIn('PLAN PREVIEW ONLY — NOT PROOF OF DEPLOYMENT', self.guide)
        self.assertIn('Changing the primary MTA requires a backup', self.guide)


if __name__ == "__main__":
    unittest.main()
