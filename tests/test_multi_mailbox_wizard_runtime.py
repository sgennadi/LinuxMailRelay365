"""Multi-mailbox experimental Wizard contract: no accidental live route switch.

Static checks complement the Linux sender/installer unit tests; they do not
prove GUI layout at 200% DPI or actual Exchange Online SMTP delivery.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "LinuxMailRelay365"
GUI = (SRC / "MainForm.cs").read_text(encoding="utf-8")
RUNTIME_GUI = (SRC / "MainForm.MultiMailbox.cs").read_text(encoding="utf-8")
ASSETS = (SRC / "EmbeddedAssets.cs").read_text(encoding="utf-8")
PROJECT = (SRC / "LinuxMailRelay365.csproj").read_text(encoding="utf-8")


class MultiMailboxWizardRuntimeTests(unittest.TestCase):
    def test_guided_setup_preserves_explicit_actions(self):
        dialog=(SRC/"MainForm.MultiMailboxIdentities.cs").read_text(encoding="utf-8")
        progress=(SRC/"MultiMailboxWizardProgress.cs").read_text(encoding="utf-8")
        for fragment in ("newApp.Visible=prepareIdentity.Visible=Show(0)",
                         "addMailbox.Visible=editMailbox.Visible=removeMailbox.Visible=restoreSource.Visible=Show(1)",
                         "registerIdentity.Visible=configureScope.Visible=verify.Visible=Show(2)",
                         "testSmtpAuth.Visible=Show(3)",
                         "stageRoute.Visible=previewRoute.Visible=applyRoute.Visible=restoreTools.Visible=Show(4)",
                         "deliveryTools.Visible=Show(5)",
                         "StageMultiMailboxRuntimeForOwnerAsync(dialog)",
                         "ApplyMultiMailboxRouteOfflineForOwnerAsync(dialog)",
                         "guidedPlanSha!=reviewedMultiMailboxPlanSha",
                         "MultiMailboxWizardProgress.SameInventory(before,latest)",
                         "lastPreparedMailbox=req.Mailbox",
                         'jumpTo="multi-mailbox-delivery-plan"'):
            self.assertIn(fragment,dialog)
        self.assertIn('ConfirmDestructive("LinuxMailRelay365 | Experimental OFFLINE',RUNTIME_GUI)
        self.assertIn('MultiMailboxCloudSelection.Capture(inventory,"source",row)',progress)
        self.assertIn("TimeSpan.FromMinutes(10)",progress)
        self.assertIn("sample.Receipt.Authenticated",progress)
        self.assertIn("ScopedConfigurationObserved==true",progress)
        self.assertNotIn("ApplyMultiMailboxDeliveryTestAsync(",dialog)
        self.assertNotIn("systemctl start",dialog)

    def test_separate_non_default_route_and_usable_gui_steps(self):
        for expected in (
                "StageMultiMailboxRuntimeAsync, false",
                "PreviewMultiMailboxRouteAsync, false",
                "ApplyMultiMailboxRouteOfflineAsync, false",
                "multiMailboxRouteSummary",
                "if (mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 0)"):
            self.assertIn(expected, GUI)
        self.assertIn('Install and configure XOAUTH2 Postfix', GUI)
        self.assertIn("Multi-mailbox sending is still blocked in this Wizard", GUI)

    def test_embedded_bundle_is_immutable_source_and_not_autostarting(self):
        for name in (
                "manage-multi-mailbox-postfix.py",
                "m365-multi-mailbox-transport.py",
                "audit-oauth-sender-map.py",
                "audit-oauth-ingress.py",
                "m365_xoauth2_transport.py",
                "m365_hardware_signer.py"):
            self.assertIn(name, ASSETS)
        self.assertIn('BuildMultiMailboxRuntimeStageBundle()', ASSETS)
        self.assertIn('BuildMultiMailboxRouteBundle(string action', ASSETS)
        self.assertIn('created_no_service_changes', ASSETS)
        self.assertIn('already_exists_no_overwrite', ASSETS)
        self.assertIn('--apply-offline --approve-sha256', ASSETS)
        self.assertIn('INSTALL_MULTI_MAILBOX_OFFLINE', ASSETS)
        self.assertIn('MultiMailboxPostfixInstaller', ASSETS)
        self.assertIn('MultiMailboxTransport', ASSETS)
        for resource in ('LinuxMailRelay365.linux.multi-mailbox-postfix.py',
                         'LinuxMailRelay365.linux.multi-mailbox-transport.py'):
            self.assertIn(resource, PROJECT)
        for forbidden in ('postfix reload', 'systemctl restart',
                          'systemctl start', 'sudo rm -rf /etc/postfix'):
            self.assertNotIn(forbidden, ASSETS)

    def test_host_and_plan_sha_guard(self):
        self.assertIn('SecurityOptionsStore.Identity(endpoint)', RUNTIME_GUI)
        self.assertIn('oauthSenderMapPath.Text.Trim()', RUNTIME_GUI)
        self.assertIn('isolatedSmtpPort.Text.Trim()', RUNTIME_GUI)
        self.assertIn('/etc/linuxmailrelay365/oauth-senders.tsv', RUNTIME_GUI)
        self.assertIn('reviewedMultiMailboxPlanSha = sha;', RUNTIME_GUI)
        self.assertIn('reviewedMultiMailboxPlanContext = context;', RUNTIME_GUI)
        self.assertIn('reviewedMultiMailboxPlanContext != context', RUNTIME_GUI)
        self.assertIn('ResetMultiMailboxRouteReview();', RUNTIME_GUI)
        for event in (
                'oauthSenderMapPath.TextChanged',
                'oauthSenderMode.SelectedIndexChanged',
                'mailTransport.SelectedIndexChanged',
                'isolatedSmtpPort.TextChanged',
                'endpointField.TextChanged'):
            self.assertIn(event, GUI)
        self.assertGreaterEqual(GUI.count('ResetMultiMailboxRouteReview();'), 5)

    def test_language_relabel_does_not_discard_reviewed_sha(self):
        sender_event = GUI.split("oauthSenderMode.SelectedIndexChanged += (_, _) =>", 1)[1].split(
            "oauthSenderMapPath.TextChanged", 1)[0]
        route_event = GUI.split("mailTransport.SelectedIndexChanged += (_, _) =>", 1)[1].split(
            "recipientScope.SelectedIndexChanged", 1)[0]
        self.assertIn("if (!routingLoading)\n            {\n                ResetMultiMailboxRouteReview();",
                      sender_event)
        self.assertIn("if (!routingLoading) {\n                ResetMultiMailboxRouteReview();",
                      route_event)
        self.assertNotIn("ResetMultiMailboxRouteReview();\n            if (!routingLoading)",
                         sender_event)
        self.assertNotIn("ResetMultiMailboxRouteReview();\n            if (!routingLoading)",
                         route_event)

    def test_stage_and_apply_have_two_explicit_typed_confirmations(self):
        self.assertIn('ConfirmDestructive("LinuxMailRelay365 | Stage multi-mailbox', RUNTIME_GUI)
        self.assertIn('"STAGE MULTI MAILBOX"', RUNTIME_GUI)
        self.assertIn('ConfirmDestructive("LinuxMailRelay365 | Experimental OFFLINE', RUNTIME_GUI)
        self.assertIn('"INSTALL MULTI MAILBOX OFFLINE"', RUNTIME_GUI)
        self.assertIn('reviewedMultiMailboxPlanSha = null;', RUNTIME_GUI)
        self.assertIn('BuildMultiMailboxRouteBundle("apply", sha)', RUNTIME_GUI)
        self.assertIn('"MULTI_OAUTH_STATUS", @"\\Aoffline_installed_NOT_started\\z"', RUNTIME_GUI)
        self.assertIn('"MULTI_OAUTH_SERVICES_CHANGED", @"\\Ano\\z"', RUNTIME_GUI)
        self.assertIn('"MULTI_OAUTH_MESSAGES_SENT", @"\\Ano\\z"', RUNTIME_GUI)
        self.assertIn('ValidatedMultiMailboxReportValue(', RUNTIME_GUI)

    def test_short_lived_root_proof_is_manually_reviewed_not_renewed_by_gui(self):
        self.assertIn("RefreshMultiMailboxIngressProofAsync, false", GUI)
        self.assertIn("RefreshMultiMailboxIngressProofAsync()", RUNTIME_GUI)
        self.assertIn("REFRESH MULTI INGRESS PROOF", RUNTIME_GUI)
        self.assertIn("BuildMultiMailboxProofRefreshBundle(sha)", RUNTIME_GUI)
        self.assertIn("BuildMultiMailboxProofRefreshBundle(string senderMapSha)", ASSETS)
        self.assertIn("REFRESH_PRIVILEGED_MULTI_INGRESS_PROOF", ASSETS)
        self.assertIn('MULTI_INGRESS_PROOF_EXPIRES_SECONDS', RUNTIME_GUI)
        self.assertIn('@"\A120\z"', RUNTIME_GUI)
        self.assertIn("Auto-renewal is NOT installed", GUI)
        self.assertIn("multi-mailbox-ingress-proof.py", ASSETS)
        self.assertIn("LinuxMailRelay365.linux.multi-mailbox-ingress-proof.py", PROJECT)
        self.assertNotIn("systemctl start", RUNTIME_GUI)

    def test_optional_proof_timer_has_sha_preview_and_separate_revocation(self):
        for name in (
            "PreviewMultiMailboxProofTimerAsync, false",
            "EnableMultiMailboxProofTimerAsync, false",
            "InspectMultiMailboxProofTimerAsync, false",
            "DisableMultiMailboxProofTimerAsync, false"):
            self.assertIn(name, GUI)
        self.assertIn("BuildMultiMailboxProofTimerBundle(", ASSETS)
        self.assertIn("ENABLE_REVIEWED_MULTI_INGRESS_TIMER", ASSETS)
        self.assertIn("DISABLE_AND_REVOKE_MULTI_INGRESS_TIMER", ASSETS)
        self.assertIn("ENABLE MULTI PROOF TIMER", RUNTIME_GUI)
        self.assertIn("DISABLE MULTI PROOF TIMER", RUNTIME_GUI)
        self.assertIn("reviewedMultiProofTimerContext != context", RUNTIME_GUI)
        self.assertIn("reviewedMultiProofTimerSha = null;", RUNTIME_GUI)
        self.assertIn("MULTI_PROOF_TIMER_M365_DELIVERY_VERIFIED", RUNTIME_GUI)
        self.assertIn("MULTI_PROOF_RECEIPT", RUNTIME_GUI)
        self.assertIn("fresh_ttl_only", RUNTIME_GUI)
        self.assertIn("map_changed", RUNTIME_GUI)
        self.assertNotIn("systemctl start", RUNTIME_GUI)

    def test_offline_restore_is_explicitly_reviewed_and_not_auto_started(self):
        self.assertIn("PreviewMultiMailboxRestoreAsync, false", GUI)
        self.assertIn("RestoreMultiMailboxRouteOfflineAsync, false", GUI)
        self.assertIn('private async Task PreviewMultiMailboxRestoreAsync()', RUNTIME_GUI)
        self.assertIn('private async Task RestoreMultiMailboxRouteOfflineAsync()', RUNTIME_GUI)
        self.assertIn('reviewedMultiMailboxRestoreSha', RUNTIME_GUI)
        self.assertIn('reviewedMultiMailboxRestoreBackupId', RUNTIME_GUI)
        self.assertIn('reviewedMultiMailboxRestoreContext != context', RUNTIME_GUI)
        self.assertIn('RESTORE MULTI MAILBOX OFFLINE', RUNTIME_GUI)
        self.assertIn('BuildMultiMailboxRestoreBundle("preview")', RUNTIME_GUI)
        self.assertIn('BuildMultiMailboxRestoreBundle("restore", sha, id)', RUNTIME_GUI)
        self.assertIn('"MULTI_RESTORE_STATUS", @"\Arestored_offline_not_started\z"',
                      RUNTIME_GUI)
        self.assertIn('BuildMultiMailboxRestoreBundle(', ASSETS)
        self.assertIn('RESTORE_MULTI_MAILBOX_OFFLINE', ASSETS)
        self.assertIn('multi-mailbox-restore.py', PROJECT)
        self.assertIn('restore-multi-mailbox-postfix.py', ASSETS)
        self.assertNotIn('systemctl restart', RUNTIME_GUI)
        self.assertNotIn('postfix reload', RUNTIME_GUI)

    def test_two_real_acceptance_emits_only_explicitly_reviewed_sender_and_recipients(self):
        self.assertIn('PreviewMultiMailboxDeliveryTestAsync, false', GUI)
        self.assertIn('ApplyMultiMailboxDeliveryTestAsync, false', GUI)
        self.assertIn('if (reviewedMultiTestSha is not null)', GUI)
        self.assertIn('multiTestSender.TextChanged', GUI)
        self.assertIn('multiTestInternal.TextChanged', GUI)
        self.assertIn('multiTestExternal.TextChanged', GUI)
        self.assertIn('private async Task PreviewMultiMailboxDeliveryTestAsync()', RUNTIME_GUI)
        self.assertIn('private async Task ApplyMultiMailboxDeliveryTestAsync()', RUNTIME_GUI)
        self.assertIn('BuildMultiMailboxAcceptanceBundle(', ASSETS)
        self.assertIn('MULTI_ACCEPTANCE_PLAN_SHA256', RUNTIME_GUI)
        self.assertIn('SEND TWO MULTI MAILBOX TESTS', RUNTIME_GUI)
        self.assertIn('MULTI_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED', RUNTIME_GUI)
        self.assertIn('MULTI_ACCEPTANCE_EXCHANGE_TRACE_VERIFIED', RUNTIME_GUI)
        self.assertIn('ResetMultiMailboxTestReview();', RUNTIME_GUI)
        self.assertIn('multi-mailbox-acceptance.py', ASSETS)
        self.assertIn('LinuxMailRelay365.linux.multi-mailbox-acceptance.py', PROJECT)
        self.assertNotIn('systemctl restart', RUNTIME_GUI)

    def test_acceptance_ledger_readonly_recovery_after_uncertain_ssh(self):
        self.assertIn("InspectLastMultiMailboxDeliveryTestAsync, false", GUI)
        self.assertIn('"multi-mailbox-delivery-ledger"', GUI)
        self.assertIn("BuildMultiMailboxAcceptanceStatusBundle(", ASSETS)
        self.assertIn("MULTI_ACCEPTANCE_LEDGER_STATE", RUNTIME_GUI)
        self.assertIn("lastMultiTestRunId = runId;", RUNTIME_GUI)
        self.assertIn("lastMultiTestContext = context;", RUNTIME_GUI)
        self.assertIn("ResetMultiMailboxTestApproval();", RUNTIME_GUI)
        self.assertIn("MULTI_ACCEPTANCE_AUTOMATIC_RETRY", RUNTIME_GUI)
        self.assertIn("no inbox delivery proven", RUNTIME_GUI)
        self.assertIn("--status --run-id", ASSETS)

    def test_no_live_send_while_multi_selected(self):
        section = GUI.split("            case 4:", 1)[1].split(
            "        pageHost.ResumeLayout();", 1)[0]
        self.assertIn('oauthSenderMode.SelectedIndex == 0', section)
        self.assertIn('Multi-mailbox XOAUTH2 is PLAN ONLY', section)
        self.assertIn('InspectRelayHealthAsync, true', section)
        self.assertIn('SendTestAsync, false', section)
        self.assertIn('mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 0',
                      section)

if __name__ == "__main__":
    unittest.main()
