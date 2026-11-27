import importlib.util
import pathlib
import unittest
from unittest.mock import Mock, patch
from contextlib import nullcontext

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("binding", ROOT / "linux/review-smtp-tls-rotation.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class ConnectorBindingTests(unittest.TestCase):
    def test_exact_san_only(self):
        self.assertTrue(M.exact_dns_san("X509v3 Subject Alternative Name:\n    DNS:Relay.example.org, DNS:example.org\nX509v3 Extended Key Usage:\n    TLS Web Client Authentication", "relay.example.org"))
        for value in ("DNS:relay.example.org", "X509v3 Subject Alternative Name:\n    DNS:*.example.org",
                      "X509v3 Subject Alternative Name:\n    DNS:evil-relay.example.org",
                      "X509v3 Extended Key Usage:\n    DNS:relay.example.org"):
            self.assertFalse(M.exact_dns_san(value, "relay.example.org"))

    def test_invalid_name_refused_before_files(self):
        with patch.object(M, "directory") as directory:
            for name in ("*.example.org", "--bad.example.org", "relay;id.example.org"):
                with self.assertRaises(ValueError):
                    M.connector_binding(name)
            directory.assert_not_called()

    def test_gui_inspection_is_not_apply(self):
        source = ROOT / "src/LinuxMailRelay365"
        dialog = (source / "MainForm.SmtpConnectorBinding.cs").read_text()
        self.assertIn('BuildSmtpTlsRotation("binding-preview"', dialog)
        self.assertIn('RunTenantConnectorManagerAsync(options, "Inspect")', dialog)
        self.assertIn('(await LocalAsync()).Sha != local.Sha', dialog)
        self.assertNotIn('connectorApproved.Checked = true', dialog)
        self.assertNotIn('RunTenantConnectorManagerAsync(options, "Apply")', dialog)

    def test_tenant_script_contract(self):
        script = (ROOT / "windows/Manage-LinuxMailRelay365Connector.ps1").read_text()
        self.assertIn("Certificate DNS identity must itself be an exact accepted domain", script)
        self.assertIn("Get-CertificateOverlap", script)
        self.assertIn("EXO_CONNECTOR_BINDING=$binding", script)
        self.assertIn("$options['RequireTls'] = $true", script)
        inspect = script.split("if ($Action -eq 'Inspect')", 1)[1].split("    foreach ($item in $connectors) {", 2)
        self.assertNotIn("New-InboundConnector", inspect[0])

    def test_workflow_navigation_does_not_authorize_changes(self):
        source = ROOT / "src/LinuxMailRelay365"
        plan = (source/"SmtpCertificateWizardPlan.cs").read_text()
        self.assertIn("[SmtpWorkflowStage.Identity, SmtpWorkflowStage.Delivery]", plan)
        self.assertIn("SmtpWorkflowStage.Binding, SmtpWorkflowStage.Delivery, SmtpWorkflowStage.Maintenance", plan)
        ui = (source/"SmtpCertificateWizardDialog.cs").read_text()
        self.assertIn("Navigation is not approval", ui)
        self.assertIn("sessionMx = dialog.SessionMx", ui)
        self.assertIn("deliveryProbe(this, sessionMx)", ui)
        self.assertIn("if (working) e.Cancel = true", ui)
        self.assertNotIn("connectorApproved.Checked = true", ui)
        main = (source/"MainForm.DeliveryMiniWizard.cs").read_text()
        self.assertIn("outboundFixedSender.Text.Trim(), sessionMx,", main)

    def test_candidate_binding_does_not_require_active_postfix(self):
        candidate = "candidate-"+"a"*64
        checker = Mock()
        checker.resolve_ca_bundle.return_value = "/etc/ssl/test-ca.pem"
        validator = Mock(return_value=dict(status="local_checks_passed", details="certificate",
                         extensions="X509v3 Subject Alternative Name:\n    DNS:relay.example.org"))
        with patch.object(M,"directory"), patch.object(M,"verify_files") as verify, \
             patch.object(M,"active_generation",return_value=None), patch.object(M,"read_file",return_value=b"CA"):
            result = M.candidate_connector_binding(candidate,"relay.example.org",checker,validator,lambda _: nullcontext())
            self.assertEqual(result["status"],"candidate_binding_reviewed")
            self.assertEqual(result["generation"],candidate)
            self.assertTrue(result["exact_dns_san"])
            self.assertFalse(result["postfix_modified"])
            self.assertFalse(result["activation_attempted"])
            self.assertEqual(verify.call_count,2)
            validator.return_value["extensions"]="X509v3 Subject Alternative Name:\n    DNS:*.example.org"
            with self.assertRaises(ValueError):
                M.candidate_connector_binding(candidate,"relay.example.org",checker,validator,lambda _: nullcontext())

    def test_candidate_binding_drift_rejected(self):
        checker = Mock()
        checker.resolve_ca_bundle.return_value = "/etc/ssl/test-ca.pem"
        validator = Mock(return_value=dict(status="local_checks_passed",
                         extensions="X509v3 Subject Alternative Name:\n    DNS:relay.example.org"))
        with patch.object(M,"directory"), patch.object(M,"verify_files"), \
             patch.object(M,"active_generation",side_effect=[None,"candidate-"+"b"*64]), \
             patch.object(M,"read_file",return_value=b"CA"):
            with self.assertRaises(ValueError):
                M.candidate_connector_binding("candidate-"+"a"*64,"relay.example.org",checker,validator,lambda _: nullcontext())

    def test_staged_connector_gui_separate_inspect_and_create(self):
        src=ROOT/"src/LinuxMailRelay365"
        main=(src/"MainForm.SmtpConnectorBinding.cs").read_text()
        staged=main.split("private async Task ReviewStagedConnectorAsync",1)[1]
        self.assertIn('BuildSmtpTlsRotation("candidate-binding-preview"',staged)
        self.assertIn('RunTenantConnectorManagerAsync(options, "Inspect")',staged)
        self.assertIn('RunTenantConnectorManagerAsync(options, "Preview")',staged)
        self.assertLess(staged.index("ConfirmDestructive("),staged.index('RunTenantConnectorManagerAsync(options, "Apply", cloudSha)'))
        self.assertIn("acceptedDomainApproved.Checked",staged)
        self.assertNotIn("connectorApproved.Checked = true",staged)
        ui=(src/"SmtpTlsRotationDialog.cs").read_text()
        self.assertIn("StagedConnectorAsync(false)",ui)
        self.assertIn("StagedConnectorAsync(true)",ui)
        self.assertIn("Invalidate();",ui)

    def test_wizard_connector_inventory_reuses_reviewed_owner_guard(self):
        src = ROOT / "src/LinuxMailRelay365"
        ui = (src/"MainForm.SmtpConnectorInventory.cs").read_text()
        self.assertIn("QueryCloudObjectsAsync(id, null, connectorOnly: true)", ui)
        self.assertIn('c?.Ownership == "verified"', ui)
        self.assertIn("ExecuteCloudConnectorOperationAsync(dialog, inventory, selected", ui)
        self.assertIn("if (busy) e.Cancel = true", ui)
        self.assertIn("stale = true", ui)
        self.assertIn("InspectWizardConnectorsAsync(owner, context)", (src/"MainForm.DeliveryMiniWizard.cs").read_text())

    def test_settings_edit_requires_backup_and_preserves_mode(self):
        source=(ROOT/"windows/Manage-LinuxMailRelay365Object.ps1").read_text()
        self.assertIn("edit_requires_disabled_connector",source)
        self.assertIn("public_ip_mode_must_be_preserved",source)
        self.assertIn("certificate_mode_must_be_preserved",source)
        self.assertIn("exact_accepted_domain_required",source)
        self.assertIn("backup_acl_not_private",source)
        self.assertLess(source.index("Write-Settings-Backup $BackupPath"),source.index("Set-InboundConnector @settings"))
        self.assertIn("unreviewed_connector_setting_changed",source)

    def test_settings_edit_gui_binds_inventory_and_retains_backup(self):
        src=ROOT/"src/LinuxMailRelay365"
        ui=(src/"MainForm.SmtpConnectorSettings.cs").read_text()
        self.assertLess(ui.index("ConfirmDestructive("),ui.index('WriteRestrictedGraphPayload(backup, "")'))
        self.assertIn('"Apply", sha, edit, backup',ui)
        self.assertIn('new FileInfo(backup).Length == 0',ui)
        self.assertIn("connector remains disabled",ui)
        runner=(src/"MainForm.CloudConnectorChanges.cs").read_text()
        self.assertIn('Add("-ExpectedSenderDomains"',runner)
        self.assertIn('Add("-BackupPath"',runner)
        shell=(ROOT/"windows/Manage-LinuxMailRelay365Object.ps1").read_text()
        self.assertIn("selected_settings_changed_refresh_inventory",shell)

    def test_connector_restore_checks_exact_snapshot_and_live_flags(self):
        src=ROOT/"src/LinuxMailRelay365"
        restore=(src/"MainForm.SmtpConnectorRestore.cs").read_text()
        for marker in ("current != expectedCurrent", "previous == current", "connector.Identity", "tenantId.ToString", "ExpectedSecurityFlags = flags", "ExactFields", "FileAttributes.ReparsePoint", "ApplyReviewedConnectorSettingsAsync"):
            self.assertIn(marker,restore)
        settings=(src/"MainForm.SmtpConnectorSettings.cs").read_text()
        self.assertIn('"RESTORE M365 CONNECTOR"',settings)
        self.assertIn('WriteRestrictedGraphPayload(backup, "")',settings)
        shell=(ROOT/"windows/Manage-LinuxMailRelay365Object.ps1").read_text()
        self.assertIn("backup_security_flags_changed_manual_review_required",shell)
        self.assertIn("restore-flags:",shell)
        self.assertIn('Add("-ExpectedSecurityFlags"',(src/"MainForm.CloudConnectorChanges.cs").read_text())
