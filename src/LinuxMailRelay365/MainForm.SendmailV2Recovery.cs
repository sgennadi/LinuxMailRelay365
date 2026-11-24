using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private SshEndpoint RequireSendmailRecoveryConnection(SshEndpoint previous, bool allowFirstPin = false)
    {
        var current = Endpoint();
        if (!SameRollbackConnection(previous, current) ||
            (previous.HostKeySha256 != current.HostKeySha256 &&
                !(allowFirstPin && previous.HostKeySha256.Length == 0 && current.HostKeySha256.Length > 0)) ||
            (current.Password.Length > 0 && current.HostKeySha256.Length == 0))
            throw new InvalidOperationException("SSH connection or trusted host key changed during Sendmail v2 recovery.");
        return current;
    }

    private SshEndpoint RequireStoppedSendmailV2Selection(SshEndpoint previous, string identity, string id)
    {
        var current = RequireSameSendmailReviewContext(previous, identity, id);
        if (inspectedHost?.MtaState != "installed_inactive")
            throw new InvalidOperationException("Reinspect stopped Sendmail and choose a verified v2 archive.");
        return current;
    }

    private string SendmailV2RecoveryLimitations() => T(
        "Экспериментально, только для тестового сервера. Изменяются только существующие sendmail.cf и submit.cf. Базы данных, ссылки, очереди и службы не изменяются. При ошибке сохраняется аварийный журнал; не запускайте MTA и не повторяйте запись без нового плана.",
        "Experimental, disposable test hosts only. Only existing sendmail.cf and submit.cf bytes may change. No databases, symlinks, queues or service actions. A failure retains recovery evidence; do not start the MTA or retry writes without a fresh reviewed plan.",
        "ניסיוני לשרת בדיקה בלבד. רק sendmail.cf ו-submit.cf משתנים. ללא שינוי מסדי נתונים, קישורים, תורים או שירותים. במקרה כשל נדרשת תוכנית חדשה.");

    private async Task ApplySendmailV2RestoreAsync()
    {
        var initial = Endpoint();
        string identity = SecurityOptionsStore.Identity(initial);
        if (foreignBackupSelector.SelectedItem is not string id ||
            inspectedHost?.MtaState != "installed_inactive" ||
            ConfirmedForeignBackupMta(allowStopped: true) != "sendmail" ||
            foreignBackupListContext != identity + "|sendmail")
            throw new InvalidOperationException("Inspect stopped Sendmail and select its verified backup first.");
        var inspection = await SshRemote.RunRootScriptAsync(initial,
            EmbeddedAssets.BuildForeignMtaPendingInspectBundle(), TimeSpan.FromMinutes(5));
        inspection.EnsureSuccess();
        if (!ForeignPendingInspection.Parse(inspection.StdOut).IsClear)
            throw new InvalidOperationException("Interrupted native Restore must be investigated first.");
        var reviewed = RequireStoppedSendmailV2Selection(initial, identity, id);
        var archive = await SshRemote.RunRootScriptAsync(reviewed,
            EmbeddedAssets.BuildForeignMtaBackupBundle("sendmail", "verify", id), TimeSpan.FromMinutes(4));
        archive.EnsureSuccess();
        string archiveSha = SendmailV2RecoveryReceipt.VerifyArchive(archive.StdOut);
        RequireStoppedSendmailV2Selection(reviewed, identity, id);
        var response = await SshRemote.RunRootScriptAsync(reviewed,
            EmbeddedAssets.BuildSendmailV2ReviewBundle(id), TimeSpan.FromMinutes(5));
        response.EnsureSuccess();
        var plan = SendmailV2Review.Parse(response.StdOut, id, archiveSha);
        RequireStoppedSendmailV2Selection(reviewed, identity, id);
        if (!SendmailV2RecoveryReceipt.CanRestore(plan))
        {
            // Explain the exact blocked/no-op plan; never carry a write
            // approval across this return or dispatch any recovery command.
            ShowSendmailV2ReviewReport(reviewed, id, plan);
            return;
        }
        string details = "Host: " + reviewed.Host + ":" + reviewed.Port + "\nMTA: Sendmail v2\nSnapshot: " + id +
            "\nChanged compiled files: " + plan.CompiledChanged + "/2\nService: " + plan.Service +
            "\nQueue: " + plan.Queue + "\nProcesses: " + plan.Processes + "\nListener: " + plan.Listener +
            "\nArchive SHA-256: " + plan.ArchiveSha + "\nManifest SHA-256: " + plan.ManifestSha +
            "\nPlan SHA-256: " + plan.PlanSha + "\n\n" + SendmailV2RecoveryLimitations();
        if (!ConfirmDestructive("LinuxMailRelay365 | EXPERIMENTAL Sendmail v2 Restore",
                details, SendmailV2RecoveryReceipt.RestoreConfirmation))
            return;
        var confirmed = RequireStoppedSendmailV2Selection(reviewed, identity, id);
        RequireSendmailRecoveryConnection(reviewed);
        try
        {
            var result = await SshRemote.RunRootScriptAsync(confirmed,
                EmbeddedAssets.BuildSendmailV2RestoreApplyBundle(id, plan.PlanSha), TimeSpan.FromMinutes(15));
            result.EnsureSuccess();
            var evidence = SendmailV2RecoveryReceipt.VerifyRestore(result.StdOut, id, plan);
            await VerifySendmailRecoveryCompletedAsync(confirmed);
            ShowSendmailRecoverySuccess(evidence);
        }
        finally { InvalidateAfterSendmailV2Write(); }
    }

    // Independent of current provider, archive selection or cached MTA discovery.
    private async Task ReviewSendmailV2RollbackAsync(bool apply)
    {
        var initial = Endpoint();
        var response = await SshRemote.RunRootScriptAsync(initial,
            EmbeddedAssets.BuildSendmailV2RollbackPlanBundle(), TimeSpan.FromMinutes(5));
        response.EnsureSuccess();
        var plan = SendmailV2RecoveryReceipt.ParseRollbackPlan(response.StdOut);
        var reviewed = RequireSendmailRecoveryConnection(initial, allowFirstPin: true);
        var evidence = plan.Evidence;
        string details = "Host: " + reviewed.Host + ":" + reviewed.Port + "\nMTA: Sendmail v2 / schema 4" +
            "\nSafety archive: " + evidence.SafetyId + "\nSHA-256: " + evidence.SafetySha +
            "\nManifest SHA-256: " + evidence.SafetyManifest + "\nTarget archive: " + evidence.TargetId +
            "\nSHA-256: " + evidence.TargetSha + "\nManifest SHA-256: " + evidence.TargetManifest +
            "\nOriginal Restore Plan: " + evidence.RestorePlanSha + "\nFiles to roll back: " + plan.Changed +
            "/2\nRollback Plan SHA-256: " + plan.Sha + "\n\n" + SendmailV2RecoveryLimitations();
        WriteLine("Sendmail v2 interrupted rollback preview: " + plan.Changed + "/2; SHA256=" + plan.Sha + ". No changes.");
        if (!apply)
        {
            MessageBox.Show(this, details, "LinuxMailRelay365 | Sendmail v2 rollback preview",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (!ConfirmDestructive("LinuxMailRelay365 | EXPERIMENTAL Sendmail v2 Rollback",
                details, SendmailV2RecoveryReceipt.RollbackConfirmation))
            return;
        var confirmed = RequireSendmailRecoveryConnection(reviewed);
        try
        {
            var result = await SshRemote.RunRootScriptAsync(confirmed,
                EmbeddedAssets.BuildSendmailV2RollbackApplyBundle(plan.Sha), TimeSpan.FromMinutes(15));
            result.EnsureSuccess();
            SendmailV2RecoveryReceipt.VerifyRollback(result.StdOut, plan);
            await VerifySendmailRecoveryCompletedAsync(confirmed);
            ShowSendmailRecoverySuccess(evidence);
        }
        finally { InvalidateAfterSendmailV2Write(); }
    }

    private async Task VerifySendmailRecoveryCompletedAsync(SshEndpoint confirmed)
    {
        RequireSendmailRecoveryConnection(confirmed);
        var inspection = await SshRemote.RunRootScriptAsync(confirmed,
            EmbeddedAssets.BuildForeignMtaPendingInspectBundle(), TimeSpan.FromMinutes(5));
        inspection.EnsureSuccess();
        if (!ForeignPendingInspection.Parse(inspection.StdOut).IsClear)
            throw new InvalidDataException("Sendmail recovery marker has not been cleared.");
        RequireSendmailRecoveryConnection(confirmed);
    }

    private void ShowSendmailRecoverySuccess(SendmailV2Evidence evidence)
    {
        WriteLine("Sendmail v2 offline recovery verified; safety archive=" + evidence.SafetyId +
            "; SHA256=" + evidence.SafetySha + ". No services started. Reinspect MTA.");
        MessageBox.Show(this, T(
            "Операция подтверждена. Sendmail не запускался. Повторно проверьте MTA. Аварийный архив: ",
            "Offline recovery verified. Sendmail was not started. Reinspect MTA. Safety archive: ",
            "השחזור אומת. Sendmail לא הופעל. גיבוי חירום: ") + evidence.SafetyId + "\nSHA-256: " + evidence.SafetySha,
            "LinuxMailRelay365 | Sendmail v2", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void InvalidateAfterSendmailV2Write()
    {
        // Lost SSH replies are not proof that no files changed.
        inspectedMail = null;
        inspectedServerIdentity = null;
        inspectedHost = null;
        inspectedHostIdentity = null;
        existingSmtpAudit = null;
        existingSmtpAuditIdentity = null;
        discoveredMailIdentity = null;
        discoveredIsolatedRelay = null;
        mailSubmissionEvidence = null;
        mailSubmissionIdentity = null;
        foreignBackupListContext = null;
        foreignBackupSelector.Items.Clear();
        allowExisting.Checked = false;
        ResetMultiMailboxRouteReview();
    }
}
