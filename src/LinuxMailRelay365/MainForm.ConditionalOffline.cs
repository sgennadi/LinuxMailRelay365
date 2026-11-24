using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private string? offlineHostIdentity;
    private string? offlineReviewContext;
    private ConditionalOfflineReview? offlineReview;
    private readonly TextBox offlineBackupSha = new()
    {
        Font = new Font("Consolas", 10f), MaxLength = 64,
        AccessibleName = "Recovery backup SHA-256"
    };

    private string? OfflineHostContext() =>
        inspectedHost is { Mta: "postfix", MtaState: "installed_inactive" }
            ? RecoveryInventoryContext() : null;

    private string? OfflineCandidateContext()
    {
        if (OfflineHostContext() is not { } hostContext ||
            CurrentConditionalStageContext() is not { } stageContext ||
            conditionalStageContext != stageContext ||
            conditionalStageReceipt is not { Status: "compiled_verified_read_only",
                CompiledSha: not null } receipt ||
            receipt.PlanSha != AdvancedRoutePlanner.PlanSha256(advancedRoutingRules))
            return null;
        return hostContext + "|" + stageContext + "|" + receipt.CompiledSha;
    }

    private void ShowConditionalOfflineActions(TableLayoutPanel page, int width, int l)
    {
        if (!HasMailDiscovery() || inspectedHost?.Mta != "postfix") return;
        string? identity = TryCurrentIdentity();
        if (offlineHostIdentity != identity)
        {
            offlineHostIdentity = identity;
            offlineReview = null;
            offlineReviewContext = null;
            offlineBackupSha.Clear();
        }
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Offline Apply / Restore — экспериментально",
            "Offline Apply / Restore — experimental",
            "החלה ושחזור לא מקוונים — ניסיוני"), true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Только остановленный Postfix, пустая очередь и исключительное окно обслуживания. Нужна полная резервная копия. SELinux/ACL пока не поддерживаются.",
            "Stopped Postfix, empty queues and exclusive maintenance only. Take a full backup first. SELinux/ACL writes are not supported.",
            "רק Postfix כבוי ותורים ריקים בחלון תחזוקה בלעדי. נדרש גיבוי מלא."),
            width, warning: true));
        if (OfflineHostContext() is null)
        {
            offlineReview = null;
            offlineReviewContext = null;
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Остановите службу самостоятельно в окно обслуживания и повторите обнаружение. Автоматического stop/start/reload нет.",
                "Manually stop Postfix during maintenance, then reinspect Linux. No automatic service control.",
                "יש לעצור את Postfix בחלון תחזוקה ולבדוק שוב את Linux."), width));
            return;
        }
        string? context = OfflineCandidateContext();
        int count = 0;
        if (context is not null)
        {
            try { count = ConditionalOfflineClient.EligibleDestinations(advancedRoutingRules); }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            { context = null; }
        }
        if (context is null || offlineReviewContext != context)
        {
            offlineReview = null;
            offlineReviewContext = null;
        }
        if (context is null)
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Сначала Validate plan и Verify compiled maps на этом остановленном сервере. Только правила отправителя STARTTLS без AUTH, максимум 4 назначения.",
                "First Validate plan and Verify compiled maps on this stopped host. Sender-only STARTTLS/no-AUTH, up to four destinations.",
                "יש לאמת תוכנית ומפות בשרת כבוי; כללי שולח ללא AUTH ועד ארבעה יעדים."), width));
        else
        {
            AddAction(page, TranslateMailFlow(l, "Offline Review — проверить TLS...",
                "Offline Review — verify TLS and configuration...", "בדוק TLS ותצורה..."),
                () => RunConditionalOfflineAsync("review"), false, "check", "conditional-offline");
            if (offlineReview is { } review && review.TlsDestinations == count)
            {
                AddLine(page, MailFlowText("Transaction SHA-256: " + review.TransactionSha +
                    Environment.NewLine + "Evidence SHA-256: " + review.EvidenceSha +
                    Environment.NewLine + "TLS destinations: " + count +
                    Environment.NewLine + "Live mail delivery is NOT verified.", width));
                AddAction(page, TranslateMailFlow(l, "Offline Apply — с резервной копией...",
                    "Offline Apply — with backup...", "החלה עם גיבוי..."),
                    () => RunConditionalOfflineAsync("apply"), false, "shield", "conditional-offline");
            }
        }
        offlineBackupSha.Width = Math.Max(250, width - 30);
        AddField(page, TranslateMailFlow(l, "SHA-256 резервной копии",
            "Recovery backup SHA-256", "SHA-256 של גיבוי"), offlineBackupSha);
        AddAction(page, TranslateMailFlow(l, "Offline Restore...",
            "Offline Restore...", "שחזור לא מקוון..."),
            () => RunConditionalOfflineAsync("restore"), false, "shield", "conditional-offline");
    }

    private async Task RunConditionalOfflineAsync(string operation)
    {
        string hostContext = OfflineHostContext() ??
            throw new InvalidOperationException("Reinspect the stopped Postfix host.");
        string? context = null, plan = null, compiled = null, backup = null;
        ConditionalOfflineReview? reviewed = null;
        int count = 0;
        if (operation == "restore")
        {
            backup = offlineBackupSha.Text.Trim().ToLowerInvariant();
            if (!ConditionalOfflineClient.IsSha(backup))
                throw new ArgumentException("Enter the exact recovery SHA-256.");
        }
        else if (operation is "review" or "apply")
        {
            context = OfflineCandidateContext() ??
                throw new InvalidOperationException("Verify compiled maps for the exact plan first.");
            count = ConditionalOfflineClient.EligibleDestinations(advancedRoutingRules);
            plan = conditionalStageReceipt!.PlanSha;
            compiled = conditionalStageReceipt.CompiledSha;
            if (operation == "apply")
            {
                reviewed = offlineReview;
                if (reviewed is null || offlineReviewContext != context ||
                    reviewed.TlsDestinations != count)
                    throw new InvalidOperationException("Fresh Offline Review required.");
            }
        }
        else throw new ArgumentException("Unknown offline operation.");
        int l = language.SelectedIndex;
        if (!ConfirmDestructive("LinuxMailRelay365 | Exclusive maintenance",
            TranslateMailFlow(l,
                "Подтвердите остановленный Postfix, пустую очередь и отсутствие параллельных отправок, запусков и изменений. Программа не гарантирует эту изоляцию.",
                "Confirm stopped Postfix, empty queues, and prevention of concurrent submissions, service starts and edits. The app cannot enforce this isolation for you.",
                "אשר ש-Postfix כבוי, התורים ריקים ואין פעולות מקבילות.") +
            Environment.NewLine + "Host: " + inspectedHost!.Fqdn,
            ConditionalOfflineClient.MaintenancePhrase))
            return;
        string? confirmation = operation switch {
            "apply" => ConditionalOfflineClient.ApplyPhrase,
            "restore" => ConditionalOfflineClient.RestorePhrase,
            _ => null
        };
        string? recovery = backup ?? reviewed?.TransactionSha;
        if (confirmation is not null && !ConfirmDestructive(
            "LinuxMailRelay365 | Experimental offline write",
            TranslateMailFlow(l,
                "Будут изменены файлы Postfix. Служба не запускается. При неопределённом результате не запускайте её; проверьте восстановление.",
                "This changes Postfix files, without starting the service. If the outcome is uncertain, keep it stopped and inspect recovery.",
                "קבצי Postfix ישתנו ללא הפעלת השירות. במקרה של ספק יש לבדוק שחזור.") +
            Environment.NewLine + "Recovery SHA-256: " + recovery, confirmation))
            return;
        if (OfflineHostContext() != hostContext ||
            (context is not null && OfflineCandidateContext() != context))
            throw new InvalidOperationException("Host or candidate changed after approval.");
        string script = ConditionalOfflineClient.Build(EmbeddedAssets.ConditionalStageManager,
            EmbeddedAssets.ConditionalTransactionManager, EmbeddedAssets.ConditionalActivationPreflight,
            EmbeddedAssets.ConditionalOfflineManager, operation,
            ConditionalOfflineClient.MaintenancePhrase, plan, compiled, reviewed, backup, confirmation);
        offlineReview = null;
        offlineReviewContext = null;
        var endpoint = Endpoint();
        bool write = operation != "review";
        if (write)
        {
            offlineBackupSha.Text = recovery!;
            conditionalStageReceipt = null;
            conditionalStageContext = null;
            conditionalRecoveryEntries = null;
            conditionalRecoveryContext = null;
            WriteLine("Offline write requested. Recovery SHA-256: " + recovery +
                ". Keep Postfix stopped until the result is verified.");
        }
        try
        {
            var result = await SshRemote.RunRootScriptAsync(endpoint, script, TimeSpan.FromMinutes(5));
            if (result.ExitCode != 0 || OfflineHostContext() != hostContext)
                throw new InvalidOperationException("Offline operation failed, refused or context changed.");
            if (!write)
            {
                if (OfflineCandidateContext() != context)
                    throw new InvalidOperationException("Candidate changed during review.");
                offlineReview = ConditionalOfflineClient.ParseReview(result.StdOut, count);
                offlineReviewContext = context;
                WriteLine("Offline Review verified. No Postfix changes or messages sent.");
            }
            else
            {
                ConditionalOfflineClient.VerifyMutation(result.StdOut, operation, recovery!);
                WriteLine("Offline " + operation + " verified. Service not started. Recovery SHA-256: " +
                    recovery + ". Reinspect before service start.");
            }
        }
        catch (Exception ex) when (write)
        {
            throw new InvalidOperationException("Offline write refused or outcome uncertain. Keep Postfix stopped. " +
                "Inspect recovery SHA-256: " + recovery + ".", ex);
        }
        finally
        {
            if (write)
            {
                // Every attempted mutation, even a lost SSH reply, invalidates
                // discovery evidence before any next write can be authorized.
                discoveredMailIdentity = null;
                inspectedServerIdentity = null;
                existingSmtpAuditIdentity = null;
                inspectedHostIdentity = null;
            }
        }
    }
}
