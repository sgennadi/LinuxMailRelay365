using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private string? credentialRotationContext;
    private CredentialRotationReview? credentialRotationReview;
    private MultiTransportInstalled? credentialRotationInstalled;

    private void ResetCredentialRotationReview()
    {
        credentialRotationContext = null;
        credentialRotationReview = null;
        credentialRotationInstalled = null;
    }

    private bool RotationTargetCurrent(string context, MultiTransportInstalled installed, int index) =>
        OfflineHostContext() == context && multiInstalledContext == RecoveryInventoryContext() &&
        ReferenceEquals(multiInstalled, installed) && installed.Status == "installed_owned" &&
        ConditionalOfflineClient.IsSha(installed.Revision) && ConditionalOfflineClient.IsSha(installed.Plan) &&
        installed.Backend is "hash" or "lmdb" && index >= 1 && index <= installed.Rules.Count &&
        installed.Rules[index - 1].AuthMode == "password";

    private bool RotationReviewCurrent(string context, CredentialRotationReview review) =>
        OfflineHostContext() == context && credentialRotationContext == context &&
        ReferenceEquals(credentialRotationReview, review) &&
        (review.IsRecovery
            ? multiRevision.Text.Trim().ToLowerInvariant() == review.Revision
            : credentialRotationInstalled is { } installed && RotationTargetCurrent(context, installed, review.Index) &&
              installed.Revision == review.Revision && installed.Plan == review.Plan && installed.Backend == review.Backend);

    private void ShowCredentialRotationActions(TableLayoutPanel page, int width, int l)
    {
        string? context = OfflineHostContext();
        if (context is null || credentialRotationContext != context ||
            credentialRotationReview is { } prior && !RotationReviewCurrent(context, prior))
            ResetCredentialRotationReview();
        if (context is null) return;
        AddLine(page, UiTheme.Text(TranslateMailFlow(l, "Смена учётных данных SMTP — экспериментально",
            "SMTP credential rotation — experimental", "החלפת פרטי SMTP — ניסיוני"), true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Только подтверждённые установленные транспорты с паролем. Остальные карты и конфигурация не меняются. При прерывании не запускайте Postfix до проверки восстановления.",
            "Only verified installed password transports. Other maps and both configuration files remain unchanged. If interrupted, keep Postfix stopped until recovery is checked.",
            "רק נתיבים מותקנים ומאומתים עם סיסמה. במקרה של הפרעה יש להשאיר את Postfix כבוי."), width, warning: true));
        if (multiInstalled is { Status: "installed_owned" } installed)
        {
            for (int i = 1; i <= installed.Rules.Count; i++)
            {
                int index = i;
                if (!RotationTargetCurrent(context, installed, index)) continue;
                var rule = installed.Rules[index - 1];
                AddLine(page, MailFlowText($"#{index} · {rule.Pattern} → {rule.Endpoint} · {rule.TlsMode}", width));
                AddAction(page, TranslateMailFlow(l, "Проверить смену credentials", "Review change credentials", "בדוק החלפת פרטי התחברות"),
                    () => ReviewCredentialRotationAsync(context, installed, index), false, "check", "rotation-review");
            }
        }
        else
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Сначала Discover installed transports. Для аварийного восстановления можно использовать ревизию из Recovery Scanner.",
                "First discover installed transports. For interrupted rotation, use a revision from Recovery Scanner.",
                "תחילה יש לזהות נתיבים מותקנים. לשחזור יש לבחור גרסה."), width));
        AddAction(page, TranslateMailFlow(l, "Проверить прерванную ротацию по выбранной ревизии...",
            "Review interrupted rotation for selected revision...", "בדוק החלפה שנקטעה לפי גרסה..."),
            () => ReviewCredentialRotationAsync(context, null, null), false, "check", "rotation-recovery-review");
        if (credentialRotationReview is not { } review || !RotationReviewCurrent(context, review)) return;
        AddLine(page, MailFlowText("Revision: " + review.Revision + Environment.NewLine +
            "Plan: " + review.Plan + Environment.NewLine + "Review: " + review.Evidence + Environment.NewLine +
            $"Transport #{review.Index} · {review.Backend} · {review.Retained}" + Environment.NewLine +
            TranslateMailFlow(l, "Проверка не подтверждает AUTH или доставку.",
                "Review does not prove SMTP AUTH or delivery.", "הבדיקה אינה מאשרת אימות SMTP או מסירה."), width));
        AddAction(page, review.IsRecovery
                ? TranslateMailFlow(l, "Завершить восстановление...", "Recover retained credential map...", "השלם שחזור...")
                : TranslateMailFlow(l, "Заменить credentials выбранного транспорта...", "Rotate credentials of reviewed transport...", "החלף פרטי התחברות לנתיב שנבדק..."),
            () => WriteCredentialRotationAsync(context, review), false, "shield", "rotation-write");
    }

    private bool ConfirmRotationMaintenance(int l) => ConfirmDestructive("LinuxMailRelay365 | Exclusive maintenance",
        TranslateMailFlow(l,
            "Подтвердите: Postfix остановлен, очередь пуста, исключены параллельные отправки, запуск службы и изменения конфигурации.",
            "Confirm stopped Postfix, empty queues, and prevention of concurrent submissions, service starts and edits.",
            "אשר ש-Postfix כבוי, התורים ריקים ואין פעולות מקבילות.") +
        Environment.NewLine + "Host: " + inspectedHost!.Fqdn, ConditionalOfflineClient.MaintenancePhrase);

    private async Task ReviewCredentialRotationAsync(string context, MultiTransportInstalled? installed, int? index)
    {
        ResetCredentialRotationReview();
        bool recovery = installed is null;
        string revision = recovery ? multiRevision.Text.Trim().ToLowerInvariant() : installed!.Revision!;
        bool Current() => OfflineHostContext() == context && ConditionalOfflineClient.IsSha(revision) &&
            (recovery ? multiRevision.Text.Trim().ToLowerInvariant() == revision && index is null
                : index is int n && RotationTargetCurrent(context, installed!, n));
        if (!Current()) throw new InvalidOperationException("Select an exact current revision and transport.");
        if (!ConfirmRotationMaintenance(language.SelectedIndex)) throw new OperationCanceledException();
        if (!Current()) throw new InvalidOperationException("Rotation target changed after approval.");
        try
        {
            string script = CredentialRotationClient.Build(recovery ? "review-recovery" : "review-rotation",
                revision, index, ConditionalOfflineClient.MaintenancePhrase);
            var result = await SshRemote.RunRootScriptAsync(Endpoint(), script, TimeSpan.FromMinutes(6));
            if (result.ExitCode != 0 || !Current()) throw new InvalidOperationException();
            var review = CredentialRotationClient.ParseReview(result.StdOut, revision, recovery,
                index, installed?.Plan, installed?.Backend);
            credentialRotationReview = review;
            credentialRotationContext = context;
            credentialRotationInstalled = installed;
            WriteLine("Credential rotation review verified. Revision: " + revision + "; state: " + review.Retained + ". No mail or AUTH attempted.");
        }
        catch
        {
            ResetCredentialRotationReview();
            throw new InvalidOperationException("Credential rotation review failed or became stale. No write requested.");
        }
    }

    private void InvalidateAfterCredentialRotation()
    {
        ResetCredentialRotationReview();
        multiInventory = null;
        multiInventoryContext = null;
        multiInstalled = null;
        multiInstalledContext = null;
        multiReview = null;
        multiReviewContext = null;
        offlineReview = null;
        offlineReviewContext = null;
        conditionalStageReceipt = null;
        conditionalStageContext = null;
        conditionalRecoveryEntries = null;
        conditionalRecoveryContext = null;
        conditionalRouteAudits.Clear();
        conditionalRouteAuditContext = null;
        discoveredMailIdentity = null;
        inspectedServerIdentity = null;
        existingSmtpAuditIdentity = null;
        inspectedHostIdentity = null;
    }

    private async Task WriteCredentialRotationAsync(string context, CredentialRotationReview review)
    {
        if (!RotationReviewCurrent(context, review)) throw new InvalidOperationException("Fresh exact rotation review required.");
        var installed = credentialRotationInstalled;
        int l = language.SelectedIndex;
        if (!ConfirmRotationMaintenance(l)) throw new OperationCanceledException();
        string phrase = review.IsRecovery ? CredentialRotationClient.RecoverPhrase : CredentialRotationClient.RotatePhrase;
        string warning = review.IsRecovery
            ? TranslateMailFlow(l,
                "Подтвердите согласование записи владения сохранённой картой. Старый пароль не восстанавливается, карта не заменяется. Служба останется остановленной.",
                "Reconcile ownership of the proven retained map. This does not recreate an old password or replace the retained map. Postfix remains stopped.",
                "אשר התאמת רישום הבעלות. הסיסמה הישנה לא תשוחזר והשירות יישאר כבוי.")
            : TranslateMailFlow(l,
                "Будет заменена только выбранная SASL-карта. Linux хранит читаемые credentials. SSH/sudo-аудит может записывать stdin; используйте канал без записи секретов. Служба останется остановленной.",
                "Only the selected SASL map will be replaced. Linux stores readable credentials. SSH/sudo input auditing may record stdin; use an approved channel without secret recording. Postfix remains stopped.",
                "רק מפת SASL שנבחרה תוחלף. יש להשתמש בערוץ שאינו מקליט סודות. Postfix יישאר כבוי.");
        string target = review.IsRecovery ? review.Retained : installed!.Rules[review.Index - 1].Pattern +
            " → " + installed.Rules[review.Index - 1].Endpoint;
        if (!ConfirmDestructive("LinuxMailRelay365 | Credential rotation write", warning + Environment.NewLine +
            "Revision: " + review.Revision + Environment.NewLine + $"Transport #{review.Index}: " + target, phrase))
            throw new OperationCanceledException();
        (string User, string Secret)? credential = null;
        string? script = null;
        bool attempted = false;
        try
        {
            if (!RotationReviewCurrent(context, review)) throw new InvalidOperationException();
            if (!review.IsRecovery)
            {
                credential = PromptRouteCredential(installed!.Rules[review.Index - 1], forApply: true);
                if (credential is null) throw new OperationCanceledException();
            }
            if (!RotationReviewCurrent(context, review)) throw new InvalidOperationException();
            script = CredentialRotationClient.Build(review.IsRecovery ? "recover" : "rotate", review.Revision,
                review.IsRecovery ? null : review.Index, ConditionalOfflineClient.MaintenancePhrase, review, credential, phrase);
            var endpoint = Endpoint();
            ResetCredentialRotationReview();
            multiRevision.Text = review.Revision;
            WriteLine("Credential rotation write requested. Revision: " + review.Revision + ". Keep Postfix stopped until verified.");
            attempted = true;
            var result = await SshRemote.RunRootScriptAsync(endpoint, script, TimeSpan.FromMinutes(6));
            if (OfflineHostContext() != context) throw new InvalidOperationException();
            var mutation = CredentialRotationClient.ParseResult(result.StdOut, review, result.ExitCode);
            WriteLine("Credential rotation: " + mutation.Status + ". Revision: " + mutation.Revision);
            if (mutation.Status is "rolled_back" or "manual_recovery_required") throw new InvalidOperationException();
            WriteLine("Credential operation verified. Postfix was not started; reinspect before service start.");
        }
        catch (OperationCanceledException) when (!attempted) { ResetCredentialRotationReview(); throw; }
        catch
        {
            ResetCredentialRotationReview();
            // Never log remote text, command, exceptions, or credential material.
            throw new InvalidOperationException(attempted
                ? "Credential write failed or outcome uncertain. Keep Postfix stopped; reinspect and scan the recovery revision."
                : "Credential rotation preparation failed; no write requested.");
        }
        finally
        {
            credential = null;
            script = null;
            if (attempted) InvalidateAfterCredentialRotation();
        }
    }
}
