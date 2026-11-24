using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private TransportEditReview? transportEditReview;
    private MultiTransportInstalled? transportEditInstalled;
    private string? transportEditContext;
    private TransportEditRecovery? transportEditRecovery;
    private string? transportEditRecoveryContext;
    private bool transportEditRecoveryScanned;

    private void ResetTransportEditReview()
    {
        transportEditReview = null;
        transportEditInstalled = null;
        transportEditContext = null;
        transportEditRecovery = null;
        transportEditRecoveryContext = null;
        transportEditRecoveryScanned = false;
    }

    private string? EditCandidateContext(MultiTransportInstalled installed)
    {
        if (multiInstalledContext != RecoveryInventoryContext() ||
            !ReferenceEquals(multiInstalled, installed) || installed.Status != "installed_owned" ||
            MultiCandidateContext() is not { } context) return null;
        try
        {
            var preview = MultiTransportClient.PreviewEdit(installed, advancedRoutingRules);
            if (preview.CurrentPlan == preview.DraftPlan) return null;
            return context + "|" + installed.Revision + "|" + installed.Plan;
        }
        catch (ArgumentException) { return null; }
    }

    // Returns true for known pending recovery: ordinary multi-provider
    // writes stay hidden until the edit has been resolved and reinspected.
    private bool ShowTransportEditActions(TableLayoutPanel page, int width, int l)
    {
        if (OfflineHostContext() is not { } host) return false;
        if (transportEditRecoveryContext != host)
        {
            transportEditRecovery = null;
            transportEditRecoveryContext = null;
            transportEditRecoveryScanned = false;
        }
        AddLine(page, UiTheme.Text(TranslateMailFlow(l, "Редактирование маршрутов — экспериментально",
            "Transport edit — experimental", "עריכת נתיבים — ניסיוני"), true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Изменение выполняется только на остановленном Postfix. Старые карты сохраняются до Commit или Rollback. Не запускайте службу, пока транзакция не завершена.",
            "Edit only during stopped Postfix maintenance. Old maps remain until Commit or Rollback. Do not start the service while an edit is pending.",
            "עריכה רק בעת עצירת Postfix. המפות הישנות נשמרות עד אישור או שחזור. אין להפעיל את השירות במהלך העסקה."), width, warning: true));
        AddAction(page, TranslateMailFlow(l, "Найти незавершённое редактирование",
            "Review pending edit", "בדוק עריכה שלא הושלמה"),
            () => ReviewPendingTransportEditAsync(host), false, "search", "edit-recovery-review");
        if (transportEditRecoveryScanned && transportEditRecovery is null)
            AddLine(page, MailFlowText(TranslateMailFlow(l, "Незавершённая транзакция не обнаружена.",
                "No pending edit found.", "לא נמצאה עריכה ממתינה."), width));
        if (transportEditRecovery is { } pending)
        {
            AddLine(page, MailFlowText("Old: " + pending.OldRevision + Environment.NewLine +
                "New: " + pending.NewRevision + Environment.NewLine +
                "Phase: " + pending.Phase + " · Layout: " + pending.Layout + Environment.NewLine +
                TranslateMailFlow(l, "Это проверка файлов, не подтверждение доставки.",
                    "File-level recovery candidates, not delivery verification.", "בדיקת קבצים בלבד, ללא אימות מסירה."), width, warning: true));
            if (pending.CanCommit)
                AddAction(page, "Commit transport edit...", () => ResolveTransportEditAsync(host, pending, "commit"),
                    false, "shield", "edit-commit");
            if (pending.CanRollback)
                AddAction(page, "Rollback transport edit...", () => ResolveTransportEditAsync(host, pending, "rollback"),
                    false, "shield", "edit-rollback");
            return true;
        }
        if (multiInstalled is not { Status: "installed_owned" } installed ||
            EditCandidateContext(installed) is not { } context) return false;
        if (transportEditContext != context || !ReferenceEquals(transportEditInstalled, installed))
        {
            transportEditReview = null;
            transportEditContext = null;
            transportEditInstalled = null;
        }
        AddAction(page, "Edit Review", () => ReviewTransportEditAsync(installed, context),
            false, "check", "edit-review");
        if (transportEditReview is { } reviewed)
        {
            AddLine(page, MailFlowText("Review: " + reviewed.Evidence + Environment.NewLine +
                "New plan: " + reviewed.NewPlan + Environment.NewLine +
                TranslateMailFlow(l, "TLS проверен. AUTH и доставка не проверены.",
                    "TLS reviewed. AUTH and delivery unverified.", "TLS נבדק. אימות ומסירה לא נבדקו."), width));
            var rules = MultiTransportClient.Eligible(advancedRoutingRules);
            for (int i = 0; i < rules.Count; i++)
            {
                if (rules[i].AuthMode != "password") continue;
                string choice = reviewed.RetainIndices[i] > 0
                    ? TranslateMailFlow(l, "Сохранить существующий пароль или ввести новый",
                        "Keep existing credentials or enter new ones", "שמור פרטי התחברות קיימים או הזן חדשים")
                    : TranslateMailFlow(l, "Требуются новые учётные данные",
                        "New credentials required", "נדרשים פרטי התחברות חדשים");
                AddLine(page, MailFlowText($"#{i+1} · {rules[i].Pattern} → {rules[i].Endpoint}" +
                    Environment.NewLine + choice, width));
            }
            AddAction(page, "Switch reviewed transport set...", () => SwitchTransportEditAsync(installed, context, reviewed),
                false, "shield", "edit-switch");
        }
        return false;
    }

    private async Task ReviewTransportEditAsync(MultiTransportInstalled installed, string context)
    {
        ResetTransportEditReview();
        bool Current() => EditCandidateContext(installed) == context;
        if (!Current()) throw new InvalidOperationException("Reinspect the installed set and draft.");
        if (!ConfirmRotationMaintenance(language.SelectedIndex)) throw new OperationCanceledException();
        if (!Current()) throw new InvalidOperationException("Edit context changed.");
        try
        {
            var rules = MultiTransportClient.Eligible(advancedRoutingRules);
            var result = await SshRemote.RunRootScriptAsync(Endpoint(),
                TransportEditClient.Build("review", ConditionalOfflineClient.MaintenancePhrase, installed, rules),
                TimeSpan.FromMinutes(11));
            if (!Current()) throw new InvalidOperationException();
            transportEditReview = TransportEditClient.ParseReview(result.StdOut, result.ExitCode, installed, rules);
            transportEditContext = context;
            transportEditInstalled = installed;
            WriteLine("Transport Edit Review verified. No passwords requested; no changes.");
        }
        catch
        {
            ResetTransportEditReview();
            throw new InvalidOperationException("Transport Edit Review failed or became stale; no write requested.");
        }
    }

    private async Task ReviewPendingTransportEditAsync(string host)
    {
        ResetTransportEditReview();
        if (OfflineHostContext() != host) throw new InvalidOperationException("Reinspect stopped Postfix.");
        if (!ConfirmRotationMaintenance(language.SelectedIndex)) throw new OperationCanceledException();
        if (OfflineHostContext() != host) throw new InvalidOperationException("Host context changed.");
        try
        {
            var result = await SshRemote.RunRootScriptAsync(Endpoint(),
                TransportEditClient.Build("review-recovery", ConditionalOfflineClient.MaintenancePhrase),
                TimeSpan.FromMinutes(11));
            if (OfflineHostContext() != host) throw new InvalidOperationException();
            transportEditRecovery = TransportEditClient.ParseRecovery(result.StdOut, result.ExitCode);
            transportEditRecoveryContext = host;
            transportEditRecoveryScanned = true;
            if (transportEditRecovery is { } pending)
            {
                multiRevision.Text = pending.NewRevision;
                WriteLine("Pending transport edit found. Keep Postfix stopped. Revision: " + pending.NewRevision);
            }
            else WriteLine("No pending transport edit found.");
        }
        catch
        {
            ResetTransportEditReview();
            throw new InvalidOperationException("Edit recovery review failed. Do not start Postfix after an uncertain write.");
        }
    }

    private async Task SwitchTransportEditAsync(MultiTransportInstalled installed, string context, TransportEditReview review)
    {
        bool Current() => EditCandidateContext(installed) == context && transportEditContext == context &&
            ReferenceEquals(transportEditReview, review) && ReferenceEquals(transportEditInstalled, installed);
        if (!Current()) throw new InvalidOperationException("Fresh exact Edit Review required.");
        int l = language.SelectedIndex;
        if (!ConfirmRotationMaintenance(l)) throw new OperationCanceledException();
        if (!ConfirmDestructive("LinuxMailRelay365 | Switch transport set",
            TranslateMailFlow(l,
                "Старые и новые читаемые SASL-карты временно сосуществуют. SSH/sudo-аудит может записывать ввод; используйте канал без записи секретов. После Switch требуется Commit или Rollback. Postfix останется остановленным.",
                "Old and new readable SASL maps coexist temporarily. SSH/sudo auditing may record input; use an approved channel without secret recording. Switch requires a separate Commit or Rollback. Postfix stays stopped.",
                "מפות SASL קריאות ישנות וחדשות יתקיימו זמנית. יש להשתמש בערוץ שאינו מקליט סודות. נדרש אישור או שחזור נפרד.") +
            Environment.NewLine + "New plan: " + review.NewPlan, TransportEditClient.SwitchPhrase))
            throw new OperationCanceledException();
        var rules = MultiTransportClient.Eligible(advancedRoutingRules);
        var slots = new TransportEditSlot?[rules.Count];
        string? script = null;
        bool attempted = false;
        try
        {
            for (int i = 0; i < rules.Count; i++)
            {
                if (!Current()) throw new InvalidOperationException();
                if (rules[i].AuthMode != "password") continue;
                if (review.RetainIndices[i] > 0)
                {
                    var choice = MessageBox.Show(this, $"#{i+1}: {rules[i].Pattern} → {rules[i].Endpoint}" +
                        Environment.NewLine + TranslateMailFlow(l,
                            "Да — сохранить существующие учётные данные. Нет — ввести новые. Отмена — прервать операцию.",
                            "Yes: keep existing credentials. No: enter new credentials. Cancel: abort.",
                            "כן: שמור פרטי התחברות קיימים. לא: הזן חדשים. ביטול: הפסק."),
                        "LinuxMailRelay365", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question,
                        MessageBoxDefaultButton.Button3);
                    if (choice == DialogResult.Cancel) throw new OperationCanceledException();
                    if (choice == DialogResult.Yes) { slots[i] = new(true); continue; }
                    if (choice != DialogResult.No) throw new OperationCanceledException();
                }
                var credential = PromptRouteCredential(rules[i], forApply: true);
                if (credential is null) throw new OperationCanceledException();
                slots[i] = new(false, credential.Value.User, credential.Value.Secret);
            }
            if (!Current()) throw new InvalidOperationException();
            script = TransportEditClient.Build("switch", ConditionalOfflineClient.MaintenancePhrase,
                installed, rules, review, slots, confirmation: TransportEditClient.SwitchPhrase);
            var endpoint = Endpoint();
            string host = OfflineHostContext()!;
            ResetTransportEditReview();
            attempted = true;
            WriteLine("Transport switch requested. Keep Postfix stopped.");
            var result = await SshRemote.RunRootScriptAsync(endpoint, script, TimeSpan.FromMinutes(11));
            if (OfflineHostContext() != host) throw new InvalidOperationException();
            multiRevision.Text = TransportEditClient.ParseSwitch(result.StdOut, result.ExitCode, review);
            WriteLine("Transport switch verified, pending resolution. Reinspect and Review pending edit; Commit or Rollback required.");
        }
        catch (OperationCanceledException) when (!attempted) { throw; }
        catch
        {
            throw new InvalidOperationException(attempted
                ? "Transport switch failed or outcome uncertain. Keep Postfix stopped; reinspect and Review pending edit."
                : "Transport edit preparation failed; no write requested.");
        }
        finally
        {
            Array.Clear(slots);
            script = null;
            if (attempted) InvalidateAfterCredentialRotation();
        }
    }

    private async Task ResolveTransportEditAsync(string host, TransportEditRecovery review, string operation)
    {
        bool Current() => OfflineHostContext() == host && transportEditRecoveryContext == host &&
            ReferenceEquals(transportEditRecovery, review) &&
            (operation == "commit" ? review.CanCommit : operation == "rollback" && review.CanRollback);
        if (!Current()) throw new InvalidOperationException("Fresh exact recovery review required.");
        int l = language.SelectedIndex;
        if (!ConfirmRotationMaintenance(l)) throw new OperationCanceledException();
        string phrase = operation == "commit" ? TransportEditClient.CommitPhrase : TransportEditClient.RollbackPhrase;
        if (!ConfirmDestructive("LinuxMailRelay365 | " + operation,
            TranslateMailFlow(l,
                "Подтвердите выбранное направление. После начала очистки изменить направление нельзя. Удаляются только подтверждённые карты другого набора. Postfix останется остановленным.",
                "Confirm the selected direction. Once cleanup begins it cannot be reversed. Only verified maps of the discarded set are removed. Postfix stays stopped.",
                "אשר את הכיוון שנבחר. לאחר תחילת הניקוי לא ניתן לשנות כיוון. השירות יישאר כבוי.") +
            Environment.NewLine + "Revision: " + review.NewRevision, phrase)) throw new OperationCanceledException();
        if (!Current()) throw new InvalidOperationException("Recovery review changed.");
        bool attempted = false;
        try
        {
            var script = TransportEditClient.Build(operation, ConditionalOfflineClient.MaintenancePhrase,
                recovery: review, confirmation: phrase);
            var endpoint = Endpoint();
            ResetTransportEditReview();
            attempted = true;
            var result = await SshRemote.RunRootScriptAsync(endpoint, script, TimeSpan.FromMinutes(11));
            if (OfflineHostContext() != host) throw new InvalidOperationException();
            multiRevision.Text = TransportEditClient.ParseResolution(result.StdOut, result.ExitCode, review, operation);
            WriteLine("Transport edit " + operation + " verified. Kept revision: " + multiRevision.Text +
                ". Postfix was not started; reinspect before restart.");
        }
        catch
        {
            throw new InvalidOperationException(attempted
                ? "Transport edit resolution failed or outcome uncertain. Keep Postfix stopped and repeat recovery review."
                : "Recovery preparation failed; no write requested.");
        }
        finally
        {
            if (attempted) InvalidateAfterCredentialRotation();
        }
    }
}
