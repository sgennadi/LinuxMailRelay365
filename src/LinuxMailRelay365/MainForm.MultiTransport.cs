using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private string? multiHostIdentity;
    private string? multiReviewContext;
    private MultiTransportReview? multiReview;
    private string? multiInstalledContext;
    private MultiTransportInstalled? multiInstalled;
    private string? multiInventoryContext;
    private IReadOnlyList<MultiTransportRecovery>? multiInventory;
    private readonly TextBox multiRevision = new()
    {
        Font = new Font("Consolas", 10f), MaxLength = 64,
        AccessibleName = "Multi-provider recovery revision"
    };

    private string? MultiCandidateContext()
    {
        if (OfflineHostContext() is not { } hostContext ||
            advancedRoutingIdentity != TryCurrentIdentity())
            return null;
        try
        {
            var rules = MultiTransportClient.Eligible(advancedRoutingRules);
            return hostContext + "|" + AdvancedRoutePlanner.PlanSha256(rules);
        }
        catch (ArgumentException) { return null; }
    }

    private void ShowMultiTransportActions(TableLayoutPanel page, int width, int l)
    {
        string? hostContext = RecoveryInventoryContext();
        if (hostContext is null)
        {
            ResetCredentialRotationReview();
            ResetTransportEditReview();
            multiReview = null;
            multiReviewContext = null;
            multiInventory = null;
            multiInventoryContext = null;
            multiInstalledContext = null;
            multiInstalled = null;
            return;
        }
        string? identity = TryCurrentIdentity();
        if (identity != multiHostIdentity)
        {
            ResetCredentialRotationReview();
            ResetTransportEditReview();
            multiHostIdentity = identity;
            multiRevision.Clear();
            multiReview = null;
            multiReviewContext = null;
            multiInventory = null;
            multiInventoryContext = null;
        }
        if (multiInventoryContext != hostContext) multiInventory = null;
        if (multiInstalledContext != hostContext) multiInstalled = null;
        string? context = MultiCandidateContext();
        if (context is null || context != multiReviewContext)
        {
            multiReview = null;
            multiReviewContext = null;
        }
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Multi-provider SMTP — экспериментально",
            "Multi-provider SMTP — experimental",
            "מספר ספקי SMTP — ניסיוני"), true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "До 8 отдельных транспортов по отправителю. STARTTLS/Implicit TLS, собственный порт и отдельный пароль. Установка и редактирование принадлежащего менеджеру набора только на остановленном Postfix. SELinux/ACL и OAuth2 ещё не поддерживаются. Нужен полный backup. Входящие порты не меняются.",
            "Up to 8 independent sender transports. STARTTLS/implicit TLS, individual ports and passwords. Install or edit a manager-owned set on stopped Postfix only. SELinux/ACL and OAuth2 are not yet supported. Full backup required. Inbound ports are unchanged.",
            "עד 8 נתיבי שולח עם TLS ופרטי התחברות נפרדים. התקנה ועריכה של תצורה מנוהלת ב-Postfix כבוי בלבד. נדרש גיבוי מלא."), width, warning: true));
        ShowInstalledMultiTransport(page, width, l, hostContext);
        AddAction(page, TranslateMailFlow(l, "Найти ревизии Multi-provider",
            "Scan multi-provider recovery revisions", "סרוק גרסאות שחזור"),
            ScanMultiTransportRecoveryAsync, false, "search", "multi-recovery");
        if (multiInventory is { } records)
        {
            if (records.Count == 0)
                AddLine(page, MailFlowText(TranslateMailFlow(l, "Ревизий нет.",
                    "No recovery revisions.", "אין גרסאות שחזור."), width));
            else
            {
                var combo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList,
                    Width = Math.Max(230, width - 25), AccessibleName = "Select observed recovery revision" };
                foreach (var item in records)
                    combo.Items.Add(item.Revision + " : " + item.State);
                combo.SelectedIndexChanged += (_, _) =>
                {
                    int index = combo.SelectedIndex;
                    if (index >= 0 && index < records.Count &&
                        RecoveryInventoryContext() == hostContext)
                        multiRevision.Text = records[index].Revision;
                };
                AddLine(page, combo);
                AddLine(page, MailFlowText(TranslateMailFlow(l,
                    "Выбор ревизии не разрешает восстановление или запуск службы.",
                    "Selecting a revision never authorizes restore or starting Postfix.",
                    "בחירת גרסה אינה מאשרת שחזור או הפעלה."), width));
            }
        }
        if (OfflineHostContext() is null)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Для Review/Apply/Restore остановите Postfix в окно обслуживания и повторите обнаружение.",
                "For Review/Apply/Restore, arrange maintenance, stop Postfix yourself and reinspect.",
                "יש לעצור את Postfix בחלון תחזוקה ולבדוק שוב."), width));
            return;
        }
        if (ShowTransportEditActions(page, width, l)) return;
        if (context is null)
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Составьте 1–8 непересекающихся правил отправителя в мастере выше. TLS обязателен.",
                "Create 1–8 disjoint sender rules in the planner above. TLS is required.",
                "יש ליצור 1–8 כללי שולח ללא חפיפה ועם TLS."), width));
        else if (multiInstalled?.Status is "installed_owned" or "external_or_unverified")
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Первичная установка заблокирована: обнаружена конфигурация. Используйте Edit для подтверждённого управляемого набора.",
                "First installation is blocked: existing configuration detected. Use Edit for a verified manager-owned set.",
                "התקנה ראשונה חסומה: זוהתה תצורה קיימת."), width, warning: true));
        else
        {
            var rules = MultiTransportClient.Eligible(advancedRoutingRules);
            AddLine(page, MailFlowText(string.Join(Environment.NewLine,
                rules.Select((r,i) => $"{i+1}. {r.Pattern} → {r.Endpoint} · {r.TlsMode} · {r.AuthMode}")), width));
            AddAction(page, "Multi-provider Review", () => RunMultiTransportAsync("review"),
                false, "check", "multi-review");
            if (multiReview is { } reviewed && multiReviewContext == context)
            {
                AddLine(page, MailFlowText("Plan: " + reviewed.Plan + Environment.NewLine +
                    "Review: " + reviewed.Evidence + Environment.NewLine +
                    "Backend: " + reviewed.Backend + " · TLS destinations: " + reviewed.Destinations +
                    Environment.NewLine + "No provider AUTH or live delivery verified.", width));
                AddAction(page, "Multi-provider Apply...", () => RunMultiTransportAsync("apply"),
                    false, "shield", "multi-apply");
            }
        }
        multiRevision.Width = Math.Max(230, width - 25);
        AddField(page, TranslateMailFlow(l, "Ревизия восстановления",
            "Recovery revision", "גרסת שחזור"), multiRevision);
        AddAction(page, "Multi-provider Restore...", () => RunMultiTransportAsync("restore"),
            false, "shield", "multi-restore");
        ShowCredentialRotationActions(page, width, l);
    }

    private void ShowInstalledMultiTransport(TableLayoutPanel page, int width, int l, string hostContext)
    {
        AddAction(page, TranslateMailFlow(l, "Обнаружить установленные транспорты",
            "Discover installed transports", "זהה נתיבי SMTP מותקנים"),
            DiscoverMultiTransportAsync, false, "search", "multi-discovery");
        if (multiInstalled is not { } installed) return;
        if (installed.Status != "installed_owned")
        {
            AddLine(page, MailFlowText(installed.Status == "no_effective_transport_map"
                ? TranslateMailFlow(l, "Карта выбора транспорта по отправителю не обнаружена.",
                    "No effective sender-dependent transport map found.", "לא נמצאה מפת נתיבים לפי שולח.")
                : TranslateMailFlow(l, "Сторонняя или неподтверждённая конфигурация. Запись не разрешена.",
                    "External or unverified configuration. Writes are not authorized.", "תצורה חיצונית או לא מאומתת."),
                width, warning: installed.Status != "no_effective_transport_map"));
            return;
        }
        AddLine(page, MailFlowText("Installed configuration · " + installed.Backend +
            Environment.NewLine + "Revision: " + installed.Revision + Environment.NewLine +
            string.Join(Environment.NewLine, installed.Rules.Select((r,i) =>
                $"{i+1}. {r.Pattern} → {r.Endpoint} · {r.TlsMode} · {r.AuthMode}")) +
            Environment.NewLine + TranslateMailFlow(l,
                "Это конфигурация на диске, не подтверждение доставки. Пароли не извлекаются.",
                "Disk configuration only; runtime delivery is unverified. No passwords retrieved.",
                "תצורה בדיסק בלבד, ללא קריאת סיסמאות."), width));
        ShowMultiTransportEditPreview(page, width, l, hostContext, installed);
        AddAction(page, TranslateMailFlow(l, "Импортировать в локальный редактор...",
            "Import into local draft editor...", "ייבא לעורך המקומי..."), () =>
        {
            if (RecoveryInventoryContext() != hostContext || multiInstalled != installed ||
                multiInstalledContext != hostContext)
                throw new InvalidOperationException("Installed observation became stale.");
            if (advancedRoutingRules.Count != 0 && MessageBox.Show(this,
                TranslateMailFlow(l,
                    "Заменить локальный проект найденными правилами? Linux не изменяется.",
                    "Replace the local draft with discovered rules? Linux is not changed.",
                    "להחליף את הטיוטה המקומית? Linux לא ישתנה."),
                "LinuxMailRelay365", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return Task.CompletedTask;
            advancedRoutingRules.Clear();
            advancedRoutingRules.AddRange(installed.Rules);
            advancedRoutingIdentity = TryCurrentIdentity();
            advancedRoutingSimulation = null;
            advancedRoutingEditIndex = -1;
            conditionalRouteAudits.Clear();
            conditionalRouteAuditContext = null;
            conditionalStageReceipt = null;
            conditionalStageContext = null;
            offlineReview = null;
            offlineReviewContext = null;
            multiReview = null;
            multiReviewContext = null;
            ResetTransportEditReview();
            advancedRoutingToggleUpdating = true;
            try { advancedRoutingToggle.Checked = true; }
            finally { advancedRoutingToggleUpdating = false; }
            multiRevision.Text = installed.Revision!;
            WriteLine("Installed transport rules copied into local draft only.");
            return Task.CompletedTask;
        }, false, "check", "multi-import");
    }

    private void ShowMultiTransportEditPreview(TableLayoutPanel page, int width, int l,
        string hostContext, MultiTransportInstalled installed)
    {
        if (multiInstalledContext != hostContext || RecoveryInventoryContext() != hostContext ||
            advancedRoutingIdentity != TryCurrentIdentity()) return;
        MultiTransportEditPreview preview;
        try { preview = MultiTransportClient.PreviewEdit(installed, advancedRoutingRules); }
        catch (ArgumentException)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Локальный проект несовместим с Multi-provider: исправьте правила перед сравнением.",
                "The local draft is not a valid multi-provider plan; correct the rules before comparison.",
                "הטיוטה אינה תואמת לתוכנית הנתיבים; יש לתקן את הכללים."), width, warning: true));
            return;
        }
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Сравнение с локальным проектом (только просмотр)",
            "Installed vs draft (read-only preview)",
            "השוואת תצורה מותקנת לטיוטה (קריאה בלבד)"), true));
        if (preview.CurrentPlan == preview.DraftPlan)
            AddLine(page, MailFlowText(TranslateMailFlow(l, "Правила совпадают.",
                "The route plans match.", "התוכניות זהות."), width));
        foreach (var item in preview.Items)
        {
            string change = item.Change switch
            {
                "unchanged" => TranslateMailFlow(l, "Без изменений", "Unchanged", "ללא שינוי"),
                "moved" => TranslateMailFlow(l, "Порядок изменён", "Order changed", "הסדר השתנה"),
                "modified" => TranslateMailFlow(l, "Изменено", "Modified", "שונה"),
                "added" => TranslateMailFlow(l, "Добавлено", "Added", "נוסף"),
                "removed" => TranslateMailFlow(l, "Удалено из проекта", "Removed from draft", "הוסר מהטיוטה"),
                _ => throw new InvalidOperationException("Unknown route change.")
            };
            string credential = item.CredentialIntent switch
            {
                "existing_candidate_only" => TranslateMailFlow(l,
                    "Существующий пароль: только кандидат на сохранение.",
                    "Existing credential: reuse candidate only.", "פרטי התחברות קיימים: מועמד לשימוש חוזר בלבד."),
                "new_credential_required" => TranslateMailFlow(l,
                    "Потребуются новые учётные данные.", "New credentials required.", "נדרשים פרטי התחברות חדשים."),
                "remove_reference_only" => TranslateMailFlow(l,
                    "Планируется удалить ссылку на старую карту.",
                    "Old credential-map reference would be removed.", "הפניה למפת פרטי ההתחברות תוסר."),
                _ => ""
            };
            string Describe(AdvancedRouteRule? r) => r is null ? "—" :
                r.Pattern + " · " + r.Endpoint + " · " + r.TlsMode + " · " + r.AuthMode;
            AddLine(page, MailFlowText(change + " · #" + (item.OldIndex?.ToString() ?? "—") +
                " → #" + (item.NewIndex?.ToString() ?? "—") + Environment.NewLine +
                Describe(item.Before) + Environment.NewLine + "→ " + Describe(item.After) +
                (credential.Length == 0 ? "" : Environment.NewLine + credential), width));
        }
        if (advancedRoutingRules.Count == 0)
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Пустой проект не разрешает удаление установленной конфигурации. Restore — отдельная операция.",
                "An empty draft cannot authorize removal of the installed set. Restore is a separate operation.",
                "טיוטה ריקה אינה מאשרת הסרת התצורה. שחזור הוא פעולה נפרדת."), width, warning: true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "При сравнении пароли не читаются. Для записи нужен отдельный Edit Review, Switch и Commit.",
            "Comparison reads no passwords. Changes require separate Edit Review, Switch and Commit.",
            "בהשוואה לא נקראות סיסמאות. החלת שינויים דורשת בדיקה, החלפה ואישור נפרדים."), width));
    }

    private async Task DiscoverMultiTransportAsync()
    {
        ResetCredentialRotationReview();
        ResetTransportEditReview();
        string context = RecoveryInventoryContext() ??
            throw new InvalidOperationException("Reinspect Postfix.");
        multiInstalled = null;
        multiInstalledContext = null;
        multiReview = null;
        multiReviewContext = null;
        try
        {
            var result = await SshRemote.RunRootScriptAsync(Endpoint(),
                MultiTransportClient.Build("installed"), TimeSpan.FromMinutes(4));
            if (RecoveryInventoryContext() != context)
                throw new InvalidOperationException();
            var observation = MultiTransportClient.ParseInstalled(result.StdOut);
            if (result.ExitCode != 0 && observation.Status != "external_or_unverified")
                throw new InvalidOperationException();
            multiInstalled = observation;
            multiInstalledContext = context;
            WriteLine("Installed transport discovery: " + observation.Status + ". Read-only.");
        }
        catch
        {
            throw new InvalidOperationException("Installed transport discovery failed or became stale.");
        }
    }

    private async Task ScanMultiTransportRecoveryAsync()
    {
        ResetCredentialRotationReview();
        ResetTransportEditReview();
        string context = RecoveryInventoryContext() ??
            throw new InvalidOperationException("Reinspect Postfix.");
        multiInventory = null;
        multiInventoryContext = null;
        try
        {
            var result = await SshRemote.RunRootScriptAsync(Endpoint(),
                MultiTransportClient.Build("scan"), TimeSpan.FromMinutes(4));
            if (result.ExitCode != 0 || RecoveryInventoryContext() != context)
                throw new InvalidOperationException();
            multiInventory = MultiTransportClient.ParseInventory(result.StdOut);
            multiInventoryContext = context;
            WriteLine("Multi-provider recovery inventory: " + multiInventory.Count +
                " record(s). Read-only observations.");
        }
        catch
        {
            throw new InvalidOperationException("Multi-provider recovery scan failed or became stale.");
        }
    }

    private async Task RunMultiTransportAsync(string operation)
    {
        string hostContext = OfflineHostContext() ??
            throw new InvalidOperationException("Reinspect the stopped Postfix host.");
        string? context = null, revision = null;
        IReadOnlyList<AdvancedRouteRule>? rules = null;
        MultiTransportReview? reviewed = null;
        if (operation == "restore")
        {
            revision = multiRevision.Text.Trim().ToLowerInvariant();
            if (!ConditionalOfflineClient.IsSha(revision))
                throw new ArgumentException("Select or enter an exact recovery revision.");
        }
        else if (operation is "review" or "apply")
        {
            if (multiInstalledContext == RecoveryInventoryContext() &&
                multiInstalled?.Status is "installed_owned" or "external_or_unverified")
                throw new InvalidOperationException("Existing configuration requires separate management.");
            context = MultiCandidateContext() ??
                throw new InvalidOperationException("Prepare a valid sender plan first.");
            rules = MultiTransportClient.Eligible(advancedRoutingRules);
            if (operation == "apply")
            {
                reviewed = multiReview;
                if (reviewed is null || multiReviewContext != context ||
                    reviewed.Plan != AdvancedRoutePlanner.PlanSha256(rules))
                    throw new InvalidOperationException("Fresh Multi-provider Review required.");
            }
        }
        else throw new ArgumentException("Unknown operation.");
        int l = language.SelectedIndex;
        if (!ConfirmDestructive("LinuxMailRelay365 | Exclusive maintenance",
            TranslateMailFlow(l,
                "Подтвердите остановленный Postfix, пустую очередь и отсутствие параллельной отправки, запуска службы и изменений конфигурации.",
                "Confirm stopped Postfix, empty queues and prevention of concurrent submissions, service starts and edits.",
                "אשר ש-Postfix כבוי, התורים ריקים ואין פעולות מקבילות.") +
            Environment.NewLine + "Host: " + inspectedHost!.Fqdn,
            ConditionalOfflineClient.MaintenancePhrase))
            throw new OperationCanceledException();
        string? phrase = operation == "apply" ? MultiTransportClient.ApplyPhrase :
            operation == "restore" ? MultiTransportClient.RestorePhrase : null;
        if (phrase is not null && !ConfirmDestructive("LinuxMailRelay365 | Multi-provider write",
            TranslateMailFlow(l,
                "Будут изменены файлы Postfix. Служба останется остановленной. При Apply пароли сохраняются в читаемых SASL-базах на Linux. SSH/sudo-аудит может записывать stdin; используйте только утверждённый канал без записи секретов. При неопределённом результате проверьте ревизии до запуска службы.",
                "Postfix files will change; service stays stopped. Apply stores readable SASL credentials on Linux. SSH/sudo input auditing can record stdin; use only an approved channel that does not record secrets. On an uncertain result scan recovery before starting Postfix.",
                "קבצי Postfix ישתנו. סיסמאות יישמרו במפות SASL קריאות. יש להשתמש בערוץ שאינו מקליט סודות.") +
            Environment.NewLine + (revision ?? reviewed?.Plan), phrase))
            throw new OperationCanceledException();

        var credentials = operation == "apply" ? new (string User, string Secret)?[rules!.Count] : null;
        string? script = null;
        bool attempted = false;
        try
        {
            if (credentials is not null)
                for (int i = 0; i < credentials.Length; i++)
                {
                    if (rules![i].AuthMode != "password") continue;
                    credentials[i] = PromptRouteCredential(rules[i], forApply: true);
                    if (credentials[i] is null) throw new OperationCanceledException();
                }
            if (OfflineHostContext() != hostContext ||
                (context is not null && MultiCandidateContext() != context))
                throw new InvalidOperationException("Host or plan changed after approval.");
            script = MultiTransportClient.Build(operation, ConditionalOfflineClient.MaintenancePhrase,
                rules, reviewed, credentials, revision, phrase);
            var endpoint = Endpoint();
            multiReview = null;
            multiReviewContext = null;
            attempted = operation != "review";
            if (attempted)
            {
                ResetCredentialRotationReview();
                ResetTransportEditReview();
                multiInventory = null;
                multiInventoryContext = null;
                multiInstalled = null;
                multiInstalledContext = null;
                offlineReview = null;
                offlineReviewContext = null;
                conditionalStageReceipt = null;
                conditionalStageContext = null;
                conditionalRecoveryEntries = null;
                conditionalRecoveryContext = null;
                conditionalRouteAudits.Clear();
                conditionalRouteAuditContext = null;
                WriteLine("Multi-provider write requested. Keep Postfix stopped until verified.");
            }
            var result = await SshRemote.RunRootScriptAsync(endpoint, script, TimeSpan.FromMinutes(6));
            if (OfflineHostContext() != hostContext)
                throw new InvalidOperationException("Host context changed.");
            if (!attempted)
            {
                if (result.ExitCode != 0 || MultiCandidateContext() != context)
                    throw new InvalidOperationException("Review failed or became stale.");
                multiReview = MultiTransportClient.ParseReview(result.StdOut,
                    AdvancedRoutePlanner.PlanSha256(rules!), MultiTransportClient.Destinations(rules!));
                multiReviewContext = context;
                WriteLine("Multi-provider Review verified; no mail or changes.");
            }
            else
            {
                var mutation = MultiTransportClient.ParseMutation(result.StdOut, operation, revision);
                multiRevision.Text = mutation.Revision;
                WriteLine("Multi-provider " + mutation.Status + ". Recovery revision: " + mutation.Revision);
                if (result.ExitCode != 0 || mutation.Status is "rolled_back" or "manual_recovery_required")
                    throw new InvalidOperationException("Write failed; inspect recovery.");
                WriteLine("Service not started. Reinspect Postfix before proceeding.");
            }
        }
        catch (OperationCanceledException) when (!attempted) { throw; }
        catch
        {
            // Never include the command, payload, native output or exception
            // chain in the GUI log: any may include private input.
            throw new InvalidOperationException(attempted
                ? "Multi-provider write failed or outcome uncertain. Keep Postfix stopped; reinspect and scan recovery revisions."
                : "Multi-provider Review or preparation failed; no write requested.");
        }
        finally
        {
            script = null;
            if (credentials is not null) Array.Clear(credentials);
            if (attempted)
            {
                discoveredMailIdentity = null;
                inspectedServerIdentity = null;
                existingSmtpAuditIdentity = null;
                inspectedHostIdentity = null;
            }
        }
    }
}
