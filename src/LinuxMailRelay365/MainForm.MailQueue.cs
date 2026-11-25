using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private bool QueueScopeDiscovered(string scope)
    {
        string? identity = TryCurrentIdentity();
        if (identity is null || discoveredMailIdentity != identity)
            return false;
        if (scope == "sidecar") return discoveredIsolatedRelay == true;
        return scope is "postfix" or "exim" or "sendmail" &&
            inspectedServerIdentity == identity && inspectedHostIdentity == identity &&
            inspectedMail?.Mta == scope && inspectedHost?.Mta == scope &&
            inspectedHost.MtaState is "active" or "installed_inactive";
    }

    private void AddMailQueueActions(TableLayoutPanel page)
    {
        bool available = false;
        foreach (string scope in new[] { "postfix", "exim", "sendmail", "sidecar" })
        {
            if (!QueueScopeDiscovered(scope)) continue;
            if (!available)
                AddLine(page, UiTheme.Text(T("Почтовые очереди", "Mail queues", "תורי דואר"), true));
            available = true;
            string name = QueueScopeName(scope);
            AddAction(page, T("Проверить очередь " + name + " (только чтение)",
                    "Inspect " + name + " queue (read-only)", "בדיקת תור " + name + " ללא שינוי"),
                () => InspectNativeQueueAsync(scope), false, "check", "mail-queue");
            if (scope == "exim")
                AddAction(page, T("Сообщения Exim и управление очередью", "Exim messages and queue actions", "הודעות Exim ופעולות תור"),
                    InspectEximQueueAsync, false, "check", "exim-queue-messages");
            if (scope == "sendmail")
            {
                AddAction(page, T("Сообщения Sendmail — MTA", "Sendmail MTA queue manager", "הודעות Sendmail MTA לקריאה בלבד"),
                    () => InspectSendmailQueueAsync("mta"), false, "check", "sendmail-queue-mta");
                AddAction(page, T("Сообщения Sendmail — MSP", "Sendmail MSP queue manager", "הודעות Sendmail MSP לקריאה בלבד"),
                    () => InspectSendmailQueueAsync("msp"), false, "check", "sendmail-queue-msp");
                AddAction(page, T("Карантин Sendmail — MTA", "Sendmail MTA quarantine (read-only)", "הסגר Sendmail MTA"),
                    () => InspectSendmailQueueAsync("mta", quarantine: true), false, "check", "sendmail-quarantine-mta");
                AddAction(page, T("Карантин Sendmail — MSP", "Sendmail MSP quarantine (read-only)", "הסגר Sendmail MSP"),
                    () => InspectSendmailQueueAsync("msp", quarantine: true), false, "check", "sendmail-quarantine-msp");
            }
            if (scope is "postfix" or "sidecar")
            {
                AddAction(page, T("Просмотреть сообщения " + name + " (без содержимого)",
                    "View " + name + " messages (metadata only)", "הצגת הודעות " + name + " (מטא-נתונים בלבד)"),
                    () => InspectQueueMessagesAsync(scope), false, "check", "mail-queue-messages");
                AddAction(page, T("Flush всей очереди " + name + " (экспериментально)...",
                    "Flush entire " + name + " queue (experimental)...", "ניסיון מסירה לכל תור " + name + " (ניסיוני)..."),
                    () => FlushPostfixQueueAsync(scope), false, "refresh", "mail-queue-maintenance");
            }
        }
        if (available)
            AddLine(page, UiTheme.Text(T(
                "Статистика без адресов, идентификаторов и текста писем. Не отправляет сообщения и не очищает очередь.",
                "Statistics and bounded metadata omit private addresses and native IDs. Experimental queue actions require separate explicit approval; Flush is not deletion.",
                "סטטיסטיקה בלבד, ללא כתובות או תוכן הודעות, ללא שליחה או ניקוי תור.")));
    }

    private string QueueScopeName(string scope) => scope switch
    {
        "postfix" => "Postfix (/etc/postfix)",
        "exim" => "Exim",
        "sendmail" => "Sendmail",
        _ => T("Изолированный Relay", "Isolated Relay", "ממסר מבודד")
    };

    private async Task InspectNativeQueueAsync(string scope)
    {
        if (!QueueScopeDiscovered(scope))
            throw new InvalidOperationException("Refresh MTA discovery for this exact host before sampling queues.");
        var initial = Endpoint();
        var result = await SshRemote.RunRootScriptAsync(initial,
            EmbeddedAssets.BuildMailQueueInspectionBundle(scope), TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        var current = RequireSameArchiveConnection(initial, allowFirstPin: true);
        if (!QueueScopeDiscovered(scope))
            throw new InvalidOperationException("MTA discovery changed during queue sample.");
        var report = MailQueueSample.Parse(result.StdOut, scope);
        WriteLine("Read-only queue sample: " + scope + "; result=" + report.Result +
            "; client=" + report.ClientResult + "; count=" + (report.Counts["TOTAL"]?.ToString() ?? "unknown") +
            ". Non-atomic; no delivery evidence.");
        ShowNativeQueueReport(current, report);
    }

    private string QueueResultText(string result) => result switch
    {
        "ok" => T("Получен снимок", "Sample obtained", "התקבלה דגימה"),
        "timeout" => T("Тайм-аут — состояние неизвестно", "Timeout — status unknown", "פסק זמן — המצב לא ידוע"),
        "tool_unavailable" => T("Нативная утилита недоступна", "Native tool unavailable", "הכלי המקורי אינו זמין"),
        "output_limit" => T("Очередь превышает лимит анализа", "Queue exceeds sample limit", "התור חורג ממגבלת הדגימה"),
        "command_failed" => T("Нативная проверка не завершилась", "Native query failed", "בדיקת התור נכשלה"),
        "invalid_output" => T("Формат ответа не подтверждён", "Native output could not be verified", "פורמט התשובה לא אומת"),
        "scope_unverified" => T("Не подтверждена область очереди", "Queue instance could not be verified", "מופע התור לא אומת"),
        "sample_changed" => T("Очередь изменилась — повторите проверку", "Queue changed — repeat the sample", "התור השתנה — דגמו שוב"),
        _ => T("Недоступно", "Unavailable", "לא זמין")
    };

    private void ShowNativeQueueReport(SshEndpoint endpoint, MailQueueSample report)
    {
        string Value(string key) => report.Counts[key]?.ToString() ?? T("Неизвестно", "Unknown", "לא ידוע");
        var lines = new List<string>
        {
            "Host: " + endpoint.Host + ":" + endpoint.Port,
            QueueScopeName(report.Scope) + ": " + QueueResultText(report.Result),
            T("Сообщений в очереди", "Queued messages", "הודעות בתור") + ": " + Value("TOTAL")
        };
        if (report.Scope == "sendmail")
        {
            lines.Add("MSP / submit.cf: " + QueueResultText(report.ClientResult) + " — " +
                (report.ClientTotal?.ToString() ?? T("Неизвестно", "Unknown", "לא ידוע")));
            string GroupText(int? groups, string truncated)
            {
                string text = T("Групп очереди", "Queue groups", "קבוצות תור") + ": " +
                    (groups?.ToString() ?? T("Неизвестно", "Unknown", "לא ידוע"));
                if (truncated == "yes")
                    text += " — " + T("Вывод списка ограничен", "Native listing truncated", "הרשימה מוגבלת");
                return text;
            }
            lines.Add("MTA: " + GroupText(report.Groups, report.ListingTruncated));
            lines.Add("MSP: " + GroupText(report.ClientGroups, report.ClientListingTruncated));
            lines.Add(T("Две очереди показаны отдельно; уникальные письма не суммируются.",
                "MTA and MSP queues are shown separately; no unique-message sum is inferred.",
                "שני התורים מוצגים בנפרד; אין חיבור של הודעות ייחודיות."));
        }
        if (report.Detailed)
        {
            lines.Add(T("Активные", "Active", "פעילות") + ": " + Value("ACTIVE"));
            lines.Add(T("Отложенные", "Deferred", "מושהות") + ": " + Value("DEFERRED"));
            lines.Add(T("Удержанные", "Held", "מוחזקות") + ": " + Value("HELD"));
            lines.Add(T("Входящие", "Incoming", "נכנסות") + ": " + Value("INCOMING"));
            lines.Add("Maildrop: " + Value("MAILDROP"));
            lines.Add(T("Другие", "Other", "אחרות") + ": " + Value("OTHER"));
            lines.Add(T("Возраст старейшего (мин)", "Oldest age (minutes)", "גיל ההודעה הוותיקה (דקות)") + ": " + Value("OLDEST_MINUTES"));
            lines.Add("");
            lines.Add(T("Предполагаемые причины задержек (только deferred)",
                "Inferred delay categories (deferred messages only)", "קטגוריות עיכוב משוערות (הודעות מושהות בלבד)"));
            string[] names = ["SMTP AUTH / OAuth", "TLS", "DNS",
                T("Сеть", "Network", "רשת"), "SMTP 4xx", "SMTP 5xx",
                T("Смешанные причины", "Mixed", "מעורב"),
                T("Другие", "Other", "אחר"), T("Причина не указана", "Not reported", "לא דווח")];
            for (int i = 0; i < names.Length; i++)
                lines.Add(names[i] + ": " + Value(MailQueueSample.ReasonKeys[i]));
            lines.Add(T("Категории приблизительные; не являются доказанной причиной сбоя.",
                "Categories are heuristic, not proven root causes.", "הקטגוריות משוערות ואינן סיבת כשל מוכחת."));
        }
        else if (report.Scope == "exim")
        {
            lines.Add(T("Дополнительная проверка", "Detailed listing", "בדיקה מפורטת") +
                ": " + QueueResultText(report.DetailResult));
            if (report.DetailResult == "ok")
            {
                lines.Add(T("Замороженные (Frozen)", "Frozen messages", "הודעות קפואות") + ": " + report.Frozen);
                lines.Add(T("Возраст старейшего (примерно, мин)", "Oldest age (approx. minutes)", "גיל ההודעה הוותיקה בקירוב (דקות)") +
                    ": " + report.EximOldestMinutes);
            }
            lines.Add(T("Причины задержек не подтверждены. Детали сверяются с нативным счётчиком, но это не атомарный снимок.",
                "Delay reasons are not verified. Listing details are cross-checked against the native count, not an atomic snapshot.",
                "סיבות העיכוב לא אומתו. הפירוט נבדק מול הספירה המקורית, ללא צילום אטומי."));
        }
        else if (report.Scope == "sendmail")
            lines.Add(T("Возраст и причины задержек в Sendmail пока не определяются.",
                "Sendmail age and delay categories are not available yet.",
                "גיל וסיבות עיכוב ב-Sendmail אינם זמינים עדיין."));
        lines.Add("");
        lines.Add(T("Неполный или изменяющийся снимок не доказывает пустую очередь или доставку. " +
            "Проверка не разрешает Restore, запуск служб, удаление или повторную отправку.",
            "A non-atomic sample is not proof of an empty queue or mail delivery. " +
            "It does not authorize Restore, service startup, deletion or retry.",
            "דגימה אינה הוכחה לתור ריק או למסירה ואינה מאשרת שחזור, הפעלה, מחיקה או ניסיון חוזר."));
        var work = Screen.FromControl(this).WorkingArea.Size;
        using var dialog = new Form
        {
            Text = "LinuxMailRelay365 | Mail queue",
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(work, DeviceDpi, 820, 650),
            MinimumSize = PreferredDialogSize(work, DeviceDpi, 440, 330),
            BackColor = UiTheme.Canvas, ShowInTaskbar = false, MinimizeBox = false
        };
        bool warning = report.Result != "ok" ||
            (report.Scope == "sendmail" && report.ClientResult != "ok") ||
            (report.Scope == "exim" && (report.DetailResult != "ok" || (report.Frozen ?? 0) > 0)) ||
            report.ListingTruncated == "yes" || report.ClientListingTruncated == "yes" ||
            (report.Counts["DEFERRED"] ?? 0) > 0 || (report.Counts["HELD"] ?? 0) > 0;
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(12) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var heading = UiTheme.Emphasis(warning
                ? T("Проверьте состояние очереди", "Queue needs review", "נדרשת בדיקת התור")
                : T("Диагностика очереди — только чтение", "Queue diagnostics — read-only", "אבחון תור לקריאה בלבד"),
            Math.Max(240, dialog.ClientSize.Width - 40), warning: warning);
        heading.Dock = DockStyle.Fill;
        var detail = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
            ScrollBars = ScrollBars.Vertical, WordWrap = true, Text = string.Join("\r\n", lines) };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), false, "back");
        close.DialogResult = DialogResult.OK;
        root.Controls.Add(heading, 0, 0);
        root.Controls.Add(detail, 0, 1);
        root.Controls.Add(close, 0, 2);
        dialog.Controls.Add(root);
        dialog.ClientSizeChanged += (_, _) =>
            heading.MaximumSize = new Size(Math.Max(240, root.ClientSize.Width - 36), 0);
        dialog.AcceptButton = close;
        dialog.CancelButton = close;
        dialog.ShowDialog(this);
    }
}
