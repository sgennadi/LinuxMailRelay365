using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task InspectSendmailQueueAsync(string queue, bool quarantine = false)
    {
        if (!QueueScopeDiscovered("sendmail") || queue is not ("mta" or "msp"))
            throw new InvalidOperationException("Refresh Sendmail discovery before inspecting a queue.");
        var initial = Endpoint();
        string nonce = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var reply = await SshRemote.RunRootScriptAsync(initial,
            EmbeddedAssets.BuildSendmailQueueInventoryBundle(queue, nonce, reviewable: true, quarantine: quarantine), TimeSpan.FromMinutes(3));
        if (reply.ExitCode != 0) throw new IOException("Sendmail normal queue inventory failed.");
        var current = RequireSameArchiveConnection(initial, allowFirstPin: true);
        if (!QueueScopeDiscovered("sendmail")) throw new InvalidOperationException("Sendmail discovery changed.");
        var inventory = SendmailQueueInventory.Parse(reply.StdOut, queue, nonce, requireReviewable: true, quarantine: quarantine);
        WriteLine("Sendmail " + queue.ToUpperInvariant() + (quarantine ? " quarantine: " : " normal queue: ") + inventory.Result +
            "; listed=" + inventory.Rows.Length + "; total=" + (inventory.Total?.ToString() ?? "unknown") +
            ". Metadata only; no native IDs.");
        ShowSendmailQueue(current, inventory, nonce);
    }

    private string SendmailState(string state) => state switch
    {
        "processing_mark" => T("Отметка обработки (*)", "Processing mark (*)", "סימון עיבוד (*)"),
        "load_limited" => T("Ограничение нагрузки (X)", "Load limited (X)", "מוגבל עקב עומס (X)"),
        "too_young" => T("Рано для обработки (-)", "Too young (-)", "צעירה מדי (-)"),
        _ => T("В очереди, без отметки", "Queued, no status mark", "בתור ללא סימון")
    };

    private void ShowSendmailQueue(SshEndpoint endpoint, SendmailQueueInventory inventory, string nonce)
    {
        var work = Screen.FromControl(this).WorkingArea.Size;
        bool quarantine = inventory.Quarantine;
        string name = (inventory.Queue == "mta" ? "MTA / sendmail.cf" : "MSP / submit.cf") +
            (quarantine ? " | " + T("Карантин", "Quarantine", "הסגר") : "");
        using var dialog = new Form
        {
            Text = "LinuxMailRelay365 | Sendmail | " + name,
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(work, DeviceDpi, 1050, 690),
            MinimumSize = PreferredDialogSize(work, DeviceDpi, 480, 350),
            BackColor = UiTheme.Canvas, ShowInTaskbar = false, MinimizeBox = false
        };
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(12) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var heading = UiTheme.Emphasis(endpoint.Host + ":" + endpoint.Port + " | " + name + " | " +
            QueueResultText(inventory.Result), Math.Max(240, dialog.ClientSize.Width - 40),
            warning: inventory.Result != "ok" || inventory.NativeTruncated == true || inventory.DisplayTruncated == true);
        heading.Dock = DockStyle.Fill;
        var filters = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        string all = T("Все", "All", "הכל");
        var states = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 190 };
        states.Items.Add(all);
        states.Items.AddRange(SendmailQueueInventory.States.Select(s => (object)SendmailState(s)).ToArray());
        states.SelectedIndex = 0;
        var groups = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 85 };
        groups.Items.Add(all);
        groups.Items.AddRange(inventory.Rows.Select(row => row.Group).Distinct().Select(n => (object)n).ToArray());
        groups.SelectedIndex = 0;
        var reasons = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 150 };
        reasons.Items.Add(all);
        reasons.Items.AddRange(SendmailQueueInventory.Reasons.Select(s => (object)QueueMessageReason(s)).ToArray());
        reasons.SelectedIndex = 0;
        filters.Controls.Add(UiTheme.Text(T("Состояние", "State", "מצב"))); filters.Controls.Add(states);
        filters.Controls.Add(UiTheme.Text(T("Группа", "Group", "קבוצה"))); filters.Controls.Add(groups);
        filters.Controls.Add(UiTheme.Text(T("Причина", "Reason", "סיבה"))); filters.Controls.Add(reasons);
        var grid = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells, RowHeadersVisible = false,
            ScrollBars = ScrollBars.Both, BackgroundColor = SystemColors.Window
        };
        void Column(string key, string label, Type type, bool sortable = true) =>
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name = key, HeaderText = label, ValueType = type,
                SortMode = sortable ? DataGridViewColumnSortMode.Automatic : DataGridViewColumnSortMode.NotSortable });
        Column("ref", "#", typeof(int));
        Column("group", T("Группа", "Group", "קבוצה"), typeof(int));
        Column("state", T("Состояние", "State", "מצב"), typeof(string));
        Column("bytes", T("Размер (байт)", "Size (bytes)", "גודל (בתים)"), typeof(long));
        Column("time", T("Время сервера (без года)", "Server time (no year)", "זמן שרת (ללא שנה)"), typeof(string), false);
        Column("reason", T("Категория задержки", "Delay category", "קטגוריית עיכוב"), typeof(string));
        grid.Columns["bytes"]!.DefaultCellStyle.Format = "N0";
        var notes = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 1 };
        notes.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var status = UiTheme.Text("");
        var help = UiTheme.Text(quarantine ? T(
            "Карантин выбранной очереди. Исходные причины, адреса и ID скрыты. Release возвращает выбранное письмо в обычную очередь после подтверждения; удаление недоступно.",
            "Quarantine for the selected queue. Raw reasons, addresses and IDs are hidden. Release returns one selected message to the normal queue after confirmation; deletion is unavailable.",
            "הסגר בתור הנבחר. סיבות מקוריות, כתובות ומזהים מוסתרים. שחרור הודעה אחת דורש אישור; מחיקה אינה זמינה.") : T(
            "Только обычная очередь (не Lost и не Quarantine). Не более 500 записей в нативном порядке. " +
            "Номера строк и групп действуют только в снимке. Время без года/часового пояса; точный возраст неизвестен. " +
            "Отсутствие * не доказывает отсутствие обработки. Причины приблизительные; адреса и ID скрыты. Retry/Flush экспериментальны.",
            "Normal queue only (not Lost or Quarantine). Up to 500 rows in native order. " +
            "Row and group numbers are sample-local. Native time has no year or zone; exact age is unknown. " +
            "No * mark is not proof of inactivity. Delay categories are heuristic; addresses and IDs are hidden. Retry/Flush are experimental and separately confirmed.",
            "תור רגיל בלבד, ללא Lost או Quarantine. עד 500 שורות בסדר המקורי. המספרים תקפים לדגימה בלבד. " +
            "אין שנה או אזור זמן; הגיל המדויק אינו ידוע. היעדר * אינו הוכחה לחוסר פעילות. ניסיון חוזר ניסיוני דורש אישור."));
        notes.Controls.Add(status, 0, 0); notes.Controls.Add(help, 0, 1);
        var footer = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true,
            FlowDirection = FlowDirection.RightToLeft };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), false, "back");
        close.DialogResult = DialogResult.OK; footer.Controls.Add(close);
        var retry = UiTheme.Action(T("Retry выбранного...", "Retry selected (experimental)...", "ניסיון חוזר לנבחרת..."), false, "refresh");
        var flush = UiTheme.Action(T("Flush очереди...", "Run this queue once (experimental)...", "הפעלת תור זה פעם אחת..."), false, "refresh");
        var reload = UiTheme.Action(T("Обновить очередь", "Refresh queue", "רענון תור"), true, "refresh");
        var transition = UiTheme.Action(quarantine ?
            T("Вернуть из карантина...", "Release selected...", "שחרור מהסגר...") :
            T("В карантин...", "Quarantine selected...", "העברה להסגר..."), false, "check");
        if (!quarantine) { footer.Controls.Add(retry); footer.Controls.Add(flush); }
        footer.Controls.Add(transition); footer.Controls.Add(reload);
        bool working = false, attempted = false, snapshotValid = true, outcomeUncertain = false;
        DateTime lastRead = DateTime.Now;
        SendmailQueueRow? Selected() => grid.SelectedRows.Count == 1 &&
            grid.SelectedRows[0].Cells["ref"].Value is int n
            ? inventory.Rows.SingleOrDefault(row => row.Reference == n) : null;
        void UpdateActions()
        {
            bool available = !working && !attempted && snapshotValid && !outcomeUncertain &&
                inventory.Result == "ok" && inventory.ContextVerified && inventory.SampledAt.HasValue;
            bool selected = Selected() is { } row && QueueRetryReview.ValidSha(row.Fingerprint);
            retry.Enabled = !quarantine && available && selected;
            flush.Enabled = !quarantine && available && inventory.Total > 0;
            transition.Enabled = available && selected;
            reload.Enabled = !working;
        }
        dialog.FormClosing += (_, args) => { if (working) args.Cancel = true; };
        grid.SelectionChanged += (_, _) => UpdateActions();
        async Task ExecuteAsync(string action, SendmailQueueRow? row)
        {
            bool whole = action == "flush";
            bool moving = action is "quarantine" or "release";
            if (action is not ("retry" or "flush" or "quarantine" or "release") ||
                quarantine != (action == "release") || working || attempted || !snapshotValid || outcomeUncertain ||
                !inventory.ContextVerified || !inventory.SampledAt.HasValue ||
                (whole ? !flush.Enabled || row is not null :
                    !(moving ? transition.Enabled : retry.Enabled) || row is null || Selected() != row)) return;
            working = true;
            reload.Enabled = retry.Enabled = flush.Enabled = transition.Enabled = close.Enabled = filters.Enabled = grid.Enabled = false;
            string operationNonce = whole
                ? Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant()
                : nonce;
            long sampled = whole ? 0 : inventory.SampledAt.Value;
            string fingerprint = row?.Fingerprint ?? "-";
            try
            {
                var initial = RequireSameArchiveConnection(endpoint);
                if (!QueueScopeDiscovered("sendmail")) throw new InvalidOperationException("Sendmail discovery changed.");
                var reply = await SshRemote.RunRootScriptAsync(initial,
                    EmbeddedAssets.BuildSendmailQueueActionBundle(inventory.Queue, action, operationNonce, sampled, fingerprint),
                    TimeSpan.FromMinutes(3));
                if (reply.ExitCode != 0) throw new IOException("Sendmail preview failed.");
                var reviewed = RequireSameArchiveConnection(initial);
                var plan = SendmailQueueAction.Parse(reply.StdOut, inventory.Queue, action, operationNonce, sampled, fingerprint);
                if (plan.Outcome != "candidate")
                {
                    snapshotValid = false;
                    MessageBox.Show(dialog, plan.Reason, "Sendmail | Preview refused", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                string details = reviewed.Host + ":" + reviewed.Port + "\r\n" + name +
                    "\r\n" + (whole ? "Fresh normal queue: " + plan.TargetCount : "Sample #" + row!.Reference + " | Bytes: " + row.Bytes) +
                    "\r\n\r\n" + T("Только тестовый сервер. План действует 60 секунд.",
                        "Disposable test host only. Plan expires after 60 seconds.", "לשרת בדיקה בלבד. התוכנית תקפה ל-60 שניות.") +
                    "\r\n\r\n" + (moving
                    ? action == "release"
                        ? T("Возврат одного письма в обычную очередь. Возможна немедленная доставка штатным обработчиком.",
                            "Return one message to the normal queue. The existing queue runner may deliver it immediately.",
                            "החזרת הודעה אחת לתור הרגיל; תיתכן מסירה מיידית.")
                        : T("Перемещение одного письма в карантин с фиксированной служебной причиной. Письмо не удаляется.",
                            "Quarantine one message with a fixed operator reason. The message is not deleted.",
                            "העברת הודעה אחת להסגר עם סיבה קבועה; ההודעה לא תימחק.")
                    : whole
                    ? T("Один проход выбранной обычной очереди. Не удаляет письма и не запускает периодический runner.",
                        "One foreground run of the selected normal queue, not deletion or a periodic runner.",
                        "מעבר יחיד בתור הרגיל הנבחר, ללא מחיקה או הפעלה מחזורית.")
                    : T("Попытка обработки одного Queue ID. Sendmail использует поиск по подстроке; совпадение проверено, но очередь может измениться.",
                        "Attempt one selected queue ID. Sendmail uses substring matching; the match was checked, but the queue can change.",
                        "ניסיון עיבוד לפי מזהה אחד. Sendmail משתמש בהתאמת מחרוזת חלקית; התור עשוי להשתנות.")) +
                    "\r\n\r\n" + T("Письма могут уйти реальным получателям. MSP может передать их в MTA. " +
                        "Операция неатомарная, доставка не подтверждается. При неизвестном результате не повторяйте автоматически.",
                        "Mail may reach real recipients. MSP may transfer mail to MTA. Not atomic; no delivery guarantee. Do not automatically repeat an unknown outcome.",
                        "הודעות עשויות להגיע לנמענים אמיתיים. MSP עשוי להעביר ל-MTA. הפעולה אינה אטומית; אין לחזור אוטומטית.") +
                    "\r\nSHA-256: " + plan.PlanSha;
                if (!ConfirmDestructive("Sendmail | EXPERIMENTAL " + action, details,
                    SendmailQueueAction.Confirmation(action), dialog)) return;
                var confirmed = RequireSameArchiveConnection(reviewed);
                if (!QueueScopeDiscovered("sendmail") || (!whole && Selected() != row))
                    throw new InvalidOperationException("Sendmail selection changed.");
                attempted = true;
                snapshotValid = false;
                // Until a strictly validated receipt arrives, the outcome is
                // unknown. A later read-only refresh must not unlock writes.
                outcomeUncertain = true;
                var response = await SshRemote.RunRootScriptAsync(confirmed,
                    EmbeddedAssets.BuildSendmailQueueActionBundle(inventory.Queue, action, operationNonce, sampled,
                        fingerprint, plan.PreparedAt, plan.PlanSha), TimeSpan.FromMinutes(3));
                if (response.ExitCode != 0) throw new IOException("Sendmail outcome unknown.");
                RequireSameArchiveConnection(confirmed);
                var receipt = SendmailQueueAction.Parse(response.StdOut, inventory.Queue, action, operationNonce,
                    sampled, fingerprint, plan.PreparedAt, plan.PlanSha);
                outcomeUncertain = receipt.Outcome == "outcome_unknown";
                WriteLine("Sendmail " + inventory.Queue + " " + action + ": " + receipt.Outcome +
                    "; " + receipt.Reason + ". Delivery unverified.");
                MessageBox.Show(dialog, receipt.Outcome switch
                {
                    "command_completed" => T("Команда завершилась. Проверьте очередь и журналы.",
                        "Native command completed. Refresh queue and inspect logs.", "הפקודה הסתיימה. בדקו תור ויומנים."),
                    "transition_verified" => T("Перемещение подтверждено в обеих очередях. Обновите список.",
                        "Message transition observed in both queue classes. Refresh the inventory.",
                        "המעבר אומת בשני סוגי התורים. יש לרענן את הרשימה."),
                    "not_requested" => receipt.Reason,
                    _ => T("Результат неизвестен. Не повторяйте автоматически.",
                        "Outcome unknown. Do not repeat automatically.", "תוצאה לא ידועה; אין לחזור אוטומטית.")
                }, "Sendmail | " + action, MessageBoxButtons.OK,
                    receipt.Outcome is "command_completed" or "transition_verified" ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            }
            catch (Exception)
            {
                snapshotValid = false;
                if (attempted) outcomeUncertain = true;
                WriteLine(attempted ? "Sendmail action outcome unknown; no automatic repeat." :
                    "Sendmail action preparation failed; no write dispatched.");
                MessageBox.Show(dialog, attempted ? "Outcome unknown. Inspect queue and logs." :
                    "Preparation failed. Refresh inventory.", "Sendmail", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                working = false;
                close.Enabled = filters.Enabled = grid.Enabled = true;
                Refresh();
                // Never automatically repeat an action or reuse its sample.
                // Refresh is read-only, even after an unknown result.
            }
        }
        retry.Click += async (_, _) => { if (retry.Enabled) await ExecuteAsync("retry", Selected()); };
        flush.Click += async (_, _) => { if (flush.Enabled) await ExecuteAsync("flush", null); };
        transition.Click += async (_, _) =>
        {
            if (transition.Enabled) await ExecuteAsync(quarantine ? "release" : "quarantine", Selected());
        };
        void Refresh()
        {
            bool warning = !snapshotValid || outcomeUncertain || inventory.Result != "ok" ||
                !inventory.ContextVerified || inventory.NativeTruncated == true || inventory.DisplayTruncated == true;
            heading.Text = endpoint.Host + ":" + endpoint.Port + " | " + name + " | " +
                (!snapshotValid ? T("Требуется обновление", "Refresh required", "נדרש רענון") : QueueResultText(inventory.Result));
            heading.BackColor = SystemInformation.HighContrast ? SystemColors.Window :
                warning ? UiTheme.WarningSurface : UiTheme.InfoSurface;
            heading.ForeColor = SystemInformation.HighContrast ? SystemColors.WindowText :
                warning ? UiTheme.WarningInk : UiTheme.Navy;
            grid.Rows.Clear();
            if (!snapshotValid)
            {
                status.Text = T("Снимок устарел. Обновите очередь перед дальнейшими действиями.",
                    "Snapshot is stale. Refresh the queue before further actions.",
                    "הדגימה אינה עדכנית. יש לרענן לפני פעולות נוספות.") +
                    (outcomeUncertain ? " | " + UnknownOutcomeText() : "");
                UpdateActions();
                return;
            }
            string? state = states.SelectedIndex <= 0 ? null : SendmailQueueInventory.States[states.SelectedIndex - 1];
            string? reason = reasons.SelectedIndex <= 0 ? null : SendmailQueueInventory.Reasons[reasons.SelectedIndex - 1];
            int? group = groups.SelectedItem is int n ? n : null;
            foreach (var row in inventory.Filter(state, group, reason))
            {
                int index = grid.Rows.Add(row.Reference, row.Group, SendmailState(row.State), row.Bytes,
                    row.NativeTime, QueueMessageReason(row.Reason));
                if (!SystemInformation.HighContrast)
                {
                    grid.Rows[index].Cells[2].Style.ForeColor = row.State switch
                    {
                        "processing_mark" => UiTheme.Navy,
                        "load_limited" => UiTheme.WarningInk,
                        "too_young" => Color.DarkSlateBlue,
                        _ => SystemColors.WindowText
                    };
                    if (row.Reason is "auth" or "tls" or "permanent" or "mixed")
                        grid.Rows[index].Cells[5].Style.ForeColor = Color.Firebrick;
                    else if (row.Reason != "no_reason")
                        grid.Rows[index].Cells[5].Style.ForeColor = UiTheme.WarningInk;
                }
            }
            grid.CurrentCell = null;
            grid.ClearSelection();
            status.Text = T("Показано / получено / нативный список / всего: ",
                "Shown / sampled / native listed / total: ", "מוצגות / נדגמו / רשימה מקורית / סך הכל: ") +
                grid.Rows.Count + " / " + inventory.Rows.Length + " / " +
                (inventory.NativeListed?.ToString() ?? "unknown") + " / " + (inventory.Total?.ToString() ?? "unknown") +
                " | " + T("Групп: ", "Groups: ", "קבוצות: ") + (inventory.Groups?.ToString() ?? "unknown") +
                (inventory.NativeTruncated == true ? " | " + T("Нативный лимит", "Native print limit", "מגבלת תצוגה מקורית") : "") +
                (inventory.DisplayTruncated == true ? " | " + T("Лимит GUI", "GUI limit", "מגבלת GUI") : "") +
                (!inventory.ContextVerified ? " | " + T("Операции недоступны", "Actions unavailable", "פעולות אינן זמינות") : "") +
                " | " + T("Получено (локальное время): ", "Read at (local time): ", "נקרא (זמן מקומי): ") +
                lastRead.ToString("yyyy-MM-dd HH:mm:ss") +
                (outcomeUncertain ? " | " + UnknownOutcomeText() : "");
            UpdateActions();
        }
        string UnknownOutcomeText() => T(
            "Результат предыдущей операции неизвестен. В этом окне доступны только просмотры; проверьте журналы.",
            "Previous operation outcome unknown. This window is read-only; inspect server logs.",
            "תוצאת הפעולה הקודמת אינה ידועה. חלון זה לקריאה בלבד; בדקו יומני שרת.");
        async Task ReloadAsync()
        {
            if (working) return;
            working = true;
            snapshotValid = false;
            grid.Enabled = filters.Enabled = close.Enabled = false;
            Refresh();
            status.Text = T("Получение нового снимка очереди...", "Reading a fresh queue snapshot...", "קורא דגימת תור חדשה...");
            try
            {
                var current = RequireSameArchiveConnection(endpoint);
                if (!QueueScopeDiscovered("sendmail"))
                    throw new InvalidOperationException("Sendmail discovery changed.");
                string queue = inventory.Queue;
                string freshNonce = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
                var reply = await SshRemote.RunRootScriptAsync(current,
                    EmbeddedAssets.BuildSendmailQueueInventoryBundle(queue, freshNonce, reviewable: true, quarantine: quarantine),
                    TimeSpan.FromMinutes(3));
                if (reply.ExitCode != 0) throw new IOException("Sendmail refresh failed.");
                RequireSameArchiveConnection(current);
                if (!QueueScopeDiscovered("sendmail"))
                    throw new InvalidOperationException("Sendmail discovery changed.");
                var next = SendmailQueueInventory.Parse(reply.StdOut, queue, freshNonce, requireReviewable: true, quarantine: quarantine);
                inventory = next;
                nonce = freshNonce;
                lastRead = DateTime.Now;
                // Row and group ordinals have meaning only in the old sample.
                // Do not retain the old group selection or selected message.
                groups.BeginUpdate();
                try
                {
                    groups.Items.Clear();
                    groups.Items.Add(all);
                    groups.Items.AddRange(inventory.Rows.Select(row => row.Group).Distinct().Select(n => (object)n).ToArray());
                    groups.SelectedIndex = 0;
                }
                finally { groups.EndUpdate(); }
                snapshotValid = inventory.Result == "ok";
                if (snapshotValid && !outcomeUncertain) attempted = false;
                WriteLine("Sendmail " + queue.ToUpperInvariant() + " refresh: " + inventory.Result +
                    "; listed=" + inventory.Rows.Length + ". Metadata only.");
            }
            catch (Exception)
            {
                snapshotValid = false;
                WriteLine("Sendmail queue refresh failed; previous sample invalidated. No write requested.");
                MessageBox.Show(dialog, T("Не удалось обновить очередь.", "Queue refresh failed.", "רענון התור נכשל."),
                    "Sendmail", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                working = false;
                close.Enabled = filters.Enabled = grid.Enabled = true;
                Refresh();
            }
        }
        reload.Click += async (_, _) => { if (reload.Enabled) await ReloadAsync(); };
        states.SelectedIndexChanged += (_, _) => Refresh();
        groups.SelectedIndexChanged += (_, _) => Refresh();
        reasons.SelectedIndexChanged += (_, _) => Refresh();
        root.Controls.Add(heading, 0, 0); root.Controls.Add(filters, 0, 1);
        root.Controls.Add(grid, 0, 2); root.Controls.Add(notes, 0, 3); root.Controls.Add(footer, 0, 4);
        dialog.Controls.Add(root);
        void Fit() { heading.MaximumSize = help.MaximumSize = status.MaximumSize =
            new Size(Math.Max(240, root.ClientSize.Width - 36), 0); }
        dialog.ClientSizeChanged += (_, _) => Fit();
        Fit(); Refresh(); dialog.CancelButton = close; dialog.ShowDialog(this);
    }
}
