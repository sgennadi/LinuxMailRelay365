using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task InspectEximQueueAsync()
    {
        if (!QueueScopeDiscovered("exim")) throw new InvalidOperationException("Refresh Exim discovery first.");
        var initial = Endpoint();
        string nonce = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var reply = await SshRemote.RunRootScriptAsync(initial, EmbeddedAssets.BuildEximQueueInventoryBundle(nonce),
            TimeSpan.FromMinutes(3));
        if (reply.ExitCode != 0) throw new IOException("Exim queue query failed.");
        var current = RequireSameArchiveConnection(initial, allowFirstPin: true);
        if (!QueueScopeDiscovered("exim")) throw new InvalidOperationException("Exim discovery changed.");
        var inventory = EximQueueInventory.Parse(reply.StdOut, nonce);
        WriteLine("Exim queue inventory: " + inventory.Result + "; listed=" + inventory.Rows.Length +
            "; total=" + (inventory.Total?.ToString() ?? "unknown") + ". No raw identities.");
        ShowEximQueue(current, nonce, inventory);
    }

    private void ShowEximQueue(SshEndpoint endpoint, string nonce, EximQueueInventory inventory)
    {
        var work = Screen.FromControl(this).WorkingArea.Size;
        using var dialog = new Form
        {
            Text = "LinuxMailRelay365 | Exim queue",
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(work, DeviceDpi, 1000, 680),
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
        var heading = UiTheme.Emphasis(endpoint.Host + ":" + endpoint.Port + " | Exim | " + QueueResultText(inventory.Result),
            Math.Max(240, dialog.ClientSize.Width - 40),
            warning: inventory.Result != "ok" || inventory.Truncated == true || !inventory.ContextVerified);
        var filters = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        var states = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 150 };
        states.Items.AddRange([T("Все", "All", "הכל"), "Queued", "Frozen"]);
        states.SelectedIndex = 0;
        var age = new NumericUpDown { Minimum = 0, Maximum = 999999999, Width = 110 };
        filters.Controls.Add(UiTheme.Text(T("Состояние", "State", "מצב")));
        filters.Controls.Add(states);
        filters.Controls.Add(UiTheme.Text(T("Мин. возраст (мин)", "Min. age (min)", "גיל מינימלי בדקות")));
        filters.Controls.Add(age);
        var grid = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells, RowHeadersVisible = false,
            ScrollBars = ScrollBars.Both, BackgroundColor = SystemColors.Window
        };
        void Column(string key, string label, Type type) => grid.Columns.Add(new DataGridViewTextBoxColumn
            { Name = key, HeaderText = label, ValueType = type, SortMode = DataGridViewColumnSortMode.Automatic });
        Column("ref", "#", typeof(int));
        Column("state", T("Состояние", "State", "מצב"), typeof(string));
        Column("age", T("Возраст (мин)", "Age (min)", "גיל בדקות"), typeof(int));
        Column("size", T("Размер (примерно)", "Size (native approximate)", "גודל משוער"), typeof(string));
        Column("pending", T("Строки получателей", "Pending recipient lines", "שורות נמענים ממתינים"), typeof(int));
        Column("delivered", T("Отмечены доставленными", "Marked delivered lines", "שורות שסומנו כנמסרו"), typeof(int));
        var notes = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 1 };
        notes.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var status = UiTheme.Text("");
        var help = UiTheme.Text(T(
            "Снимок до 500 старейших сообщений. Размер и возраст приблизительные; Queued не означает активную доставку. Адреса и ID скрыты. Freeze/Thaw экспериментальны; после команды проверяйте состояние заново.",
            "Sample of up to 500 oldest messages. Native size and age are approximate; Queued is not active delivery. Addresses and IDs are hidden. Freeze/Thaw, Retry, Flush and Delete are experimental; refresh to verify the effect.",
            "דגימה של עד 500 הודעות. הגודל והגיל משוערים; Queued אינו מסירה פעילה. מזהים וכתובות מוסתרים. יש לבדוק שוב לאחר הקפאה או הפשרה."));
        notes.Controls.Add(status, 0, 0); notes.Controls.Add(help, 0, 1);
        var footer = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true,
            FlowDirection = FlowDirection.RightToLeft };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), false, "back");
        close.DialogResult = DialogResult.OK;
        var change = UiTheme.Action("Freeze / Thaw (experimental)...", false, "shield");
        var retry = UiTheme.Action(T("Retry выбранного...", "Retry selected...", "ניסיון חוזר לנבחרת..."), false, "refresh");
        var flush = UiTheme.Action(T("Flush всей очереди...", "Flush default queue...", "ניסיון מסירה לכל התור..."), false, "refresh");
        var delete = UiTheme.Action(T("Удалить Frozen...", "Delete frozen...", "מחיקת הודעה קפואה..."), false, "trash");
        footer.Controls.Add(close); footer.Controls.Add(change); footer.Controls.Add(retry);
        footer.Controls.Add(delete); footer.Controls.Add(flush);
        var reload = UiTheme.Action(T("Обновить очередь", "Refresh queue", "רענון תור"), true, "refresh");
        footer.Controls.Add(reload);
        bool working = false, attempted = false, snapshotValid = inventory.Result == "ok", outcomeUncertain = false;
        DateTime lastRead = DateTime.Now;
        EximQueueRow? Selected() => grid.SelectedRows.Count == 1 &&
            grid.SelectedRows[0].Cells["ref"].Value is int number
            ? inventory.Rows.SingleOrDefault(row => row.Reference == number) : null;
        void Update()
        {
            var row = Selected();
            bool available = !working && !attempted && snapshotValid && !outcomeUncertain &&
                inventory.ContextVerified && inventory.Result == "ok";
            change.Enabled = available && row is not null && QueueRetryReview.ValidSha(row.Fingerprint);
            change.Text = row?.State == "frozen" ? "Thaw (experimental)..." : "Freeze (experimental)...";
            retry.Enabled = change.Enabled && row?.State == "queued";
            delete.Enabled = change.Enabled && row?.State == "frozen";
            // A fresh whole-queue plan, not a visible-row selection, controls Flush.
            flush.Enabled = available && inventory.Total > 0;
            reload.Enabled = !working;
        }
        string UnknownOutcomeText() => T(
            "Результат неизвестен. В этом окне доступен только просмотр; проверьте журналы.",
            "Previous operation outcome unknown. This window is read-only; inspect server logs.",
            "תוצאת הפעולה אינה ידועה. חלון זה לקריאה בלבד; בדקו יומני שרת.");
        void Refresh()
        {
            bool warning = !snapshotValid || outcomeUncertain || inventory.Truncated == true || !inventory.ContextVerified;
            heading.Text = endpoint.Host + ":" + endpoint.Port + " | Exim | " +
                (snapshotValid ? QueueResultText(inventory.Result) : T("Требуется обновление", "Refresh required", "נדרש רענון"));
            QueueVisuals.ApplyHeading(heading, warning, outcomeUncertain);
            grid.Rows.Clear();
            if (!snapshotValid)
            {
                status.Text = T("Снимок недействителен. Обновите очередь.", "Snapshot invalid. Refresh the queue.", "הדגימה אינה תקפה. יש לרענן את התור.") +
                    (outcomeUncertain ? " | " + UnknownOutcomeText() : "");
                Update();
                return;
            }
            foreach (var row in inventory.Rows.Where(row => (states.SelectedIndex == 0 ||
                row.State == (states.SelectedIndex == 1 ? "queued" : "frozen")) && row.AgeMinutes >= age.Value))
            {
                int index = grid.Rows.Add(row.Reference, row.State == "frozen" ? "Frozen" : "Queued",
                    row.AgeMinutes, row.NativeSize, row.PendingLines, row.DeliveredLines);
                QueueVisuals.ApplyState(grid.Rows[index].Cells["state"], row.State);
            }
            grid.CurrentCell = null;
            grid.ClearSelection();
            status.Text = T("Показано / получено / всего: ", "Shown / sampled / total: ", "מוצגות / נדגמו / סך הכל: ") +
                grid.Rows.Count + " / " + inventory.Rows.Length + " / " + (inventory.Total?.ToString() ?? "unknown") +
                (inventory.Truncated == true ? " | partial" : "") +
                (!inventory.ContextVerified ? " | " + T("Изменения недоступны", "Actions unavailable", "פעולות אינן זמינות") : "") +
                " | " + T("Получено: ", "Read at (local time): ", "נקרא: ") + lastRead.ToString("yyyy-MM-dd HH:mm:ss") +
                (outcomeUncertain ? " | " + UnknownOutcomeText() : "");
            Update();
        }
        async Task ReloadAsync()
        {
            if (working) return;
            working = true;
            snapshotValid = false;
            close.Enabled = filters.Enabled = grid.Enabled = false;
            Refresh();
            status.Text = T("Обновление очереди...", "Reading a fresh queue snapshot...", "קורא דגימת תור חדשה...");
            try
            {
                var current = RequireSameArchiveConnection(endpoint);
                if (!QueueScopeDiscovered("exim")) throw new InvalidOperationException("Exim discovery changed.");
                string freshNonce = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
                var reply = await SshRemote.RunRootScriptAsync(current,
                    EmbeddedAssets.BuildEximQueueInventoryBundle(freshNonce), TimeSpan.FromMinutes(3));
                if (reply.ExitCode != 0) throw new IOException("Exim refresh failed.");
                RequireSameArchiveConnection(current);
                if (!QueueScopeDiscovered("exim")) throw new InvalidOperationException("Exim discovery changed.");
                inventory = EximQueueInventory.Parse(reply.StdOut, freshNonce);
                nonce = freshNonce;
                lastRead = DateTime.Now;
                snapshotValid = inventory.Result == "ok";
                if (snapshotValid && !outcomeUncertain) attempted = false;
                WriteLine("Exim queue refresh: " + inventory.Result + "; listed=" + inventory.Rows.Length + ". Metadata only.");
            }
            catch (Exception)
            {
                snapshotValid = false;
                WriteLine("Exim queue refresh failed; previous sample invalidated. No write requested.");
                MessageBox.Show(dialog, T("Не удалось обновить очередь.", "Queue refresh failed.", "רענון התור נכשל."),
                    "Exim", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                working = false;
                close.Enabled = filters.Enabled = grid.Enabled = true;
                Refresh();
            }
        }
        reload.Click += async (_, _) => { if (reload.Enabled) await ReloadAsync(); };
        grid.SelectionChanged += (_, _) => Update();
        states.SelectedIndexChanged += (_, _) => Refresh();
        age.ValueChanged += (_, _) => Refresh();
        dialog.FormClosing += (_, args) => { if (working) args.Cancel = true; };
        async Task ExecuteAsync(string action, EximQueueRow? row)
        {
            bool wholeQueue = action == "flush";
            if (working || attempted || !snapshotValid || outcomeUncertain || !inventory.ContextVerified ||
                (wholeQueue ? !flush.Enabled || row is not null : row is null ||
                 !QueueRetryReview.ValidSha(row.Fingerprint) || Selected() != row)) return;
            long sampled = wholeQueue ? 0 : inventory.SampledAt;
            string fingerprint = row?.Fingerprint ?? "-";
            string actionNonce = wholeQueue
                ? Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant()
                : nonce;
            working = true;
            reload.Enabled = change.Enabled = retry.Enabled = flush.Enabled = delete.Enabled = close.Enabled = filters.Enabled = grid.Enabled = false;
            try
            {
                var initial = RequireSameArchiveConnection(endpoint);
                if (!QueueScopeDiscovered("exim")) throw new InvalidOperationException("Exim discovery changed.");
                var reply = await SshRemote.RunRootScriptAsync(initial,
                    EmbeddedAssets.BuildEximQueueActionBundle(action, actionNonce, sampled, fingerprint),
                    TimeSpan.FromMinutes(3));
                if (reply.ExitCode != 0) throw new IOException("Exim preview failed.");
                var reviewed = RequireSameArchiveConnection(initial);
                var plan = EximQueueAction.Parse(reply.StdOut, action, actionNonce, sampled, row);
                if (plan.Outcome != "candidate")
                {
                    snapshotValid = false;
                    MessageBox.Show(dialog, plan.Reason, "Exim | Preview refused", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                string details = reviewed.Host + ":" + reviewed.Port + "\r\nExim / " + action +
                    "\r\n" + (wholeQueue
                        ? "Fresh default queue: " + plan.Total + " | Frozen: " + plan.Frozen
                        : "Sample #" + row!.Reference + " | " + row.State + " | " + row.NativeSize) +
                    "\r\n\r\n" + T("Только тестовый сервер. План действует 60 секунд.",
                        "Disposable test host only. Plan expires after 60 seconds.", "לשרת בדיקה בלבד. התוכנית תקפה ל-60 שניות.") + "\r\n\r\n";
                details += action switch
                {
                    "retry" => T("Принудительный проход очереди в диапазоне одного ID. Exim может использовать SMTP-соединение для других писем. Не используется -M или -qff. Письма могут быть доставлены; эффект не гарантирован.",
                        "Forced queue run restricted to one ID range. Exim may reuse SMTP connections for other messages. No -M or -qff. Mail may be delivered; effect is not guaranteed.",
                        "מעבר כפוי בטווח מזהה אחד. Exim עשוי להשתמש בחיבור גם להודעות נוספות. הודעות עשויות להימסר."),
                    "flush" => T("Однократный принудительный проход всей очереди по умолчанию. Не удаляет письма и не использует -qff. Новые сообщения могут попасть в очередь; auto_thaw может разморозить письма. Частый Flush снижает производительность.",
                        "One forced default-queue run, not deletion. No -qff. Mail may arrive after preview; auto_thaw may thaw messages. Frequent Flush can harm performance.",
                        "מעבר כפוי חד-פעמי בכל תור ברירת המחדל, ללא מחיקה. הודעות חדשות עשויות להגיע והפשרה אוטומטית אפשרית."),
                    "delete" => T("НЕОБРАТИМОЕ удаление одного Frozen-сообщения. Exim не отправит уведомление о недоставке. Резервная копия письма не создаётся.",
                        "IRREVERSIBLE removal of one frozen message. Exim sends no bounce. This manager does not back up the message.",
                        "מחיקה בלתי הפיכה של הודעה קפואה אחת. אין הודעת כשל ואין גיבוי אוטומטי."),
                    _ => T("Одна операция над выбранным письмом. Freeze может быть отменён auto_thaw; Thaw разрешает доставку. Активное письмо может не измениться.",
                        "One selected message. Freeze may be undone by auto_thaw; Thaw permits delivery. An active message may not change.",
                        "הודעה נבחרת אחת. הקפאה עשויה להתבטל אוטומטית; הפשרה מאפשרת מסירה.")
                };
                details += "\r\n\r\n" + T("Операция неатомарная. При неизвестном результате не повторяйте автоматически.",
                    "Not atomic. Do not automatically repeat an unconfirmed operation.", "הפעולה אינה אטומית; אין לחזור אוטומטית אם התוצאה לא ידועה.") +
                    "\r\nSHA-256: " + plan.PlanSha;
                if (!ConfirmDestructive("Exim | EXPERIMENTAL " + action, details,
                        EximQueueAction.Confirmation(action), dialog)) return;
                var confirmed = RequireSameArchiveConnection(reviewed);
                if (!QueueScopeDiscovered("exim") || (!wholeQueue && Selected() != row))
                    throw new InvalidOperationException("Exim selected message changed.");
                attempted = true;
                snapshotValid = false;
                outcomeUncertain = true;
                var result = await SshRemote.RunRootScriptAsync(confirmed,
                    EmbeddedAssets.BuildEximQueueActionBundle(action, actionNonce, sampled, fingerprint,
                        plan.PreparedAt, plan.PlanSha), TimeSpan.FromMinutes(3));
                if (result.ExitCode != 0) throw new IOException("Exim action outcome unknown.");
                RequireSameArchiveConnection(confirmed);
                var receipt = EximQueueAction.Parse(result.StdOut, action, actionNonce, sampled,
                    row, plan.PreparedAt, plan.PlanSha);
                outcomeUncertain = receipt.Outcome == "outcome_unknown";
                WriteLine("Exim " + action + ": " + receipt.Outcome + "; " + receipt.Reason + ". Effect unverified.");
                string message = receipt.Outcome switch
                {
                    "command_completed" => T("Команда завершилась. Обновите очередь для проверки эффекта.",
                        "Native command completed. Refresh the queue to verify the effect.", "הפקודה הסתיימה; יש לבדוק את התור מחדש."),
                    "not_requested" => receipt.Reason,
                    _ => T("Результат неизвестен. Не повторяйте автоматически.",
                        "Outcome unknown. Do not repeat automatically.", "תוצאה לא ידועה; אין לחזור אוטומטית.")
                };
                MessageBox.Show(dialog, message, "Exim | " + action, MessageBoxButtons.OK,
                    receipt.Outcome == "command_completed" ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            }
            catch (Exception)
            {
                snapshotValid = false;
                if (attempted) outcomeUncertain = true;
                WriteLine(attempted ? "Exim action outcome unknown; inspect before any further action." :
                    "Exim action preview failed; no command dispatched.");
                MessageBox.Show(dialog, attempted ? "Outcome unknown. Refresh queue and inspect logs." :
                    "Preview failed. Refresh queue.", "Exim", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                working = false;
                close.Enabled = filters.Enabled = grid.Enabled = true;
                Refresh();
            }
        }
        change.Click += async (_, _) =>
        {
            var row = Selected();
            if (change.Enabled && row is not null)
                await ExecuteAsync(row.State == "frozen" ? "thaw" : "freeze", row);
        };
        retry.Click += async (_, _) =>
        {
            if (retry.Enabled && Selected() is { State: "queued" } row) await ExecuteAsync("retry", row);
        };
        delete.Click += async (_, _) =>
        {
            if (delete.Enabled && Selected() is { State: "frozen" } row) await ExecuteAsync("delete", row);
        };
        flush.Click += async (_, _) => { if (flush.Enabled) await ExecuteAsync("flush", null); };
        root.Controls.Add(heading, 0, 0); root.Controls.Add(filters, 0, 1);
        root.Controls.Add(grid, 0, 2); root.Controls.Add(notes, 0, 3); root.Controls.Add(footer, 0, 4);
        dialog.Controls.Add(root);
        void Fit() { heading.MaximumSize = help.MaximumSize = status.MaximumSize =
            new Size(Math.Max(240, root.ClientSize.Width - 36), 0); }
        dialog.ClientSizeChanged += (_, _) => Fit();
        Fit(); Refresh();
        dialog.CancelButton = close;
        dialog.ShowDialog(this);
    }
}
