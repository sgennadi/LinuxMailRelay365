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
            "Sample of up to 500 oldest messages. Native size and age are approximate; Queued is not active delivery. Addresses and IDs are hidden. Freeze/Thaw are experimental; refresh to verify the effect.",
            "דגימה של עד 500 הודעות. הגודל והגיל משוערים; Queued אינו מסירה פעילה. מזהים וכתובות מוסתרים. יש לבדוק שוב לאחר הקפאה או הפשרה."));
        notes.Controls.Add(status, 0, 0); notes.Controls.Add(help, 0, 1);
        var footer = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true,
            FlowDirection = FlowDirection.RightToLeft };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), false, "back");
        close.DialogResult = DialogResult.OK;
        var change = UiTheme.Action("Freeze / Thaw (experimental)...", false, "shield");
        footer.Controls.Add(close); footer.Controls.Add(change);
        bool working = false, attempted = false;
        EximQueueRow? Selected() => grid.SelectedRows.Count == 1 &&
            grid.SelectedRows[0].Cells["ref"].Value is int number
            ? inventory.Rows.SingleOrDefault(row => row.Reference == number) : null;
        void Update()
        {
            var row = Selected();
            change.Enabled = !working && !attempted && inventory.ContextVerified && row is not null &&
                QueueRetryReview.ValidSha(row.Fingerprint);
            change.Text = row?.State == "frozen" ? "Thaw (experimental)..." : "Freeze (experimental)...";
        }
        void Refresh()
        {
            grid.Rows.Clear();
            foreach (var row in inventory.Rows.Where(row => (states.SelectedIndex == 0 ||
                row.State == (states.SelectedIndex == 1 ? "queued" : "frozen")) && row.AgeMinutes >= age.Value))
            {
                int index = grid.Rows.Add(row.Reference, row.State == "frozen" ? "Frozen" : "Queued",
                    row.AgeMinutes, row.NativeSize, row.PendingLines, row.DeliveredLines);
                if (!SystemInformation.HighContrast && row.State == "frozen")
                    grid.Rows[index].Cells[1].Style.ForeColor = Color.DarkOrange;
            }
            grid.ClearSelection();
            status.Text = T("Показано / получено / всего: ", "Shown / sampled / total: ", "מוצגות / נדגמו / סך הכל: ") +
                grid.Rows.Count + " / " + inventory.Rows.Length + " / " + (inventory.Total?.ToString() ?? "unknown") +
                (inventory.Truncated == true ? " | partial" : "") +
                (!inventory.ContextVerified ? " | " + T("Изменения недоступны", "Actions unavailable", "פעולות אינן זמינות") : "");
            Update();
        }
        grid.SelectionChanged += (_, _) => Update();
        states.SelectedIndexChanged += (_, _) => Refresh();
        age.ValueChanged += (_, _) => Refresh();
        dialog.FormClosing += (_, args) => { if (working) args.Cancel = true; };
        change.Click += async (_, _) =>
        {
            var row = Selected();
            if (!change.Enabled || row is null || working || attempted) return;
            string action = row.State == "frozen" ? "thaw" : "freeze";
            working = true;
            change.Enabled = close.Enabled = filters.Enabled = grid.Enabled = false;
            try
            {
                var initial = RequireSameArchiveConnection(endpoint);
                if (!QueueScopeDiscovered("exim")) throw new InvalidOperationException("Exim discovery changed.");
                var reply = await SshRemote.RunRootScriptAsync(initial,
                    EmbeddedAssets.BuildEximQueueActionBundle(action, nonce, inventory.SampledAt, row.Fingerprint),
                    TimeSpan.FromMinutes(3));
                if (reply.ExitCode != 0) throw new IOException("Exim preview failed.");
                var reviewed = RequireSameArchiveConnection(initial);
                var plan = EximQueueAction.Parse(reply.StdOut, action, nonce, inventory.SampledAt, row);
                if (plan.Outcome != "candidate")
                {
                    MessageBox.Show(dialog, plan.Reason, "Exim | Preview refused", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                string details = reviewed.Host + ":" + reviewed.Port + "\r\nExim / " + action +
                    "\r\nSample #" + row.Reference + " | " + row.State + " | " + row.NativeSize + "\r\n\r\n" +
                    T("Только тестовый сервер. Одна операция над выбранным письмом. Freeze может быть отменён auto_thaw; Thaw позволяет доставку. Активное письмо может не измениться. План действует 60 секунд.",
                        "Disposable test host only. One selected message. Freeze may be undone by auto_thaw; Thaw permits delivery. An active message may not change. Plan expires after 60 seconds.",
                        "לשרת בדיקה בלבד. הודעה נבחרת אחת. הקפאה עשויה להתבטל אוטומטית; הפשרה מאפשרת מסירה. התוכנית תקפה ל-60 שניות.") +
                    "\r\nSHA-256: " + plan.PlanSha;
                if (!ConfirmDestructive("Exim | EXPERIMENTAL " + action, details,
                        EximQueueAction.Confirmation(action), dialog)) return;
                var confirmed = RequireSameArchiveConnection(reviewed);
                if (!QueueScopeDiscovered("exim") || Selected() != row)
                    throw new InvalidOperationException("Exim selected message changed.");
                attempted = true;
                var result = await SshRemote.RunRootScriptAsync(confirmed,
                    EmbeddedAssets.BuildEximQueueActionBundle(action, nonce, inventory.SampledAt, row.Fingerprint,
                        plan.PreparedAt, plan.PlanSha), TimeSpan.FromMinutes(3));
                if (result.ExitCode != 0) throw new IOException("Exim action outcome unknown.");
                RequireSameArchiveConnection(confirmed);
                var receipt = EximQueueAction.Parse(result.StdOut, action, nonce, inventory.SampledAt,
                    row, plan.PreparedAt, plan.PlanSha);
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
                WriteLine(attempted ? "Exim action outcome unknown; inspect before any further action." :
                    "Exim action preview failed; no command dispatched.");
                MessageBox.Show(dialog, attempted ? "Outcome unknown. Refresh queue and inspect logs." :
                    "Preview failed. Refresh queue.", "Exim", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                working = false;
                close.Enabled = filters.Enabled = grid.Enabled = true;
                Update();
                if (attempted) dialog.Close();
            }
        };
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
