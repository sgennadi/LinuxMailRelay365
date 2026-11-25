using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task InspectSendmailQueueAsync(string queue)
    {
        if (!QueueScopeDiscovered("sendmail") || queue is not ("mta" or "msp"))
            throw new InvalidOperationException("Refresh Sendmail discovery before inspecting a queue.");
        var initial = Endpoint();
        string nonce = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var reply = await SshRemote.RunRootScriptAsync(initial,
            EmbeddedAssets.BuildSendmailQueueInventoryBundle(queue, nonce), TimeSpan.FromMinutes(3));
        if (reply.ExitCode != 0) throw new IOException("Sendmail normal queue inventory failed.");
        var current = RequireSameArchiveConnection(initial, allowFirstPin: true);
        if (!QueueScopeDiscovered("sendmail")) throw new InvalidOperationException("Sendmail discovery changed.");
        var inventory = SendmailQueueInventory.Parse(reply.StdOut, queue, nonce);
        WriteLine("Sendmail " + queue.ToUpperInvariant() + " normal queue: " + inventory.Result +
            "; listed=" + inventory.Rows.Length + "; total=" + (inventory.Total?.ToString() ?? "unknown") +
            ". Read-only; no native IDs.");
        ShowSendmailQueue(current, inventory);
    }

    private string SendmailState(string state) => state switch
    {
        "processing_mark" => T("Отметка обработки (*)", "Processing mark (*)", "סימון עיבוד (*)"),
        "load_limited" => T("Ограничение нагрузки (X)", "Load limited (X)", "מוגבל עקב עומס (X)"),
        "too_young" => T("Рано для обработки (-)", "Too young (-)", "צעירה מדי (-)"),
        _ => T("В очереди, без отметки", "Queued, no status mark", "בתור ללא סימון")
    };

    private void ShowSendmailQueue(SshEndpoint endpoint, SendmailQueueInventory inventory)
    {
        var work = Screen.FromControl(this).WorkingArea.Size;
        string name = inventory.Queue == "mta" ? "MTA / sendmail.cf" : "MSP / submit.cf";
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
        var help = UiTheme.Text(T(
            "Только обычная очередь (не Lost и не Quarantine). Не более 500 записей в нативном порядке. " +
            "Номера строк и групп действуют только в снимке. Время без года/часового пояса; точный возраст неизвестен. " +
            "Отсутствие * не доказывает отсутствие обработки. Причины приблизительные; адреса и ID скрыты. Нет операций записи.",
            "Normal queue only (not Lost or Quarantine). Up to 500 rows in native order. " +
            "Row and group numbers are sample-local. Native time has no year or zone; exact age is unknown. " +
            "No * mark is not proof of inactivity. Delay categories are heuristic; addresses and IDs are hidden. No write actions.",
            "תור רגיל בלבד, ללא Lost או Quarantine. עד 500 שורות בסדר המקורי. המספרים תקפים לדגימה בלבד. " +
            "אין שנה או אזור זמן; הגיל המדויק אינו ידוע. היעדר * אינו הוכחה לחוסר פעילות. ללא פעולות כתיבה."));
        notes.Controls.Add(status, 0, 0); notes.Controls.Add(help, 0, 1);
        var footer = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true,
            FlowDirection = FlowDirection.RightToLeft };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), false, "back");
        close.DialogResult = DialogResult.OK; footer.Controls.Add(close);
        void Refresh()
        {
            string? state = states.SelectedIndex <= 0 ? null : SendmailQueueInventory.States[states.SelectedIndex - 1];
            string? reason = reasons.SelectedIndex <= 0 ? null : SendmailQueueInventory.Reasons[reasons.SelectedIndex - 1];
            int? group = groups.SelectedItem is int n ? n : null;
            grid.Rows.Clear();
            foreach (var row in inventory.Filter(state, group, reason))
            {
                int index = grid.Rows.Add(row.Reference, row.Group, SendmailState(row.State), row.Bytes,
                    row.NativeTime, QueueMessageReason(row.Reason));
                if (!SystemInformation.HighContrast && row.State != "queued")
                    grid.Rows[index].Cells[2].Style.ForeColor = Color.DarkOrange;
            }
            grid.ClearSelection();
            status.Text = T("Показано / получено / нативный список / всего: ",
                "Shown / sampled / native listed / total: ", "מוצגות / נדגמו / רשימה מקורית / סך הכל: ") +
                grid.Rows.Count + " / " + inventory.Rows.Length + " / " +
                (inventory.NativeListed?.ToString() ?? "unknown") + " / " + (inventory.Total?.ToString() ?? "unknown") +
                " | " + T("Групп: ", "Groups: ", "קבוצות: ") + (inventory.Groups?.ToString() ?? "unknown") +
                (inventory.NativeTruncated == true ? " | " + T("Нативный лимит", "Native print limit", "מגבלת תצוגה מקורית") : "") +
                (inventory.DisplayTruncated == true ? " | " + T("Лимит GUI", "GUI limit", "מגבלת GUI") : "");
        }
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
