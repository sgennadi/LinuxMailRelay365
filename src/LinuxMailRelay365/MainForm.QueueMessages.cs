using System.Drawing;
using System.Globalization;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task InspectQueueMessagesAsync(string scope)
    {
        if (scope is not ("postfix" or "sidecar") || !QueueScopeDiscovered(scope))
            throw new InvalidOperationException("Refresh Postfix instance discovery before viewing messages.");
        var initial = Endpoint();
        string nonce = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var response = await SshRemote.RunRootScriptAsync(initial,
            EmbeddedAssets.BuildMailQueueInspectionBundle(scope, messages: true, selectionNonce: nonce), TimeSpan.FromMinutes(3));
        // Do not put raw command output into the log even on a failed reply.
        if (response.ExitCode != 0)
            throw new IOException("Queue metadata query failed (exit " + response.ExitCode + ").");
        var current = RequireSameArchiveConnection(initial, allowFirstPin: true);
        if (!QueueScopeDiscovered(scope))
            throw new InvalidOperationException("Postfix discovery changed during message inventory.");
        var inventory = QueueMessageInventory.Parse(response.StdOut, scope, requireReviewContext: true);
        WriteLine("Queue message metadata: " + scope + "; result=" + inventory.Result +
            "; listed=" + inventory.Rows.Length + "; total=" + (inventory.Total?.ToString() ?? "unknown") +
            ". Read-only; temporary sample references.");
        ShowQueueMessages(current, inventory, nonce);
    }

    private string QueueMessageState(string state) => state switch
    {
        "active" => T("Активные", "Active", "פעילות"),
        "deferred" => T("Отложенные", "Deferred", "מושהות"),
        "held" => T("Удержанные", "Held", "מוחזקות"),
        "incoming" => T("Входящие", "Incoming", "נכנסות"),
        "maildrop" => "Maildrop",
        _ => T("Другие", "Other", "אחרות")
    };

    private string QueueMessageReason(string reason) => reason switch
    {
        "auth" => "SMTP AUTH / OAuth",
        "tls" => "TLS",
        "dns" => "DNS",
        "network" => T("Сеть", "Network", "רשת"),
        "temporary" => "SMTP 4xx",
        "permanent" => "SMTP 5xx",
        "mixed" => T("Смешанные", "Mixed", "מעורב"),
        "other_reason" => T("Другие", "Other", "אחר"),
        "no_reason" => T("Не указана", "Not reported", "לא דווח"),
        _ => "—"
    };

    private void ShowQueueMessages(SshEndpoint endpoint, QueueMessageInventory inventory, string nonce)
    {
        var work = Screen.FromControl(this).WorkingArea.Size;
        using var dialog = new Form
        {
            Text = "LinuxMailRelay365 | " + QueueScopeName(inventory.Scope) + " | Mail messages",
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(work, DeviceDpi, 1050, 700),
            MinimumSize = PreferredDialogSize(work, DeviceDpi, 500, 380),
            BackColor = UiTheme.Canvas, ShowInTaskbar = false, MinimizeBox = false,
            Font = new Font("Segoe UI", 9f)
        };
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(12) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var heading = UiTheme.Emphasis(
            endpoint.Host + ":" + endpoint.Port + " | " + QueueScopeName(inventory.Scope) +
            " | " + QueueResultText(inventory.Result),
            Math.Max(240, dialog.ClientSize.Width - 36),
            warning: inventory.Result != "ok" || inventory.Truncated == true);
        heading.Dock = DockStyle.Fill;

        var filters = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true,
            WrapContents = true, Padding = new Padding(0, 4, 0, 4) };
        string all = T("Все", "All", "הכל");
        var state = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 145 };
        state.Items.Add(all);
        state.Items.AddRange(QueueMessageInventory.States.Select(s => (object)QueueMessageState(s)).ToArray());
        state.SelectedIndex = 0;
        var reason = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 150 };
        reason.Items.Add(all);
        reason.Items.AddRange(QueueMessageInventory.Reasons.Select(s => (object)QueueMessageReason(s)).ToArray());
        reason.SelectedIndex = 0;
        var age = new NumericUpDown { Minimum = 0, Maximum = 999999999, Width = 105, ThousandsSeparator = true };
        var reference = new TextBox { Width = 85, MaxLength = 3 };
        filters.Controls.Add(UiTheme.Text(T("Очередь", "Queue", "תור")));
        filters.Controls.Add(state);
        filters.Controls.Add(UiTheme.Text(T("Причина", "Reason", "סיבה")));
        filters.Controls.Add(reason);
        filters.Controls.Add(UiTheme.Text(T("Мин. возраст (мин)", "Min. age (min)", "גיל מינימלי (דקות)")));
        filters.Controls.Add(age);
        filters.Controls.Add(UiTheme.Text(T("№ снимка", "Sample #", "מספר בדגימה")));
        filters.Controls.Add(reference);

        var grid = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false,
            AllowUserToDeleteRows = false, AllowUserToResizeRows = false,
            MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            RowHeadersVisible = false, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells,
            BackgroundColor = SystemColors.Window, BorderStyle = BorderStyle.FixedSingle,
            ScrollBars = ScrollBars.Both, ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableWithoutHeaderText,
            AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None
        };
        void Column(string key, string title, Type type)
        {
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name = key, HeaderText = title,
                ValueType = type, SortMode = DataGridViewColumnSortMode.Automatic, MinimumWidth = 65 });
        }
        Column("ref", "#", typeof(int));
        Column("state", T("Очередь", "Queue", "תור"), typeof(string));
        Column("age", T("Возраст (мин)", "Age (min)", "גיל (דקות)"), typeof(int));
        Column("size", T("Размер (байт)", "Size (bytes)", "גודל (בתים)"), typeof(long));
        Column("recipients", T("Получатели (число)", "Recipients (count)", "נמענים (כמות)"), typeof(int));
        Column("reason", T("Категория задержки", "Delay category", "קטגוריית עיכוב"), typeof(string));
        grid.Columns["size"]!.DefaultCellStyle.Format = "N0";
        var status = UiTheme.Text("");
        var explanation = UiTheme.Text(T(
            "Только текущий снимок. Номера не являются Queue ID и меняются при новой проверке. " +
            "Фильтры применяются только к полученным строкам (до 500 старейших). Адреса и содержимое не показаны. Retry экспериментальный, с отдельным подтверждением.",
            "Current sample only. Numbers are not native Queue IDs and change on refresh. " +
            "Filters cover only the returned rows (up to the oldest 500). No addresses or message content. Selected Retry is experimental and separately confirmed. Hold / Release also require separate approval.",
            "דגימה בלבד. המספרים אינם מזהי תור. הסינון חל על עד 500 ההודעות הוותיקות, ללא כתובות או תוכן. ניסיון חוזר ניסיוני דורש אישור נפרד."));
        var footer = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft, WrapContents = true };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), false, "back");
        close.DialogResult = DialogResult.OK;
        footer.Controls.Add(close);
        var retry = UiTheme.Action(T("Проверить Retry (без отправки)", "Preview selected Retry (read-only)", "בדיקת ניסיון חוזר ללא שליחה"), false, "check");
        retry.Enabled = false;
        footer.Controls.Add(retry);
        var applyRetry = UiTheme.Action(T("Retry выбранного сообщения (экспериментально)...",
            "Retry selected message (experimental)...", "ניסיון חוזר להודעה נבחרת (ניסיוני)..."), false, "refresh");
        applyRetry.Enabled = false;
        footer.Controls.Add(applyRetry);
        var holdRelease = UiTheme.Action("Hold / Release (experimental)...", false, "shield");
        holdRelease.Enabled = false;
        footer.Controls.Add(holdRelease);
        bool attempted = false;
        bool reviewing = false;
        bool closed = false;
        QueueMessageRow? SelectedRow()
        {
            if (grid.SelectedRows.Count != 1 ||
                grid.SelectedRows[0].Cells["ref"].Value is not int referenceNumber)
                return null;
            return inventory.Rows.SingleOrDefault(item => item.Reference == referenceNumber);
        }
        void UpdateRetry()
        {
            retry.Enabled = !closed && !attempted && !reviewing && inventory.SampledAt.HasValue &&
                inventory.RetryState == "review_only" && SelectedRow() is { State: "deferred" } selected &&
                QueueRetryReview.ValidSha(selected.Fingerprint);
            applyRetry.Enabled = retry.Enabled;
            var candidate = SelectedRow();
            holdRelease.Enabled = !closed && !attempted && !reviewing && inventory.SampledAt.HasValue &&
                inventory.RetryState == "review_only" && candidate is not null &&
                candidate.State is "deferred" or "held" && QueueRetryReview.ValidSha(candidate.Fingerprint);
            holdRelease.Text = candidate?.State == "held"
                ? T("Release (экспериментально)...", "Release (experimental)...", "שחרור (ניסיוני)...")
                : T("Hold (экспериментально)...", "Hold (experimental)...", "השהיה (ניסיוני)...");
        }
        grid.SelectionChanged += (_, _) => UpdateRetry();
        dialog.FormClosing += (_, args) => { if (reviewing) args.Cancel = true; else closed = true; };
        retry.Click += async (_, _) =>
        {
            var selected = SelectedRow();
            if (reviewing || selected is null || !retry.Enabled || inventory.SampledAt is not long sampledAt)
                return;
            reviewing = true;
            holdRelease.Enabled = applyRetry.Enabled = retry.Enabled = close.Enabled = filters.Enabled = grid.Enabled = false;
            try
            {
                var current = RequireSameArchiveConnection(endpoint);
                if (!QueueScopeDiscovered(inventory.Scope))
                    throw new InvalidOperationException("Refresh discovery before reviewing Retry.");
                var reply = await SshRemote.RunRootScriptAsync(current,
                    EmbeddedAssets.BuildQueueRetryReviewBundle(inventory.Scope, nonce, sampledAt, selected.Fingerprint),
                    TimeSpan.FromMinutes(3));
                if (reply.ExitCode != 0)
                    throw new IOException("Read-only Retry review failed.");
                RequireSameArchiveConnection(current);
                if (!QueueScopeDiscovered(inventory.Scope))
                    throw new InvalidOperationException("Discovery changed during Retry review.");
                var plan = QueueRetryReview.Parse(reply.StdOut, inventory.Scope, sampledAt, selected);
                string message = plan.Candidate
                    ? T("Выбранное отложенное сообщение повторно найдено. Запись не разрешена.",
                        "Selected deferred message was reidentified. No queue operation is authorized.",
                        "ההודעה המושהית זוהתה מחדש. אין אישור לפעולה בתור.")
                    : T("Повторно определить сообщение не удалось. Обновите список.",
                        "Message could not be revalidated. Refresh the inventory.",
                        "לא ניתן לאמת שוב את ההודעה. רעננו את הרשימה.") + "\r\n" + plan.Result;
                WriteLine("Read-only selected Retry review: " + plan.Result + ". No submission or retry scheduled.");
                MessageBox.Show(dialog, message, "LinuxMailRelay365 | Retry Plan",
                    MessageBoxButtons.OK, plan.Candidate ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            }
            catch (Exception)
            {
                // Never log a malformed reply, fingerprint or native identity.
                WriteLine("Read-only Retry review failed; refresh the sample. No queue operation requested.");
                MessageBox.Show(dialog, T("Проверка не завершилась. Обновите список.",
                    "Review failed. Refresh the inventory.", "הבדיקה נכשלה. רעננו את הרשימה."),
                    "LinuxMailRelay365 | Retry Plan", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                reviewing = false;
                close.Enabled = filters.Enabled = grid.Enabled = true;
                UpdateRetry();
            }
        };
        applyRetry.Click += async (_, _) =>
        {
            var selected = SelectedRow();
            if (reviewing || attempted || selected is null || !applyRetry.Enabled ||
                inventory.SampledAt is not long sampledAt)
                return;
            reviewing = true;
            holdRelease.Enabled = applyRetry.Enabled = retry.Enabled = close.Enabled = filters.Enabled = grid.Enabled = false;
            try
            {
                var current = RequireSameArchiveConnection(endpoint);
                if (!QueueScopeDiscovered(inventory.Scope))
                    throw new InvalidOperationException("Refresh discovery before Retry.");
                var reply = await SshRemote.RunRootScriptAsync(current,
                    EmbeddedAssets.BuildQueueRetryPrepareBundle(inventory.Scope, nonce, sampledAt, selected.Fingerprint),
                    TimeSpan.FromMinutes(3));
                if (reply.ExitCode != 0) throw new IOException("Retry preparation failed.");
                RequireSameArchiveConnection(current);
                var plan = QueueRetryApplyReceipt.ParsePrepare(reply.StdOut, inventory.Scope, sampledAt, selected);
                if (!plan.Review.Candidate || plan.PreparedAt is not long preparedAt || plan.PlanSha is not string planSha)
                {
                    MessageBox.Show(dialog, T("Подготовка Retry отклонена. Обновите список.",
                        "Retry preparation refused. Refresh the inventory.", "הכנת ניסיון חוזר נדחתה. רעננו את הרשימה.") +
                        "\r\n" + plan.Review.Result, "LinuxMailRelay365 | Retry", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                string details = "Host: " + current.Host + ":" + current.Port +
                    "\r\n" + QueueScopeName(inventory.Scope) + "\r\nSample #" + selected.Reference +
                    "\r\nBytes: " + selected.Bytes + "\r\nRecipients: " + selected.RecipientCount +
                    "\r\nPlan SHA-256: " + planSha + "\r\n\r\n" +
                    T("Только тестовый сервер. Запросить немедленную доставку одного уже находящегося в deferred сообщения. " +
                        "Письмо может уйти реальному получателю. Это не атомарная операция: состояние и часы сервера могут измениться. " +
                        "Нет гарантии доставки. План действует 60 секунд. Не повторяйте запрос при неизвестном результате.",
                        "Disposable test host only. Request immediate delivery of one existing deferred message. " +
                        "It may reach a real recipient. This is not atomic; queue state and server time can change. " +
                        "Delivery is not guaranteed. Plan expires after 60 seconds. Do not repeat an unconfirmed request.",
                        "לשרת בדיקה בלבד. בקשת מסירה מיידית של הודעה מושהית אחת. ההודעה עשויה להגיע לנמען אמיתי. " +
                        "הפעולה אינה אטומית ואין הבטחת מסירה. התוכנית תקפה ל-60 שניות; אין לחזור על בקשה שלא אומתה.");
                if (!ConfirmDestructive("LinuxMailRelay365 | EXPERIMENTAL selected Retry", details,
                        QueueRetryApplyReceipt.Confirmation, dialog))
                    return;
                var confirmed = RequireSameArchiveConnection(current);
                if (!QueueScopeDiscovered(inventory.Scope) || SelectedRow() != selected)
                    throw new InvalidOperationException("Selected message context changed.");
                // Once dispatched, never reuse this sample, even if the reply is lost.
                attempted = true;
                var result = await SshRemote.RunRootScriptAsync(confirmed,
                    EmbeddedAssets.BuildQueueRetryApplyBundle(inventory.Scope, nonce, sampledAt,
                        selected.Fingerprint, preparedAt, planSha), TimeSpan.FromMinutes(3));
                if (result.ExitCode != 0) throw new IOException("Retry request outcome unconfirmed.");
                RequireSameArchiveConnection(confirmed);
                var receipt = QueueRetryApplyReceipt.ParseApply(result.StdOut, inventory.Scope, sampledAt,
                    selected.Fingerprint, preparedAt, planSha);
                WriteLine("Selected Retry outcome: " + receipt.Outcome + "; " + receipt.Reason +
                    ". Delivery unverified. Refresh queue.");
                string message = receipt.Outcome switch
                {
                    "request_accepted" => T("Postfix принял запрос повторной доставки. Доставка не подтверждена.",
                        "Postfix accepted the delivery request. Delivery is not verified.", "Postfix קיבל את בקשת המסירה. המסירה לא אומתה."),
                    "not_requested" => T("Запрос не отправлен: ", "No request issued: ", "הבקשה לא נשלחה: ") + receipt.Reason,
                    _ => T("Результат неизвестен. Не повторяйте запрос; проверьте очередь и журналы.",
                        "Outcome unknown. Do not repeat the request; inspect the queue and logs.", "תוצאה לא ידועה. בדקו תור ויומנים לפני פעולה נוספת.")
                };
                MessageBox.Show(dialog, message, "LinuxMailRelay365 | Retry",
                    MessageBoxButtons.OK, receipt.Outcome == "request_accepted" ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            }
            catch (Exception)
            {
                WriteLine(attempted ? "Selected Retry outcome unknown; do not automatically retry." :
                    "Selected Retry preparation failed; no write dispatched.");
                MessageBox.Show(dialog, attempted
                    ? T("Результат неизвестен. Проверьте очередь и журналы; не повторяйте автоматически.",
                        "Outcome unknown. Inspect queue and logs; do not automatically retry.", "תוצאה לא ידועה. בדקו תור ויומנים.")
                    : T("Подготовка не завершилась. Обновите список.", "Preparation failed. Refresh the inventory.", "ההכנה נכשלה. רעננו את הרשימה."),
                    "LinuxMailRelay365 | Retry", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                reviewing = false;
                close.Enabled = filters.Enabled = grid.Enabled = true;
                UpdateRetry();
                if (attempted) dialog.Close();
            }
        };
        holdRelease.Click += async (_, _) =>
        {
            var selected = SelectedRow();
            if (!holdRelease.Enabled || reviewing || attempted || selected is null ||
                inventory.SampledAt is not long sampledAt) return;
            reviewing = true;
            holdRelease.Enabled = applyRetry.Enabled = retry.Enabled = close.Enabled = filters.Enabled = grid.Enabled = false;
            try
            {
                await RunQueueMaintenanceAsync(endpoint, inventory.Scope,
                    selected.State == "held" ? "release" : "hold", nonce, sampledAt,
                    selected, dialog, () => SelectedRow() == selected, () => attempted = true);
            }
            finally
            {
                reviewing = false;
                close.Enabled = filters.Enabled = grid.Enabled = true;
                UpdateRetry();
                if (attempted) dialog.Close();
            }
        };
        var notes = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 1 };
        notes.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        notes.Controls.Add(status, 0, 0);
        notes.Controls.Add(explanation, 0, 1);
        var retryNote = UiTheme.Text(inventory.RetryState == "review_only"
            ? T("Retry Plan: только выбранные отложенные сообщения с длинным Queue ID; снимок действителен до 5 минут.",
                "Retry Plan: deferred long-ID messages only; sample expires after five minutes. Experimental Apply requires a new 60-second plan and confirmation.",
                "תוכנית ניסיון חוזר: הודעות מושהות עם מזהים ארוכים בלבד; הדגימה תקפה לחמש דקות.")
            : T("Retry Plan недоступен: длинные идентификаторы отключены или контекст не подтверждён.",
                "Retry Plan unavailable: long IDs are disabled or instance context is unverified.",
                "תוכנית ניסיון חוזר אינה זמינה: מזהים ארוכים כבויים או שההקשר לא אומת."));
        notes.Controls.Add(retryNote, 0, 2);

        void RefreshRows()
        {
            string? stateKey = state.SelectedIndex <= 0 ? null : QueueMessageInventory.States[state.SelectedIndex - 1];
            string? reasonKey = reason.SelectedIndex <= 0 ? null : QueueMessageInventory.Reasons[reason.SelectedIndex - 1];
            int? selectedReference = null;
            bool validReference = reference.Text.Length == 0 ||
                (int.TryParse(reference.Text, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) &&
                    parsed is >= 1 and <= QueueMessageInventory.Limit);
            if (validReference && reference.Text.Length > 0)
                selectedReference = int.Parse(reference.Text, CultureInfo.InvariantCulture);
            grid.SuspendLayout();
            try
            {
                grid.Rows.Clear();
                if (validReference)
                    foreach (var item in inventory.Filter(stateKey, reasonKey, (int)age.Value, selectedReference))
                    {
                        int index = grid.Rows.Add(item.Reference, QueueMessageState(item.State), item.AgeMinutes,
                            item.Bytes, item.RecipientCount, QueueMessageReason(item.Reason));
                        if (!SystemInformation.HighContrast && item.State is "deferred" or "held")
                            grid.Rows[index].Cells[1].Style.ForeColor = Color.DarkOrange;
                    }
                grid.ClearSelection();
                UpdateRetry();
                status.Text = T("Показано / получено / всего: ", "Shown / sampled / total: ", "מוצגות / נדגמו / סך הכל: ") +
                    grid.Rows.Count + " / " + inventory.Rows.Length + " / " +
                    (inventory.Total?.ToString() ?? T("Неизвестно", "Unknown", "לא ידוע")) +
                    (inventory.Truncated == true ? " — " + T("частичный список", "partial listing", "רשימה חלקית") : "") +
                    (!validReference ? " — " + T("Некорректный номер", "Invalid reference", "מספר לא תקין") : "");
            }
            finally { grid.ResumeLayout(); }
        }
        state.SelectedIndexChanged += (_, _) => RefreshRows();
        reason.SelectedIndexChanged += (_, _) => RefreshRows();
        age.ValueChanged += (_, _) => RefreshRows();
        reference.TextChanged += (_, _) => RefreshRows();
        root.Controls.Add(heading, 0, 0);
        root.Controls.Add(filters, 0, 1);
        root.Controls.Add(grid, 0, 2);
        root.Controls.Add(notes, 0, 3);
        root.Controls.Add(footer, 0, 4);
        dialog.Controls.Add(root);
        void ResizeNotes()
        {
            int width = Math.Max(240, root.ClientSize.Width - root.Padding.Horizontal - 12);
            heading.MaximumSize = explanation.MaximumSize = status.MaximumSize = retryNote.MaximumSize = new Size(width, 0);
        }
        dialog.ClientSizeChanged += (_, _) => ResizeNotes();
        ResizeNotes();
        RefreshRows();
        dialog.CancelButton = close;
        dialog.ShowDialog(this);
    }
}
