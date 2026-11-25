using System.Drawing;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private MultiMailboxSourceEditRequest? PromptMultiMailboxSourceEdit(Form owner,
        string action, MultiMailboxIdentityMap map, MultiMailboxIdentityRow? row,
        MultiMailboxSourceBackupCatalog? catalog = null)
    {
        if (action is not ("add" or "edit" or "remove" or "restore") || map.Status is not ("ok" or "absent") ||
            (action is "edit" or "remove" && (row is null || !map.Rows.Contains(row)))) return null;
        string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        if (action == "restore")
        {
            if (map.Status != "ok" || catalog is null) return null;
            using var restore = new Form { Text = "LinuxMailRelay365 | Restore planned mailbox map",
                StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
                ClientSize = PreferredDialogSize(Screen.FromControl(owner).WorkingArea.Size, owner.DeviceDpi, 680, 360),
                Font = new Font("Segoe UI", 10f), MinimizeBox = false };
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3,
                Padding = new Padding(12) };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            var text = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
                ScrollBars = ScrollBars.Vertical, Text =
                "Select a backup whose recorded successor matches the current source map, or enter an exact backup ID for manual review." +
                Environment.NewLine + "Compatible maps: " + catalog.Backups.Length + " / " + catalog.Scanned + " entries inspected." +
                Environment.NewLine + "Preview rechecks the backup bytes and all required identities and certificates." +
                Environment.NewLine + "The current map will be backed up again. Runtime, keys, mailboxes and services remain unchanged." };
            var id = new ComboBox { Dock = DockStyle.Fill, MaxLength = 15, DropDownStyle = ComboBoxStyle.DropDown };
            foreach (var item in catalog.Backups) id.Items.Add(item.BackupId);
            var count = new Label { AutoSize = true, Dock = DockStyle.Fill };
            void UpdateCount()
            {
                var choice = catalog.Backups.FirstOrDefault(x => x.BackupId == id.Text.Trim());
                count.Text = choice is null ? "Manual ID / no selection; preview required." :
                    "Stored map: " + choice.RowCount + " mailbox(es). Identity verification pending preview.";
            }
            UpdateCount();
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true,
                FlowDirection = FlowDirection.RightToLeft };
            var abort = new Button { Text = T("Отмена", "Cancel", "ביטול"), AutoSize = true, DialogResult = DialogResult.Cancel };
            var review = new Button { Text = T("Предпросмотр", "Preview", "תצוגה מקדימה"), AutoSize = true,
                DialogResult = DialogResult.OK, Enabled = false };
            MultiMailboxSourceEditRequest RequestRestore() => new("restore", map.Sha256, map.Rows.Length,
                "", "", "", "", nonce, id.Text.Trim());
            id.TextChanged += (_, _) => { UpdateCount(); review.Enabled = RequestRestore().Valid; };
            buttons.Controls.Add(abort); buttons.Controls.Add(review);
            var picker = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 1 };
            picker.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            picker.Controls.Add(id, 0, 0); picker.Controls.Add(count, 0, 1);
            layout.Controls.Add(text, 0, 0); layout.Controls.Add(picker, 0, 1); layout.Controls.Add(buttons, 0, 2);
            restore.Controls.Add(layout); restore.CancelButton = abort; restore.AcceptButton = review;
            return restore.ShowDialog(owner) == DialogResult.OK && RequestRestore().Valid ? RequestRestore() : null;
        }
        if (action == "remove")
        {
            var removal = new MultiMailboxSourceEditRequest(action, map.Sha256, map.Rows.Length,
                row!.Mailbox, "", "", "", nonce);
            return removal.Valid ? removal : null;
        }
        using var dialog = new Form { Text = "LinuxMailRelay365 | " +
            (action == "add" ? "Add planned mailbox" : "Edit planned mailbox"),
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(Screen.FromControl(owner).WorkingArea.Size, owner.DeviceDpi, 700, 530),
            Font = new Font("Segoe UI", 10f), MinimizeBox = false };
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(12) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        var fields = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 1, AutoSize = true };
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var login = new TextBox { MaxLength = 64, Dock = DockStyle.Fill, Text = row?.Login ?? "" };
        var address = new TextBox { MaxLength = 254, Dock = DockStyle.Fill, Text = row?.Mailbox ?? "" };
        var file = new TextBox { MaxLength = 125, Dock = DockStyle.Fill };
        var help = UiTheme.Text(T(
            "Привязка существующего OAuth-идентификатора. Оставьте имя JSON пустым для однозначного поиска по ящику или сохранения текущего идентификатора. Новые ключи не создаются.",
            "Bind an existing OAuth identity. Leave JSON filename empty to keep the current identity or find one exact mailbox match. No new keys are created.",
            "שיוך זהות OAuth קיימת. השאירו את שם קובץ JSON ריק כדי לשמור זהות קיימת או למצוא התאמה יחידה. לא ייווצרו מפתחות."));
        void FitHelp() => help.MaximumSize = new Size(Math.Max(150, dialog.ClientSize.Width - 64), 0);
        FitHelp();
        dialog.ClientSizeChanged += (_, _) => FitHelp();
        AddLine(fields, help);
        AddField(fields, "SMTP login", login);
        AddField(fields, "Microsoft 365 mailbox / envelope sender", address);
        AddField(fields, "Existing identity JSON filename (optional)", file);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true,
            FlowDirection = FlowDirection.RightToLeft };
        var cancel = new Button { Text = T("Отмена", "Cancel", "ביטול"), AutoSize = true, DialogResult = DialogResult.Cancel };
        var preview = new Button { Text = T("Предпросмотр", "Preview", "תצוגה מקדימה"), AutoSize = true, DialogResult = DialogResult.OK };
        MultiMailboxSourceEditRequest Request() => new(action, map.Sha256, map.Rows.Length, row?.Mailbox ?? "",
            login.Text.Trim().ToLowerInvariant(), address.Text.Trim().ToLowerInvariant(), file.Text.Trim(), nonce);
        void Validate() => preview.Enabled = Request().Valid;
        login.TextChanged += (_, _) => Validate(); address.TextChanged += (_, _) => Validate();
        file.TextChanged += (_, _) => Validate(); Validate();
        actions.Controls.Add(cancel); actions.Controls.Add(preview);
        scroll.Controls.Add(fields); root.Controls.Add(scroll, 0, 0); root.Controls.Add(actions, 0, 1);
        dialog.Controls.Add(root); dialog.CancelButton = cancel; dialog.AcceptButton = preview;
        return dialog.ShowDialog(owner) == DialogResult.OK && Request().Valid ? Request() : null;
    }
}
