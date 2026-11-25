using System.Drawing;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task InspectInstalledPostfixRouteAsync()
    {
        string initialIdentity = TryCurrentIdentity() ?? throw new InvalidOperationException("Discover Linux first.");
        var endpoint = Endpoint();
        var scopes = new List<string>();
        if (QueueScopeDiscovered("postfix")) scopes.Add("primary");
        if (QueueScopeDiscovered("sidecar")) scopes.Add("sidecar");
        if (scopes.Count == 0) throw new InvalidOperationException("No discovered Postfix instance.");
        string target, sender, recipient;
        using (var dialog = new Form
        {
            Text = "LinuxMailRelay365 | " + T("Установленный маршрут Postfix", "Installed Postfix route", "נתיב Postfix קיים"),
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            Font = new Font("Segoe UI", 10f),
            ClientSize = PreferredDialogSize(Screen.FromControl(this).WorkingArea.Size, DeviceDpi, 650, 450),
            MinimizeBox = false, MaximizeBox = false
        })
        {
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(12) };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
            var fields = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1 };
            fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            var scope = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
            scope.Items.AddRange(scopes.Cast<object>().ToArray());
            scope.SelectedIndex = 0;
            var from = new TextBox { Dock = DockStyle.Fill, MaxLength = 254 };
            var to = new TextBox { Dock = DockStyle.Fill, MaxLength = 254 };
            if (InstalledPostfixRoute.ValidAddress(mailbox.Text.Trim().ToLowerInvariant())) from.Text = mailbox.Text.Trim();
            AddLine(fields, MailFlowText(T(
                "Только чтение. Проверяются карты выбранного экземпляра, без SMTP, изменений или отправки письма.",
                "Read only. Inspect the chosen instance's routing maps; no SMTP, changes or message submission.",
                "קריאה בלבד. בדיקת מפות ניתוב ללא SMTP, שינויים או שליחה."), Math.Max(220, dialog.ClientSize.Width - 65), warning: true));
            AddLine(fields, UiTheme.Text(T("Экземпляр Postfix", "Postfix instance", "מופע Postfix")));
            AddLine(fields, scope);
            AddField(fields, T("Envelope From", "Envelope sender", "שולח מעטפה"), from);
            AddField(fields, T("Envelope To", "Envelope recipient", "נמען מעטפה"), to);
            scroll.Controls.Add(fields);
            var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true,
                FlowDirection = FlowDirection.RightToLeft };
            var cancel = new Button { Text = T("Отмена", "Cancel", "ביטול"), AutoSize = true, DialogResult = DialogResult.Cancel };
            var inspect = new Button { Text = T("Проверить", "Inspect route", "בדיקת נתיב"), AutoSize = true, DialogResult = DialogResult.OK };
            void Validate() => inspect.Enabled = InstalledPostfixRoute.ValidAddress(from.Text.Trim().ToLowerInvariant()) &&
                InstalledPostfixRoute.ValidAddress(to.Text.Trim().ToLowerInvariant());
            from.TextChanged += (_, _) => Validate();
            to.TextChanged += (_, _) => Validate();
            Validate();
            actions.Controls.Add(cancel); actions.Controls.Add(inspect);
            layout.Controls.Add(scroll, 0, 0); layout.Controls.Add(actions, 0, 1);
            dialog.Controls.Add(layout); dialog.CancelButton = cancel; dialog.AcceptButton = inspect;
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            target = (string)scope.SelectedItem!;
            sender = from.Text.Trim().ToLowerInvariant();
            recipient = to.Text.Trim().ToLowerInvariant();
        }
        string scopeName = target == "primary" ? "postfix" : "sidecar";
        RequireSameArchiveConnection(endpoint);
        if (TryCurrentIdentity() != initialIdentity || !QueueScopeDiscovered(scopeName))
            throw new InvalidOperationException("Postfix selection changed.");
        string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        string request = InstalledPostfixRoute.Request(target, sender, recipient, nonce);
        InstalledPostfixRoute report;
        try
        {
            var reply = await SshRemote.RunRootScriptAsync(endpoint,
                EmbeddedAssets.BuildInstalledPostfixRouteBundle(request), TimeSpan.FromSeconds(150));
            if (reply.ExitCode != 0) throw new IOException("Route inspection refused.");
            RequireSameArchiveConnection(endpoint, allowFirstPin: true);
            if (TryCurrentIdentity() != initialIdentity || !QueueScopeDiscovered(scopeName))
                throw new InvalidOperationException("Postfix selection changed.");
            report = InstalledPostfixRoute.Parse(reply.StdOut, target, nonce, InstalledPostfixRoute.Sha(request));
        }
        catch (Exception)
        {
            throw new InvalidOperationException("Installed Postfix route inspection failed or became stale. No changes requested.");
        }
        WriteLine("Installed Postfix route inspection: " + report.Status + "; " + report.Route + ". No mail sent.");
        using var result = new Form { Text = "LinuxMailRelay365 | Postfix route",
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(Screen.FromControl(this).WorkingArea.Size, DeviceDpi, 760, 580),
            Font = new Font("Segoe UI", 10f), MinimizeBox = false };
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(12) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var text = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true,
            ScrollBars = ScrollBars.Vertical, Text = sender + " → " + recipient + Environment.NewLine + Environment.NewLine + report.Describe() };
        var close = new Button { Text = T("Закрыть", "Close", "סגור"), AutoSize = true, DialogResult = DialogResult.Cancel };
        root.Controls.Add(text, 0, 0); root.Controls.Add(close, 0, 1);
        result.Controls.Add(root); result.CancelButton = close; result.ShowDialog(this);
    }
}
