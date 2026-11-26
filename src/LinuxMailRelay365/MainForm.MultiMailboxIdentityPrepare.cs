using System.Drawing;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private (MultiMailboxIdentityPrepareRequest Request, string? Handle)? PromptUnboundMailboxIdentity(
        Form owner, string sourceSha, MultiMailboxTpmDiscovery tpm)
    {
        using var dialog = new Form { Text = "LinuxMailRelay365 | Prepare new OAuth identity",
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(Screen.FromControl(owner).WorkingArea.Size, owner.DeviceDpi, 720, 670),
            Font = new Font("Segoe UI", 10f), MinimizeBox = false };
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(12) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        var fields = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 1, AutoSize = true };
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var tenantField = new TextBox { Dock = DockStyle.Fill, MaxLength = 36, Text = tenant.Text.Trim() };
        var clientField = new TextBox { Dock = DockStyle.Fill, MaxLength = 36 };
        var mailboxField = new TextBox { Dock = DockStyle.Fill, MaxLength = 254 };
        var days = new NumericUpDown { Dock = DockStyle.Fill, Minimum = 1, Maximum = 365, Value = 365 };
        var help = UiTheme.Text(T(
            "Подготовка нового локального OAuth-идентификатора для существующего приложения Entra. Приватный ключ останется на Linux. Новый сертификат можно сохранить отдельно. Без активации Postfix, выдачи разрешений или отправки писем. TPM предлагается только после проверки доступности. Для программного ключа при активном SELinux проверяется политика новых файлов. TPM при активном SELinux пока недоступен.",
            "Prepare a new local OAuth identity for an existing Entra application. The private key stays on Linux. Save only the public certificate. No Postfix activation, permission grants or mail sending. Optional TPM protection is offered only after prerequisite checks. Software identity creation checks installed SELinux file-label policy when active. TPM on active SELinux still requires separate acceptance.",
            "הכנת זהות OAuth מקומית ליישום Entra קיים. המפתח הפרטי נשאר בלינוקס. ניתן לשמור רק את האישור הציבורי. ללא הפעלת Postfix, הרשאות או שליחת דואר. אפשרות TPM זמינה רק לאחר בדיקות."));
        void Fit() => help.MaximumSize = new Size(Math.Max(150, dialog.ClientSize.Width - 70), 0);
        Fit(); dialog.ClientSizeChanged += (_, _) => Fit();
        AddLine(fields, help);
        AddField(fields, "Microsoft Entra Tenant ID", tenantField);
        AddField(fields, "Existing application (Client) ID", clientField);
        AddField(fields, "Microsoft 365 mailbox", mailboxField);
        AddLine(fields, UiTheme.Text("Certificate validity (days)"));
        AddLine(fields, days);
        var backend = new ComboBox { Dock=DockStyle.Fill, DropDownStyle=ComboBoxStyle.DropDownList };
        backend.Items.Add("Software RSA-3072 (default)");
        if (tpm.Available) backend.Items.Add("TPM 2.0 RSA-2048 ("+tpm.Handle+")");
        backend.SelectedIndex=0;
        AddLine(fields, UiTheme.Text("Private key protection"));
        AddLine(fields, backend);
        var tpmStatus=UiTheme.Text(tpm.Describe());
        tpmStatus.ForeColor=tpm.Available ? Color.DarkGreen : UiTheme.WarningInk;
        AddLine(fields,tpmStatus);
        void FitTpm()=>tpmStatus.MaximumSize=new Size(Math.Max(150,dialog.ClientSize.Width-70),0);
        FitTpm();dialog.ClientSizeChanged+=(_,_)=>FitTpm();
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true,
            FlowDirection = FlowDirection.RightToLeft };
        var cancel = new Button { Text = T("Отмена", "Cancel", "ביטול"), AutoSize = true, DialogResult = DialogResult.Cancel };
        var preview = new Button { Text = T("Предпросмотр", "Preview", "תצוגה מקדימה"), AutoSize = true, DialogResult = DialogResult.OK };
        string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        MultiMailboxIdentityPrepareRequest Request() => new(tenantField.Text.Trim().ToLowerInvariant(),
            clientField.Text.Trim().ToLowerInvariant(), mailboxField.Text.Trim().ToLowerInvariant(),
            (int)days.Value, sourceSha, nonce);
        void Validate() => preview.Enabled = Request().Valid;
        tenantField.TextChanged += (_, _) => Validate(); clientField.TextChanged += (_, _) => Validate();
        mailboxField.TextChanged += (_, _) => Validate(); days.ValueChanged += (_, _) => Validate(); Validate();
        buttons.Controls.Add(cancel); buttons.Controls.Add(preview);
        scroll.Controls.Add(fields); root.Controls.Add(scroll, 0, 0); root.Controls.Add(buttons, 0, 1);
        dialog.Controls.Add(root); dialog.CancelButton = cancel; dialog.AcceptButton = preview;
        return dialog.ShowDialog(owner) == DialogResult.OK && Request().Valid
            ? (Request(), backend.SelectedIndex==1 ? tpm.Handle : null) : null;
    }
}
