using System.Drawing;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private MultiMailboxGraphPairRequest? PromptMailboxGraphPair(Form owner, string scope,
        MultiMailboxIdentityInventory inventory, MultiMailboxIdentityRow donor, string lastPrepared)
    {
        using var dialog = new Form { Text = "LinuxMailRelay365 | Register prepared public certificate",
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(Screen.FromControl(owner).WorkingArea.Size, owner.DeviceDpi, 740, 490),
            Font = new Font("Segoe UI", 10f), MinimizeBox = false };
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(12) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var help = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Vertical,
            Text = "Existing proof mailbox: " + donor.Mailbox + Environment.NewLine +
                "Tenant: " + donor.Tenant + Environment.NewLine + "Application: " + donor.Client +
                Environment.NewLine + Environment.NewLine +
                "Enter the prepared mbx-...json identity for another mailbox in the SAME Entra application. " +
                "The selected existing software certificate must still be registered and valid. " +
                "Graph addKey appends only a public certificate. The new key can authenticate as the same app and inherits its existing authority. " +
                "No mailbox permission is granted or narrowed here. For a new app without a valid certificate, " +
                "export and upload the first certificate manually in Entra; no credential collection replacement is attempted." };
        var input = new TextBox { Dock = DockStyle.Fill, MaxLength = 41, Text = lastPrepared,
            PlaceholderText = "mbx-<32 hexadecimal characters>.json" };
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true,
            FlowDirection = FlowDirection.RightToLeft };
        var cancel = new Button { Text = T("Отмена", "Cancel", "ביטול"), AutoSize = true, DialogResult = DialogResult.Cancel };
        var review = new Button { Text = T("Предпросмотр", "Preview", "תצוגה מקדימה"), AutoSize = true,
            DialogResult = DialogResult.OK };
        string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        MultiMailboxGraphPairRequest Request() => new(scope, inventory.Source.Sha256, inventory.Runtime.Sha256,
            donor, input.Text.Trim(), nonce);
        void Validate() => review.Enabled = Request().Valid;
        input.TextChanged += (_, _) => Validate(); Validate();
        actions.Controls.Add(cancel); actions.Controls.Add(review);
        root.Controls.Add(help, 0, 0); root.Controls.Add(input, 0, 1); root.Controls.Add(actions, 0, 2);
        dialog.Controls.Add(root); dialog.CancelButton = cancel; dialog.AcceptButton = review;
        return dialog.ShowDialog(owner) == DialogResult.OK && Request().Valid ? Request() : null;
    }
}
