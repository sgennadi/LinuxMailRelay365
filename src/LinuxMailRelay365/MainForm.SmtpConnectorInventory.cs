using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task InspectWizardConnectorsAsync(Form owner, string context)
    {
        if (!Guid.TryParse(tenant.Text.Trim(), out Guid id) || id == Guid.Empty ||
            (discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption))
            throw new InvalidOperationException("Select the exact Microsoft 365 tenant first.");
        string name = outboundConnectorName.Text.Trim();
        void Guard()
        {
            CheckCloudTenant(id);
            if (owner.IsDisposed || TryCurrentIdentity() != context || mailTransport.SelectedIndex != 1 ||
                outboundConnectorName.Text.Trim() != name)
                throw new InvalidOperationException("Connector inventory context changed.");
        }
        Guard();
        var inventory = await QueryCloudObjectsAsync(id, null, connectorOnly: true);
        Guard();
        using var dialog = new Form
        {
            Text = "Microsoft 365 | Connector inventory and management",
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = new Size(800, 560), MinimumSize = new Size(460, 350)
        };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 1, RowCount = 5 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 35));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 65));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var heading = new Label { Text = "Tenant: " + id.ToString("D") + " | " + inventory.Connectors.Count +
            " candidate connectors. Only verified project-owned objects can be changed.", AutoSize = true };
        var list = new ListBox { Dock = DockStyle.Fill, HorizontalScrollbar = true };
        var details = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false };
        var action = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
        action.Items.AddRange(["Enable", "Disable", "Rename", "Delete"]);
        action.SelectedIndex = 0;
        var rename = new TextBox { Width = 240, MaxLength = 70, PlaceholderText = "LinuxMailRelay365 New Name" };
        var apply = new Button { Text = "Review selected change", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var status = new Label { AutoSize = true, Text = "Select an object. No changes have been requested." };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        buttons.Controls.AddRange([action, rename, apply, close]);
        bool busy = false, stale = false;
        foreach (var connector in inventory.Connectors)
            list.Items.Add(connector.Name + (connector.Enabled ? " | enabled" : " | disabled") +
                (connector.Ownership == "verified" ? " | managed" : " | read-only"));
        CloudConnectorObject? Selection() => list.SelectedIndex >= 0 ? inventory.Connectors[list.SelectedIndex] : null;
        void UpdateControls()
        {
            var c = Selection();
            string operation = action.SelectedItem?.ToString() ?? "";
            bool managed = c?.Ownership == "verified" && !busy && !stale;
            action.Enabled = managed;
            rename.Visible = operation == "Rename";
            rename.Enabled = managed;
            apply.Enabled = managed && c is not null && (operation switch
            {
                "Enable" => !c.Enabled,
                "Disable" => c.Enabled,
                "Rename" or "Delete" => !c.Enabled,
                _ => false
            });
            close.Enabled = list.Enabled = !busy;
            if (c is not null)
                details.Text = "Name: " + c.Name + Environment.NewLine + "Identity: " + c.Identity +
                    Environment.NewLine + "Type: " + c.Type + Environment.NewLine + "Enabled: " + c.Enabled +
                    Environment.NewLine + "Sender domains: " + string.Join(", ", c.SenderDomains) +
                    Environment.NewLine + "Public IPs: " + string.Join(", ", c.SenderIps) +
                    Environment.NewLine + "TLS identity: " + c.TlsCertificateName +
                    Environment.NewLine + "Ownership: " + c.Ownership + Environment.NewLine +
                    "Rename and delete require a disabled connector. Each change requires a fresh SHA review and typed consent.";
        }
        list.SelectedIndexChanged += (_, _) => UpdateControls();
        action.SelectedIndexChanged += (_, _) => UpdateControls();
        dialog.FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        apply.Click += async (_, _) =>
        {
            if (busy || stale || !apply.Enabled || Selection() is not { } selected) return;
            string operation = action.SelectedItem?.ToString() ?? "";
            busy = true;
            UpdateControls();
            try
            {
                Guard();
                // Even an uncertain cloud mutation invalidates cached route approval.
                connectorApproved.Checked = false;
                previewedTenantConnectorSha = previewedTenantConnectorContext = null;
                bool changed = await ExecuteCloudConnectorOperationAsync(dialog, inventory, selected,
                    operation, rename.Text.Trim(), Guard);
                if (changed)
                {
                    stale = true;
                    status.Text = "Change verified. Close and reopen this inventory before another operation.";
                    status.ForeColor = Color.SeaGreen;
                }
                else status.Text = "No change approved.";
            }
            catch (Exception ex)
            {
                stale = true;
                status.Text = "Operation refused or uncertain: " + ex.GetType().Name +
                    ". Close and reopen inventory before retrying.";
                status.ForeColor = Color.DarkOrange;
            }
            finally { busy = false; UpdateControls(); }
        };
        layout.Controls.Add(heading, 0, 0);
        layout.Controls.Add(list, 0, 1);
        layout.Controls.Add(details, 0, 2);
        layout.Controls.Add(status, 0, 3);
        layout.Controls.Add(buttons, 0, 4);
        dialog.Controls.Add(layout);
        dialog.CancelButton = close;
        if (list.Items.Count > 0) list.SelectedIndex = 0;
        UpdateControls();
        dialog.ShowDialog(owner);
    }
}
