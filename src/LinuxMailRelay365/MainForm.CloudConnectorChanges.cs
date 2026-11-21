using System.Diagnostics;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task<bool> ExecuteCloudConnectorOperationAsync(
        Form owner, CloudObjectsInventory inventory,
        CloudConnectorObject connector, string operation, string newName)
    {
        if (connector.Ownership != "verified" ||
            operation is not ("Enable" or "Disable" or "Rename" or "Delete"))
            throw new InvalidOperationException("Only tenant-stamped connectors can be changed.");
        if (operation == "Rename")
        {
            if (!System.Text.RegularExpressions.Regex.IsMatch(newName,
                    @"\ALinuxMailRelay365[A-Za-z0-9._ -]{3,58}\z"))
                throw new ArgumentException("New Connector name must start with LinuxMailRelay365.");
        }
        else newName = "";
        CheckCloudTenant(inventory.Tenant);
        if ((operation is "Delete" or "Rename") && connector.Enabled)
            throw new InvalidOperationException(
                "Disable this exact connector, then refresh inventory before renaming or deleting.");
        var preview = await RunCloudConnectorOperationAsync(
            inventory.Tenant, connector, operation, newName, "Review");
        string reviewedSha = ValidateCloudConnectorReport(preview, operation, false);
        if (!ConfirmCloudConnectorChange(owner, connector, operation, newName))
            return false;
        CheckCloudTenant(inventory.Tenant);
        var result = await RunCloudConnectorOperationAsync(
            inventory.Tenant, connector, operation, newName, "Apply", reviewedSha);
        if (ValidateCloudConnectorReport(result, operation, true) != reviewedSha)
            throw new InvalidDataException("Connector fingerprint changed after Apply.");
        WriteLine("Microsoft 365 Connector " + operation +
            " completed, tenant/ownership and postcheck verified. No other tenant objects modified.");
        MessageBox.Show(owner, T(
            "Exchange Online подтвердил изменение. Откройте инвентаризацию заново и отдельно проверьте доставку писем.",
            "Exchange Online confirmed the change. Rerun object inventory and separately verify mail delivery.",
            "השינוי אושר על ידי Exchange Online. יש לרענן רשימה ולבדוק דואר."),
            "LinuxMailRelay365", MessageBoxButtons.OK, MessageBoxIcon.Information);
        return true;
    }

    private void CheckCloudTenant(Guid tenantId)
    {
        if (!Guid.TryParse(tenant.Text.Trim(), out Guid actual) || actual != tenantId ||
            (tenantSelector.SelectedItem is TenantOption selected && selected.Id != tenantId))
            throw new InvalidOperationException("Selected Microsoft 365 tenant changed. Review again.");
    }

    private async Task<string> RunCloudConnectorOperationAsync(
        Guid tenantId, CloudConnectorObject connector, string operation,
        string newName, string phase, string? expectedSha = null)
    {
        string script = Path.Combine(dataDirectory, "Manage-LinuxMailRelay365Object.ps1");
        string report = Path.Combine(dataDirectory,
            "connector-action-" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(script, EmbeddedAssets.CloudConnectorManager, new UTF8Encoding(false));
        var psi = new ProcessStartInfo("pwsh.exe")
        {
            UseShellExecute = true, WorkingDirectory = dataDirectory
        };
        foreach (string part in new[] {
            "-NoLogo", "-NoProfile", "-File", script,
            "-Phase", phase, "-Operation", operation,
            "-TenantId", tenantId.ToString("D"),
            "-ConnectorName", connector.Name,
            "-ConnectorIdentity", connector.Identity,
            "-ResultPath", report
        })
            psi.ArgumentList.Add(part);
        if (newName.Length > 0)
        {
            psi.ArgumentList.Add("-NewName");
            psi.ArgumentList.Add(newName);
        }
        if (phase == "Apply")
        {
            if (expectedSha is null)
                throw new InvalidOperationException("A fresh SHA-reviewed Connector plan is required.");
            psi.ArgumentList.Add("-ExpectedSha256");
            psi.ArgumentList.Add(expectedSha);
            psi.ArgumentList.Add("-TypedConfirmation");
            psi.ArgumentList.Add(operation == "Delete" ?
                "DELETE_REVIEWED_LMR365_CONNECTOR" : "MODIFY_REVIEWED_LMR365_CONNECTOR");
        }
        try
        {
            using var process = Process.Start(psi) ??
                throw new IOException("Cannot start PowerShell 7.");
            await process.WaitForExitAsync();
            if (process.ExitCode != 0)
                throw new InvalidOperationException(
                    "Connector operation failed or its tenant proof changed. Review Exchange console.");
            if (!File.Exists(report))
                throw new InvalidDataException("Connector operation evidence is missing.");
            return await File.ReadAllTextAsync(report);
        }
        finally { if (File.Exists(report)) File.Delete(report); }
    }

    private static string ValidateCloudConnectorReport(string text, string operation, bool applied)
    {
        if (text.Length > 2048 || text.Contains('\0'))
            throw new InvalidDataException("Invalid cloud operation evidence size.");
        var data = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in text.Replace("\r\n", "\n")
                     .Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            int i = line.IndexOf('=');
            if (i < 1 || !data.TryAdd(line[..i], line[(i + 1)..]))
                throw new InvalidDataException("Duplicate cloud operation evidence.");
        }
        string[] keys = {
            "M365_CONNECTOR_MANAGE_TENANT",
            "M365_CONNECTOR_MANAGE_OWNERSHIP",
            "M365_CONNECTOR_MANAGE_OPERATION",
            "M365_CONNECTOR_MANAGE_PLAN_SHA256",
            "M365_CONNECTOR_MANAGE_APPLIED",
            "M365_CONNECTOR_MANAGE_POSTCHECK",
            "CHANGES_APPLIED"
        };
        if (data.Count != keys.Length || data.Keys.Except(keys).Any() ||
            data["M365_CONNECTOR_MANAGE_TENANT"] != "exact_match" ||
            data["M365_CONNECTOR_MANAGE_OWNERSHIP"] != "tenant_marker_verified" ||
            data["M365_CONNECTOR_MANAGE_OPERATION"] != operation ||
            data["M365_CONNECTOR_MANAGE_APPLIED"] != (applied ? "yes" : "no") ||
            data["M365_CONNECTOR_MANAGE_POSTCHECK"] != (applied ? "passed" : "not_run") ||
            data["CHANGES_APPLIED"] != (applied ? "tenant_connector_only" : "no"))
            throw new InvalidDataException("Incomplete cloud operation evidence.");
        string sha = data["M365_CONNECTOR_MANAGE_PLAN_SHA256"];
        if (!System.Text.RegularExpressions.Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z"))
            throw new InvalidDataException("Invalid reviewed Connector SHA-256.");
        return sha;
    }

    private static bool ConfirmCloudConnectorChange(Form owner, CloudConnectorObject connector,
        string operation, string newName)
    {
        string phrase = operation == "Delete" ?
            "DELETE " + connector.Name :
            operation.ToUpperInvariant() + " " + connector.Name;
        var screen = Screen.FromControl(owner).WorkingArea.Size;
        using var form = new Form
        {
            Text = "LinuxMailRelay365 | Approve " + operation,
            StartPosition = FormStartPosition.CenterParent,
            ClientSize = new Size(Math.Min(700, Math.Max(420, screen.Width - 100)),
                                  Math.Min(480, Math.Max(300, screen.Height - 100))),
            MinimumSize = new Size(420, 300),
            BackColor = UiTheme.Canvas,
            AutoScaleMode = AutoScaleMode.Dpi,
            FormBorderStyle = FormBorderStyle.Sizable,
            Font = new Font("Segoe UI", 10f)
        };
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3,
            Padding = new Padding(14, 12, 14, 12)
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var warning = new TextBox
        {
            Dock = DockStyle.Fill, ReadOnly = true,
            Multiline = true, ScrollBars = ScrollBars.Vertical,
            BackColor = Color.White,
            Text = "REAL MICROSOFT 365 CHANGE: " + operation + Environment.NewLine +
                "Connector: " + connector.Name + Environment.NewLine +
                "Identity: " + connector.Identity + Environment.NewLine +
                (operation == "Rename" ? "New name: " + newName + Environment.NewLine : "") +
                Environment.NewLine +
                "May interrupt mail for every Linux server sharing this Connector. " +
                "The app checks exact tenant, ownership marker, SHA-reviewed live inventory " +
                "and post-change state, but cannot prove recipient delivery or other hosts' " +
                "dependencies. Deletion is irreversible." + Environment.NewLine +
                "Type EXACTLY: " + phrase
        };
        var input = new TextBox
        {
            Dock = DockStyle.Fill, Margin = new Padding(0, 10, 0, 10)
        };
        var footer = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft, WrapContents = true
        };
        var cancel = UiTheme.Action("Cancel", false, "back");
        cancel.Click += (_, _) => { form.DialogResult = DialogResult.Cancel; form.Close(); };
        var proceed = UiTheme.Action("Approve cloud change", false, "shield");
        proceed.Click += (_, _) =>
        {
            if (input.Text == phrase)
            {
                form.DialogResult = DialogResult.OK;
                form.Close();
            }
            else
                MessageBox.Show(form, "Typed confirmation does not match.", "LinuxMailRelay365",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
        };
        footer.Controls.Add(cancel);
        footer.Controls.Add(proceed);
        layout.Controls.Add(warning, 0, 0);
        layout.Controls.Add(input, 0, 1);
        layout.Controls.Add(footer, 0, 2);
        form.Controls.Add(layout);
        form.CancelButton = cancel;
        return form.ShowDialog(owner) == DialogResult.OK;
    }
}
