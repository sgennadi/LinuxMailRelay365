using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private sealed record ConnectorSettingsEdit(string Domains, string Ips, string Certificate,
        string ExpectedSecurityFlags = "");

    private static bool CanEditConnectorSettings(CloudConnectorObject connector) =>
        connector.Ownership == "verified" && !connector.Enabled &&
        connector.Type == "OnPremises" &&
        (connector.SenderIps.Count > 0) != !string.IsNullOrWhiteSpace(connector.TlsCertificateName);

    private static ConnectorSettingsEdit? PromptConnectorSettings(Form owner, CloudConnectorObject connector)
    {
        if (!CanEditConnectorSettings(connector))
            throw new InvalidOperationException("A disabled, tenant-owned connector with one authentication mode is required.");
        bool ipMode = connector.SenderIps.Count > 0;
        using var form = new Form
        {
            Text = "Edit disabled Connector | " + connector.Name,
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = new Size(680, 480), MinimumSize = new Size(420, 320)
        };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6,
            Padding = new Padding(14), AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 6; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var intro = new Label { AutoSize = true, MaximumSize = new Size(600, 0),
            Text = "Authentication mode: " + (ipMode ? "Public IPv4" : "TLS certificate") +
                ". Existing security flags are preserved. Every sender domain must be an exact accepted domain. " +
                "A protected backup is required before Apply. The connector stays disabled." };
        var domains = new TextBox { Dock = DockStyle.Top, Multiline = true, Height = 100,
            MaxLength = 10240, ScrollBars = ScrollBars.Vertical, Text = string.Join(", ", connector.SenderDomains) };
        var identity = new TextBox { Dock = DockStyle.Top, MaxLength = ipMode ? 512 : 253,
            Text = ipMode ? string.Join(", ", connector.SenderIps) : connector.TlsCertificateName };
        var next = new Button { Text = "Review in Exchange", AutoSize = true };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top, WrapContents = true };
        actions.Controls.AddRange([next, cancel]);
        ConnectorSettingsEdit? result = null;
        next.Click += (_, _) =>
        {
            string[] domainRows = domains.Text.Split([',', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(x => x.ToLowerInvariant()).ToArray();
            string[] ids = identity.Text.Split(',', StringSplitOptions.TrimEntries);
            bool validDns(string name) => name.Length is >= 4 and <= 253 &&
                Regex.IsMatch(name, @"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z") &&
                Uri.CheckHostName(name) == UriHostNameType.Dns;
            if (domainRows.Length is < 1 or > 40 || domainRows.Distinct().Count() != domainRows.Length ||
                !domainRows.All(validDns) ||
                (ipMode ? ids.Length is < 1 or > 24 || ids.Any(x => !Regex.IsMatch(x, @"\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}(?:/32)?\z")) :
                    ids.Length != 1 || !validDns(ids[0].ToLowerInvariant())))
            {
                MessageBox.Show(form, "Enter exact DNS domains and exact individual IPv4 addresses or one certificate DNS name. Wildcards and ranges are not supported.", "Review inputs", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            result = new ConnectorSettingsEdit(string.Join(",", domainRows),
                ipMode ? string.Join(",", ids) : "", ipMode ? "" : ids[0].ToLowerInvariant());
            form.DialogResult = DialogResult.OK;
        };
        layout.Controls.Add(intro, 0, 0);
        layout.Controls.Add(new Label { Text = "Sender Domains (comma-separated or one per line)", AutoSize = true }, 0, 1);
        layout.Controls.Add(domains, 0, 2);
        layout.Controls.Add(new Label { Text = ipMode ? "Public IPv4 addresses (comma-separated)" : "Exact TLS certificate DNS identity", AutoSize = true }, 0, 3);
        layout.Controls.Add(identity, 0, 4);
        layout.Controls.Add(actions, 0, 5);
        form.Controls.Add(layout);
        form.CancelButton = cancel;
        return form.ShowDialog(owner) == DialogResult.OK ? result : null;
    }

    private async Task<bool> EditCloudConnectorSettingsAsync(Form owner, CloudObjectsInventory inventory,
        CloudConnectorObject connector, Action contextGuard)
    {
        contextGuard();
        CheckCloudTenant(inventory.Tenant);
        var edit = PromptConnectorSettings(owner, connector);
        if (edit is null) return false;
        return await ApplyReviewedConnectorSettingsAsync(owner, inventory, connector, edit, contextGuard);
    }

    private async Task<bool> ApplyReviewedConnectorSettingsAsync(Form owner, CloudObjectsInventory inventory,
        CloudConnectorObject connector, ConnectorSettingsEdit edit, Action contextGuard, string? restoreSource = null)
    {
        contextGuard();
        CheckCloudTenant(inventory.Tenant);
        const string operation = "EditSettings";
        string report = await RunCloudConnectorOperationAsync(inventory.Tenant, connector, operation,
            "", "Review", edit: edit);
        string sha = ValidateCloudConnectorReport(report, operation, false);
        contextGuard();
        string backup = Path.GetFullPath(Path.Combine(dataDirectory, "connector-settings-backup-" +
            Guid.NewGuid().ToString("N") + ".json"));
        string display = "Tenant: " + inventory.Tenant.ToString("D") + Environment.NewLine +
            "Connector: " + connector.Name + Environment.NewLine +
            "Identity: " + connector.Identity + Environment.NewLine +
            "Review SHA-256: " + sha + Environment.NewLine + Environment.NewLine +
            "Sender Domains: " + string.Join(", ", connector.SenderDomains) + " -> " + edit.Domains + Environment.NewLine +
            "Public IPv4: " + string.Join(", ", connector.SenderIps) + " -> " + edit.Ips + Environment.NewLine +
            "TLS certificate: " + connector.TlsCertificateName + " -> " + edit.Certificate + Environment.NewLine +
            (restoreSource is null ? "" : "Restore source: " + restoreSource + Environment.NewLine +
                "Live security flags must still match the backup. The source is an unsigned local settings snapshot." + Environment.NewLine) +
            "Backup: " + backup + Environment.NewLine + Environment.NewLine +
            "This modifies a real Exchange Online connector. Confirm ownership of the new public IP or certificate. " +
            "Authentication mode and security flags are preserved. Other servers may depend on this connector. " +
            "The connector remains disabled; re-enabling it is a separate reviewed operation. " +
            "Backup records previous settings, not automatic rollback. No Linux or DNS changes.";
        if (!ConfirmDestructive(restoreSource is null ? "LinuxMailRelay365 | Edit Exchange Connector" :
            "LinuxMailRelay365 | Restore Exchange Connector settings", display,
            restoreSource is null ? "EDIT M365 CONNECTOR" : "RESTORE M365 CONNECTOR", owner)) return false;
        contextGuard();
        CheckCloudTenant(inventory.Tenant);
        connectorApproved.Checked = false;
        previewedTenantConnectorSha = previewedTenantConnectorContext = null;
        try
        {
            // Reuse the restricted, exclusive file creation helper. The cloud
            // script checks the DACL and flushes the old state before Set.
            WriteRestrictedGraphPayload(backup, "");
            string applied = await RunCloudConnectorOperationAsync(inventory.Tenant, connector,
                operation, "", "Apply", sha, edit, backup);
            contextGuard();
            if (ValidateCloudConnectorReport(applied, operation, true) != sha ||
                !File.Exists(backup) || new FileInfo(backup).Length is < 1 or > 65536)
                throw new InvalidDataException("Settings edit or backup was not verified.");
            using var snapshot = JsonDocument.Parse(await File.ReadAllTextAsync(backup));
            var root = snapshot.RootElement;
            if (root.GetProperty("schema").GetString() != "linuxmailrelay365-connector-settings-backup/v1" ||
                root.GetProperty("tenantId").GetString() != inventory.Tenant.ToString("D") ||
                root.GetProperty("identity").GetString() != connector.Identity ||
                root.GetProperty("reviewedSha256").GetString() != sha ||
                root.GetProperty("before").GetProperty("enabled").GetBoolean())
                throw new InvalidDataException("Backup identity or reviewed SHA mismatch.");
            WriteLine("Exchange Connector settings " + (restoreSource is null ? "edit" : "restore") +
                " verified. Connector remains disabled. Backup: " + backup);
            MessageBox.Show(owner, "Settings verified. The connector remains disabled. Refresh inventory before enabling." +
                Environment.NewLine + "Private backup: " + backup, "Exchange Connector", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return true;
        }
        catch
        {
            if (File.Exists(backup) && new FileInfo(backup).Length > 0)
                WriteLine("Connector edit outcome uncertain; preserve private backup: " + backup);
            throw;
        }
        finally
        {
            // Never delete a written backup, including after an uncertain Apply.
            if (File.Exists(backup) && new FileInfo(backup).Length == 0) File.Delete(backup);
        }
    }
}
