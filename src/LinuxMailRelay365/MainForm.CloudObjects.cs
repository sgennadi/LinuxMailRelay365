using System.Diagnostics;
using System.Drawing;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using Microsoft365Auth;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private CloudObjectsInventory? lastReadOnlyCloudInventory;
    private string? lastReadOnlyCloudLinuxIdentity;
    private async Task InspectCloudObjectsAsync()
    {
        if (selectedMailTarget != MailFlowIntent.TargetM365 ||
            selectedMailScenario is MailScenarioPlanner.Choose or MailScenarioPlanner.Keep)
            throw new InvalidOperationException("Microsoft 365 object inspection is available only for a selected Microsoft 365 route. Gmail and Custom SMTP do not require a Tenant ID.");
        if (!HasMailDiscovery())
            throw new InvalidOperationException("Reinspect the Linux host and select the Microsoft 365 route first.");
        if (!Guid.TryParse(tenant.Text.Trim(), out Guid tenantId) || tenantId == Guid.Empty)
            throw new ArgumentException("Select the intended organization using Sign in to Microsoft Entra, or enter the exact Tenant ID in the tenant section before inspecting Microsoft 365 objects.");
        if (discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption)
            throw new InvalidOperationException("Select the intended Entra tenant before inspecting.");
        if (tenantSelector.SelectedItem is TenantOption selected && selected.Id != tenantId)
            throw new InvalidOperationException("The Entra tenant selection changed.");

        // An app ID is optional: Exchange Connectors can be inspected on their own.
        // Never find/edit an application based on a display-name collision.
        Guid? clientId = null;
        string value = existingAppId.Text.Trim();
        if (value.Length > 0)
        {
            if (!Guid.TryParse(value, out Guid chosen) || chosen == Guid.Empty)
                throw new ArgumentException("Existing App Client ID must be a valid GUID.");
            clientId = chosen;
        }
        else
        {
            try
            {
                string saved = StatePath(tenantId);
                if (File.Exists(saved))
                {
                    using var json = JsonDocument.Parse(await File.ReadAllTextAsync(saved));
                    var root = json.RootElement;
                    if (root.TryGetProperty("tenantId", out var savedTenant) &&
                        root.TryGetProperty("clientId", out var savedClient) &&
                        Guid.TryParse(savedTenant.GetString(), out Guid knownTenant) &&
                        knownTenant == tenantId &&
                        Guid.TryParse(savedClient.GetString(), out Guid knownClient) &&
                        knownClient != Guid.Empty)
                        clientId = knownClient;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                         JsonException or ArgumentException)
            {
                // Local state is a hint, never authority. Connector-only review is still possible.
            }
        }
        var output = await QueryCloudObjectsAsync(tenantId, clientId);
        lastReadOnlyCloudInventory = output;
        lastReadOnlyCloudLinuxIdentity = TryCurrentIdentity();
        ShowCloudObjectInventory(output);
        if (!IsDisposed) RenderPage();
    }

    private async Task<CloudObjectsInventory> QueryCloudObjectsAsync(
        Guid tenantId, Guid? clientId)
    {
        // Freeze the exact UI selection before asynchronous admin sign-in.
        // A valid GUID in the field AFTER sign-in is insufficient: it must
        // match the original requested app, not just parse successfully.
        string requestedClientField = existingAppId.Text.Trim();
        string requestedConnectorName = outboundConnectorName.Text.Trim();
        string requestedBootstrap = entraSignInClientId.Text.Trim();
        ValidateCloudInventorySelection(
            tenantId, clientId, requestedClientField, requestedConnectorName);
        // App Registration / Enterprise Application / public credentials are
        // read directly via C# Graph. Exchange cmdlets below remain EXO-only.
        EntraApplicationInventory? nativeGraph = null;
        if (clientId is { } exactApp)
        {
            Guid? bootstrap = null;
            if (requestedBootstrap.Length > 0)
            {
                if (!Guid.TryParse(requestedBootstrap, out var parsed) || parsed == Guid.Empty)
                    throw new ArgumentException("Approved Microsoft Graph public sign-in Client ID must be a GUID.");
                bootstrap = parsed;
            }
            WriteLine("Microsoft Graph App/SP/certificates: native C# MSAL read-only inspection (Application.Read.All).");
            nativeGraph = await WithNativeMicrosoftSignInAsync((show, ct) =>
                EntraGraphInventoryClient.InspectAsync(tenantId, exactApp, bootstrap, show, ct));
            ValidateCloudInventorySelection(tenantId, clientId, requestedClientField, requestedConnectorName);
            if (!string.Equals(requestedBootstrap, entraSignInClientId.Text.Trim(), StringComparison.Ordinal))
                throw new InvalidOperationException("Microsoft sign-in client changed during read-only inspection.");
        }
        Directory.CreateDirectory(dataDirectory);
        string script = Path.Combine(dataDirectory, "Inspect-LinuxMailRelay365Objects.ps1");
        string report = Path.Combine(dataDirectory,
            "objects-inventory-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(script, EmbeddedAssets.CloudObjectsInspector, new UTF8Encoding(false));
        var psi = new ProcessStartInfo("pwsh.exe")
        {
            UseShellExecute = true, WorkingDirectory = dataDirectory
        };
        foreach (string item in new[] {
            "-NoLogo", "-NoProfile", "-File", script,
            "-TenantId", tenantId.ToString("D"),
            "-ResultPath", report
        })
            psi.ArgumentList.Add(item);
        if (clientId.HasValue)
        {
            psi.ArgumentList.Add("-ClientId");
            psi.ArgumentList.Add(clientId.Value.ToString("D"));
        }
        if (requestedConnectorName.Length > 0)
        {
            psi.ArgumentList.Add("-ConnectorName");
            psi.ArgumentList.Add(requestedConnectorName);
        }
        WriteLine("Microsoft 365 object audit: interactive admin sign-in; exact tenant-bound and read-only.");
        try
        {
            using var process = Process.Start(psi) ??
                throw new InvalidOperationException("PowerShell 7 did not start.");
            await process.WaitForExitAsync();
            if (process.ExitCode != 0)
                throw new InvalidOperationException(
                    "Cloud inventory could not be read. Check the PowerShell console and tenant permissions.");
            if (!File.Exists(report))
                throw new InvalidDataException("Microsoft 365 cloud inventory report is missing.");
            var inventory = CloudObjectsInventory.Parse(
                await File.ReadAllTextAsync(report), tenantId, clientId);
            if (nativeGraph is not null)
            {
                inventory = inventory with
                {
                    ApplicationStatus = "found",
                    ApplicationObjectId = nativeGraph.AppObjectId,
                    ApplicationName = nativeGraph.DisplayName,
                    ServicePrincipalStatus = nativeGraph.EnterpriseStatus,
                    ServicePrincipalObjectId = nativeGraph.EnterpriseObjectId,
                    Certificates = nativeGraph.Certificates.Select(c =>
                        new CloudCredentialObject(c.KeyId, c.Label, c.Type,
                            c.Usage, c.ValidFrom, c.ValidUntil)).ToArray()
                };
            }
            ValidateCloudInventorySelection(
                tenantId, clientId, requestedClientField, requestedConnectorName);
            WriteLine("Native C# Graph + Exchange-only PowerShell object inspection: " +
                inventory.Connectors.Count + " candidate connectors, " +
                inventory.Certificates.Count + " public credential records, " +
                inventory.Scopes.Count + " candidate scopes. No tenant objects changed.");
            return inventory;
        }
        finally
        {
            if (File.Exists(report)) File.Delete(report);
        }
    }

    private void ValidateCloudInventorySelection(
        Guid expectedTenant, Guid? expectedClient,
        string requestedClientField, string requestedConnectorName)
    {
        if (!Guid.TryParse(tenant.Text.Trim(), out Guid selectedTenant) ||
            selectedTenant != expectedTenant ||
            (tenantSelector.SelectedItem is TenantOption option &&
             option.Id != expectedTenant) ||
            (discoveredTenants.Count > 1 &&
             tenantSelector.SelectedItem is not TenantOption) ||
            !string.Equals(existingAppId.Text.Trim(), requestedClientField,
                           StringComparison.Ordinal) ||
            !string.Equals(outboundConnectorName.Text.Trim(), requestedConnectorName,
                           StringComparison.Ordinal))
            throw new InvalidOperationException(
                "Microsoft 365 tenant, app or Connector selection changed. Inspect again.");

        if (requestedClientField.Length > 0 &&
            (!Guid.TryParse(requestedClientField, out Guid chosenClient) ||
             !expectedClient.HasValue || chosenClient != expectedClient.Value))
            throw new InvalidOperationException(
                "Microsoft 365 application ID changed. Inspect again.");

        if (requestedConnectorName.Length > 0 &&
            !System.Text.RegularExpressions.Regex.IsMatch(requestedConnectorName,
                @"\A[A-Za-z0-9][A-Za-z0-9._ -]{2,69}\z"))
            throw new InvalidOperationException(
                "Connector name is not a safe exact-match selection.");
    }

    private void ShowCloudObjectInventory(CloudObjectsInventory inventory)
    {
        var screen = Screen.FromControl(this).WorkingArea.Size;
        using var modal = new Form
        {
            Text = T("LinuxMailRelay365 | Объекты Microsoft 365",
                "LinuxMailRelay365 | Microsoft 365 objects",
                "LinuxMailRelay365 | אובייקטים של Microsoft 365"),
            StartPosition = FormStartPosition.CenterParent,
            ClientSize = PreferredDialogSize(screen, DeviceDpi, 1130, 740),
            MinimumSize = PreferredDialogSize(screen, DeviceDpi, 660, 440),
            Font = new Font("Segoe UI", 10f),
            AutoScaleMode = AutoScaleMode.Dpi, FormBorderStyle = FormBorderStyle.Sizable,
            BackColor = UiTheme.Canvas, MaximizeBox = true
        };
        var main = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3,
            Padding = new Padding(14, 12, 14, 12)
        };
        main.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        main.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        main.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        main.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var heading = new Label
        {
            AutoSize = true, Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            ForeColor = UiTheme.Navy,
            Text = T("Только чтение: найденные объекты (имя не доказывает принадлежность)",
                "Read-only: candidate cloud objects (names do not prove ownership)",
                "לקריאה בלבד: שמות אינם מוכיחים בעלות"),
            Margin = new Padding(0, 0, 0, 8)
        };
        main.Controls.Add(heading, 0, 0);
        var content = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 };
        content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 38));
        content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 62));
        content.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var tree = new TreeView
        {
            Dock = DockStyle.Fill, HideSelection = false,
            Font = new Font("Segoe UI", 10f),
            Margin = new Padding(0, 0, 8, 0),
            BorderStyle = BorderStyle.FixedSingle
        };
        var details = new TextBox
        {
            Dock = DockStyle.Fill, Multiline = true,
            ReadOnly = true, ScrollBars = ScrollBars.Vertical,
            Font = new Font("Consolas", 9.5f),
            BackColor = Color.White, BorderStyle = BorderStyle.FixedSingle
        };
        void AddChild(TreeNode parent, string label, object value) =>
            parent.Nodes.Add(new TreeNode(label) { Tag = value });
        var app = tree.Nodes.Add("App Registration — " + inventory.ApplicationStatus);
        app.Tag = inventory;
        var enterprise = tree.Nodes.Add("Enterprise Application — " + inventory.ServicePrincipalStatus);
        enterprise.Tag = inventory;
        var certificates = tree.Nodes.Add("OAuth certificates (" + inventory.Certificates.Count + ")");
        foreach (var certificate in inventory.Certificates)
            AddChild(certificates, certificate.Name + " | " + certificate.ValidUntil.ToString("yyyy-MM-dd"), certificate);
        var connectors = tree.Nodes.Add("Inbound Connectors (" + inventory.Connectors.Count + ")");
        foreach (var connector in inventory.Connectors)
            AddChild(connectors, connector.Name, connector);
        var scopes = tree.Nodes.Add("Management Scopes (" + inventory.Scopes.Count + ")");
        foreach (var scope in inventory.Scopes)
            AddChild(scopes, scope.Name, scope);
        var assignments = tree.Nodes.Add("Exchange role assignments (" + inventory.RoleAssignments.Count + ")");
        foreach (var assignment in inventory.RoleAssignments)
            AddChild(assignments, assignment.Name, assignment);
        tree.AfterSelect += (_, _) =>
        {
            details.Text = tree.SelectedNode?.Tag switch
            {
                CloudObjectsInventory full => full.Summary() + Environment.NewLine +
                    "Only exact Client IDs and selected Connector candidates are shown." + Environment.NewLine +
                    "Existing OAuth users may share one app and its union of mailbox scopes.",
                CloudCredentialObject c => "Certificate credential: " + c.Name +
                    Environment.NewLine + "Key ID: " + c.KeyId +
                    Environment.NewLine + "Type: " + c.Type +
                    Environment.NewLine + "Usage: " + c.Usage +
                    Environment.NewLine + "Valid: " + c.ValidFrom.ToString("u") +
                    " to " + c.ValidUntil.ToString("u") +
                    Environment.NewLine + "Private key: NOT exposed",
                CloudConnectorObject c => "Connector: " + c.Name +
                    Environment.NewLine + "Identity: " + c.Identity +
                    Environment.NewLine + "Type: " + c.Type +
                    Environment.NewLine + "Enabled: " + c.Enabled +
                    Environment.NewLine + "Sender domains: " + string.Join(", ", c.SenderDomains) +
                    Environment.NewLine + "Public source IPs: " + string.Join(", ", c.SenderIps) +
                    Environment.NewLine + "TLS identity: " + c.TlsCertificateName +
                    Environment.NewLine + "Ownership: " +
                    (c.Ownership == "verified" ?
                        "verified tenant marker; edits require reviewed SHA + typed approval" :
                        "UNVERIFIED; edits/deletion blocked"),
                CloudScopeObject c => "Management scope: " + c.Name +
                    Environment.NewLine + "Recipient filter: " + c.Filter +
                    Environment.NewLine + "Do not change without checking affected mailbox permissions.",
                CloudAssignmentObject c => "Role assignment: " + c.Name +
                    Environment.NewLine + "Role: " + c.Role +
                    Environment.NewLine + "Scope: " + c.Scope +
                    Environment.NewLine + "Do not remove while SMTP apps depend on this role.",
                _ => inventory.Summary()
            };
        };
        tree.ExpandAll();
        tree.SelectedNode = app;
        content.Controls.Add(tree, 0, 0);
        content.Controls.Add(details, 1, 0);
        main.Controls.Add(content, 0, 1);
        var footer = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true,
            WrapContents = true, FlowDirection = FlowDirection.RightToLeft,
            Margin = new Padding(0, 10, 0, 0)
        };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), false, "check");
        close.Click += (_, _) => modal.Close();
        var copy = UiTheme.Action(T("Копировать сведения", "Copy details", "העתק פרטים"), false, "check");
        copy.Click += (_, _) => { if (details.Text.Length > 0) Clipboard.SetText(details.Text); };
        var operation = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList, Width = 132,
            Font = new Font("Segoe UI", 9.5f),
            Margin = new Padding(5, 4, 5, 4)
        };
        operation.Items.AddRange(new object[] { "Disable", "Enable", "Rename", "Delete" });
        operation.SelectedIndex = 0;
        var newName = new TextBox
        {
            Width = 230, Visible = false,
            PlaceholderText = "LinuxMailRelay365 New Name",
            Margin = new Padding(5, 5, 5, 5)
        };
        operation.SelectedIndexChanged += (_, _) =>
            newName.Visible = operation.Enabled && operation.SelectedIndex == 2;
        var change = UiTheme.Action(T("Проверить и применить...", "Review & apply...",
            "בדוק והחל שינוי"), false, "shield");
        operation.Enabled = false;
        change.Enabled = false;
        tree.AfterSelect += (_, _) =>
        {
            bool managed = tree.SelectedNode?.Tag is CloudConnectorObject connector &&
                connector.Ownership == "verified";
            operation.Enabled = managed;
            change.Enabled = managed;
            newName.Visible = managed && operation.SelectedIndex == 2;
        };
        change.Click += async (_, _) =>
        {
            if (tree.SelectedNode?.Tag is not CloudConnectorObject connector ||
                connector.Ownership != "verified" || operation.SelectedIndex < 0)
                return;
            string selectedOperation = operation.SelectedItem?.ToString() ?? "";
            change.Enabled = false;
            try
            {
                bool applied = await ExecuteCloudConnectorOperationAsync(
                    modal, inventory, connector, selectedOperation, newName.Text.Trim());
                if (applied) modal.Close();
            }
            catch (Exception)
            {
                MessageBox.Show(modal, T(
                    "Операция не подтверждена. Проверьте PowerShell/Exchange и повторите инвентаризацию.",
                    "Operation not verified. Inspect PowerShell/Exchange and refresh inventory.",
                    "הפעולה לא אומתה. יש לבדוק את Exchange ולרענן מלאי."),
                    "LinuxMailRelay365", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                change.Enabled = tree.SelectedNode?.Tag is CloudConnectorObject c &&
                                 c.Ownership == "verified";
            }
        };
        footer.Controls.Add(close);
        footer.Controls.Add(copy);
        footer.Controls.Add(change);
        footer.Controls.Add(operation);
        footer.Controls.Add(newName);
        main.Controls.Add(footer, 0, 2);
        modal.Controls.Add(main);
        modal.AcceptButton = close;
        modal.CancelButton = close;
        modal.ShowDialog(this);
    }
}
