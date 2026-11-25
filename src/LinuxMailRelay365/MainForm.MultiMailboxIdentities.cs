using System.Drawing;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task InspectMultiMailboxIdentitiesAsync()
    {
        string context = CurrentMultiMailboxContext();
        if (!HasMailDiscovery()) throw new InvalidOperationException("Discover the Linux host first.");
        var endpoint = Endpoint();
        async Task<MultiMailboxIdentityInventory> ReadAsync()
        {
            if (context != CurrentMultiMailboxContext())
                throw new InvalidOperationException("Multi-mailbox selection changed.");
            var current = RequireSameArchiveConnection(endpoint, allowFirstPin: true);
            string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
            var reply = await SshRemote.RunRootScriptAsync(current,
                EmbeddedAssets.BuildMultiMailboxIdentityInventoryBundle(nonce), TimeSpan.FromMinutes(3));
            if (reply.ExitCode != 0) throw new InvalidOperationException("Multi-mailbox identity inventory unavailable or changed.");
            endpoint = RequireSameArchiveConnection(current, allowFirstPin: true);
            if (context != CurrentMultiMailboxContext())
                throw new InvalidOperationException("Multi-mailbox selection changed.");
            return MultiMailboxIdentityInventory.Parse(reply.StdOut, nonce);
        }

        MultiMailboxIdentityInventory inventory = await ReadAsync();
        WriteLine("Multi-mailbox identity inventory: source=" + inventory.Source.Rows.Length +
            "; runtime=" + inventory.Runtime.Rows.Length + "; map relation=" + inventory.Relation +
            "; installed marker=" + inventory.InstalledBinding + ". No mail or changes.");
        using var dialog = new Form
        {
            Text = "LinuxMailRelay365 | " + T("Ящики Multi-mailbox", "Multi-mailbox identities", "זהויות Multi-mailbox"),
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(Screen.FromControl(this).WorkingArea.Size, DeviceDpi, 1060, 730),
            MinimumSize = PreferredDialogSize(Screen.FromControl(this).WorkingArea.Size, DeviceDpi, 620, 420),
            Font = new Font("Segoe UI", 10f), BackColor = UiTheme.Canvas
        };
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4,
            Padding = new Padding(12) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 62));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 38));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var heading = new Label { AutoSize = true, Dock = DockStyle.Fill, Padding = new Padding(8) };
        var tabs = new TabControl { Dock = DockStyle.Fill };
        var sourceTab = new TabPage("Source / planned");
        var runtimeTab = new TabPage("Installed / runtime");
        tabs.TabPages.Add(sourceTab);
        tabs.TabPages.Add(runtimeTab);
        var details = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true,
            ScrollBars = ScrollBars.Vertical };
        var footer = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft, WrapContents = true };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), false, "close");
        close.DialogResult = DialogResult.Cancel;
        var refresh = UiTheme.Action(T("Обновить", "Refresh", "רענון"), true, "refresh");
        footer.Controls.Add(close);
        footer.Controls.Add(refresh);
        var verify = UiTheme.Action(T("Проверить в Microsoft 365...", "Verify selected mailbox in Microsoft 365...",
            "בדיקת התיבה ב-Microsoft 365..."), true, "check");
        footer.Controls.Add(verify);
        DataGridView Grid(TabPage tab)
        {
            var grid = new DataGridView { Dock = DockStyle.Fill, ReadOnly = true,
                AllowUserToAddRows = false, AllowUserToDeleteRows = false, RowHeadersVisible = false,
                MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill };
            foreach (var column in new[] { ("login", "SMTP login", 85), ("mailbox", "M365 mailbox", 175),
                ("signer", "Signer", 75), ("status", "Linux evidence", 140), ("cloud", "Graph sample", 145) })
            {
                grid.Columns.Add(new DataGridViewTextBoxColumn { Name = column.Item1, HeaderText = column.Item2,
                    MinimumWidth = column.Item3, SortMode = DataGridViewColumnSortMode.NotSortable });
            }
            tab.Controls.Add(grid);
            return grid;
        }
        var sourceGrid = Grid(sourceTab);
        var runtimeGrid = Grid(runtimeTab);
        bool loading = false, reading = false, inventoryValid = true;
        // Only within this dialog and exact source/runtime map selection.
        var observations = new Dictionary<MultiMailboxCloudSelection, MultiMailboxCloudObservation>();
        CloudObjectsInventory? CloudSample() => lastReadOnlyCloudLinuxIdentity is not null &&
            lastReadOnlyCloudLinuxIdentity == TryCurrentIdentity() ? lastReadOnlyCloudInventory : null;
        string SelectedScope() => tabs.SelectedTab == runtimeTab ? "runtime" : "source";
        MultiMailboxCloudObservation? Observation(string scope, MultiMailboxIdentityRow? row)
        {
            var key = inventoryValid ? MultiMailboxCloudSelection.Capture(inventory, scope, row) : null;
            return key is not null && observations.TryGetValue(key, out var result) ? result : null;
        }
        MultiMailboxIdentityRow? Selected() =>
            (tabs.SelectedTab == runtimeTab ? runtimeGrid : sourceGrid).SelectedRows
                .Cast<DataGridViewRow>().FirstOrDefault()?.Tag as MultiMailboxIdentityRow;
        void Detail()
        {
            if (loading || !inventoryValid) return;
            var row = Selected();
            string scope = SelectedScope();
            verify.Enabled = !reading && MultiMailboxCloudSelection.Capture(inventory, scope, row) is not null;
            var observed = Observation(scope, row);
            details.Text = row is null
                ? "Select one mailbox. Source and runtime maps are distinct. No automatic changes or cloud sign-in."
                : "SMTP login: " + row.Login + Environment.NewLine +
                    "Envelope sender / mailbox: " + row.Mailbox + Environment.NewLine +
                    "Tenant ID: " + (row.Tenant?.ToString("D") ?? "unverified") + Environment.NewLine +
                    "Client ID: " + (row.Client?.ToString("D") ?? "unverified") + Environment.NewLine +
                    "Configured signer: " + row.Signer + Environment.NewLine +
                    "Public certificate SHA-256: " + (row.CertificateSha.Length > 0 ? row.CertificateSha : "unverified") + Environment.NewLine +
                    (observed is not null ? observed.Describe(DateTimeOffset.UtcNow) :
                        "Previous Objects Manager Graph sample: " + row.CompareCloud(CloudSample(), DateTimeOffset.UtcNow) + Environment.NewLine +
                        "Previous Objects Manager mailbox RBAC sample: " + row.CompareMailboxRbac(CloudSample()) + Environment.NewLine +
                        "Choose Verify selected mailbox for a new read-only cloud sample. " +
                        "Local certificate validity, key possession, SMTP login and delivery remain unverified.");
        }
        void Populate(DataGridView grid, MultiMailboxIdentityMap map, string scope)
        {
            grid.Rows.Clear();
            foreach (var row in map.Rows)
            {
                var observed = Observation(scope, row);
                string cloud = observed is not null ? observed.GraphStatus(DateTimeOffset.UtcNow) :
                    row.CompareCloud(CloudSample(), DateTimeOffset.UtcNow);
                int index = grid.Rows.Add(row.Login, row.Mailbox, row.Signer, row.Status, cloud);
                grid.Rows[index].Tag = row;
                if (!SystemInformation.HighContrast)
                {
                    var cell = grid.Rows[index].Cells["status"];
                    if (observed is not null)
                    {
                        var cloudCell = grid.Rows[index].Cells["cloud"];
                        bool match = cloud == "matches_graph_credential_dates" &&
                            observed.Cloud.MailboxAudit?.ScopedConfigurationObserved == true;
                        cloudCell.Style.ForeColor = match ? Color.DarkGreen : UiTheme.WarningInk;
                    }
                    if (row.Status != "public_certificate_read")
                    {
                        cell.Style.BackColor = UiTheme.WarningSurface;
                        cell.Style.ForeColor = UiTheme.WarningInk;
                    }
                }
            }
            grid.CurrentCell = null;
            grid.ClearSelection();
        }
        void Render(MultiMailboxCloudSelection? restore = null)
        {
            inventoryValid = true;
            loading = true;
            try
            {
                heading.Text = "Source: " + inventory.Source.Status + " (" + inventory.Source.Rows.Length + ")" +
                    " | Runtime: " + inventory.Runtime.Status + " (" + inventory.Runtime.Rows.Length + ")" +
                    Environment.NewLine + "Map comparison: " + inventory.Relation +
                    " | Installed recovery marker: " + inventory.InstalledBinding +
                    Environment.NewLine + "Read-only snapshot, not proof of a running transport.";
                heading.ForeColor = SystemInformation.HighContrast ? SystemColors.WindowText :
                    inventory.Relation == "same" && inventory.InstalledBinding == "matches_marker" ? UiTheme.Navy : UiTheme.WarningInk;
                heading.MaximumSize = new Size(Math.Max(160, dialog.ClientSize.Width - 38), 0);
                Populate(sourceGrid, inventory.Source, "source");
                Populate(runtimeGrid, inventory.Runtime, "runtime");
                if (restore is not null)
                {
                    tabs.SelectedTab = restore.Scope == "runtime" ? runtimeTab : sourceTab;
                    var grid = restore.Scope == "runtime" ? runtimeGrid : sourceGrid;
                    foreach (DataGridViewRow candidate in grid.Rows)
                        if (candidate.Tag is MultiMailboxIdentityRow row && row == restore.Row)
                        {
                            grid.CurrentCell = candidate.Cells[0];
                            candidate.Selected = true;
                            break;
                        }
                }
            }
            finally { loading = false; }
            Detail();
        }
        sourceGrid.SelectionChanged += (_, _) => Detail();
        runtimeGrid.SelectionChanged += (_, _) => Detail();
        tabs.SelectedIndexChanged += (_, _) => Detail();
        dialog.ClientSizeChanged += (_, _) => heading.MaximumSize = new Size(Math.Max(160, dialog.ClientSize.Width - 38), 0);
        dialog.FormClosing += (_, e) => { if (reading) e.Cancel = true; };
        void Invalidate(string reason)
        {
            inventoryValid = false;
            observations.Clear();
            sourceGrid.Rows.Clear();
            runtimeGrid.Rows.Clear();
            heading.Text = reason;
            details.Text = "No current cloud result accepted. Refresh the Linux inventory before retrying.";
            verify.Enabled = false;
        }
        verify.Click += async (_, _) =>
        {
            if (reading || !inventoryValid) return;
            var selection = MultiMailboxCloudSelection.Capture(inventory, SelectedScope(), Selected());
            if (selection is null) return;
            if (MessageBox.Show(dialog,
                "Read Microsoft Graph and Exchange Online for this exact selected identity only?" +
                Environment.NewLine + "Mailbox: " + selection.Row.Mailbox +
                Environment.NewLine + "Tenant ID: " + selection.Row.Tenant +
                Environment.NewLine + "Client ID: " + selection.Row.Client +
                Environment.NewLine + "Use an authorized administrator account in this tenant. No cloud or Linux settings will change.",
                "Microsoft 365 | Read-only mailbox audit", MessageBoxButtons.OKCancel,
                MessageBoxIcon.Information) != DialogResult.OK) return;
            observations.Remove(selection);
            reading = true;
            refresh.Enabled = close.Enabled = tabs.Enabled = verify.Enabled = false;
            heading.Text = "Checking Linux identity, then Microsoft Graph / Exchange Online...";
            details.Clear();
            try
            {
                string bootstrapField = entraSignInClientId.Text.Trim();
                Guid bootstrap = ApprovedGraphPublicClientId();
                void ValidateContext()
                {
                    RequireSameArchiveConnection(endpoint);
                    if (!HasMailDiscovery() || context != CurrentMultiMailboxContext() ||
                        bootstrapField != entraSignInClientId.Text.Trim() ||
                        !selection.Matches(inventory, SelectedScope(), Selected()))
                        throw new InvalidOperationException("Mailbox, Linux or sign-in selection changed.");
                }
                ValidateContext();
                selection.RequireUnchanged(await ReadAsync());
                ValidateContext();
                var cloud = await QueryMultiMailboxCloudAsync(selection, dialog, bootstrap, ValidateContext);
                DateTimeOffset sampled = DateTimeOffset.UtcNow;
                ValidateContext();
                var latest = await ReadAsync();
                selection.RequireUnchanged(latest);
                ValidateContext();
                var observation = MultiMailboxCloudObservation.Create(selection, cloud, sampled);
                inventory = latest;
                observations[selection] = observation;
                Render(selection);
                WriteLine("Selected multi-mailbox cloud configuration sample completed. No SMTP, signer or delivery test.");
            }
            catch (Exception)
            {
                Invalidate("Mailbox audit failed or became stale.");
                WriteLine("Selected mailbox read-only cloud audit incomplete. Refresh Linux inventory and verify tenant permissions.");
            }
            finally
            {
                reading = false;
                refresh.Enabled = close.Enabled = tabs.Enabled = true;
                Detail();
            }
        };
        refresh.Click += async (_, _) =>
        {
            if (reading) return;
            reading = true;
            refresh.Enabled = close.Enabled = tabs.Enabled = verify.Enabled = false;
            inventoryValid = false;
            observations.Clear();
            sourceGrid.Rows.Clear(); runtimeGrid.Rows.Clear();
            heading.Text = "Reading fresh identity inventory...";
            details.Clear();
            try { inventory = await ReadAsync(); Render(); }
            catch (Exception)
            {
                Invalidate("Refresh failed. Previous inventory invalidated.");
                WriteLine("Multi-mailbox inventory refresh failed. No changes requested.");
            }
            finally { reading = false; refresh.Enabled = close.Enabled = tabs.Enabled = true; Detail(); }
        };
        root.Controls.Add(heading, 0, 0); root.Controls.Add(tabs, 0, 1);
        root.Controls.Add(details, 0, 2); root.Controls.Add(footer, 0, 3);
        dialog.Controls.Add(root); dialog.CancelButton = close;
        Render();
        dialog.ShowDialog(this);
    }
}
