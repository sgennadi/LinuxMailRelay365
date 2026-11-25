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
            RequireSameArchiveConnection(current, allowFirstPin: true);
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
        bool loading = false;
        CloudObjectsInventory? CloudSample() => lastReadOnlyCloudLinuxIdentity == TryCurrentIdentity()
            ? lastReadOnlyCloudInventory : null;
        MultiMailboxIdentityRow? Selected() =>
            (tabs.SelectedTab == runtimeTab ? runtimeGrid : sourceGrid).SelectedRows
                .Cast<DataGridViewRow>().FirstOrDefault()?.Tag as MultiMailboxIdentityRow;
        void Detail()
        {
            if (loading) return;
            var row = Selected();
            details.Text = row is null
                ? "Select one mailbox. Source and runtime maps are distinct. No automatic changes or cloud sign-in."
                : "SMTP login: " + row.Login + Environment.NewLine +
                    "Envelope sender / mailbox: " + row.Mailbox + Environment.NewLine +
                    "Tenant ID: " + (row.Tenant?.ToString("D") ?? "unverified") + Environment.NewLine +
                    "Client ID: " + (row.Client?.ToString("D") ?? "unverified") + Environment.NewLine +
                    "Configured signer: " + row.Signer + Environment.NewLine +
                    "Public certificate SHA-256: " + (row.CertificateSha.Length > 0 ? row.CertificateSha : "unverified") + Environment.NewLine +
                    "Previous exact Graph sample: " + row.CompareCloud(CloudSample(), DateTimeOffset.UtcNow) + Environment.NewLine +
                    "Previous exact mailbox RBAC sample: " + row.CompareMailboxRbac(CloudSample()) + Environment.NewLine +
                    "Linux public PEM bytes only. Local X.509 dates, key possession, live SMTP login and delivery are not verified. " +
                    "The Graph/Exchange sample may be stale; it is never applied to another tenant, app or mailbox.";
        }
        void Populate(DataGridView grid, MultiMailboxIdentityMap map)
        {
            grid.Rows.Clear();
            foreach (var row in map.Rows)
            {
                string cloud = row.CompareCloud(CloudSample(), DateTimeOffset.UtcNow);
                int index = grid.Rows.Add(row.Login, row.Mailbox, row.Signer, row.Status, cloud);
                grid.Rows[index].Tag = row;
                if (!SystemInformation.HighContrast)
                {
                    var cell = grid.Rows[index].Cells["status"];
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
        void Render()
        {
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
                Populate(sourceGrid, inventory.Source);
                Populate(runtimeGrid, inventory.Runtime);
            }
            finally { loading = false; }
            Detail();
        }
        sourceGrid.SelectionChanged += (_, _) => Detail();
        runtimeGrid.SelectionChanged += (_, _) => Detail();
        tabs.SelectedIndexChanged += (_, _) => Detail();
        dialog.ClientSizeChanged += (_, _) => heading.MaximumSize = new Size(Math.Max(160, dialog.ClientSize.Width - 38), 0);
        bool reading = false;
        dialog.FormClosing += (_, e) => { if (reading) e.Cancel = true; };
        refresh.Click += async (_, _) =>
        {
            if (reading) return;
            reading = true;
            refresh.Enabled = close.Enabled = tabs.Enabled = false;
            sourceGrid.Rows.Clear(); runtimeGrid.Rows.Clear();
            heading.Text = "Reading fresh identity inventory...";
            details.Clear();
            try { inventory = await ReadAsync(); Render(); }
            catch (Exception)
            {
                sourceGrid.Rows.Clear(); runtimeGrid.Rows.Clear();
                heading.Text = "Refresh failed. Previous inventory invalidated.";
                details.Text = "No changes requested. Reinspect the Linux connection before retrying.";
                WriteLine("Multi-mailbox inventory refresh failed. No changes requested.");
            }
            finally { reading = false; refresh.Enabled = close.Enabled = tabs.Enabled = true; }
        };
        root.Controls.Add(heading, 0, 0); root.Controls.Add(tabs, 0, 1);
        root.Controls.Add(details, 0, 2); root.Controls.Add(footer, 0, 3);
        dialog.Controls.Add(root); dialog.CancelButton = close;
        Render();
        dialog.ShowDialog(this);
    }
}
