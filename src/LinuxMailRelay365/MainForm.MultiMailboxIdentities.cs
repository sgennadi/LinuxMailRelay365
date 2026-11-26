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
        var testSmtpAuth = UiTheme.Action(T("Проверить SMTP AUTH...", "Test SMTP AUTH only...", "בדיקת SMTP AUTH..."), true, "check");
        footer.Controls.Add(testSmtpAuth);
        var addMailbox = UiTheme.Action(T("Добавить", "Add mailbox", "הוספת תיבה"), false, "add");
        var editMailbox = UiTheme.Action(T("Изменить", "Edit mailbox", "עריכת תיבה"), false, "edit");
        var removeMailbox = UiTheme.Action(T("Удалить запись", "Remove row", "הסרת שורה"), false, "delete");
        var restoreSource = UiTheme.Action(T("Восстановить карту...", "Restore source map...", "שחזור מפת מקור..."), false, "restore");
        footer.Controls.Add(addMailbox); footer.Controls.Add(editMailbox); footer.Controls.Add(removeMailbox);
        footer.Controls.Add(restoreSource);
        var prepareIdentity = UiTheme.Action(T("Новый OAuth-идентификатор...", "New OAuth identity...", "זהות OAuth חדשה..."), false, "add");
        footer.Controls.Add(prepareIdentity);
        var newApp = UiTheme.Action(T("Новое приложение Entra...", "New Entra app / recover...", "יישום Entra חדש..."), true, "add");
        footer.Controls.Add(newApp);
        var registerIdentity = UiTheme.Action(T("Регистрация сертификата...", "Register prepared certificate...", "רישום אישור..."), false, "check");
        footer.Controls.Add(registerIdentity);
        var configureScope = UiTheme.Action(T("Настроить SMTP RBAC...", "Configure SMTP RBAC...", "הגדרת SMTP RBAC..."), false, "check");
        footer.Controls.Add(configureScope);
        string lastPreparedIdentity = "";
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
        bool loading = false, reading = false, inventoryValid = true, saveUncertain = false;
        // Only within this dialog and exact source/runtime map selection.
        var observations = new Dictionary<MultiMailboxCloudSelection, MultiMailboxCloudObservation>();
        var smtpAuthSamples = new Dictionary<MultiMailboxCloudSelection, (MultiMailboxSmtpAuthReceipt Receipt, DateTimeOffset Sampled)>();
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
        void EditingActions()
        {
            bool source = !loading && !reading && inventoryValid && !saveUncertain &&
                SelectedScope() == "source" && inventory.Source.Status is "ok" or "absent";
            addMailbox.Enabled = source && inventory.Source.Rows.Length < 64;
            editMailbox.Enabled = source && Selected() is not null;
            removeMailbox.Enabled = source && Selected() is not null && inventory.Source.Rows.Length > 1;
            restoreSource.Enabled = source && inventory.Source.Status == "ok";
            prepareIdentity.Enabled = source && inventory.Runtime.Status is "ok" or "absent";
            newApp.Enabled = prepareIdentity.Enabled && inventory.Source.Rows.Length < 64;
            testSmtpAuth.Enabled = !loading && !reading && inventoryValid && !saveUncertain &&
                Selected() is { Status: "public_certificate_read" } &&
                MultiMailboxCloudSelection.Capture(inventory, SelectedScope(), Selected()) is not null;
            configureScope.Enabled = !loading && !reading && inventoryValid && !saveUncertain &&
                SelectedScope() == "source" && Selected() is { Status: "public_certificate_read" };
            registerIdentity.Enabled = !loading && !reading && inventoryValid && !saveUncertain &&
                inventory.Source.Status is "ok" or "absent" && inventory.Runtime.Status is "ok" or "absent" &&
                Selected() is { Signer: "software", Status: "public_certificate_read" };
        }
        void Detail()
        {
            EditingActions();
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
            var authSelection = MultiMailboxCloudSelection.Capture(inventory, scope, row);
            if (authSelection is not null && smtpAuthSamples.TryGetValue(authSelection, out var sample))
                details.AppendText(Environment.NewLine + Environment.NewLine +
                    "Live AUTH-only sample (UTC): " + sample.Sampled.ToString("u") + Environment.NewLine +
                    sample.Receipt.Describe() + Environment.NewLine + "No mail or delivery proof; historical sample only.");
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
                    Environment.NewLine + (saveUncertain ?
                        "Save outcome uncertain: editing locked for this window. Review the backup before reopening." :
                        "Source edits require preview and approval. Installed/runtime remains read-only.");
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
            observations.Clear(); smtpAuthSamples.Clear();
            sourceGrid.Rows.Clear();
            runtimeGrid.Rows.Clear();
            heading.Text = reason;
            details.Text = "No current cloud result accepted. Refresh the Linux inventory before retrying.";
            verify.Enabled = false;
            EditingActions();
        }
        async Task EditSourceAsync(string action)
        {
            if (reading || !inventoryValid || saveUncertain || SelectedScope() != "source") return;
            var oldMap = inventory.Source;
            var selected = action is "add" or "restore" ? null : Selected();
            reading = true;
            refresh.Enabled = close.Enabled = tabs.Enabled = verify.Enabled = false;
            EditingActions();
            bool saveAttempted = false;
            string backupId = "";
            try
            {
                void ValidateContext()
                {
                    RequireSameArchiveConnection(endpoint);
                    if (context != CurrentMultiMailboxContext() || !HasMailDiscovery())
                        throw new InvalidOperationException("Linux or source selection changed.");
                }
                MultiMailboxSourceBackupCatalog? catalog = null;
                if (action == "restore")
                {
                    ValidateContext();
                    heading.Text = "Reading compatible source-map backups; no changes...";
                    string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
                    var reply = await SshRemote.RunRootScriptAsync(endpoint,
                        EmbeddedAssets.BuildMultiMailboxSourceEditBundle(
                            MultiMailboxSourceBackupCatalog.Request(oldMap.Sha256, nonce)), TimeSpan.FromMinutes(3));
                    ValidateContext();
                    if (reply.ExitCode != 0) throw new IOException("Backup catalog unavailable or changed.");
                    catalog = MultiMailboxSourceBackupCatalog.Parse(reply.StdOut, oldMap.Sha256, oldMap.Rows.Length, nonce);
                }
                var request = PromptMultiMailboxSourceEdit(dialog, action, oldMap, selected, catalog);
                if (request is null) { Render(); return; }
                async Task<(MultiMailboxSourceEditPlan Plan, string BackupId)> Execute(
                    MultiMailboxSourceEditPlan? approved)
                {
                    ValidateContext();
                    var reply = await SshRemote.RunRootScriptAsync(endpoint,
                        EmbeddedAssets.BuildMultiMailboxSourceEditBundle(request.Serialize(approved?.PlanSha ?? "")),
                        TimeSpan.FromMinutes(3));
                    foreach (string line in reply.StdErr.Split('\n', StringSplitOptions.TrimEntries))
                    {
                        if (System.Text.RegularExpressions.Regex.IsMatch(line, @"\ASOURCE_MAP_BACKUP_ID=source-[a-z0-9_]{8}\z"))
                        {
                            backupId = line["SOURCE_MAP_BACKUP_ID=".Length..];
                            WriteLine("Prepared source-map backup: " + backupId);
                        }
                    }
                    if (reply.ExitCode != 0) throw new IOException("Source-map edit refused or requires review.");
                    ValidateContext();
                    return MultiMailboxSourceEditPlan.Parse(reply.StdOut, request, approved);
                }
                heading.Text = "Preparing source-map preview; no changes...";
                var fresh = await ReadAsync();
                if (fresh.Source.Status != oldMap.Status || fresh.Source.Sha256 != oldMap.Sha256 ||
                    !fresh.Source.Rows.SequenceEqual(oldMap.Rows))
                    throw new InvalidOperationException("Source map or identity evidence changed.");
                var preview = (await Execute(null)).Plan;
                if (!ConfirmDestructive("LinuxMailRelay365 | Save planned mailbox map",
                    preview.Describe(request), request.ConfirmationPhrase, dialog))
                {
                    Render();
                    return;
                }
                ValidateContext();
                ResetMultiMailboxRouteReview();
                observations.Clear(); smtpAuthSamples.Clear();
                saveAttempted = true;
                heading.Text = "Saving approved source map; runtime is not activated...";
                var saved = await Execute(preview);
                backupId = saved.BackupId;
                var latest = await ReadAsync();
                if (latest.Source.Status != "ok" || latest.Source.Sha256 != preview.NewSha ||
                    latest.Source.Rows.Length != preview.NewCount ||
                    (preview.Selected is not null && !latest.Source.Rows.Contains(preview.Selected)) ||
                    (request.Action == "remove" && latest.Source.Rows.Any(r => r.Mailbox == request.OldMailbox)))
                    throw new InvalidDataException("Saved source inventory differs from preview.");
                inventory = latest;
                Render(preview.Selected is null ? null :
                    MultiMailboxCloudSelection.Capture(inventory, "source", preview.Selected));
                WriteLine("Planned mailbox map saved. Backup: " + backupId + ". Runtime was not activated.");
                MessageBox.Show(dialog, "Source map saved. Backup: " + backupId +
                    Environment.NewLine + "Review and apply the isolated route separately. No live route changed.",
                    "Source map saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception)
            {
                if (saveAttempted) saveUncertain = true;
                Invalidate(saveAttempted ? "Save outcome uncertain. Editing locked; inspect backup and source map." :
                    "Source preview refused or stale. Refresh before retrying.");
                if (saveAttempted)
                {
                    details.Text = "Do not retry blindly. Backup: " + (backupId == "" ? "not confirmed" : backupId) +
                        Environment.NewLine + "Review /etc/linuxmailrelay365/oauth-source-backups and the actual source map.";
                    WriteLine("Source map save outcome requires manual review. Runtime activation was not requested.");
                }
                else WriteLine("Source-map preview refused or stale. No save requested.");
            }
            finally
            {
                reading = false;
                refresh.Enabled = close.Enabled = tabs.Enabled = true;
                Detail();
            }
        }
        async Task<MultiMailboxTpmDiscovery?> DiscoverTpmForCertificateAsync()
        {
            var tpm=MultiMailboxTpmDiscovery.Unavailable;
            reading=true;
            refresh.Enabled=close.Enabled=tabs.Enabled=verify.Enabled=false;
            EditingActions();
            try
            {
                heading.Text="Checking TPM 2.0 prerequisites before certificate choices...";
                RequireSameArchiveConnection(endpoint);
                var probe=await SshRemote.RunRootScriptAsync(endpoint,
                    EmbeddedAssets.BuildMultiMailboxTpmPrepareBundle("{\"action\":\"discover\"}"),TimeSpan.FromMinutes(3));
                RequireSameArchiveConnection(endpoint);
                if(context!=CurrentMultiMailboxContext() || !HasMailDiscovery())
                    throw new InvalidOperationException("Linux context changed.");
                if(probe.ExitCode==0) tpm=MultiMailboxTpmDiscovery.Parse(probe.StdOut);
            }
            catch(Exception)
            {
                try
                {
                    RequireSameArchiveConnection(endpoint);
                    if(context!=CurrentMultiMailboxContext() || !HasMailDiscovery())
                        throw new InvalidOperationException("Linux context changed.");
                }
                catch(Exception)
                { Invalidate("Linux context changed during TPM discovery.");return null; }
                WriteLine("TPM prerequisites unavailable; no hardware creation was attempted.");
            }
            finally
            {
                reading=false;refresh.Enabled=close.Enabled=tabs.Enabled=true;Detail();
            }
            Render();
            return tpm;
        }
        newApp.Click += async (_,_) =>
        {
            if (!newApp.Enabled) return;
            var tpm=await DiscoverTpmForCertificateAsync();
            if(tpm is null) return;
            var choice=PromptNewMailboxApp(dialog,inventory,tpm);
            if (choice is null) return;
            var (req,resume)=choice.Value;
            var before=inventory;
            reading=true;
            refresh.Enabled=close.Enabled=tabs.Enabled=verify.Enabled=false;
            EditingActions();
            bool attempted=false;
            string clientEvidence="";
            try
            {
                string bootstrapField=entraSignInClientId.Text.Trim();
                Guid bootstrap=ApprovedGraphPublicClientId();
                void ValidateContext()
                {
                    RequireSameArchiveConnection(endpoint);
                    if (!HasMailDiscovery() || context!=CurrentMultiMailboxContext() ||
                        bootstrapField!=entraSignInClientId.Text.Trim() || SelectedScope()!="source")
                        throw new InvalidOperationException("Linux or sign-in context changed.");
                }
                async Task CheckMaps()
                {
                    ValidateContext();
                    var latest=await ReadAsync();
                    if (latest.Source.Status!=before.Source.Status || latest.Source.Sha256!=before.Source.Sha256 ||
                        latest.Runtime.Status!=before.Runtime.Status || latest.Runtime.Sha256!=before.Runtime.Sha256 ||
                        latest.InstalledBinding!=before.InstalledBinding ||
                        !latest.Source.Rows.SequenceEqual(before.Source.Rows) || !latest.Runtime.Rows.SequenceEqual(before.Runtime.Rows))
                        throw new InvalidDataException("Source or runtime inventory changed.");
                    ValidateContext();
                }
                async Task<MultiMailboxNewAppReceipt> Execute(string action, string approval="",
                    MultiMailboxNewAppReceipt? previous=null, Guid? client=null)
                {
                    ValidateContext();
                    var reply=await SshRemote.RunRootScriptAsync(endpoint,EmbeddedAssets.BuildMultiMailboxNewAppBundle(
                        req.Serialize(action,approval,client)),TimeSpan.FromMinutes(req.TpmHandle is null?4:10));
                    ValidateContext();
                    if (reply.ExitCode!=0) throw new IOException("New application local stage refused or requires review.");
                    return MultiMailboxNewAppReceipt.Parse(reply.StdOut,req,action,previous,client);
                }
                await CheckMaps();
                MultiMailboxNewAppReceipt stage;
                if (resume)
                {
                    heading.Text="Recovering exact pending Linux certificate...";
                    stage=await Execute("inspect");
                }
                else
                {
                    heading.Text="Checking local prerequisites for a new Entra application...";
                    var preview=await Execute("preview");
                    if (!ConfirmDestructive("LinuxMailRelay365 | Stage initial certificate",
                        "Tenant: "+req.Tenant+Environment.NewLine+"Mailbox: "+req.Mailbox+
                        Environment.NewLine+"Application name: "+req.Name+Environment.NewLine+req.KeyDescription+", days: "+req.Days+
                        Environment.NewLine+"Recovery code: "+req.Nonce+Environment.NewLine+"Plan SHA-256: "+preview.ApprovalSha+
                        Environment.NewLine+(req.TpmHandle is null?"Only a protected local key and public certificate are created.":
                            "One new persistent TPM key and public certificate will be created; no PEM fallback. Never automatically evict or retry.")+" No cloud action.",
                        MultiMailboxNewAppRequest.Phrase("stage"),dialog)) { Render(); return; }
                    await CheckMaps();
                    ResetMultiMailboxRouteReview(); observations.Clear(); smtpAuthSamples.Clear();
                    attempted=true;
                    WriteLine("New Entra app recovery code: "+req.Nonce+"; name: "+req.Name+
                        "; tenant: "+req.Tenant+"; mailbox: "+req.Mailbox+"; days: "+req.Days+"; key: "+req.KeyDescription);
                    heading.Text=req.TpmHandle is null?"Generating initial public certificate on Linux...":
                        "Creating reviewed TPM key and initial public certificate...";
                    stage=await Execute("stage",preview.ApprovalSha,preview);
                }
                Guid appId;
                Guid enterprise;
                if (stage.Claimed)
                {
                    if (req.ResumeClient is not Guid recovered)
                        throw new InvalidOperationException("Creation already claimed; recover exact Client ID, never recreate.");
                    appId=recovered;
                    clientEvidence=appId.ToString("D");
                    enterprise=await VerifyNewMailboxAppAsync(req,stage,appId,bootstrap,dialog,ValidateContext);
                    if (!ConfirmDestructive("LinuxMailRelay365 | Complete recovered identity",
                        "Verified existing app: "+req.Name+Environment.NewLine+"Client ID: "+appId+
                        Environment.NewLine+"Mailbox: "+req.Mailbox+Environment.NewLine+"Certificate SHA-256: "+stage.CertificateSha+
                        Environment.NewLine+"Publish the local identity only; no cloud or route changes.",
                        MultiMailboxNewAppRequest.Phrase("finalize"),dialog)) { Render(); return; }
                }
                else
                {
                    if (req.ResumeClient is not null) throw new InvalidDataException("Unclaimed stage cannot reuse an existing app.");
                    if (!ConfirmDestructive("LinuxMailRelay365 | Create new Entra application",
                        "MICROSOFT ENTRA CHANGE: create one new single-tenant App Registration with its initial public certificate, "+
                        "then its Enterprise Application. No existing app is modified. No Exchange or Graph mail permissions are granted."+
                        Environment.NewLine+"Tenant: "+req.Tenant+Environment.NewLine+"Mailbox: "+req.Mailbox+
                        Environment.NewLine+"App name: "+req.Name+Environment.NewLine+"Certificate SHA-256: "+stage.CertificateSha+
                        Environment.NewLine+"Recovery code: "+req.Nonce+
                        Environment.NewLine+"After verified cloud creation, publish the unbound Linux identity. No mail or route activation.",
                        MultiMailboxNewAppRequest.Phrase("claim"),dialog)) { Render(); return; }
                    await CheckMaps();
                    await WithNativeMicrosoftSignInAsync(async (show,ct)=>
                    {
                        await Microsoft365Auth.EntraGraphCertificateAddKeyClient.PrepareWriteSignInAsync(req.Tenant,bootstrap,show,ct);
                        return true;
                    },mayModifyEntra:true,signInOwner:dialog);
                    await CheckMaps();
                    var recent=await Execute("inspect",previous:stage);
                    if (recent.Claimed) throw new InvalidDataException("Creation already claimed.");
                    ResetMultiMailboxRouteReview(); observations.Clear(); smtpAuthSamples.Clear();
                    attempted=true;
                    WriteLine("Claiming new Entra app creation once: "+req.Name+"; recovery code: "+req.Nonce);
                    stage=await Execute("claim",stage.ApprovalSha,stage);
                    ValidateContext();
                    heading.Text="Creating dedicated App Registration and Enterprise Application...";
                    var created=await WithNativeMicrosoftSignInAsync((show,ct)=>
                        Microsoft365Auth.EntraGraphProvisioner.ProvisionAsync(req.Tenant,bootstrap,null,req.Name,
                            Microsoft365Auth.EntraGraphCertificateAddKeyClient.MultiMailboxLabel,stage.PublicPem,show,ct),
                        mayModifyEntra:true,signInOwner:dialog);
                    if (created.ClientId!=Guid.Empty) clientEvidence=created.ClientId.ToString("D");
                    if (!created.AppCreated || !created.PublicCertificateAdded || created.TenantId!=req.Tenant ||
                        created.ClientId==Guid.Empty || created.ApplicationObjectId==Guid.Empty ||
                        created.EnterpriseApplicationObjectId==Guid.Empty || created.DisplayName!=req.Name ||
                        !string.Equals(created.CertificateSha256,stage.CertificateSha,StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("New app creation receipt unverified.");
                    appId=created.ClientId;
                    WriteLine("Entra new app Client ID: "+appId+"; name: "+req.Name+"; recovery code: "+req.Nonce);
                    enterprise=await VerifyNewMailboxAppAsync(req,stage,appId,bootstrap,dialog,ValidateContext);
                    if (enterprise!=created.EnterpriseApplicationObjectId)
                        throw new InvalidDataException("Enterprise identity changed.");
                }
                await CheckMaps();
                var claimed=await Execute("inspect",previous:stage);
                if (!claimed.Claimed) throw new InvalidDataException("Creation claim disappeared.");
                ResetMultiMailboxRouteReview(); observations.Clear(); smtpAuthSamples.Clear();
                attempted=true;
                heading.Text="Publishing unbound local identity for verified Entra application...";
                _=await Execute("finalize",claimed.ApprovalSha,claimed,appId);
                await CheckMaps();
                lastPreparedIdentity=req.IdentityFile;
                Render();
                WriteLine("New dedicated Entra application and local identity verified: "+req.IdentityFile+
                    "; Client ID: "+appId+"; Enterprise ID: "+enterprise+". No route or Exchange permission changes.");
                MessageBox.Show(dialog,"Dedicated application and unbound local OAuth identity ready."+
                    Environment.NewLine+"Client ID: "+appId+Environment.NewLine+"Identity: "+req.IdentityFile+
                    Environment.NewLine+"Key: "+req.KeyDescription+(req.TpmHandle is null?"":"; hardware attestation not verified")+
                    Environment.NewLine+"Next: Add mailbox to source map, Configure SMTP RBAC, then offline route review.",
                    "New Entra app ready",MessageBoxButtons.OK,MessageBoxIcon.Information);
            }
            catch (Exception)
            {
                if (attempted) saveUncertain=true;
                Invalidate(attempted ? "New application outcome requires review; editing locked." : "New application preview or recovery refused.");
                details.Text="Do not create again if a claim exists. Find exact app in Entra by name: "+req.Name+
                    Environment.NewLine+"Recovery code: "+req.Nonce+Environment.NewLine+"Client ID (if known): "+clientEvidence+
                    Environment.NewLine+"Mailbox: "+req.Mailbox+"; days: "+req.Days+"; key: "+req.KeyDescription+
                    Environment.NewLine+"Reopen this window and use recovery with the original parameters. No automatic cleanup.";
                WriteLine("New app review required: "+req.Name+"; recovery code: "+req.Nonce+"; known Client ID: "+clientEvidence+"; key: "+req.KeyDescription);
            }
            finally
            {
                reading=false; refresh.Enabled=close.Enabled=tabs.Enabled=true; Detail();
            }
        };
        prepareIdentity.Click += async (_, _) =>
        {
            if (reading || !inventoryValid || saveUncertain || SelectedScope() != "source") return;
            var tpm=await DiscoverTpmForCertificateAsync();
            if(tpm is null) return;
            var choice=PromptUnboundMailboxIdentity(dialog,inventory.Source.Sha256,tpm);
            if (choice is null) return;
            var (req,handle)=choice.Value;
            var before = inventory;
            reading = true;
            refresh.Enabled = close.Enabled = tabs.Enabled = verify.Enabled = false;
            EditingActions();
            bool attempted = false;
            MultiMailboxIdentityPrepareReceipt? saved = null;
            try
            {
                void ValidateContext()
                {
                    RequireSameArchiveConnection(endpoint);
                    if (context != CurrentMultiMailboxContext() || !HasMailDiscovery())
                        throw new InvalidOperationException("Linux selection changed.");
                }
                async Task<MultiMailboxIdentityPrepareReceipt> Execute(MultiMailboxIdentityPrepareReceipt? approved)
                {
                    ValidateContext();
                    var reply = await SshRemote.RunRootScriptAsync(endpoint,
                        handle is null
                            ? EmbeddedAssets.BuildMultiMailboxIdentityPrepareBundle(req.Serialize(approved?.PlanSha ?? ""))
                            : EmbeddedAssets.BuildMultiMailboxTpmPrepareBundle(MultiMailboxTpmPrepare.Serialize(req,handle,approved?.PlanSha ?? "")),
                        TimeSpan.FromMinutes(handle is null ? 4 : 9));
                    ValidateContext();
                    if (reply.ExitCode != 0) throw new IOException("Identity preparation refused or requires review.");
                    return handle is null ? MultiMailboxIdentityPrepareReceipt.Parse(reply.StdOut,req,approved)
                        : MultiMailboxTpmPrepare.Parse(reply.StdOut,req,handle,approved);
                }
                void CheckMaps(MultiMailboxIdentityInventory sample)
                {
                    if (sample.Source.Status != before.Source.Status || sample.Source.Sha256 != before.Source.Sha256 ||
                        sample.Runtime.Status != before.Runtime.Status || sample.Runtime.Sha256 != before.Runtime.Sha256 ||
                        sample.InstalledBinding != before.InstalledBinding ||
                        !sample.Source.Rows.SequenceEqual(before.Source.Rows) ||
                        !sample.Runtime.Rows.SequenceEqual(before.Runtime.Rows))
                        throw new InvalidDataException("Source or runtime inventory changed.");
                }
                heading.Text = "Checking Linux prerequisites for an unbound OAuth identity...";
                CheckMaps(await ReadAsync());
                var preview = await Execute(null);
                if (preview.RuntimeSha != before.Runtime.Sha256)
                    throw new InvalidDataException("Runtime map changed.");
                if (!ConfirmDestructive("LinuxMailRelay365 | Prepare new local identity",
                    "Tenant: " + req.Tenant + Environment.NewLine + "Existing application: " + req.Client +
                    Environment.NewLine + "Mailbox: " + req.Mailbox +
                    Environment.NewLine + (handle is null ? "Software RSA 3072" : "TPM 2.0 RSA 2048, new persistent handle: "+handle) +
                    ", validity: " + req.Days + " days" +
                    Environment.NewLine + "New file: " + req.IdentityFile +
                    Environment.NewLine + "Plan SHA-256: " + preview.PlanSha +
                    Environment.NewLine + "Only new local protected identity files will be created. No mailbox, cloud permissions, source map, runtime, service or mail changes.",
                    handle is null ? MultiMailboxIdentityPrepareRequest.Confirmation : MultiMailboxTpmPrepare.Confirmation, dialog))
                { Render(); return; }
                CheckMaps(await ReadAsync());
                ValidateContext();
                ResetMultiMailboxRouteReview();
                observations.Clear(); smtpAuthSamples.Clear();
                attempted = true;
                heading.Text = handle is null ? "Preparing RSA key and verifying local service-account signature..." :
                    "Creating reviewed TPM persistent key and verifying m365mailer PS256 signature...";
                saved = await Execute(preview);
                var latest = await ReadAsync();
                CheckMaps(latest);
                lastPreparedIdentity = req.IdentityFile;
                inventory = latest;
                Render();
                WriteLine("Unbound local OAuth identity prepared: " + req.IdentityFile +
                    "; public certificate SHA-256: " + saved.CertificateSha + ". No route or cloud changes.");
                MessageBox.Show(dialog, "Identity prepared: " + req.IdentityFile +
                    Environment.NewLine + "Public certificate SHA-256: " + saved.CertificateSha +
                    Environment.NewLine + (handle is null ? "" : "TPM persistent handle: "+handle+
                        ". Hardware attestation is not verified. Import this public certificate manually; automated prepared-certificate registration currently requires software identities."+Environment.NewLine) +
                    "Save the public certificate, register it with the exact Entra application, review Exchange permissions, then use Add mailbox to bind this identity. No live route changed.",
                    "Unbound identity prepared", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception)
            {
                if (attempted) saveUncertain = true;
                Invalidate(attempted ? "Identity creation outcome requires review; editing locked." :
                    "Identity preview refused or stale. Check prerequisites and refresh.");
                if (attempted)
                {
                    details.Text = "Do not retry blindly. Inspect the protected directory for " + req.IdentityFile +
                        (handle is null ? " and its matching .key/.crt files." :
                            " and matching .crt/.tpm2.cnf files; inspect TPM handle "+handle+". Never evict or retry automatically.") +
                        " No route activation requested.";
                    WriteLine("Identity preparation outcome requires manual review: " + req.IdentityFile +
                        (handle is null ? "" : "; TPM handle "+handle));
                }
                else WriteLine("Identity preparation preview refused. Check OpenSSL, service account, directory permissions and SELinux.");
            }
            finally
            {
                reading = false;
                refresh.Enabled = close.Enabled = tabs.Enabled = true;
                Detail();
            }
            if (saved is not null)
            {
                // Only public DER was returned; never download the private key.
                using var export = new SaveFileDialog { Filter = "Public X.509 certificate (*.cer)|*.cer",
                    FileName = Path.GetFileNameWithoutExtension(req.IdentityFile) + ".cer", AddExtension = true,
                    DefaultExt = "cer", OverwritePrompt = true };
                if (export.ShowDialog(dialog) == DialogResult.OK)
                {
                    try
                    {
                        using var output = new FileStream(export.FileName, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                        output.Write(saved.PublicDer);
                        output.Flush(true);
                        WriteLine("Public certificate exported. Private key remains on Linux.");
                    }
                    catch (Exception)
                    {
                        MessageBox.Show(dialog, "Public certificate was not saved. Choose a new filename or export the public .crt from Linux separately.",
                            "Public certificate export", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
            }
        };
        registerIdentity.Click += async (_, _) =>
        {
            if (!registerIdentity.Enabled || Selected() is not { } donor) return;
            var selection = MultiMailboxCloudSelection.Capture(inventory, SelectedScope(), donor);
            if (selection is null) return;
            var req = PromptMailboxGraphPair(dialog, selection.Scope, inventory, donor, lastPreparedIdentity);
            if (req is null) return;
            reading = true;
            refresh.Enabled = close.Enabled = tabs.Enabled = verify.Enabled = false;
            EditingActions();
            bool graphAttempted = false;
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
                        throw new InvalidOperationException("Mailbox or sign-in context changed.");
                }
                async Task<MultiMailboxGraphPair> ReadPair()
                {
                    ValidateContext();
                    var reply = await SshRemote.RunRootScriptAsync(endpoint,
                        EmbeddedAssets.BuildMultiMailboxGraphPairBundle(req.Serialize()), TimeSpan.FromMinutes(3));
                    ValidateContext();
                    if (reply.ExitCode != 0) throw new IOException("Prepared pair could not be verified.");
                    return MultiMailboxGraphPair.Parse(reply.StdOut, req);
                }
                ValidateContext();
                selection.RequireUnchanged(await ReadAsync());
                heading.Text = "Checking prepared certificate and existing Graph application...";
                var pair = await ReadPair();
                string report = await WithNativeMicrosoftSignInAsync((show, ct) =>
                    Microsoft365Auth.EntraGraphCertificateAddKeyClient.PreviewAsync(pair.Evidence, bootstrap, show, ct),
                    signInOwner: dialog);
                ValidateContext();
                string Value(string key, string allowed) => ValidatedMultiMailboxReportValue(report, key, allowed);
                string plan = Value("ENTRA_CERT_PLAN_SHA256", @"\A[a-f0-9]{64}\z");
                var objectId = Guid.Parse(Value("ENTRA_CERT_OBJECT_ID", @"\A[a-f0-9-]{36}\z"));
                if (objectId == Guid.Empty) throw new InvalidDataException("Missing exact application object ID.");
                _ = Value("ENTRA_CERT_TENANT", "exact_match");
                _ = Value("ENTRA_CERT_APP", "exact_client_id");
                _ = Value("ENTRA_CERT_ACTIVE_KEY", "valid");
                _ = Value("ENTRA_CERT_CANDIDATE", "not_registered");
                _ = Value("ENTRA_CERT_EXISTING_KEYS_PRESERVED", "yes");
                _ = Value("CHANGES_APPLIED", "no");
                if (!ConfirmDestructive("LinuxMailRelay365 | Add prepared public certificate in Entra",
                    "MICROSOFT ENTRA CHANGE: append only one public certificate to this existing app." +
                    Environment.NewLine + "Tenant: " + pair.Evidence.TenantId +
                    Environment.NewLine + "Client ID: " + pair.Evidence.ClientId +
                    Environment.NewLine + "App Registration object ID: " + objectId +
                    Environment.NewLine + "Existing proof mailbox: " + donor.Mailbox +
                    Environment.NewLine + "Prepared mailbox: " + pair.CandidateMailbox +
                    Environment.NewLine + "New public certificate SHA-256: " + pair.Evidence.CandidateCertSha +
                    Environment.NewLine + "Graph plan SHA-256: " + plan +
                    Environment.NewLine + "The new credential can authenticate as the same app and inherits its existing authority. " +
                    "No Exchange permission or mailbox restriction is added by this action. Existing keys are preserved. " +
                    "No route activation, mail sending or private key export.",
                    MultiMailboxGraphPairRequest.Confirmation, dialog))
                { Render(selection); return; }
                ValidateContext();
                await WithNativeMicrosoftSignInAsync(async (show, ct) =>
                {
                    await Microsoft365Auth.EntraGraphCertificateAddKeyClient.PrepareWriteSignInAsync(
                        pair.Evidence.TenantId, bootstrap, show, ct);
                    return true;
                }, mayModifyEntra: true, signInOwner: dialog);
                selection.RequireUnchanged(await ReadAsync());
                if (await ReadPair() != pair)
                    throw new InvalidDataException("Prepared pair changed after review.");
                ValidateContext();
                var proofReply = await SshRemote.RunRootScriptAsync(endpoint,
                    EmbeddedAssets.BuildMultiMailboxGraphPairBundle(req.Serialize(pair.PairSha, objectId)),
                    TimeSpan.FromMinutes(2));
                ValidateContext();
                // Never log the ephemeral proof or include SSH output in exceptions.
                if (proofReply.ExitCode != 0) throw new IOException("Local proof signing failed.");
                string proof = EntraCertificateReview.ParseProof(proofReply.StdOut);
                ResetMultiMailboxRouteReview();
                observations.Clear(); smtpAuthSamples.Clear();
                graphAttempted = true;
                heading.Text = "Adding one reviewed public certificate to Entra...";
                string added = await WithNativeMicrosoftSignInAsync((show, ct) =>
                    Microsoft365Auth.EntraGraphCertificateAddKeyClient.AddAsync(pair.Evidence, bootstrap, plan, proof, show, ct),
                    mayModifyEntra: true, signInOwner: dialog);
                ValidateContext();
                _ = ValidatedMultiMailboxReportValue(added, "ENTRA_CERT_ADDED", "yes");
                _ = ValidatedMultiMailboxReportValue(added, "ENTRA_CERT_EXISTING_KEYS_PRESERVED", "yes");
                _ = ValidatedMultiMailboxReportValue(added, "CHANGES_APPLIED", "entra_addkey_only");
                if (ValidatedMultiMailboxReportValue(added, "ENTRA_CERT_PLAN_SHA256", @"\A[a-f0-9]{64}\z") != plan ||
                    ValidatedMultiMailboxReportValue(added, "ENTRA_CERT_OBJECT_ID", @"\A[a-f0-9-]{36}\z") != objectId.ToString("D"))
                    throw new InvalidDataException("Graph addKey receipt differs from review.");
                var latest = await ReadAsync();
                selection.RequireUnchanged(latest);
                if (await ReadPair() != pair) throw new InvalidDataException("Prepared pair changed after Graph operation.");
                inventory = latest;
                Render(selection);
                WriteLine("Graph addKey verified: prepared public certificate added; existing keys preserved. No mail or route changes.");
                MessageBox.Show(dialog, "Public certificate added to the exact Entra application." +
                    Environment.NewLine + "Review Exchange mailbox permissions separately before Add mailbox and offline route deployment.",
                    "Entra certificate registered", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception)
            {
                if (graphAttempted) saveUncertain = true;
                Invalidate(graphAttempted ? "Graph outcome requires review; editing locked for this window." :
                    "Graph preview or proof refused. No addKey requested.");
                if (graphAttempted)
                    details.Text = "Do not retry blindly. Inspect the selected Entra application for the new public certificate.";
                WriteLine(graphAttempted ? "Graph addKey outcome requires independent review." :
                    "Registration unavailable or stale. An existing valid same-app software proof certificate is required. No addKey requested.");
            }
            finally
            {
                reading = false;
                refresh.Enabled = close.Enabled = tabs.Enabled = true;
                Detail();
            }
        };
        addMailbox.Click += async (_, _) => await EditSourceAsync("add");
        editMailbox.Click += async (_, _) => await EditSourceAsync("edit");
        removeMailbox.Click += async (_, _) => await EditSourceAsync("remove");
        restoreSource.Click += async (_, _) => await EditSourceAsync("restore");
        configureScope.Click += async (_, _) =>
        {
            if (!configureScope.Enabled || SelectedScope() != "source") return;
            var selection = MultiMailboxCloudSelection.Capture(inventory,"source",Selected());
            if (selection is null) return;
            var choice = MessageBox.Show(dialog,
                "Review scoped Exchange SMTP permission for " + selection.Row.Mailbox + "?" +
                Environment.NewLine + "YES: also allow mailbox-only SMTP AUTH enable if effectively disabled." +
                Environment.NewLine + "NO: RBAC only; leave SMTP AUTH policy unchanged." +
                Environment.NewLine + "CANCEL: no operation. Apply requires separate typed confirmation.",
                "Microsoft 365 | Scope and SMTP policy",MessageBoxButtons.YesNoCancel,MessageBoxIcon.Information,MessageBoxDefaultButton.Button2);
            if (choice == DialogResult.Cancel) return;
            reading=true;
            refresh.Enabled=close.Enabled=tabs.Enabled=verify.Enabled=false;
            EditingActions();
            bool attempted=false;
            try
            {
                string bootstrapField=entraSignInClientId.Text.Trim();
                Guid bootstrap=ApprovedGraphPublicClientId();
                void ValidateContext()
                {
                    RequireSameArchiveConnection(endpoint);
                    if (!HasMailDiscovery() || context != CurrentMultiMailboxContext() ||
                        bootstrapField != entraSignInClientId.Text.Trim() || !selection.Matches(inventory,SelectedScope(),Selected()))
                        throw new InvalidOperationException("Mailbox or sign-in context changed.");
                }
                ValidateContext();
                selection.RequireUnchanged(await ReadAsync());
                heading.Text="Checking exact Graph application and public certificate...";
                Guid enterprise=await ReadScopeEnterpriseAsync(selection.Row,bootstrap,dialog,ValidateContext);
                var req=new MultiMailboxSmtpScopeRequest(selection.Row.Tenant!.Value,selection.Row.Client!.Value,
                    enterprise,selection.Row.Mailbox,Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant(),
                    choice == DialogResult.Yes);
                heading.Text="Reading exact Exchange mailbox, scope and SMTP policy...";
                var preview=await RunMailboxSmtpScopeAsync(req,null,ValidateContext);
                selection.RequireUnchanged(await ReadAsync());
                if (!preview.ChangesNeeded)
                {
                    MessageBox.Show(dialog,"Existing SMTP RBAC already authorizes this mailbox." +
                        Environment.NewLine+"Effective SMTP AUTH: "+preview.EffectivePolicy+
                        Environment.NewLine+"Other application grants may exist. Live SMTP is not tested.",
                        "Exchange SMTP RBAC review",MessageBoxButtons.OK,MessageBoxIcon.Information);
                    Render(selection); return;
                }
                if (!ConfirmDestructive("LinuxMailRelay365 | Scoped Exchange SMTP authorization",
                    preview.Describe(req),MultiMailboxSmtpScopeRequest.Confirmation,dialog))
                { Render(selection); return; }
                ValidateContext();
                selection.RequireUnchanged(await ReadAsync());
                if (await ReadScopeEnterpriseAsync(selection.Row,bootstrap,dialog,ValidateContext) != enterprise)
                    throw new InvalidDataException("Enterprise application changed.");
                selection.RequireUnchanged(await ReadAsync());
                ValidateContext();
                ResetMultiMailboxRouteReview();
                observations.Clear(); smtpAuthSamples.Clear();
                attempted=true;
                heading.Text="Applying reviewed Exchange mailbox scope...";
                _=await RunMailboxSmtpScopeAsync(req,preview,ValidateContext);
                var latest=await ReadAsync();
                selection.RequireUnchanged(latest);
                ValidateContext();
                inventory=latest;
                Render(selection);
                WriteLine("Scoped Exchange SMTP RBAC postcheck passed. No organization policy, Entra API grant, Postfix or mail changes.");
                MessageBox.Show(dialog,"Exchange RBAC configuration verified for selected mailbox."+
                    Environment.NewLine+"Effective SMTP AUTH: "+(preview.EnableMailboxSmtp ? "enabled" : preview.EffectivePolicy)+
                    Environment.NewLine+"Run separate live SMTP AUTH verification. Existing app grants remain cumulative.",
                    "Exchange scope configured",MessageBoxButtons.OK,MessageBoxIcon.Information);
            }
            catch (Exception)
            {
                if (attempted) saveUncertain=true;
                Invalidate(attempted ? "Exchange Apply outcome requires review; editing locked." :
                    "Exchange preview refused or stale. No Apply requested.");
                if (attempted) details.Text="Do not retry blindly. Inspect Exchange principal, scope, assignment and mailbox policy.";
                WriteLine(attempted ? "Scoped Exchange operation outcome requires independent review." :
                    "Scoped Exchange preview unavailable. Check Graph certificate and Exchange scope prerequisites.");
            }
            finally
            {
                reading=false;
                refresh.Enabled=close.Enabled=tabs.Enabled=true;
                Detail();
            }
        };
        testSmtpAuth.Click += async (_, _) =>
        {
            if (!testSmtpAuth.Enabled) return;
            var selection=MultiMailboxCloudSelection.Capture(inventory,SelectedScope(),Selected());
            if (selection is null) return;
            var req=new MultiMailboxSmtpAuthRequest(selection,Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant());
            if (!req.Valid) return;
            if (MessageBox.Show(dialog,
                "Test only this mailbox from the connected Linux host as m365mailer?" +
                Environment.NewLine+"Mailbox: "+selection.Row.Mailbox+
                Environment.NewLine+"Tenant: "+selection.Row.Tenant+
                Environment.NewLine+"Application: "+selection.Row.Client+
                Environment.NewLine+"Map: "+selection.Scope+
                Environment.NewLine+"Connect to login.microsoftonline.com:443 and smtp.office365.com:587; validate TLS and XOAUTH2. "+
                "No MAIL FROM, RCPT TO or DATA. No configuration change or mail delivery. This may appear in Microsoft sign-in logs.",
                "Microsoft 365 | Live SMTP AUTH only",MessageBoxButtons.OKCancel,MessageBoxIcon.Information,
                MessageBoxDefaultButton.Button2)!=DialogResult.OK) return;
            smtpAuthSamples.Remove(selection);
            reading=true; refresh.Enabled=close.Enabled=tabs.Enabled=verify.Enabled=false;
            EditingActions();
            try
            {
                void ValidateContext()
                {
                    RequireSameArchiveConnection(endpoint);
                    if (!HasMailDiscovery() || context!=CurrentMultiMailboxContext() ||
                        !selection.Matches(inventory,SelectedScope(),Selected()))
                        throw new InvalidOperationException("Mailbox or Linux context changed.");
                }
                ValidateContext();
                selection.RequireUnchanged(await ReadAsync());
                ValidateContext();
                heading.Text="Checking local signer, Entra token and live STARTTLS / XOAUTH2...";
                var reply=await SshRemote.RunRootScriptAsync(endpoint,EmbeddedAssets.BuildMultiMailboxSmtpAuthBundle(req.Serialize()),
                    TimeSpan.FromMinutes(5));
                ValidateContext();
                if (reply.ExitCode!=0) throw new IOException("Selected mailbox authentication probe refused or stale.");
                var receipt=MultiMailboxSmtpAuthReceipt.Parse(reply.StdOut,req);
                var latest=await ReadAsync();
                selection.RequireUnchanged(latest);
                ValidateContext();
                inventory=latest;
                smtpAuthSamples[selection]=(receipt,DateTimeOffset.UtcNow);
                Render(selection);
                WriteLine("Selected mailbox SMTP AUTH-only: "+receipt.Status+". No message submitted or route changed.");
                MessageBox.Show(dialog,receipt.Describe()+Environment.NewLine+
                    "No message sent. Local Postfix ingress, From Guard, queue and delivery are NOT verified.",
                    "Microsoft 365 SMTP AUTH only",MessageBoxButtons.OK,
                    receipt.Authenticated?MessageBoxIcon.Information:MessageBoxIcon.Warning);
            }
            catch (Exception)
            {
                Invalidate("Selected mailbox authentication result unavailable or stale.");
                WriteLine("SMTP AUTH-only probe did not return a verified result. No mail or configuration change requested.");
            }
            finally
            {
                reading=false; refresh.Enabled=close.Enabled=tabs.Enabled=true; Detail();
            }
        };
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
            EditingActions();
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
            EditingActions();
            observations.Clear(); smtpAuthSamples.Clear();
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
