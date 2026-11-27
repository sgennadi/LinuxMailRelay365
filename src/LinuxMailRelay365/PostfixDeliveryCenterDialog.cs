using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class PostfixDeliveryCenterDialog : Form
{
    internal string SessionRecipient { get; private set; } = "";
    internal string SessionRunId { get; private set; } = "";

    internal PostfixDeliveryCenterDialog(Func<string,string,string?,Task<string>> remote,
        Func<string,string,Task<string>> exchangeTrace, string relayRequest, string localRecipient, string localRun)
    {
        using var input = PostfixDeliveryCenterEvidence.Parse(relayRequest);
        var req = input.RootElement;
        PostfixDeliveryCenterEvidence.Exact(req,"accepted_domain","external","internal","mx","run_id","sender");
        string domain = PostfixDeliveryCenterEvidence.Field(req,"accepted_domain");
        string mx = PostfixDeliveryCenterEvidence.Field(req,"mx");
        string relayRun = PostfixDeliveryCenterEvidence.Field(req,"run_id");
        string sender = PostfixDeliveryCenterEvidence.Field(req,"sender");
        string internalAddress = PostfixDeliveryCenterEvidence.Field(req,"internal");
        string externalAddress = PostfixDeliveryCenterEvidence.Field(req,"external");
        Text = "Primary Postfix | Delivery diagnostics center";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(900,650);
        MinimumSize = new Size(470,370);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 1, RowCount = 7 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        for (int i=0;i<4;i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var intro = new Label { AutoSize = true, Text =
            "Read-only observations for independently recorded local and relay runs. No send, retry, flush, or configuration change." };
        var context = new TextBox { Dock = DockStyle.Top, Multiline = true, ReadOnly = true, Height = 82,
            WordWrap = false, ScrollBars = ScrollBars.Both, Text =
            "Relay Run ID: " + relayRun + Environment.NewLine + "Sender: " + sender +
            Environment.NewLine + "Internal: " + internalAddress + " | External: " + externalAddress +
            Environment.NewLine + "Domain: " + domain + " | MX: " + mx };
        var recipient = new TextBox { Dock = DockStyle.Fill, Text = localRecipient, MaxLength = 254, PlaceholderText = "testuser@mail.example.org" };
        var run = new TextBox { Dock = DockStyle.Fill, Text = localRun, MaxLength = 32, PlaceholderText = "Recorded local Run ID" };
        var localInputs = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 2, RowCount = 2 };
        localInputs.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        localInputs.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        localInputs.Controls.Add(new Label { Text = "Local recipient", AutoSize = true, Anchor = AnchorStyles.Left },0,0);
        localInputs.Controls.Add(recipient,1,0);
        localInputs.Controls.Add(new Label { Text = "Local Run ID", AutoSize = true, Anchor = AnchorStyles.Left },0,1);
        localInputs.Controls.Add(run,1,1);
        var status = new Label { AutoSize = true, Text = "Select a read-only check. Previous runs must already have a local ledger." };
        var grid = new DataGridView { Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false,
            AllowUserToDeleteRows = false, AllowUserToOrderColumns = false, AllowUserToResizeRows = true,
            RowHeadersVisible = false, AutoGenerateColumns = false, AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false, BackgroundColor = SystemColors.Window, BorderStyle = BorderStyle.FixedSingle };
        grid.DefaultCellStyle.WrapMode = DataGridViewTriState.True;
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Evidence", FillWeight = 24, SortMode = DataGridViewColumnSortMode.NotSortable });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "State", FillWeight = 25, SortMode = DataGridViewColumnSortMode.NotSortable });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Sample (UTC) / details", FillWeight = 51, SortMode = DataGridViewColumnSortMode.NotSortable });
        string[] names = ["Local delivery agent","Local mailbox","M365 internal SMTP","M365 external SMTP",
            "Exchange internal trace","Exchange external trace","Primary Postfix queue"];
        const int localAgent=0, localBox=1, internalSmtp=2, externalSmtp=3, internalCloud=4, externalCloud=5, primaryQueue=6;
        foreach (string name in names) grid.Rows.Add(name,"Not checked","");
        var local = new Button { Text = "Local trace", AutoSize = true };
        var mailbox = new Button { Text = "Verify local mailbox", AutoSize = true };
        var relay = new Button { Text = "Internal / external trace", AutoSize = true };
        var cloud = new Button { Text = "Exchange Message Trace", AutoSize = true };
        var queue = new Button { Text = "Postfix queue", AutoSize = true };
        var all = new Button { Text = "Refresh Linux traces / queue", AutoSize = true };
        var copy = new Button { Text = "Copy diagnostic report", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        actions.Controls.AddRange([local,mailbox,relay,cloud,queue,all,copy,close]);
        var note = new Label { AutoSize = true, Text =
            "Green = the named evidence level observed (not overall delivery). Amber = pending, failure, unavailable or review. " +
            "Exchange Delivered is not inbox confirmation. Local and relay runs are independent." };
        bool busy = false;
        bool ValidLocal() => Regex.IsMatch(run.Text.Trim(),@"\A[a-f0-9]{32}\z") &&
            Regex.IsMatch(recipient.Text.Trim(),@"\A[a-z_][a-z0-9_-]{0,31}@[a-z0-9.-]+\z") &&
            recipient.Text.Trim().Length <= 254;
        bool ValidRelay() => Regex.IsMatch(relayRun,@"\A[a-f0-9]{32}\z") &&
            new[] {sender,internalAddress,externalAddress}.All(s => s.Length is > 0 and <= 254 && s.Contains('@'));
        bool ValidAudit() => Uri.CheckHostName(domain) == UriHostNameType.Dns &&
            (mx.Length == 0 || mx.EndsWith(".mail.protection.outlook.com",StringComparison.Ordinal));
        string LocalRequest() => JsonSerializer.Serialize(new { recipient = recipient.Text.Trim(), run_id = run.Text.Trim() });
        void UpdateControls()
        {
            recipient.Enabled = run.Enabled = close.Enabled = copy.Enabled = !busy;
            local.Enabled = mailbox.Enabled = !busy && ValidLocal();
            relay.Enabled = cloud.Enabled = !busy && ValidRelay();
            queue.Enabled = !busy && ValidAudit();
            all.Enabled = !busy && (ValidLocal() || ValidRelay() || ValidAudit());
        }
        void Reset(int index)
        {
            var row = grid.Rows[index];
            row.Cells[1].Value = "Not checked";
            row.Cells[2].Value = "";
            row.Cells[1].Style.ForeColor = SystemColors.ControlText;
        }
        void Set(int index, PostfixDeliveryCenterEvidence.Observation value)
        {
            var row = grid.Rows[index];
            row.Cells[1].Value = value.State.Replace('_',' ');
            row.Cells[2].Value = DateTimeOffset.UtcNow.ToString("u") + Environment.NewLine + value.Detail;
            row.Cells[1].Style.ForeColor = value.Positive ? Color.SeaGreen : Color.DarkOrange;
        }
        void Failed(int index) => Set(index,new("unavailable","Check the original run, Linux connection, configuration or tenant permissions. No retry or send."));
        async Task DoLocal()
        {
            try { string request = LocalRequest(); Set(localAgent,PostfixDeliveryCenterEvidence.LocalTrace(await remote("local-trace",request,null),request)); }
            catch (Exception) { Failed(localAgent); }
        }
        async Task DoMailbox()
        {
            try { string request = LocalRequest(); Set(localBox,PostfixDeliveryCenterEvidence.Mailbox(await remote("local-mailbox",request,null),request)); }
            catch (Exception) { Failed(localBox); }
        }
        async Task DoRelay(bool includeExchange)
        {
            string proof;
            (PostfixDeliveryCenterEvidence.Observation Internal,PostfixDeliveryCenterEvidence.Observation External) states;
            try
            {
                proof = await remote("trace",relayRequest,null);
                states = PostfixDeliveryCenterEvidence.RelayTrace(proof,relayRequest);
                Set(internalSmtp,states.Internal);
                Set(externalSmtp,states.External);
            }
            catch (Exception)
            {
                Failed(internalSmtp); Failed(externalSmtp);
                if (includeExchange) { Failed(internalCloud); Failed(externalCloud); }
                return;
            }
            if (!includeExchange) return;
            try
            {
                status.Text = "Querying the selected Exchange tenant; sign in if prompted...";
                var result = PostfixDeliveryCenterEvidence.Exchange(await exchangeTrace(relayRequest,proof),
                    relayRequest,states.Internal,states.External);
                Set(internalCloud,result.Internal);
                Set(externalCloud,result.External);
            }
            catch (Exception) { Failed(internalCloud); Failed(externalCloud); }
        }
        async Task DoQueue()
        {
            try
            {
                string request = JsonSerializer.Serialize(new { accepted_domain = domain,mx });
                Set(primaryQueue,PostfixDeliveryCenterEvidence.Queue(await remote("audit",request,null),domain,mx));
            }
            catch (Exception) { Failed(primaryQueue); }
        }
        async Task RunAsync(string message,Func<Task> action)
        {
            if (busy) return;
            busy = true;
            UpdateControls();
            status.Text = message;
            try { await action(); }
            finally
            {
                busy = false;
                status.Text = "Samples complete. Each row retains its own observation time; review unavailable rows independently.";
                UpdateControls();
            }
        }
        local.Click += async (_,_) => { if (local.Enabled) await RunAsync("Reading local ledger and trace...",DoLocal); };
        relay.Click += async (_,_) => { if (relay.Enabled) await RunAsync("Reading internal and external Linux trace...",() => DoRelay(false)); };
        cloud.Click += async (_,_) => { if (cloud.Enabled) await RunAsync("Verifying recorded relay run before Exchange trace...",() => DoRelay(true)); };
        queue.Click += async (_,_) => { if (queue.Enabled) await RunAsync("Sampling primary Postfix queue...",DoQueue); };
        mailbox.Click += async (_,_) =>
        {
            if (!mailbox.Enabled || MessageBox.Show(this,
                "Confirm authorization to search the recorded test headers in " + recipient.Text.Trim() +
                ". No message content is exported. A missing or incomplete observation is not a delivery failure.",
                "Confirm test mailbox observation",MessageBoxButtons.YesNo,MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            await RunAsync("Checking the recorded local test in its mailbox...",DoMailbox);
        };
        all.Click += async (_,_) =>
        {
            if (!all.Enabled) return;
            await RunAsync("Refreshing Linux observations independently...",async () =>
            {
                if (ValidLocal()) { status.Text = "Reading local trace..."; await DoLocal(); }
                if (ValidRelay()) { status.Text = "Reading relay trace..."; await DoRelay(false); }
                if (ValidAudit()) { status.Text = "Sampling primary queue..."; await DoQueue(); }
                // Never auto-read mailbox contents or launch a cloud sign-in.
            });
        };
        foreach (var field in new[] {recipient,run})
            field.TextChanged += (_,_) => { Reset(localAgent); Reset(localBox); UpdateControls(); };
        copy.Click += (_,_) =>
        {
            if (busy) return;
            var lines = new List<string> { "LinuxMailRelay365 delivery diagnostic report (read-only)",
                context.Text, "Local recipient: " + recipient.Text.Trim(), "Local Run ID: " + run.Text.Trim(),"",
                "Independent point-in-time evidence; no aggregate delivery guarantee." };
            foreach (DataGridViewRow row in grid.Rows)
            {
                lines.Add(""); lines.Add(row.Cells[0].Value + " | " + row.Cells[1].Value);
                lines.Add(row.Cells[2].Value?.ToString() ?? "");
            }
            lines.Add(""); lines.Add(note.Text);
            try { Clipboard.SetText(string.Join(Environment.NewLine,lines)); }
            catch (System.Runtime.InteropServices.ExternalException) { status.Text = "Clipboard unavailable; try copying again."; }
        };
        FormClosing += (_,e) =>
        {
            if (busy) { e.Cancel = true; return; }
            SessionRecipient = recipient.Text.Trim(); SessionRunId = run.Text.Trim();
        };
        layout.Controls.Add(intro,0,0);
        layout.Controls.Add(context,0,1);
        layout.Controls.Add(localInputs,0,2);
        layout.Controls.Add(status,0,3);
        layout.Controls.Add(grid,0,4);
        layout.Controls.Add(note,0,5);
        layout.Controls.Add(actions,0,6);
        Controls.Add(layout);
        CancelButton = close;
        UpdateControls();
    }
}
