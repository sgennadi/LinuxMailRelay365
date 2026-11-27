using System.Drawing;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class PostfixLocalDeliveryDialog : Form
{
    internal string SessionRecipient { get; private set; } = "";
    internal string SessionRunId { get; private set; } = "";
    internal PostfixLocalDeliveryDialog(Func<string, string, string?, Task<string>> remote, string? primaryBackupSha = null)
    {
        if(primaryBackupSha is not null && !PrimaryMailboxOfflineClient.IsSha(primaryBackupSha))
            throw new ArgumentException("Exact primary migration backup SHA required.");
        Text = primaryBackupSha is null ? "Primary Postfix | Local UNIX mailbox test" :
            "Primary XOAUTH2 migration | Local UNIX mailbox test";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(730, 520);
        MinimumSize = new Size(460, 350);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12),
            ColumnCount = 1, RowCount = 8, AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 6; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var intro = new Label { AutoSize = true, MaximumSize = new Size(650, 0),
            Text = "Send one explicitly approved local test to a non-privileged UNIX user at the exact Postfix hostname. " +
                "Standard aliases and .forward paths are checked for this recipient. Existing forwarding or custom maps, transports and rewriting are refused. Do not change mail settings just to pass this test. " +
                "Trace observes only the delivery agent. A separate approved mailbox check searches bounded local headers for this test only." };
        if(primaryBackupSha is not null)
            intro.Text="Applied migration SHA: "+primaryBackupSha+Environment.NewLine+
                "Local delivery is reviewed independently of Microsoft 365 authentication. "+intro.Text;
        var recipient = new TextBox { Dock = DockStyle.Top, MaxLength = 254, PlaceholderText = "testuser@mail.example.org" };
        var run = new TextBox { Dock = DockStyle.Top, MaxLength = 32, Text = Guid.NewGuid().ToString("N") };
        var status = new Label { AutoSize = true, Text = "Enter a designated local mailbox." };
        var report = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both,
            WordWrap = false, MinimumSize = new Size(0, 120) };
        var discover = new Button { Text = "Find local accounts", AutoSize = true };
        var diagnose = new Button { Text = "Inspect mailbox / forwarding", AutoSize = true };
        var preview = new Button { Text = "Review local route", AutoSize = true };
        var submit = new Button { Text = "Send one local test", AutoSize = true };
        var trace = new Button { Text = "Refresh local trace", AutoSize = true };
        var mailbox = new Button { Text = "Verify test in mailbox", AutoSize = true };
        var copy = new Button { Text = "Copy Run ID", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true };
        actions.Controls.AddRange([discover, diagnose, preview, submit, trace, mailbox, copy, close]);
        bool busy = false;
        string? approvedSha = null, approvedRequest = null;
        var attempted = new HashSet<string>(StringComparer.Ordinal);
        bool Valid() => Regex.IsMatch(run.Text.Trim(), @"\A[a-f0-9]{32}\z") &&
            Regex.IsMatch(recipient.Text.Trim(), @"\A[a-z_][a-z0-9_-]{0,31}@[a-z0-9.-]+\z");
        string Request()
        {
            var fields=new SortedDictionary<string,string>(StringComparer.Ordinal)
            {
                ["recipient"]=recipient.Text.Trim(),["run_id"]=run.Text.Trim()
            };
            if(primaryBackupSha is not null) fields["backup_sha256"]=primaryBackupSha;
            return JsonSerializer.Serialize(fields,new JsonSerializerOptions {Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping});
        }
        string DiscoveryRequest()=>primaryBackupSha is null ? "{\"discover_local_accounts\":true}" :
            JsonSerializer.Serialize(new {backup_sha256=primaryBackupSha,discover_local_accounts=true});
        void InvalidateReview() { approvedSha = approvedRequest = null; }
        void UpdateControls()
        {
            recipient.Enabled = run.Enabled = close.Enabled = discover.Enabled = !busy;
            diagnose.Enabled = !busy && Valid();
            preview.Enabled = !busy && Valid() && !attempted.Contains(run.Text.Trim());
            submit.Enabled = preview.Enabled && approvedSha is not null && approvedRequest == Request();
            trace.Enabled = mailbox.Enabled = !busy && Valid();
            copy.Enabled = !busy && Regex.IsMatch(run.Text.Trim(), @"\A[a-f0-9]{32}\z");
        }
        async Task RunAsync(string message, Func<Task> action)
        {
            if (busy) return;
            busy = true; UpdateControls();
            status.ForeColor = SystemColors.ControlText;
            status.Text = message;
            try { await action(); }
            catch (Exception ex)
            {
                InvalidateReview();
                status.ForeColor = Color.DarkOrange;
                status.Text = "Refused or uncertain: " + ex.GetType().Name +
                    ". Do not change existing routing to pass this test or resend an uncertain Run ID.";
            }
            finally { busy = false; UpdateControls(); }
        }
        static string StringField(JsonElement root, string key) => root.GetProperty(key).GetString() ??
            throw new InvalidDataException("Missing local probe field.");
        static void FalseFlag(JsonElement root, string key)
        {
            if (root.GetProperty(key).ValueKind != JsonValueKind.False) throw new InvalidDataException("Unexpected claim.");
        }
        void MatchRun(JsonElement root, string expected)
        {
            if (StringField(root,"status") != expected || StringField(root,"run_id") != run.Text.Trim())
                throw new InvalidDataException("Local probe context mismatch.");
            FalseFlag(root,"mailbox_verified");
        }
        discover.Click += async (_, _) =>
        {
            if (!discover.Enabled || MessageBox.Show(this,
                "List up to 200 candidate local UNIX account names on this connected Linux server? " +
                "Confirm you are authorized to view this account inventory. No mailbox contents, passwords, home paths or forwarding targets are returned.",
                "Confirm local account discovery", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            InvalidateReview();
            await RunAsync("Discovering local account candidates...", async () =>
            {
                using var doc = JsonDocument.Parse(await remote("local-discover", DiscoveryRequest(), null));
                var root = doc.RootElement;
                if (StringField(root,"status") != "local_account_candidates") throw new InvalidDataException();
                foreach (string flag in new[] { "mailboxes_verified", "mail_sent", "postfix_modified", "content_exported" })
                    FalseFlag(root,flag);
                string host = StringField(root,"hostname");
                if (host.Length > 253 || Uri.CheckHostName(host) != UriHostNameType.Dns ||
                    !Regex.IsMatch(host, @"\A[a-z0-9.-]+\z") || !host.Contains('.'))
                    throw new InvalidDataException("Invalid local hostname.");
                var rows = root.GetProperty("recipients").EnumerateArray().Select(x => x.GetString() ?? "").ToArray();
                bool truncated = root.GetProperty("truncated").GetBoolean();
                if (rows.Length > 200 || (truncated && rows.Length != 200) ||
                    rows.Distinct(StringComparer.Ordinal).Count() != rows.Length ||
                    rows.Any(x => x.Length > 254 || !Regex.IsMatch(x, @"\A[a-z_][a-z0-9_-]{0,31}@" + Regex.Escape(host) + @"\z")))
                    throw new InvalidDataException("Invalid candidate list.");
                report.Text = "Local hostname: " + host + Environment.NewLine +
                    "Account candidates: " + rows.Length + (truncated ? " (limited; manual entry available)" : "") +
                    Environment.NewLine + "These are names only. Mailbox existence and routing are not verified.";
                status.Text = rows.Length == 0 ? "No supported candidate accounts; manual entry remains available." :
                    "Select a designated account, then inspect its mailbox and forwarding.";
                if (rows.Length == 0) return;
                using var picker = new Form { Text = "Choose designated test account", StartPosition = FormStartPosition.CenterParent,
                    AutoScaleMode = AutoScaleMode.Dpi, ClientSize = new Size(500,420), MinimumSize = new Size(320,250) };
                var panel = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(10), ColumnCount = 1, RowCount = 3 };
                panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
                panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                panel.RowStyles.Add(new RowStyle(SizeType.Percent,100));
                panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                var filter = new TextBox { Dock = DockStyle.Top, PlaceholderText = "Filter accounts" };
                var list = new ListBox { Dock = DockStyle.Fill, HorizontalScrollbar = true };
                var choose = new Button { Text = "Use selected account", AutoSize = true, Enabled = false };
                var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
                var footer = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
                footer.Controls.AddRange([choose,cancel]);
                void Filter()
                {
                    list.Items.Clear();
                    list.Items.AddRange(rows.Where(x => x.Contains(filter.Text.Trim(),StringComparison.OrdinalIgnoreCase)).Cast<object>().ToArray());
                    choose.Enabled = false;
                }
                filter.TextChanged += (_,_) => Filter();
                list.SelectedIndexChanged += (_,_) => choose.Enabled = list.SelectedItem is string;
                choose.Click += (_,_) => { if (list.SelectedItem is string) picker.DialogResult = DialogResult.OK; };
                panel.Controls.Add(filter,0,0);
                panel.Controls.Add(list,0,1);
                panel.Controls.Add(footer,0,2);
                picker.Controls.Add(panel);
                picker.CancelButton = cancel;
                Filter();
                if (picker.ShowDialog(this) == DialogResult.OK && list.SelectedItem is string selected)
                    recipient.Text = selected;
            });
        };
        diagnose.Click += async (_, _) =>
        {
            if (!diagnose.Enabled || MessageBox.Show(this,
                "Inspect the selected account's configured local route, presence of alias/forwarding entries and mailbox storage metadata? " +
                "Confirm authorization for " + recipient.Text.Trim() + ". No forwarding targets or message contents will be shown.",
                "Confirm local route inspection", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            InvalidateReview();
            await RunAsync("Inspecting selected local route and storage...", async () =>
            {
                using var doc = JsonDocument.Parse(await remote("local-diagnose",Request(),null));
                var root = doc.RootElement;
                if (StringField(root,"status") != "local_route_observation" ||
                    StringField(root,"run_id") != run.Text.Trim() || StringField(root,"recipient") != recipient.Text.Trim())
                    throw new InvalidDataException("Diagnostic identity mismatch.");
                foreach (string flag in new[] { "mail_sent","postfix_modified","content_exported","submission_approved" })
                    FalseFlag(root,flag);
                string policy = StringField(root,"policy"), alias = StringField(root,"alias"),
                    forward = StringField(root,"forward"), storage = StringField(root,"storage");
                string? kind = root.GetProperty("mailbox_kind").GetString();
                bool standard = policy == "standard_policy_observed";
                if (policy is not ("standard_policy_observed" or "manual_review_required" or "unverified") ||
                    alias is not ("not_configured" or "recipient_not_found" or "alias_entry_observed" or "unverified") ||
                    forward is not ("not_configured" or "no_forward_file_observed" or "forward_entry_observed" or "unverified") ||
                    (standard ? kind is not ("maildir" or "system_spool") || storage is not ("storage_observed" or "not_present" or "unverified") :
                        kind is not null || storage != "not_inspected" || alias != "unverified" || forward != "unverified"))
                    throw new InvalidDataException("Inconsistent route observation.");
                bool clear = standard && (alias is "not_configured" or "recipient_not_found") &&
                    (forward is "not_configured" or "no_forward_file_observed");
                report.Text = "Recipient: " + recipient.Text.Trim() + Environment.NewLine +
                    "Policy: " + policy + Environment.NewLine + "Alias lookup: " + alias + Environment.NewLine +
                    ".forward entry: " + forward + Environment.NewLine + "Mailbox kind: " + (kind ?? "unknown") +
                    Environment.NewLine + "Storage metadata: " + storage + Environment.NewLine +
                    "An absent mailbox may be created on first delivery. An alias or forwarding entry is not proof of where it delivers." +
                    Environment.NewLine + "Diagnostic only; no approval. Use Review local route before any test submission.";
                status.Text = clear ? "No supported forwarding entry observed. Separate route review required." :
                    "Forwarding, unsupported policy or uncertain state requires review.";
                status.ForeColor = clear ? SystemColors.ControlText : Color.DarkOrange;
            });
        };
        preview.Click += async (_, _) =>
        {
            if (!preview.Enabled) return;
            InvalidateReview();
            await RunAsync("Checking exact local UNIX recipient and delivery policy...", async () =>
            {
                string request = Request();
                using var doc = JsonDocument.Parse(await remote("local-preview", request, null));
                var root = doc.RootElement;
                MatchRun(root,"local_review_ready");
                FalseFlag(root,"mail_sent");
                string sha = StringField(root,"plan_sha256");
                string kind = StringField(root,"mailbox_kind");
                string alias = StringField(root,"alias_status");
                string forward = StringField(root,"forward_status");
                if (!Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z") || StringField(root,"recipient") != recipient.Text.Trim() ||
                    kind is not ("maildir" or "system_spool") ||
                    alias is not ("not_configured" or "recipient_not_found") ||
                    forward is not ("not_configured" or "no_forward_file_observed")) throw new InvalidDataException();
                approvedSha = sha; approvedRequest = request;
                report.Text = "Recipient: " + recipient.Text.Trim() + Environment.NewLine +
                    "Mailbox kind: " + kind + Environment.NewLine +
                    "Alias lookup: " + alias + Environment.NewLine + ".forward: " + forward +
                    Environment.NewLine + "Review SHA-256: " + sha +
                    (primaryBackupSha is null?"":Environment.NewLine+"Applied migration SHA: "+primaryBackupSha)+
                    Environment.NewLine + "No mail sent. This is a point-in-time check, not a guarantee of queued delivery routing.";
                status.Text = "Local route reviewed.";
            });
        };
        submit.Click += async (_, _) =>
        {
            if (!submit.Enabled || approvedSha is not { } sha || approvedRequest is not { } request || request != Request()) return;
            if (MessageBox.Show(this, "Submit one real local test to " + recipient.Text.Trim() +
                "? Confirm this designated mailbox is yours or you have permission to use it. " +
                "Keep configuration, alias databases, local account and its forwarding files unchanged until delivery completes, including any queued retries. " +
                "Use a dedicated test account and prevent concurrent edits. Postfix processes may retain prior configuration; this review is not an atomic delivery guarantee. " +
                "This uses a null envelope sender and is not an Exchange delivery test. " +
                "Retain Run ID " + run.Text.Trim() + "; do not resubmit an uncertain test.",
                "Confirm local delivery test", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            attempted.Add(run.Text.Trim());
            InvalidateReview();
            await RunAsync("Submitting one reviewed local message...", async () =>
            {
                using var doc = JsonDocument.Parse(await remote("local-submit", request, sha));
                var root = doc.RootElement;
                MatchRun(root,"local_submission_recorded");
                FalseFlag(root,"automatic_retry");
                string state = StringField(root,"submission");
                if (StringField(root,"plan_sha256") != sha ||
                    state is not ("local_submission_accepted" or "submission_uncertain"))
                    throw new InvalidDataException();
                report.Text = "Submission: " + state + Environment.NewLine + "Run ID: " + run.Text.Trim() +
                    Environment.NewLine + "Refresh local trace. Submission is not mailbox delivery.";
                status.Text = "Attempt recorded. No automatic retry.";
                status.ForeColor = Color.DarkOrange;
            });
        };
        trace.Click += async (_, _) =>
        {
            if (!trace.Enabled) return;
            InvalidateReview();
            await RunAsync("Reading matching local ledger, journal and queue...", async () =>
            {
                string request = Request();
                using var doc = JsonDocument.Parse(await remote("local-trace", request, null));
                var root = doc.RootElement;
                MatchRun(root,"local_trace_observed");
                FalseFlag(root,"automatic_retry");
                string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(request))).ToLowerInvariant();
                if (StringField(root,"request_sha256") != hash ||
                    StringField(root,"source") is not ("journal_recent_only" or "journal_unavailable"))
                    throw new InvalidDataException();
                var outcome = root.GetProperty("outcome");
                string submission = StringField(outcome,"submission");
                string transport = StringField(outcome,"transport");
                if (submission is not ("not_attempted" or "attempted" or "local_submission_accepted" or "submission_uncertain") ||
                    transport is not ("not_attempted" or "correlation_unavailable" or "unknown" or "local_agent_accepted" or
                        "local_destination_unverified" or "deferred" or "bounced") ||
                    (submission == "not_attempted") != (transport == "not_attempted"))
                    throw new InvalidDataException();
                bool hasId = outcome.TryGetProperty("queue_id",out var qid);
                bool hasQueue = outcome.TryGetProperty("queue",out var queue);
                bool hasDsn = outcome.TryGetProperty("dsn",out var dsn);
                if (hasId != hasQueue || hasId != (transport is not ("not_attempted" or "correlation_unavailable")) ||
                    (hasId && (!Regex.IsMatch(qid.GetString() ?? "", @"\A[A-Za-z0-9]{5,80}\z") ||
                        queue.GetString() is not ("unavailable" or "not_observed" or "active" or "deferred" or "incoming" or "hold" or "maildrop" or "other"))) ||
                    (hasDsn && (!hasId || !Regex.IsMatch(dsn.GetString() ?? "", @"\A[245]\.[0-9]{1,3}\.[0-9]{1,3}\z"))) ||
                    (transport == "local_agent_accepted" && (!hasDsn || !dsn.GetString()!.StartsWith("2.",StringComparison.Ordinal))))
                    throw new InvalidDataException("Invalid local transport evidence.");
                attempted.Add(run.Text.Trim());
                report.Text = "Run ID: " + run.Text.Trim() + Environment.NewLine +
                    "Submission: " + submission + Environment.NewLine + "Local transport: " + transport +
                    Environment.NewLine + "Journal: " + StringField(root,"source") +
                    (hasId ? Environment.NewLine + "Queue ID: " + qid.GetString() + Environment.NewLine + "Queue: " + queue.GetString() : "") +
                    (hasDsn ? Environment.NewLine + "DSN: " + dsn.GetString() : "") +
                    Environment.NewLine + "Mailbox contents and arrival are not verified. No mail sent by trace.";
                status.Text = transport == "local_agent_accepted" ? "Local delivery agent accepted the message." : "Local delivery not confirmed.";
                status.ForeColor = transport == "local_agent_accepted" ? Color.SeaGreen : Color.DarkOrange;
            });
        };
        mailbox.Click += async (_, _) =>
        {
            if (!mailbox.Enabled) return;
            if (MessageBox.Show(this, "Search the designated mailbox for only the recorded test Message-ID and fixed test headers? " +
                "Confirm you are authorized to inspect this mailbox. The Linux helper drops root privileges and reads at most a bounded portion of the mailbox. " +
                "No message headers or bodies are returned. A missing result does not prove non-delivery.",
                "Confirm test mailbox observation", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            InvalidateReview();
            await RunAsync("Checking reviewed mailbox for this test message...", async () =>
            {
                string request = Request();
                using var doc = JsonDocument.Parse(await remote("local-mailbox", request, null));
                var root = doc.RootElement;
                string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(request))).ToLowerInvariant();
                string[] expectedFields = ["status", "run_id", "request_sha256", "mailbox_kind", "observation",
                    "mailbox_verified", "mail_sent", "mailbox_modified", "content_exported", "automatic_retry"];
                var names = root.EnumerateObject().Select(p => p.Name).ToArray();
                if (names.Length != expectedFields.Length || names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
                    names.Except(expectedFields, StringComparer.Ordinal).Any() ||
                    StringField(root,"status") != "local_mailbox_observation" ||
                    StringField(root,"run_id") != run.Text.Trim() || StringField(root,"request_sha256") != hash)
                    throw new InvalidDataException("Mailbox observation context mismatch.");
                foreach (string flag in new[] { "mail_sent", "mailbox_modified", "content_exported", "automatic_retry" })
                    FalseFlag(root,flag);
                string observation = StringField(root,"observation");
                string? kind = root.GetProperty("mailbox_kind").GetString();
                bool found = root.GetProperty("mailbox_verified").GetBoolean();
                if (observation is not ("message_observed" or "not_observed" or "scan_incomplete" or
                    "mailbox_not_present" or "review_context_changed" or "not_attempted") ||
                    found != (observation == "message_observed") ||
                    (observation is "review_context_changed" or "not_attempted" ? kind is not null :
                        kind is not ("maildir" or "system_spool")))
                    throw new InvalidDataException("Inconsistent mailbox observation.");
                attempted.Add(run.Text.Trim());
                report.Text = "Run ID: " + run.Text.Trim() + Environment.NewLine +
                    "Mailbox: " + (kind ?? "not inspected") + Environment.NewLine +
                    "Observation: " + observation + Environment.NewLine +
                    "Only exact test headers are matched. No message contents exported, no messages submitted or modified." +
                    Environment.NewLine + "Absence or an incomplete scan is not a delivery failure; check local trace separately.";
                status.Text = found ? "Matching test message observed in the designated mailbox." :
                    "Test message presence not confirmed.";
                status.ForeColor = found ? Color.SeaGreen : Color.DarkOrange;
            });
        };
        foreach (var field in new[] { recipient, run })
            field.TextChanged += (_, _) => { InvalidateReview(); UpdateControls(); };
        copy.Click += (_, _) => Clipboard.SetText(run.Text.Trim());
        FormClosing += (_, e) =>
        {
            if (busy) { e.Cancel = true; return; }
            SessionRecipient = recipient.Text.Trim();
            SessionRunId = run.Text.Trim();
        };
        layout.Controls.Add(intro,0,0);
        layout.Controls.Add(new Label { Text = "Exact local UNIX user @ Postfix hostname", AutoSize = true },0,1);
        layout.Controls.Add(recipient,0,2);
        layout.Controls.Add(new Label { Text = "Run ID (retain for trace)", AutoSize = true },0,3);
        layout.Controls.Add(run,0,4);
        layout.Controls.Add(status,0,5);
        layout.Controls.Add(report,0,6);
        layout.Controls.Add(actions,0,7);
        Controls.Add(layout);
        CancelButton = close;
        UpdateControls();
    }
}
