using System.Drawing;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private Task OpenPrimaryEopOfflineAsync(Form owner, string context, string selectedMx)
    {
        string domain = acceptedDomain.Text.Trim().ToLowerInvariant();
        string mx = selectedMx.Trim().ToLowerInvariant();
        string ip = outboundPublicIp.Text.Trim();
        string name = outboundConnectorName.Text.Trim();
        var endpoint = Endpoint();
        void Guard()
        {
            if (owner.IsDisposed || TryCurrentIdentity() != context || mailTransport.SelectedIndex != 1 ||
                acceptedDomain.Text.Trim().ToLowerInvariant() != domain ||
                outboundPublicIp.Text.Trim() != ip || outboundConnectorName.Text.Trim() != name)
                throw new InvalidOperationException("Host or route context changed. Reopen the wizard.");
        }
        Guard();
        using var dialog = new Form
        {
            Text = "Experimental | Primary Postfix offline relayhost",
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(Screen.FromControl(owner).WorkingArea.Size, DeviceDpi, 860, 650),
            MinimumSize = PreferredDialogSize(Screen.FromControl(owner).WorkingArea.Size, DeviceDpi, 460, 350)
        };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 1, RowCount = 7 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 5; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var intro = new Label { AutoSize = true, Text =
            "Domain: " + domain + Environment.NewLine + "Session MX: " + (mx.Length == 0 ? "(not selected)" : mx) +
            Environment.NewLine + "Configured public IPv4: " + (ip.Length == 0 ? "(not set)" : ip) +
            Environment.NewLine + "Experimental global relayhost change. No automatic service start.", ForeColor = Color.DarkOrange };
        var maintenance = new CheckBox { AutoSize = true, Text =
            "I have stopped Postfix and prevented all submissions, service starts and configuration edits." };
        var backupLabel = new Label { AutoSize = true, Text = "Recovery / native check SHA-256 (retain this before Apply)" };
        var backup = new TextBox { Dock = DockStyle.Top, MaxLength = 64 };
        var status = new Label { AutoSize = true, Text = "No operations requested." };
        var report = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false };
        var review = new Button { AutoSize = true, Text = "Preview offline route" };
        var apply = new Button { AutoSize = true, Text = "Backup / Apply" };
        var check = new Button { AutoSize = true, Text = "Run postfix check" };
        var start = new Button { AutoSize = true, Text = "Start reviewed Postfix" };
        var restore = new Button { AutoSize = true, Text = "Restore backup" };
        var copy = new Button { AutoSize = true, Text = "Copy SHA" };
        var close = new Button { AutoSize = true, Text = "Close", DialogResult = DialogResult.Cancel };
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        actions.Controls.AddRange([review, apply, check, start, restore, copy, close]);
        bool busy = false;
        string? approvedSha = null, reviewedOld = null, checkedSha = null;
        bool startAttempted = false;
        bool ValidSha(string? sha) => Regex.IsMatch(sha ?? "", @"\A[a-f0-9]{64}\z");
        void Invalidate() { approvedSha = reviewedOld = checkedSha = null; }
        void Update()
        {
            bool available = !busy && maintenance.Checked && !startAttempted;
            review.Enabled = available && mx.EndsWith(".mail.protection.outlook.com", StringComparison.Ordinal);
            apply.Enabled = available && approvedSha is not null && backup.Text.Trim() == approvedSha &&
                acceptedDomainApproved.Checked && SmtpPublicIpConnectorDialog.IsPublicIpv4(ip);
            check.Enabled = restore.Enabled = available && ValidSha(backup.Text.Trim());
            start.Enabled = available && checkedSha is not null && backup.Text.Trim() == checkedSha &&
                acceptedDomainApproved.Checked && SmtpPublicIpConnectorDialog.IsPublicIpv4(ip) &&
                mx.EndsWith(".mail.protection.outlook.com", StringComparison.Ordinal);
            maintenance.Enabled = !busy && !startAttempted;
            backup.Enabled = close.Enabled = !busy;
            copy.Enabled = !busy && ValidSha(backup.Text.Trim());
        }
        async Task RunAsync(string message, Func<Task> work)
        {
            if (busy || !maintenance.Checked) return;
            busy = true;
            Update();
            status.Text = message;
            status.ForeColor = SystemColors.ControlText;
            try { Guard(); await work(); Guard(); }
            catch (Exception ex)
            {
                Invalidate();
                status.Text = "Refused or uncertain: " + ex.GetType().Name +
                    (startAttempted ? ". Service may be running. Inspect status and queue; do not retry or restore blindly." :
                        ". Keep Postfix stopped; inspect retained backup.");
                status.ForeColor = Color.DarkOrange;
            }
            finally { busy = false; Update(); }
        }
        static Dictionary<string, string> Fields(string output)
        {
            if (output.Length > 4096 || output.Contains('\0')) throw new InvalidDataException("Invalid operation report.");
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string line in output.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                int split = line.IndexOf('=');
                if (split < 1 || !fields.TryAdd(line[..split], line[(split + 1)..]))
                    throw new InvalidDataException("Unexpected or duplicate operation evidence.");
            }
            return fields;
        }
        const string prefix = "PRIMARY_EOP_OFFLINE_";
        async Task<Dictionary<string, string>> LinuxAsync(string action, string? sha)
        {
            Guard();
            if (!maintenance.Checked) throw new InvalidOperationException("Maintenance attestation missing.");
            bool target = action is "review" or "apply" or "start";
            string script = EmbeddedAssets.BuildPrimaryEopOffline(action, target ? mx : "", target ? domain : "", sha);
            var result = endpoint.Username == "root"
                ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script, TimeSpan.FromSeconds(270))
                : await SshRemote.RunRootScriptAsync(endpoint, script, TimeSpan.FromSeconds(270));
            Guard();
            result.EnsureSuccess();
            var fields = Fields(result.StdOut);
            if (fields.Count != (action == "review" ? 8 : 6) ||
                fields[prefix+"SERVICE_STARTED"] != (action == "start" ? "observed_running" : "no") ||
                fields[prefix+"MAIL_SENT"] != (action == "start" ? "not_verified" : "no") ||
                fields[prefix+"QUEUE_MODIFIED"] != (action is "check" or "start" ? "not_verified" : "no"))
                throw new InvalidDataException("Unexpected operation flags.");
            if (action == "review")
            {
                if (fields[prefix+"STATUS"] != "reviewed_experimental" ||
                    fields[prefix+"POSTFIX_CHANGED"] != "no" ||
                    !ValidSha(fields[prefix+"SHA256"]) || fields[prefix+"NEW_RELAYHOST"] != "["+mx+"]:25" ||
                    !Regex.IsMatch(fields[prefix+"OLD_RELAYHOST"], @"\A[a-zA-Z0-9.\[\]:-]{0,261}\z"))
                    throw new InvalidDataException("Unexpected reviewed route.");
            }
            else
            {
                string expectedStatus = action switch {
                    "apply" => "applied_offline_not_started",
                    "restore" => "restored_offline_not_started",
                    "start" => "started_running_observed",
                    _ => "checked_offline_not_started" };
                string expectedChange = action == "apply" ? "yes" : action == "restore" ? "restored" : "no";
                if (fields[prefix+"STATUS"] != expectedStatus || fields[prefix+"POSTFIX_CHANGED"] != expectedChange ||
                    fields[prefix+"BACKUP_SHA256"] != sha)
                    throw new InvalidDataException("Unexpected backup operation evidence.");
            }
            return fields;
        }
        review.Click += async (_, _) => await RunAsync("Reviewing offline configuration and public STARTTLS...", async () =>
        {
            Invalidate();
            report.Clear();
            var fields = await LinuxAsync("review", null);
            backup.Text = fields[prefix+"SHA256"];
            approvedSha = backup.Text;
            reviewedOld = fields[prefix+"OLD_RELAYHOST"];
            report.Text = "Current relayhost: " + (reviewedOld.Length == 0 ? "(empty)" : reviewedOld) +
                Environment.NewLine + "Proposed relayhost: [" + mx + "]:25" + Environment.NewLine +
                "Review / recovery SHA-256: " + approvedSha + Environment.NewLine +
                "Only the literal relayhost assignment will change. All remote delivery is affected. Local destinations and master.cf are preserved." +
                Environment.NewLine + "Keep the SHA for recovery. Connector acceptance and delivery are not verified.";
            status.Text = "Offline preview completed; separate approval required.";
        });
        apply.Click += async (_, _) =>
        {
            if (busy || !apply.Enabled || approvedSha is not { } sha || !maintenance.Checked) return;
            if (!Guid.TryParse(tenant.Text.Trim(), out Guid id) || id == Guid.Empty ||
                (discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption))
            {
                status.Text = "Select the exact tenant first."; return;
            }
            string old = reviewedOld ?? "";
            await RunAsync("Reviewing exact Exchange IP Connector before Apply...", async () =>
            {
                Guard();
                CheckCloudTenant(id);
                if (!acceptedDomainApproved.Checked || !SmtpPublicIpConnectorDialog.IsPublicIpv4(ip) ||
                    !Regex.IsMatch(name, @"\A[A-Za-z0-9][A-Za-z0-9._ -]{2,69}\z"))
                    throw new InvalidOperationException("Accepted domain, name or static IPv4 missing.");
                var options = (Tenant: id, Domain: domain, Name: name, Ip: ip, Certificate: "");
                if (!ConfirmDestructive("Apply global primary Postfix relayhost",
                    "Tenant: " + id + Environment.NewLine + "Domain: " + domain + Environment.NewLine +
                    "IPv4: " + ip + Environment.NewLine + "Current: " + old + Environment.NewLine +
                    "Proposed: [" + mx + "]:25" + Environment.NewLine + "Recovery SHA: " + sha +
                    Environment.NewLine + "Confirm exclusive maintenance, correct tenant MX, static exclusive SMTP NAT identity, and approval of ALL affected outgoing mail. Postfix remains stopped. No automatic service start.",
                    "APPLY PRIMARY POSTFIX RELAYHOST", dialog)) { status.Text = "No change approved."; return; }
                Guard();
                CheckCloudTenant(id);
                var cloud = Fields(await RunTenantConnectorManagerAsync(options, "Inspect"));
                Guard();
                CheckCloudTenant(id);
                if (cloud.Count != 9 || cloud["EXO_CONNECTOR_TENANT"] != "exact_match" ||
                    cloud["EXO_CONNECTOR_ACCEPTED_DOMAIN"] != "verified" || cloud["EXO_CONNECTOR_PUBLIC_IPV4"] != ip ||
                    cloud["EXO_CONNECTOR_BINDING"] != "exact_enabled_connector_observed" ||
                    cloud["EXO_CONNECTOR_EXACT_COUNT"] != "1" || cloud["EXO_CONNECTOR_CONFLICT_COUNT"] != "0" ||
                    !int.TryParse(cloud["EXO_CONNECTOR_NAME_TAKEN"], out int count) || count is < 0 or > 500 ||
                    cloud["EXO_CONNECTOR_DELIVERY_VERIFIED"] != "no" || cloud["CHANGES_APPLIED"] != "no" ||
                    !acceptedDomainApproved.Checked || !maintenance.Checked || approvedSha != sha)
                    throw new InvalidOperationException("Exact enabled IP Connector not observed.");
                Invalidate();
                // Keep the recovery SHA in the editable field, even on interruption.
                connectorApproved.Checked = false;
                previewedTenantConnectorSha = previewedTenantConnectorContext = null;
                await LinuxAsync("apply", sha);
                report.Text = "Applied: [" + mx + "]:25" + Environment.NewLine +
                    "Backup: /var/lib/linuxmailrelay365-primary-eop-recovery/" + sha +
                    Environment.NewLine + "Run the separately approved native postfix check before administrator-reviewed service start.";
                status.Text = "Applied offline. Postfix remains stopped.";
                status.ForeColor = Color.SeaGreen;
            });
        };
        async Task BackupAction(string action)
        {
            if (busy || !maintenance.Checked || !ValidSha(backup.Text.Trim())) return;
            string sha = backup.Text.Trim();
            string explanation = action == "check"
                ? "Run native postfix check against the exact applied snapshot. Native check may repair directory metadata or create directories; queue metadata changes are not verified."
                : "Restore the exact previous main.cf. Refuse unrelated configuration drift. The service remains stopped.";
            if (!ConfirmDestructive("Primary Postfix | " + action, explanation + Environment.NewLine +
                "Backup SHA-256: " + sha + Environment.NewLine + "Confirm exclusive maintenance.",
                action == "check" ? "CHECK PRIMARY POSTFIX" : "RESTORE PRIMARY POSTFIX", dialog)) return;
            await RunAsync("Checking retained backup and offline configuration...", async () =>
            {
                Invalidate();
                connectorApproved.Checked = false;
                previewedTenantConnectorSha = previewedTenantConnectorContext = null;
                await LinuxAsync(action, sha);
                if (action == "check") checkedSha = sha;
                report.Text = (action == "check" ? "Native postfix check completed; reviewed configuration verified afterwards." :
                    "Previous main.cf restored and native effective policy verified.") +
                    Environment.NewLine + "Recovery SHA-256: " + sha + Environment.NewLine +
                    "Postfix remains stopped. Review local delivery, queue and service state before a separate administrator start.";
                status.Text = action == "check" ? "Native check verified." : "Restore verified.";
                status.ForeColor = Color.SeaGreen;
            });
        }
        start.Click += async (_, _) =>
        {
            if (busy || !start.Enabled || checkedSha is not { } sha || !maintenance.Checked) return;
            if (!Guid.TryParse(tenant.Text.Trim(), out Guid id) || id == Guid.Empty ||
                (discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption))
            {
                status.Text = "Select the exact tenant first."; return;
            }
            if (!ConfirmDestructive("Start reviewed primary Postfix",
                "Tenant: " + id + Environment.NewLine + "Domain: " + domain +
                Environment.NewLine + "MX: " + mx + ":25" + Environment.NewLine + "Static SMTP IPv4: " + ip +
                Environment.NewLine + "Applied backup SHA-256: " + sha + Environment.NewLine +
                "Recheck Exchange Connector, native Postfix configuration, empty queue and verified STARTTLS before starting postfix.service. " +
                "Confirm the exact SMTP egress IP, tenant MX and all affected remote routes. Keep submissions blocked until post-start review. " +
                "Starting a mail service may allow normal mail activity; no automatic rollback, stop, restart or delivery is requested.",
                "START REVIEWED POSTFIX", dialog)) return;
            await RunAsync("Rechecking Exchange and the exact applied route before service start...", async () =>
            {
                Guard();
                CheckCloudTenant(id);
                if (!acceptedDomainApproved.Checked || !maintenance.Checked || checkedSha != sha ||
                    !SmtpPublicIpConnectorDialog.IsPublicIpv4(ip) ||
                    !Regex.IsMatch(name, @"\A[A-Za-z0-9][A-Za-z0-9._ -]{2,69}\z"))
                    throw new InvalidOperationException("Start context incomplete.");
                var options = (Tenant: id, Domain: domain, Name: name, Ip: ip, Certificate: "");
                var cloud = Fields(await RunTenantConnectorManagerAsync(options, "Inspect"));
                Guard();
                CheckCloudTenant(id);
                if (cloud.Count != 9 || cloud["EXO_CONNECTOR_TENANT"] != "exact_match" ||
                    cloud["EXO_CONNECTOR_ACCEPTED_DOMAIN"] != "verified" || cloud["EXO_CONNECTOR_PUBLIC_IPV4"] != ip ||
                    cloud["EXO_CONNECTOR_BINDING"] != "exact_enabled_connector_observed" ||
                    cloud["EXO_CONNECTOR_EXACT_COUNT"] != "1" || cloud["EXO_CONNECTOR_CONFLICT_COUNT"] != "0" ||
                    !int.TryParse(cloud["EXO_CONNECTOR_NAME_TAKEN"], out int count) || count is < 0 or > 500 ||
                    cloud["EXO_CONNECTOR_DELIVERY_VERIFIED"] != "no" || cloud["CHANGES_APPLIED"] != "no" ||
                    !acceptedDomainApproved.Checked || !maintenance.Checked || checkedSha != sha)
                    throw new InvalidOperationException("Exact enabled IP Connector not observed.");
                Invalidate();
                connectorApproved.Checked = false;
                previewedTenantConnectorSha = previewedTenantConnectorContext = null;
                // From this point SSH failure cannot establish stopped state.
                startAttempted = true;
                await LinuxAsync("start", sha);
                report.Text = "Postfix service and master observed running; applied configuration reverified." +
                    Environment.NewLine + "Recovery SHA-256: " + sha +
                    Environment.NewLine + "No automatic message submission. Normal mail and queue activity are unverified." +
                    Environment.NewLine + "Close this window and use primary Postfix audit, then separately approved local and external delivery tests.";
                status.Text = "Service running observed; delivery unverified.";
                status.ForeColor = Color.SeaGreen;
            });
            if (startAttempted) { maintenance.Checked = false; Update(); }
        };
        check.Click += async (_, _) => await BackupAction("check");
        restore.Click += async (_, _) => await BackupAction("restore");
        copy.Click += (_, _) => { if (ValidSha(backup.Text.Trim())) Clipboard.SetText(backup.Text.Trim()); };
        maintenance.CheckedChanged += (_, _) => { Invalidate(); Update(); };
        backup.TextChanged += (_, _) => { Invalidate(); Update(); };
        dialog.FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        layout.Controls.Add(intro, 0, 0);
        layout.Controls.Add(maintenance, 0, 1);
        layout.Controls.Add(backupLabel, 0, 2);
        layout.Controls.Add(backup, 0, 3);
        layout.Controls.Add(status, 0, 4);
        layout.Controls.Add(report, 0, 5);
        layout.Controls.Add(actions, 0, 6);
        dialog.Controls.Add(layout);
        dialog.CancelButton = close;
        Update();
        dialog.ShowDialog(owner);
        return Task.CompletedTask;
    }
}
