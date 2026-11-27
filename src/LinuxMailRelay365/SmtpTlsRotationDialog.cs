using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpTlsRotationDialog : Form
{
    // Session-only context. Never writes the main routing plan.
    internal string SessionMx { get; private set; } = "";
    internal string SessionCertificateName { get; private set; } = "";
    internal SmtpTlsRotationDialog(Func<string, string?, string?, string?, Task<string>> remote, string dnsName, string acceptedDomain = "", string configuredMx = "")
    {
        Text = "SMTP TLS | Reviewed deployment";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(820, 600);
        MinimumSize = new Size(500, 350);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1,
            RowCount = 10, Padding = new Padding(12) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 8; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        SessionMx = configuredMx;
        SessionCertificateName = dnsName;
        var domain = new TextBox { Text = dnsName, Dock = DockStyle.Top };
        var mx = new TextBox { Text = configuredMx, Dock = DockStyle.Fill, PlaceholderText = "tenant.mail.protection.outlook.com", MaxLength = 253 };
        string senderDomain = acceptedDomain.Trim().ToLowerInvariant();
        var discoverMx = new Button { Text = "Discover MX", AutoSize = true };
        var mxStatus = new Label { AutoSize = true, Dock = DockStyle.Top,
            Text = "Accepted domain: " + (senderDomain.Length == 0 ? "not selected" : senderDomain) };
        var mxRow = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2 };
        mxRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        mxRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        mxRow.Controls.Add(mx, 0, 0);
        mxRow.Controls.Add(discoverMx, 1, 0);
        var candidates = new ComboBox { Dock = DockStyle.Top, DropDownStyle = ComboBoxStyle.DropDownList };
        var status = new Label { Text = "Select a staged generation.", AutoSize = true, Dock = DockStyle.Top };
        var report = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true,
            ScrollBars = ScrollBars.Both, WordWrap = false };
        var refresh = new Button { Text = "Refresh staged certificates", AutoSize = true };
        var preview = new Button { Text = "Review", AutoSize = true };
        var activate = new Button { Text = "Activate reviewed deployment", AutoSize = true, Enabled = false };
        var candidateTls = new Button { Text = "Test staged certificate STARTTLS", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        var recovery = new Button { Text = "Review interrupted transaction", AutoSize = true };
        var selinux = new Button { Text = "Review SELinux contexts", AutoSize = true };
        var avc = new Button { Text = "Recent SELinux AVC denials", AutoSize = true };
        buttons.Controls.AddRange([refresh, preview, candidateTls, activate, recovery, selinux, avc, close]);
        bool busy = false;
        string? approvedSha = null;
        string? approvedName = null;
        string? approvedDomain = null;
        string? approvedMode = null;
        void Invalidate()
        {
            approvedSha = approvedName = approvedDomain = approvedMode = null;
            activate.Enabled = false;
            report.Clear();
            status.ForeColor = SystemColors.ControlText;
        }
        void SetBusy(bool value)
        {
            busy = value;
            discoverMx.Enabled = mx.Enabled = candidateTls.Enabled = domain.Enabled = candidates.Enabled = refresh.Enabled = preview.Enabled = recovery.Enabled = selinux.Enabled = avc.Enabled = close.Enabled = !value;
            activate.Enabled = !value && approvedSha is not null;
        }
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        domain.TextChanged += (_, _) => { SessionCertificateName = domain.Text.Trim(); Invalidate(); };
        candidates.SelectedIndexChanged += (_, _) => Invalidate();
        async Task RefreshAsync()
        {
            if (busy) return;
            Invalidate();
            SetBusy(true);
            candidates.Items.Clear();
            try
            {
                using var json = JsonDocument.Parse(await remote("inventory", null, null, null));
                var root = json.RootElement;
                if (root.GetProperty("status").GetString() != "inventory") throw new InvalidDataException();
                foreach (var row in root.GetProperty("candidates").EnumerateArray())
                {
                    string name = row.GetString() ?? "";
                    if (!Regex.IsMatch(name, @"\Acandidate-[a-f0-9]{64}\z")) throw new InvalidDataException();
                    candidates.Items.Add(name);
                }
                if (candidates.Items.Count > 0) candidates.SelectedIndex = 0;
                status.Text = root.GetProperty("truncated").GetBoolean() ? "Inventory limited; review selected candidate." :
                    "Active generation: " + (root.GetProperty("active").GetString() ?? "none");
            }
            catch (Exception ex) { status.Text = "Inventory refused: " + ex.GetType().Name; }
            finally { SetBusy(false); }
        }
        refresh.Click += async (_, _) => await RefreshAsync();
        async Task DiscoverMxAsync()
        {
            if (busy || Uri.CheckHostName(senderDomain) != UriHostNameType.Dns || !senderDomain.Contains('.')) return;
            Invalidate();
            SetBusy(true);
            mxStatus.ForeColor = SystemColors.ControlText;
            mxStatus.Text = "Checking public MX for " + senderDomain + " via 1.1.1.1...";
            try
            {
                using var json = JsonDocument.Parse(await remote("mx-discovery", null, senderDomain, null));
                var root = json.RootElement;
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("domain").GetString() != senderDomain ||
                    root.GetProperty("resolver").GetString() != "1.1.1.1")
                    throw new InvalidDataException("Unexpected MX discovery identity.");
                foreach (string flag in new[] { "tenant_verified", "postfix_modified", "mail_sent" })
                    if (root.GetProperty(flag).GetBoolean()) throw new InvalidDataException("Unexpected MX claim.");
                string? state = root.GetProperty("status").GetString();
                if (state is not ("direct_m365" or "mixed_or_gateway" or "multiple_preferred" or "no_mx" or "null_mx" or "nxdomain" or "dns_unverified" or "dig_missing"))
                    throw new InvalidDataException("Unexpected MX status.");
                var records = root.GetProperty("records");
                if (records.GetArrayLength() > 32) throw new InvalidDataException("Too many MX records.");
                var rows = new List<(int Preference, string Host, bool Eop)>();
                foreach (var row in records.EnumerateArray())
                {
                    int preference = row.GetProperty("preference").GetInt32();
                    string host = row.GetProperty("host").GetString() ?? "";
                    bool eop = row.GetProperty("microsoft365").GetBoolean();
                    if (preference is < 0 or > 65535 || host.Length > 253 ||
                        !Regex.IsMatch(host, @"\A[a-z0-9.-]+\z") || Uri.CheckHostName(host) != UriHostNameType.Dns ||
                        eop != host.EndsWith(".mail.protection.outlook.com", StringComparison.Ordinal))
                        throw new InvalidDataException("Invalid MX record.");
                    rows.Add((preference, host, eop));
                }
                if (rows.Distinct().Count() != rows.Count) throw new InvalidDataException("Duplicate MX record.");
                string? recommendation = root.GetProperty("recommended_mx").GetString();
                var best = rows.OrderBy(x => x.Preference).ToArray();
                bool direct = best.Length > 0 && best.All(x => x.Eop) &&
                    (best.Length == 1 || best[0].Preference < best[1].Preference);
                if ((state == "direct_m365") != direct ||
                    (direct ? recommendation != best[0].Host : recommendation is not null))
                    throw new InvalidDataException("Inconsistent MX recommendation.");
                string existing = mx.Text.Trim();
                if (recommendation is not null && existing.Length == 0)
                    mx.Text = recommendation;
                bool matches = recommendation is not null && string.Equals(mx.Text.Trim(), recommendation, StringComparison.OrdinalIgnoreCase);
                mxStatus.ForeColor = matches ? Color.SeaGreen : Color.DarkOrange;
                mxStatus.Text = matches ? "Public MX observed: " + recommendation :
                    recommendation is not null ? "Public MX differs from entered MX; existing value preserved." :
                    "No unique direct Microsoft 365 MX: " + state + ". Enter the exact tenant MX manually.";
                report.Text = "Accepted domain: " + senderDomain + Environment.NewLine +
                    "Public resolver: 1.1.1.1" + Environment.NewLine +
                    "Discovery: " + state + Environment.NewLine +
                    string.Join(Environment.NewLine, best.Select(r => r.Preference + "  " + r.Host +
                        (r.Eop ? "  [Microsoft 365 suffix]" : "  [other MX]"))) + Environment.NewLine +
                    "Suggested MX: " + (recommendation ?? "none") + Environment.NewLine +
                    "Current MX: " + mx.Text + Environment.NewLine +
                    "Public DNS is not tenant ownership or connector verification. Existing route is not changed.";
            }
            catch (Exception ex)
            {
                mxStatus.ForeColor = Color.DarkOrange;
                mxStatus.Text = "MX discovery unavailable: " + ex.GetType().Name + ". Existing value preserved.";
            }
            finally { SetBusy(false); }
        }
        discoverMx.Click += async (_, _) => await DiscoverMxAsync();
        Shown += async (_, _) =>
        {
            await RefreshAsync();
            if (Uri.CheckHostName(senderDomain) == UriHostNameType.Dns && senderDomain.Contains('.'))
                await DiscoverMxAsync();
        };
        mx.TextChanged += (_, _) =>
        {
            SessionMx = mx.Text.Trim();
            mxStatus.ForeColor = SystemColors.ControlText;
            mxStatus.Text = "MX entered; confirm the intended tenant before testing.";
        };
        preview.Click += async (_, _) =>
        {
            if (busy) return;
            Invalidate();
            string? name = candidates.SelectedItem as string;
            string dns = domain.Text.Trim().ToLowerInvariant();
            if (name is null || Uri.CheckHostName(dns) != UriHostNameType.Dns)
            {
                status.Text = "Select a staged certificate and enter its DNS name.";
                return;
            }
            SetBusy(true);
            try
            {
                using var json = JsonDocument.Parse(await remote("preview", name, dns, null));
                var root = json.RootElement;
                if (root.GetProperty("status").GetString() != "review_ready" ||
                    root.GetProperty("candidate").GetString() != name ||
                    root.GetProperty("domain").GetString() != dns ||
                    root.GetProperty("mail_sent").GetBoolean()) throw new InvalidDataException();
                string sha = root.GetProperty("plan_sha256").GetString() ?? "";
                if (!Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z")) throw new InvalidDataException();
                string? mode = root.GetProperty("mode").GetString();
                report.Text = "Mode: " + mode + Environment.NewLine +
                    "Previous: " + (root.GetProperty("previous").GetString() ?? "none") + Environment.NewLine +
                    "Candidate: " + name + Environment.NewLine +
                    "DNS identity: " + dns + Environment.NewLine +
                    "SELinux: " + root.GetProperty("selinux").GetString() + Environment.NewLine +
                    "Postfix plan: " + root.GetProperty("changes").GetRawText() + Environment.NewLine +
                    "SMTP TLS security level (unchanged): " + root.GetProperty("tls_security_level").GetString() + Environment.NewLine +
                    (mode == "initial" ? "main.cf review: " + root.GetProperty("initial_config").GetRawText() + Environment.NewLine +
                        "The outgoing client certificate is a global Postfix setting; other outbound SMTP routes may use it." + Environment.NewLine : "") +
                    root.GetProperty("certificate_details").GetString() + Environment.NewLine +
                    "Plan SHA-256: " + sha + Environment.NewLine +
                    "Exchange Online acceptance and live delivery remain unverified.";
                if (root.GetProperty("apply_supported").GetBoolean() && mode is ("rotation" or "initial"))
                {
                    approvedSha = sha;
                    approvedName = name;
                    approvedDomain = dns;
                    approvedMode = mode;
                    status.Text = mode == "initial" ? "Reviewed initial deployment. Explicit approval required." :
                        "Reviewed managed rotation. Explicit approval required.";
                }
                else status.Text = "Preview only: unchanged certificate, unsupported Postfix or SELinux requires separate review.";
            }
            catch (Exception ex) { status.Text = "Review refused: " + ex.GetType().Name; }
            finally { SetBusy(false); }
        };
        candidateTls.Click += async (_, _) =>
        {
            if (busy) return;
            string? name = candidates.SelectedItem as string;
            string dns = domain.Text.Trim().ToLowerInvariant();
            string target = mx.Text.Trim().ToLowerInvariant();
            if (name is null || Uri.CheckHostName(dns) != UriHostNameType.Dns ||
                !Regex.IsMatch(target, @"\A[a-z0-9.-]{1,253}\z") ||
                Uri.CheckHostName(target) != UriHostNameType.Dns ||
                !target.EndsWith(".mail.protection.outlook.com", StringComparison.Ordinal))
            {
                status.Text = "Select a staged certificate and enter the certificate name and exact Microsoft 365 MX.";
                return;
            }
            if (MessageBox.Show(this, "Test the inactive candidate " + name + " against " + target + ":25?" +
                Environment.NewLine + "The remote peer may request the public client certificate. No mail, AUTH, activation or reload. Confirm the target is your intended tenant MX.",
                "Confirm candidate STARTTLS test", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            Invalidate();
            SetBusy(true);
            status.Text = "Validating candidate and probing STARTTLS from Linux...";
            try
            {
                using var json = JsonDocument.Parse(await remote("candidate-starttls", name, dns, target));
                var root = json.RootElement;
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("host").GetString() != target || root.GetProperty("port").GetInt32() != 25 ||
                    root.GetProperty("client_generation").GetString() != name ||
                    root.GetProperty("certificate_domain").GetString() != dns ||
                    root.GetProperty("client_identity_mode").GetString() != "inactive_candidate" ||
                    !root.GetProperty("active_generation_unchanged").GetBoolean() ||
                    !root.GetProperty("client_certificate_loaded").GetBoolean() ||
                    !Regex.IsMatch(root.GetProperty("client_certificate_sha256").GetString() ?? "", @"\A[a-f0-9]{64}\z"))
                    throw new InvalidDataException("Unexpected candidate TLS evidence.");
                foreach (string flag in new[] { "mail_sent", "auth_attempted", "postfix_process_tested",
                    "exchange_connector_verified", "client_certificate_presentation_verified", "postfix_modified", "activation_attempted" })
                    if (root.GetProperty(flag).GetBoolean()) throw new InvalidDataException("Unexpected TLS claim.");
                var lines = new List<string> { "MX: " + target + ":25", "Candidate: " + name,
                    "Certificate SHA-256: " + root.GetProperty("client_certificate_sha256").GetString(),
                    "DNS: " + root.GetProperty("dns").GetString(), "" };
                var observations = root.GetProperty("observations");
                if (observations.GetArrayLength() > 2) throw new InvalidDataException("Unexpected sample size.");
                bool verified = false;
                foreach (var row in observations.EnumerateArray())
                {
                    string? state = row.GetProperty("status").GetString();
                    string? family = row.GetProperty("family").GetString();
                    if (family is not ("ipv4" or "ipv6") || !System.Net.IPAddress.TryParse(row.GetProperty("address").GetString(), out var address))
                        throw new InvalidDataException("Unexpected address.");
                    if (state == "tls_verified")
                    {
                        if (!row.GetProperty("certificate_chain_and_hostname_verified").GetBoolean() ||
                            row.GetProperty("post_tls_ehlo_code").GetInt32() != 250 ||
                            row.GetProperty("protocol").GetString() is not ("TLSv1.2" or "TLSv1.3"))
                            throw new InvalidDataException("Inconsistent TLS result.");
                        verified = true;
                    }
                    lines.Add(family + " " + address + ": " + state);
                    if (row.TryGetProperty("protocol", out var protocol)) lines.Add("    Protocol: " + protocol.GetString());
                    if (row.TryGetProperty("cipher", out var cipher)) lines.Add("    Cipher: " + cipher.GetString());
                }
                lines.Add("");
                lines.Add("Client certificate loaded locally. Presentation, connector acceptance and delivery remain unverified.");
                lines.Add("No activation, Postfix reload, AUTH or mail submission requested. Run a fresh deployment review before activation.");
                report.Text = string.Join(Environment.NewLine, lines);
                status.Text = verified ? "Verified server TLS on at least one sampled address; client acceptance unverified." :
                    "No verified TLS handshake established by this sample.";
                status.ForeColor = verified ? Color.SeaGreen : Color.DarkOrange;
            }
            catch (Exception ex)
            {
                status.Text = "Candidate STARTTLS refused or uncertain: " + ex.GetType().Name;
                status.ForeColor = Color.DarkOrange;
            }
            finally { SetBusy(false); }
        };
        activate.Click += async (_, _) =>
        {
            if (busy || approvedSha is null || approvedName is null || approvedDomain is null || approvedMode is null) return;
            string impact = approvedMode == "initial"
                ? "Back up main.cf and set global outbound smtp_tls_chain_files, then reload Postfix. Other outbound routes may present this certificate. A failed deployment attempts to restore main.cf; staged files are retained. "
                : "Switch the managed SMTP client certificate and reload Postfix. A failed rotation attempts to restore the previous generation. ";
            if (MessageBox.Show(this, impact + "Delivery is not verified. Do not edit Postfix concurrently.",
                "Confirm managed TLS deployment", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string sha = approvedSha, name = approvedName, dns = approvedDomain;
            Invalidate();
            SetBusy(true);
            status.Text = "Activating reviewed deployment...";
            try
            {
                using var json = JsonDocument.Parse(await remote("activate", name, dns, sha));
                var root = json.RootElement;
                if (root.GetProperty("plan_sha256").GetString() != sha ||
                    root.GetProperty("status").GetString() != "reloaded")
                    throw new InvalidDataException();
                status.Text = "Postfix reload reported successful; Exchange acceptance remains unverified.";
            }
            catch
            {
                status.Text = "Activation refused or outcome uncertain. Inspect the Linux transaction journal before retry.";
            }
            finally { SetBusy(false); }
        };
        avc.Click += async (_, _) =>
        {
            if (busy) return;
            Invalidate();
            SetBusy(true);
            status.Text = "Reading bounded recent SELinux audit records...";
            try
            {
                using var json = JsonDocument.Parse(await remote("avc-preview", null, null, null));
                var root = json.RootElement;
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("window").GetString() != "recent" ||
                    root.GetProperty("access_verified").GetBoolean() ||
                    root.GetProperty("policy_changed").GetBoolean() ||
                    root.GetProperty("raw_records_exported").GetBoolean())
                    throw new InvalidDataException("Unexpected audit evidence.");
                string? state = root.GetProperty("status").GetString();
                if (state is not ("observed" or "partial" or "unverified" or "no_matches_or_audit_unavailable"))
                    throw new InvalidDataException();
                int count = root.GetProperty("matching_denials").GetInt32();
                int enforcing = root.GetProperty("enforcing_denials").GetInt32();
                int permissive = root.GetProperty("permissive_denials").GetInt32();
                int unknown = root.GetProperty("unknown_mode_denials").GetInt32();
                if (count < 0 || enforcing < 0 || permissive < 0 || unknown < 0 ||
                    count != (long)enforcing + permissive + unknown)
                    throw new InvalidDataException();
                report.Text = "Audit window: recent (ausearch)" + Environment.NewLine +
                    "Read status: " + state + Environment.NewLine +
                    "Audit daemon: " + root.GetProperty("audit_health").GetString() + Environment.NewLine +
                    "Kernel audit lost total: " + root.GetProperty("audit_lost_total").ToString() + Environment.NewLine +
                    "Related denial events: " + count + Environment.NewLine +
                    "    Enforcing: " + enforcing + Environment.NewLine +
                    "    Permissive: " + permissive + Environment.NewLine +
                    "    Unknown mode: " + unknown + Environment.NewLine +
                    "Parsed / unparsed AVC records: " + root.GetProperty("parsed_records").GetInt32() +
                    " / " + root.GetProperty("unparsed_records").GetInt32() + Environment.NewLine + Environment.NewLine +
                    "Historical hints only. No matches, unavailable logs or matching contexts do not prove runtime access." +
                    Environment.NewLine + "No policy changes or raw audit data exported.";
                status.Text = count > 0 ? "Related AVC denials observed; review the Linux audit log." :
                    "No related denials established by this sample. Access remains unverified.";
            }
            catch (Exception ex) { status.Text = "AVC diagnosis unavailable: " + ex.GetType().Name; }
            finally { SetBusy(false); }
        };
        selinux.Click += async (_, _) =>
        {
            if (busy || candidates.SelectedItem is not string name) return;
            Invalidate();
            SetBusy(true);
            bool started = false;
            status.Text = "Inspecting SELinux contexts for the selected generation...";
            try
            {
                using var json = JsonDocument.Parse(await remote("selinux-preview", name, null, null));
                var root = json.RootElement;
                string sha = root.GetProperty("plan_sha256").GetString() ?? "";
                string? mode = root.GetProperty("mode").GetString();
                if (root.GetProperty("status").GetString() != "selinux_review_ready" ||
                    root.GetProperty("candidate").GetString() != name ||
                    root.GetProperty("access_verified").GetBoolean() ||
                    root.GetProperty("policy_changed").GetBoolean() ||
                    mode is not ("enforcing" or "permissive" or "disabled") ||
                    !Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z"))
                    throw new InvalidDataException("Unexpected SELinux review.");
                var lines = new List<string> { "SELinux: " + mode,
                    "Generation: " + name, "Review: " + root.GetProperty("reason").GetString(),
                    "Plan SHA-256: " + sha, "" };
                foreach (var row in root.GetProperty("paths").EnumerateArray())
                {
                    lines.Add(row.GetProperty("path").GetString() ?? "");
                    lines.Add("    Current: " + row.GetProperty("actual").GetString());
                    lines.Add("    Expected: " + row.GetProperty("expected").GetString());
                    string? method = row.GetProperty("repair_method").GetString();
                    if (method is not ("none" or "type_only" or "full_default" or "manual"))
                        throw new InvalidDataException("Unknown SELinux repair method.");
                    lines.Add(row.GetProperty("matches").GetBoolean() ? "    Matches" :
                        method == "type_only" ? "    Repair proposed: restore default type" :
                        method == "full_default" ? "    Repair proposed: restore full default label (-F; unchanged MLS/MCS)" :
                        "    Manual review required");
                }
                lines.Add("");
                lines.Add("Matching labels do not prove access by the confined Postfix process.");
                lines.Add("Activation on an enforcing or unknown host remains blocked until independently tested.");
                report.Text = string.Join(Environment.NewLine, lines);
                if (!root.GetProperty("apply_supported").GetBoolean())
                {
                    status.Text = "SELinux review complete; no automatic repair offered.";
                    return;
                }
                var changes = root.GetProperty("changes");
                if (changes.GetArrayLength() is < 1 or > 5) throw new InvalidDataException();
                var methods = root.GetProperty("paths").EnumerateArray().ToDictionary(
                    row => row.GetProperty("path").GetString() ?? "",
                    row => row.GetProperty("repair_method").GetString());
                string targets = string.Join(Environment.NewLine, changes.EnumerateArray().Select(row =>
                {
                    string path = row.GetString() ?? "";
                    return methods[path] switch
                    {
                        "type_only" => path + " (restore default type)",
                        "full_default" => path + " (restorecon -F, unchanged MLS/MCS)",
                        _ => throw new InvalidDataException("Unreviewed relabel method.")
                    };
                }));
                if (MessageBox.Show(this, "Restore the reviewed default SELinux labels for these exact private paths?" +
                    Environment.NewLine + targets + Environment.NewLine + Environment.NewLine +
                    "Full-label restore is used only where reviewed. No MLS/MCS range change, recursive relabel, policy change, SELinux mode change or Postfix reload.",
                    "Confirm reviewed SELinux repair", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                {
                    status.Text = "SELinux repair cancelled.";
                    return;
                }
                started = true;
                status.Text = "Restoring reviewed default contexts...";
                using var result = JsonDocument.Parse(await remote("selinux-restore", name, null, sha));
                var outcome = result.RootElement;
                if (outcome.GetProperty("status").GetString() != "contexts_verified" ||
                    outcome.GetProperty("candidate").GetString() != name ||
                    outcome.GetProperty("mode").GetString() != mode ||
                    outcome.GetProperty("plan_sha256").GetString() != sha ||
                    outcome.GetProperty("access_verified").GetBoolean() ||
                    outcome.GetProperty("policy_changed").GetBoolean())
                    throw new InvalidDataException("Unexpected SELinux repair result.");
                status.Text = "Default labels verified. Confined process access remains unverified.";
                report.AppendText(Environment.NewLine + Environment.NewLine + status.Text);
            }
            catch (Exception ex)
            {
                status.Text = started ? "Repair failed or partial. Review current labels before retrying."
                    : "SELinux review refused: " + ex.GetType().Name;
            }
            finally { SetBusy(false); }
        };
        recovery.Click += async (_, _) =>
        {
            if (busy) return;
            Invalidate();
            SetBusy(true);
            bool started = false;
            status.Text = "Inspecting interrupted transactions...";
            try
            {
                using var json = JsonDocument.Parse(await remote("recovery-preview", null, null, null));
                var root = json.RootElement;
                string? state = root.GetProperty("status").GetString();
                if (state is "no_transaction" or "no_pending_transaction")
                {
                    status.Text = "No interrupted transaction to recover.";
                    return;
                }
                if (state != "recovery_review_ready" || root.GetProperty("mail_sent").GetBoolean())
                    throw new InvalidDataException("Unexpected recovery review.");
                string sha = root.GetProperty("plan_sha256").GetString() ?? "";
                string? mode = root.GetProperty("mode").GetString();
                if (!Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z") || mode is not ("initial" or "rotation"))
                    throw new InvalidDataException();
                report.Text = "Recovery type: " + mode + Environment.NewLine +
                    "Journal phases: " + root.GetProperty("phases").GetRawText() + Environment.NewLine +
                    "Active generation: " + (root.GetProperty("active").GetString() ?? "none") + Environment.NewLine +
                    "Restore target: " + root.GetProperty("restore_target").GetString() + Environment.NewLine +
                    "SELinux: " + root.GetProperty("selinux").GetString() + Environment.NewLine +
                    "Configuration SHA review: " + root.GetProperty("state").GetRawText() + Environment.NewLine +
                    "Recovery plan SHA-256: " + sha + Environment.NewLine +
                    "Restoration does not verify certificate expiry or mail delivery. No staged certificates are deleted.";
                if (!root.GetProperty("apply_supported").GetBoolean())
                {
                    status.Text = "Recovery preview only; manual review required.";
                    return;
                }
                string impact = mode == "initial"
                    ? "Restore the original main.cf from its verified backup and reload Postfix. The staged pointer may remain unused."
                    : "Restore the previous certificate generation and reload Postfix. The previous certificate may be expired.";
                if (MessageBox.Show(this, impact + Environment.NewLine + Environment.NewLine +
                    "Proceed with the reviewed recovery? Do not edit Postfix concurrently.",
                    "Confirm interrupted TLS recovery", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                {
                    status.Text = "Recovery cancelled before execution.";
                    return;
                }
                started = true;
                status.Text = "Recovering reviewed transaction...";
                using var result = JsonDocument.Parse(await remote("recover", null, null, sha));
                var outcome = result.RootElement;
                if (outcome.GetProperty("status").GetString() != "restored" ||
                    outcome.GetProperty("plan_sha256").GetString() != sha ||
                    outcome.GetProperty("mode").GetString() != mode)
                    throw new InvalidDataException();
                status.Text = "Previous configuration restored and Postfix reloaded. Delivery remains unverified.";
                report.AppendText(Environment.NewLine + Environment.NewLine + status.Text);
            }
            catch (Exception ex)
            {
                status.Text = started
                    ? "Recovery outcome uncertain. Inspect the Linux journal before retrying."
                    : "Recovery refused: " + ex.GetType().Name + ". Review the Linux journal.";
            }
            finally { SetBusy(false); }
        };
        layout.Controls.Add(new Label { Text = "Staged certificate generation", AutoSize = true }, 0, 0);
        layout.Controls.Add(candidates, 0, 1);
        layout.Controls.Add(new Label { Text = "Certificate DNS name", AutoSize = true }, 0, 2);
        layout.Controls.Add(domain, 0, 3);
        layout.Controls.Add(new Label { Text = "Microsoft 365 MX (for staged STARTTLS test)", AutoSize = true }, 0, 4);
        layout.Controls.Add(mxRow, 0, 5);
        layout.Controls.Add(mxStatus, 0, 6);
        layout.Controls.Add(status, 0, 7);
        layout.Controls.Add(report, 0, 8);
        layout.Controls.Add(buttons, 0, 9);
        Controls.Add(layout);
        CancelButton = close;
    }
}
