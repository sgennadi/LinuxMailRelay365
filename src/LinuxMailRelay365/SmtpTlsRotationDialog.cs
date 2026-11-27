using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpTlsRotationDialog : Form
{
    internal SmtpTlsRotationDialog(Func<string, string?, string?, string?, Task<string>> remote, string dnsName)
    {
        Text = "SMTP TLS | Reviewed deployment";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(820, 600);
        MinimumSize = new Size(500, 350);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1,
            RowCount = 7, Padding = new Padding(12) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 5; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var domain = new TextBox { Text = dnsName, Dock = DockStyle.Top };
        var candidates = new ComboBox { Dock = DockStyle.Top, DropDownStyle = ComboBoxStyle.DropDownList };
        var status = new Label { Text = "Select a staged generation.", AutoSize = true, Dock = DockStyle.Top };
        var report = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true,
            ScrollBars = ScrollBars.Both, WordWrap = false };
        var refresh = new Button { Text = "Refresh staged certificates", AutoSize = true };
        var preview = new Button { Text = "Review", AutoSize = true };
        var activate = new Button { Text = "Activate reviewed deployment", AutoSize = true, Enabled = false };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        var recovery = new Button { Text = "Review interrupted transaction", AutoSize = true };
        var selinux = new Button { Text = "Review SELinux contexts", AutoSize = true };
        buttons.Controls.AddRange([refresh, preview, activate, recovery, selinux, close]);
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
        }
        void SetBusy(bool value)
        {
            busy = value;
            domain.Enabled = candidates.Enabled = refresh.Enabled = preview.Enabled = recovery.Enabled = selinux.Enabled = close.Enabled = !value;
            activate.Enabled = !value && approvedSha is not null;
        }
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        domain.TextChanged += (_, _) => Invalidate();
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
        Shown += async (_, _) => await RefreshAsync();
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
                    lines.Add(row.GetProperty("matches").GetBoolean() ? "    Matches" :
                        row.GetProperty("repairable").GetBoolean() ? "    Repair proposed" : "    Manual review required");
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
                string targets = string.Join(Environment.NewLine, changes.EnumerateArray().Select(row => row.GetString()));
                if (MessageBox.Show(this, "Restore default SELinux labels for these exact paths?" +
                    Environment.NewLine + targets + Environment.NewLine + Environment.NewLine +
                    "No recursive relabel, policy change, SELinux mode change or Postfix reload.",
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
        layout.Controls.Add(status, 0, 4);
        layout.Controls.Add(report, 0, 5);
        layout.Controls.Add(buttons, 0, 6);
        Controls.Add(layout);
        CancelButton = close;
    }
}
