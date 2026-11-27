using System.Drawing;
using System.Text.Json;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpRenewalInventoryDialog : Form
{
    internal SmtpRenewalInventoryDialog(Func<Task<string>> inspect, Func<string?, Task<string>> dryRun)
    {
        Text = "SMTP TLS | Renewal inventory and reviewed dry-run";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(740, 540);
        MinimumSize = new Size(440, 320);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1,
            RowCount = 3, Padding = new Padding(12) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var status = new Label { Dock = DockStyle.Top, AutoSize = true,
            ForeColor = SystemColors.ControlText, Text = "Renewal is not verified." };
        var report = new TextBox { Dock = DockStyle.Fill, Multiline = true,
            ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true };
        var refresh = new Button { Text = "Refresh from Linux", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var test = new Button { Text = "Review and test renewal", AutoSize = true };
        buttons.Controls.AddRange([refresh, test, close]);
        bool busy = false;
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };

        async Task RefreshAsync()
        {
            if (busy) return;
            busy = true;
            refresh.Enabled = test.Enabled = close.Enabled = false;
            status.Text = "Inspecting renewal configuration and systemd...";
            report.Clear();
            try
            {
                using var json = JsonDocument.Parse(await inspect());
                if (IsDisposed) return;
                var root = json.RootElement;
                if (root.GetProperty("version").GetInt32() != 2 ||
                    root.GetProperty("status").GetString() != "read_only_inventory" ||
                    root.GetProperty("automatic_renewal_verified").GetBoolean() ||
                    root.GetProperty("activation_supported_by_inspector").GetBoolean())
                    throw new InvalidDataException("Unexpected renewal inventory.");
                var lines = new List<string> {
                    "System Certbot configuration: " + root.GetProperty("system_config").GetString(),
                    "Managed ACME configuration: " + root.GetProperty("managed_config").GetString(),
                    "Managed profile: " + root.GetProperty("managed_profile").GetString(),
                    "", "Certificate lineages"
                };
                var lineages = root.GetProperty("lineages");
                if (lineages.GetArrayLength() == 0)
                    lines.Add("No readable lineages reported (see configuration status).");
                foreach (var row in lineages.EnumerateArray())
                {
                    var hooks = row.GetProperty("configured_hooks_detected").ValueKind switch
                    {
                        JsonValueKind.True => "detected; review required",
                        JsonValueKind.False => "none detected in inspected file",
                        _ => "unverified"
                    };
                    lines.Add(row.GetProperty("scope").GetString() + " | " +
                        row.GetProperty("lineage").GetString() + " | " +
                        row.GetProperty("renewal_method").GetString());
                    lines.Add("    Hooks: " + hooks + "; renewal test: " + row.GetProperty("renewal_test").GetString());
                }
                lines.Add("");
                lines.Add("Systemd renewal units");
                foreach (var unit in root.GetProperty("timers").EnumerateObject())
                {
                    var fields = unit.Value.EnumerateObject()
                        .Select(field => field.Name + "=" + field.Value.GetString()).ToArray();
                    lines.Add(unit.Name + ": " + (fields.Length == 0 ? "unverified" : string.Join(" | ", fields)));
                }
                lines.Add("");
                lines.Add("An active timer does not prove renewal or delivery.");
                lines.Add("The existing managed service may activate renewed material; this inspector never starts it.");
                lines.Add("No hooks, dry-run, renewal, activation, Postfix reload or Exchange changes were performed.");
                report.Text = string.Join(Environment.NewLine, lines);
                status.Text = "Inventory received — automatic renewal remains unverified.";
            }
            catch (Exception ex)
            {
                if (!IsDisposed) status.Text = "Inspection refused: " + ex.GetType().Name;
            }
            finally
            {
                busy = false;
                if (!IsDisposed) refresh.Enabled = test.Enabled = close.Enabled = true;
            }
        }

        test.Click += async (_, _) =>
        {
            if (busy) return;
            busy = true;
            refresh.Enabled = test.Enabled = close.Enabled = false;
            bool started = false;
            try
            {
                status.Text = "Reviewing the managed renewal profile...";
                using var preview = JsonDocument.Parse(await dryRun(null));
                var plan = preview.RootElement;
                if (plan.GetProperty("status").GetString() != "ready_for_review" ||
                    !plan.GetProperty("dry_run").GetBoolean() ||
                    plan.GetProperty("activation_requested").GetBoolean() ||
                    !plan.GetProperty("dns_challenge_writes_possible").GetBoolean())
                    throw new InvalidDataException("Unexpected renewal review.");
                string sha = plan.GetProperty("plan_sha256").GetString() ?? "";
                string details = "Managed lineage: " + plan.GetProperty("lineage").GetString() +
                    Environment.NewLine + "DNS provider: " + plan.GetProperty("provider").GetString() +
                    Environment.NewLine + "Staging CA: " + plan.GetProperty("staging_ca").GetString() +
                    Environment.NewLine + "Plan SHA-256: " + sha;
                report.Text = details + Environment.NewLine + Environment.NewLine +
                    "This staging test can create and remove DNS TXT records and write local Certbot state/logs. No production renewal, Postfix activation or reload is requested.";
                if (MessageBox.Show(this, report.Text + Environment.NewLine + Environment.NewLine + "Run the staging renewal test now?",
                    "Confirm DNS challenge test", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                {
                    status.Text = "Dry-run cancelled before execution.";
                    return;
                }
                status.Text = "Running the reviewed staging test (no automatic retry)...";
                started = true;
                using var outcome = JsonDocument.Parse(await dryRun(sha));
                var root = outcome.RootElement;
                if (!root.GetProperty("dry_run").GetBoolean() ||
                    root.GetProperty("activation_requested").GetBoolean() ||
                    root.GetProperty("plan_sha256").GetString() != sha)
                    throw new InvalidDataException("Unexpected renewal result.");
                string? state = root.GetProperty("status").GetString();
                status.Text = state switch
                {
                    "dry_run_passed" => "Staging dry-run passed. Live renewal and delivery remain unverified.",
                    "dry_run_failed" => "Dry-run failed. Review DNS and private Certbot logs before retrying.",
                    _ => "Outcome unverified. Inspect Linux and DNS before retrying."
                };
                report.AppendText(Environment.NewLine + Environment.NewLine + status.Text);
            }
            catch (Exception ex)
            {
                status.Text = started ? "Test outcome unverified; inspect Linux and DNS before retrying."
                    : "Renewal review refused: " + ex.GetType().Name;
            }
            finally
            {
                busy = false;
                if (!IsDisposed) refresh.Enabled = test.Enabled = close.Enabled = true;
            }
        };
        refresh.Click += async (_, _) => await RefreshAsync();
        Shown += async (_, _) => await RefreshAsync();
        layout.Controls.Add(status, 0, 0);
        layout.Controls.Add(report, 0, 1);
        layout.Controls.Add(buttons, 0, 2);
        Controls.Add(layout);
        CancelButton = close;
    }
}
