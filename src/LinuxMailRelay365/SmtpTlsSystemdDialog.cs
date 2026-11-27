using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpTlsSystemdDialog : Form
{
    internal SmtpTlsSystemdDialog(Func<string, string?, Task<string>> remote)
    {
        Text = "SMTP TLS | Renewal schedule and recovery services";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(860, 620);
        MinimumSize = new Size(480, 340);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1,
            RowCount = 5, Padding = new Padding(12) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 3; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var actions = new (string Key, string Label, string Impact)[]
        {
            ("inspect", "Inspect current state", "Read-only inspection."),
            ("install", "Install missing runtime and unit files", "Create missing files only and reload systemd. No timer is enabled or started."),
            ("enable-recovery", "Enable boot recovery", "Enable the two managed boot recovery units. This affects future Postfix startup."),
            ("enable-timer", "Enable and start renewal timer", "Enable persistent automatic LIVE renewal. A missed schedule may run immediately and activate a new certificate in Postfix."),
            ("start-timer", "Start timer for this boot", "Start the LIVE timer; persistent scheduling may trigger immediately."),
            ("stop-timer", "Stop renewal timer", "Stop future scheduled triggers for this boot. An already running renewal service is not stopped."),
            ("disable-timer", "Disable and stop timer", "Disable future scheduled triggers. An already running renewal service is not stopped."),
            ("renew-now", "Request live renewal now", "Queue a real CA renewal check. This can update DNS, issue and activate a certificate, and reload Postfix. No forced renewal.")
        };
        var choice = new ComboBox { Dock = DockStyle.Top, DropDownStyle = ComboBoxStyle.DropDownList };
        choice.Items.AddRange(actions.Select(item => (object)item.Label).ToArray());
        choice.SelectedIndex = 0;
        var hint = new Label { AutoSize = true, Text = actions[0].Impact, Dock = DockStyle.Top };
        var status = new Label { AutoSize = true, Text = "No action has run.", Dock = DockStyle.Top };
        var report = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true,
            ScrollBars = ScrollBars.Both, WordWrap = false };
        var review = new Button { Text = "Review selected action", AutoSize = true };
        var apply = new Button { Text = "Apply reviewed action", AutoSize = true, Enabled = false };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        buttons.Controls.AddRange([review, apply, close]);
        string? approvedSha = null, approvedAction = null;
        bool busy = false;
        void InvalidatePlan()
        {
            approvedSha = approvedAction = null;
            apply.Enabled = false;
        }
        void SetBusy(bool value)
        {
            busy = value;
            choice.Enabled = review.Enabled = close.Enabled = !value;
            apply.Enabled = !value && approvedSha is not null;
        }
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        choice.SelectedIndexChanged += (_, _) =>
        {
            InvalidatePlan();
            report.Clear();
            hint.Text = actions[choice.SelectedIndex].Impact;
            status.Text = "Review required.";
        };

        async Task ReviewAsync()
        {
            if (busy) return;
            InvalidatePlan();
            SetBusy(true);
            var action = actions[choice.SelectedIndex];
            report.Clear();
            status.Text = "Inspecting packaged runtime, systemd units and prerequisites...";
            try
            {
                using var json = JsonDocument.Parse(await remote(action.Key, null));
                var root = json.RootElement;
                if (root.GetProperty("status").GetString() != "review_ready" ||
                    root.GetProperty("action").GetString() != action.Key ||
                    root.GetProperty("renewal_completion_verified").GetBoolean())
                    throw new InvalidDataException("Unexpected review.");
                string sha = root.GetProperty("plan_sha256").GetString() ?? "";
                if (!Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z")) throw new InvalidDataException();
                var lines = new List<string> {
                    action.Label, action.Impact, "",
                    "Packaged schedule: twice daily (00:00 / 12:00 server time), randomized delay up to 1 hour.",
                    "Effective next/last trigger below; overrides are not accepted for managed changes.",
                    "Review: " + root.GetProperty("reason").GetString(), "Plan SHA-256: " + sha, "",
                    "Runtime files:"
                };
                foreach (var row in root.GetProperty("runtime").EnumerateArray())
                    lines.Add(row.GetProperty("status").GetString() + " | " + row.GetProperty("name").GetString());
                lines.Add("");
                lines.Add("Packaged units:");
                foreach (var row in root.GetProperty("unit_plan").GetProperty("units").EnumerateArray())
                    lines.Add(row.GetProperty("status").GetString() + " | " + row.GetProperty("name").GetString());
                lines.Add("");
                lines.Add("Effective systemd state:");
                foreach (var row in root.GetProperty("units").EnumerateObject())
                {
                    lines.Add(row.Name);
                    foreach (var field in row.Value.EnumerateObject())
                        lines.Add("    " + field.Name + " = " + field.Value.GetString());
                }
                lines.Add("");
                lines.Add("TLS preflight: " + root.GetProperty("tls").GetRawText());
                lines.Add("A successful systemctl command does not prove renewal, certificate activation or delivery.");
                report.Text = string.Join(Environment.NewLine, lines);
                if (root.GetProperty("apply_supported").GetBoolean() && action.Key != "inspect")
                {
                    approvedSha = sha;
                    approvedAction = action.Key;
                    status.Text = "Reviewed action ready. Explicit confirmation required.";
                }
                else status.Text = "Inspection complete: " + root.GetProperty("reason").GetString();
            }
            catch (Exception ex) { status.Text = "Review refused: " + ex.GetType().Name; }
            finally { SetBusy(false); }
        }

        review.Click += async (_, _) => await ReviewAsync();
        Shown += async (_, _) => await ReviewAsync();
        apply.Click += async (_, _) =>
        {
            if (busy || approvedSha is null || approvedAction is null) return;
            var action = actions[choice.SelectedIndex];
            if (action.Key != approvedAction) { InvalidatePlan(); return; }
            if (MessageBox.Show(this, action.Impact + Environment.NewLine + Environment.NewLine +
                "Apply this reviewed action? Do not modify the Linux configuration or units concurrently.",
                "Confirm systemd action", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string sha = approvedSha;
            InvalidatePlan();
            SetBusy(true);
            status.Text = "Applying reviewed systemd action...";
            try
            {
                using var json = JsonDocument.Parse(await remote(action.Key, sha));
                var root = json.RootElement;
                if (root.GetProperty("action").GetString() != action.Key ||
                    root.GetProperty("plan_sha256").GetString() != sha ||
                    root.GetProperty("renewal_completion_verified").GetBoolean())
                    throw new InvalidDataException();
                string? result = root.GetProperty("status").GetString();
                status.Text = result switch
                {
                    "installed" => "Files installed. Timer not started. Review current state.",
                    "command_accepted" => "Systemd accepted the command. Refresh to inspect actual state.",
                    "command_failed" => "Systemd command failed. Inspect state before retrying.",
                    _ => "Outcome unverified. Inspect state before retrying."
                };
                report.AppendText(Environment.NewLine + Environment.NewLine + status.Text);
            }
            catch { status.Text = "Action refused or outcome uncertain. Inspect state before retrying."; }
            finally { SetBusy(false); }
        };
        layout.Controls.Add(choice, 0, 0);
        layout.Controls.Add(hint, 0, 1);
        layout.Controls.Add(status, 0, 2);
        layout.Controls.Add(report, 0, 3);
        layout.Controls.Add(buttons, 0, 4);
        Controls.Add(layout);
        CancelButton = close;
    }
}
