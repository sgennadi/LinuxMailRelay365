using System.Drawing;
using System.Text.Json;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpAcmePlanDialog : Form
{
    internal SmtpAcmePlanDialog(Func<string, Task<string>> inspect, string acceptedDomain, string certificateName)
    {
        Text = "ACME | DNS-01 readiness (read-only)";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(710, 540);
        MinimumSize = new Size(440, 340);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1,
            RowCount = 10, Padding = new Padding(12), AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 8; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var accepted = new TextBox { Text = acceptedDomain, Dock = DockStyle.Top };
        var name = new TextBox { Text = certificateName, Dock = DockStyle.Top };
        var provider = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
        provider.Items.AddRange(new object[] { "manual", "dns-azure", "dns-cloudflare", "dns-route53", "dns-google", "dns-rfc2136" });
        provider.SelectedIndex = 0;
        var result = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
            ScrollBars = ScrollBars.Vertical, WordWrap = true, MinimumSize = new Size(0, 120) };
        var run = new Button { Text = "Inspect from Linux", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        bool busy = false;
        void InvalidateReport() => result.Clear();
        accepted.TextChanged += (_, _) => InvalidateReport();
        name.TextChanged += (_, _) => InvalidateReport();
        provider.SelectedIndexChanged += (_, _) => InvalidateReport();
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        run.Click += async (_, _) =>
        {
            if (busy) return;
            string acceptedValue = accepted.Text.Trim();
            string certificateValue = name.Text.Trim();
            string selectedProvider = provider.SelectedItem?.ToString() ?? "";
            if (Uri.CheckHostName(acceptedValue) != UriHostNameType.Dns ||
                Uri.CheckHostName(certificateValue) != UriHostNameType.Dns)
            {
                result.Text = "Enter both DNS names. The accepted domain must contain the certificate name.";
                return;
            }
            busy = true;
            run.Enabled = close.Enabled = accepted.Enabled = name.Enabled = provider.Enabled = false;
            result.Text = "Inspecting Linux resolver and local tools...";
            try
            {
                using var report = JsonDocument.Parse(await inspect(JsonSerializer.Serialize(new {
                    accepted_domain = acceptedValue, certificate_name = certificateValue, provider = selectedProvider
                })));
                if (IsDisposed) return;
                var root = report.RootElement;
                if (root.GetProperty("status").GetString() != "read_only_plan" ||
                    root.GetProperty("issuance_supported").GetBoolean() ||
                    root.GetProperty("automatic_renewal_verified").GetBoolean())
                    throw new InvalidDataException("Unexpected readiness report.");
                if (!string.Equals(root.GetProperty("accepted_domain").GetString(), acceptedValue, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(root.GetProperty("certificate_name").GetString(), certificateValue, StringComparison.OrdinalIgnoreCase) ||
                    root.GetProperty("provider").GetString() != selectedProvider)
                    throw new InvalidDataException("Readiness report does not match request.");
                var observations = root.GetProperty("dns_observations");
                var lines = new List<string> {
                    "DNS challenge: " + root.GetProperty("challenge").GetString(),
                    "Renewal method: " + root.GetProperty("renewal_method").GetString(),
                    "Certbot executable detected: " + (root.GetProperty("certbot_executable_detected").GetBoolean() ? "Yes" : "No"),
                    "", "Resolver observations (not proof of public DNS propagation):",
                    "TXT answer: " + observations.GetProperty("challenge_txt").GetString(),
                    "CNAME answer: " + observations.GetProperty("challenge_cname").GetString(),
                    "CAA at certificate name: " + observations.GetProperty("certificate_name_caa").GetString(),
                    "NS at selected domain: " + observations.GetProperty("selected_domain_ns").GetString(),
                    "", "Effective CAA policy, DNS ownership, provider credentials, Exchange accepted domain and client TLS eligibility remain unverified.",
                    "Plan SHA-256 (inputs only): " + root.GetProperty("plan_sha256").GetString(),
                    "", "No certificate was issued. No DNS, Postfix or Microsoft 365 settings were changed."
                };
                result.Text = string.Join(Environment.NewLine, lines);
            }
            catch (Exception ex)
            {
                if (!IsDisposed) result.Text = "Inspection refused: " + ex.GetType().Name;
            }
            finally
            {
                busy = false;
                if (!IsDisposed) run.Enabled = close.Enabled = accepted.Enabled = name.Enabled = provider.Enabled = true;
            }
        };
        layout.Controls.Add(new Label { Text = "Exchange accepted domain (candidate, not verified)", AutoSize = true }, 0, 0);
        layout.Controls.Add(accepted, 0, 1);
        layout.Controls.Add(new Label { Text = "Certificate DNS name", AutoSize = true }, 0, 2);
        layout.Controls.Add(name, 0, 3);
        layout.Controls.Add(new Label { Text = "DNS-01 provider", AutoSize = true }, 0, 4);
        layout.Controls.Add(provider, 0, 5);
        layout.Controls.Add(new Label { Text = "No DNS secrets are requested. Manual mode is not automatic renewal.", AutoSize = true }, 0, 6);
        layout.Controls.Add(run, 0, 7);
        layout.Controls.Add(result, 0, 8);
        layout.Controls.Add(close, 0, 9);
        Controls.Add(layout);
        CancelButton = close;
    }
}
