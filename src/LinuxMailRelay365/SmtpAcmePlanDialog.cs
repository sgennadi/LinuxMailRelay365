using System.Drawing;
using System.Text.Json;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpAcmePlanDialog : Form
{
    internal SmtpAcmePlanDialog(Func<string, Task<string>> inspect, Func<string, string, Task<string>> discoverProvider, Func<string, Task<string>> reviewIssuance, string acceptedDomain, string certificateName)
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
        var discover = new Button { Text = "Detect DNS provider and plugins", AutoSize = true };
        var choose = new Button { Text = "Select recommended provider", AutoSize = true, Enabled = false };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        bool busy = false;
        string? recommended = null;
        void InvalidateReport()
        {
            recommended = null;
            choose.Enabled = false;
            result.Clear();
        }
        choose.Click += (_, _) =>
        {
            if (busy || recommended is null) return;
            string selected = recommended;
            provider.SelectedItem = selected;
            recommended = null;
            choose.Enabled = false;
            result.Text = "Selected candidate provider: " + selected +
                ". Inspect the plan and verify credentials separately; no issuance approved.";
        };
        accepted.TextChanged += (_, _) => InvalidateReport();
        name.TextChanged += (_, _) => InvalidateReport();
        provider.SelectedIndexChanged += (_, _) => InvalidateReport();
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        discover.Click += async (_, _) =>
        {
            if (busy) return;
            InvalidateReport();
            string acceptedValue = accepted.Text.Trim().ToLowerInvariant();
            string certificateValue = name.Text.Trim().ToLowerInvariant();
            if (Uri.CheckHostName(acceptedValue) != UriHostNameType.Dns ||
                Uri.CheckHostName(certificateValue) != UriHostNameType.Dns)
            {
                result.Text = "Enter the accepted domain and certificate DNS name first.";
                return;
            }
            busy = true;
            run.Enabled = discover.Enabled = close.Enabled = accepted.Enabled = name.Enabled = provider.Enabled = false;
            result.Text = "Discovering public DNS delegation and registered Certbot authenticators from Linux...";
            try
            {
                using var report = JsonDocument.Parse(await discoverProvider(acceptedValue, certificateValue));
                if (IsDisposed) return;
                var root = report.RootElement;
                var req = root.GetProperty("request");
                var dns = root.GetProperty("dns");
                var delegation = root.GetProperty("delegation");
                var rec = root.GetProperty("recommendation");
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("status").GetString() != "completed" ||
                    root.GetProperty("public_resolver").GetString() != "1.1.1.1" ||
                    root.GetProperty("automatic_issuance_allowed").GetBoolean() ||
                    root.GetProperty("postfix_modified").GetBoolean() ||
                    req.GetProperty("accepted_domain").GetString() != acceptedValue ||
                    req.GetProperty("certificate_name").GetString() != certificateValue ||
                    rec.GetProperty("automatic_issuance_allowed").GetBoolean() ||
                    rec.GetProperty("delegated").GetBoolean() != delegation.GetProperty("delegated").GetBoolean())
                    throw new InvalidDataException("Unexpected DNS discovery report.");
                bool delegated = delegation.GetProperty("delegated").GetBoolean();
                string? candidate = rec.GetProperty("recommended_provider").GetString();
                var lines = new List<string> {
                    "Public resolver: 1.1.1.1 (one observation, not propagation proof)",
                    "Observed DNS zone: " + (dns.GetProperty("zone").GetString() ?? "unknown"),
                    "DNS provider hint: " + dns.GetProperty("provider_hint").GetString(),
                    "Nameservers: " + string.Join(", ", dns.GetProperty("nameservers").EnumerateArray().Select(x => x.GetString())),
                    "Challenge target: " + delegation.GetProperty("target").GetString(),
                    "Challenge delegated: " + (delegated ? "Yes - manual review required" : "No direct delegation observed"),
                    "Certbot plugin inventory: " + root.GetProperty("plugins").GetProperty("status").GetString(),
                    "", "Provider candidates:"
                };
                var seen = new HashSet<string>(StringComparer.Ordinal);
                int recommendations = 0;
                foreach (var option in rec.GetProperty("options").EnumerateArray())
                {
                    string value = option.GetProperty("provider").GetString() ?? "";
                    if (value == "manual" || !provider.Items.Contains(value) || !seen.Add(value) ||
                        option.GetProperty("credentials_verified").GetBoolean() ||
                        option.GetProperty("issuance_verified").GetBoolean())
                        throw new InvalidDataException("Unexpected provider result.");
                    bool registered = option.GetProperty("registered").GetBoolean();
                    bool matches = option.GetProperty("dns_hint_matches").GetBoolean();
                    if (option.GetProperty("recommended").GetBoolean())
                    {
                        if (delegated || !registered || !matches || value != candidate)
                            throw new InvalidDataException("Inconsistent provider recommendation.");
                        recommendations++;
                    }
                    lines.Add(value + ": " + (registered ? "plugin registered" : "registration not verified") +
                        (matches ? "; matches DNS hint" : ""));
                }
                if (seen.Count != provider.Items.Count - 1 || recommendations != (candidate is null ? 0 : 1))
                    throw new InvalidDataException("Incomplete provider report.");
                recommended = candidate;
                choose.Enabled = recommended is not null;
                lines.Add("");
                lines.Add("Suggested provider: " + (recommended ?? "manual review"));
                lines.Add("DNS ownership, credentials, CA client TLS eligibility and issuance remain unverified.");
                lines.Add("No DNS writes, certificate issuance or Postfix configuration changes.");
                result.Text = string.Join(Environment.NewLine, lines);
            }
            catch (Exception ex)
            {
                if (!IsDisposed)
                {
                    InvalidateReport();
                    result.Text = "Discovery unavailable: " + ex.GetType().Name +
                        ". Check public DNS access, dig and Certbot. Manual planning is still available.";
                }
            }
            finally
            {
                busy = false;
                if (!IsDisposed) run.Enabled = discover.Enabled = close.Enabled = accepted.Enabled = name.Enabled = provider.Enabled = true;
            }
        };
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
            InvalidateReport();
            busy = true;
            run.Enabled = discover.Enabled = close.Enabled = accepted.Enabled = name.Enabled = provider.Enabled = false;
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
                if (!IsDisposed) run.Enabled = discover.Enabled = close.Enabled = accepted.Enabled = name.Enabled = provider.Enabled = true;
            }
        };
        layout.Controls.Add(new Label { Text = "Exchange accepted domain (candidate, not verified)", AutoSize = true }, 0, 0);
        layout.Controls.Add(accepted, 0, 1);
        layout.Controls.Add(new Label { Text = "Certificate DNS name", AutoSize = true }, 0, 2);
        layout.Controls.Add(name, 0, 3);
        layout.Controls.Add(new Label { Text = "DNS-01 provider", AutoSize = true }, 0, 4);
        layout.Controls.Add(provider, 0, 5);
        layout.Controls.Add(new Label { Text = "No DNS secrets are requested. Manual mode is not automatic renewal.", AutoSize = true }, 0, 6);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        var review = new Button { Text = "Review certificate issuance", AutoSize = true };
        review.Click += (_, _) =>
        {
            if (busy) return;
            string selected = provider.SelectedItem?.ToString() ?? "";
            if (selected == "manual" || Uri.CheckHostName(accepted.Text.Trim()) != UriHostNameType.Dns ||
                Uri.CheckHostName(name.Text.Trim()) != UriHostNameType.Dns)
            {
                result.Text = "Select an automatic DNS plugin and enter valid DNS names first. Manual planning remains available.";
                return;
            }
            using var dialog = new SmtpAcmeIssuanceReviewDialog(reviewIssuance, accepted.Text.Trim().ToLowerInvariant(),
                name.Text.Trim().ToLowerInvariant(), selected);
            dialog.ShowDialog(this);
        };
        actions.Controls.AddRange([discover, choose, run, review]);
        layout.Controls.Add(actions, 0, 7);
        layout.Controls.Add(result, 0, 8);
        layout.Controls.Add(close, 0, 9);
        Controls.Add(layout);
        CancelButton = close;
    }
}
