using System.Drawing;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpPublicIpConnectorDialog : Form
{
    internal string SessionMx { get; private set; }

    internal static bool IsPublicIpv4(string value)
    {
        if (!Regex.IsMatch(value, @"\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z") ||
            !IPAddress.TryParse(value, out var ip) || ip.ToString() != value) return false;
        byte[] b = ip.GetAddressBytes();
        return b.Length == 4 && !(b[0] is 0 or 10 or 127 || b[0] >= 224 ||
            (b[0] == 169 && b[1] == 254) || (b[0] == 172 && b[1] is >= 16 and <= 31) ||
            (b[0] == 192 && (b[1] == 168 || (b[1] == 0 && b[2] is 0 or 2) || (b[1] == 88 && b[2] == 99))) ||
            (b[0] == 100 && b[1] is >= 64 and <= 127) ||
            (b[0] == 198 && (b[1] is 18 or 19 || (b[1] == 51 && b[2] == 100))) ||
            (b[0] == 203 && b[1] == 0 && b[2] == 113));
    }
    private static bool ValidMx(string value) =>
        Regex.IsMatch(value, @"\A[a-z0-9.-]{1,253}\z") && Uri.CheckHostName(value) == UriHostNameType.Dns &&
        value.EndsWith(".mail.protection.outlook.com", StringComparison.Ordinal);

    internal SmtpPublicIpConnectorDialog(string domain, string name, string configuredIp, string mx,
        Func<Task<string>> observe, Func<Task<string>> discover, Func<string, Task<string>> diagnose,
        Func<Form, string, bool, Task> cloud)
    {
        SessionMx = mx;
        Text = "Microsoft 365 | Public IP Connector";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(800, 620);
        MinimumSize = new Size(460, 390);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(14),
            ColumnCount = 1, RowCount = 8, AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 6; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var heading = new Label { AutoSize = true, MaximumSize = new Size(720, 0),
            Text = "Accepted domain: " + domain + Environment.NewLine + "Connector: " + name +
                Environment.NewLine + "Use only a static, exclusively controlled public SMTP IPv4. HTTPS discovery is a hint, not SMTP identity proof." };
        var ip = new TextBox { Dock = DockStyle.Top, Text = configuredIp, MaxLength = 15 };
        var mxField = new TextBox { Dock = DockStyle.Top, Text = mx, MaxLength = 253 };
        var status = new Label { AutoSize = true, Text = "Choose a diagnostic or a separate Exchange review." };
        var report = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both,
            WordWrap = false, MinimumSize = new Size(0, 120) };
        var observeButton = new Button { Text = "Observe public IPv4", AutoSize = true };
        var discoverButton = new Button { Text = "Discover MX", AutoSize = true };
        var tlsButton = new Button { Text = "Test SMTP 25 / STARTTLS", AutoSize = true };
        var inspectButton = new Button { Text = "Inspect Exchange Connector", AutoSize = true };
        var createButton = new Button { Text = "Preview / create NEW Connector", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true };
        actions.Controls.AddRange([observeButton, discoverButton, tlsButton, inspectButton, createButton, close]);
        bool busy = false;
        void Update()
        {
            ip.Enabled = mxField.Enabled = observeButton.Enabled = discoverButton.Enabled = close.Enabled = !busy;
            tlsButton.Enabled = !busy && ValidMx(mxField.Text.Trim().ToLowerInvariant());
            inspectButton.Enabled = createButton.Enabled = !busy && IsPublicIpv4(ip.Text.Trim());
        }
        async Task RunAsync(string title, Func<Task> action)
        {
            if (busy) return;
            busy = true;
            Update();
            status.ForeColor = SystemColors.ControlText;
            status.Text = title;
            report.Clear();
            try { await action(); }
            catch (Exception ex)
            {
                status.ForeColor = Color.DarkOrange;
                status.Text = "Unavailable or uncertain: " + ex.GetType().Name + ". Reinspect before retrying.";
            }
            finally { busy = false; Update(); }
        }
        static void FalseFlags(JsonElement root, params string[] flags)
        {
            foreach (string flag in flags)
                if (root.GetProperty(flag).GetBoolean()) throw new InvalidDataException("Unexpected diagnostic claim.");
        }
        observeButton.Click += async (_, _) =>
        {
            if (busy || MessageBox.Show(this,
                "Make two direct HTTPS requests from Linux to api.ipify.org and checkip.amazonaws.com? " +
                "These services will observe the server's HTTPS public IP. No mail is sent.",
                "Confirm external IP observation", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            await RunAsync("Observing HTTPS egress...", async () =>
            {
                using var doc = JsonDocument.Parse(await observe());
                var root = doc.RootElement;
                if (root.GetProperty("version").GetInt32() != 1) throw new InvalidDataException();
                FalseFlags(root, "smtp_egress_verified", "static_ip_verified", "ownership_verified", "postfix_modified", "mail_sent");
                var rows = root.GetProperty("observations").EnumerateArray().ToArray();
                if (rows.Length != 2) throw new InvalidDataException("Unexpected observer count.");
                var values = new List<string>();
                var lines = new List<string>();
                string[] providers = ["ipify", "aws_checkip"];
                for (int i = 0; i < rows.Length; i++)
                {
                    string state = rows[i].GetProperty("status").GetString() ?? "";
                    string? value = rows[i].GetProperty("ipv4").GetString();
                    if (rows[i].GetProperty("provider").GetString() != providers[i] ||
                        state is not ("observed" or "unavailable" or "nonpublic_or_invalid" or "curl_missing") ||
                        (state == "observed" ? value is null || !IsPublicIpv4(value) : value is not null))
                        throw new InvalidDataException("Invalid IP observation.");
                    if (value is not null) values.Add(value);
                    lines.Add(providers[i] + ": " + state + (value is null ? "" : " " + value));
                }
                bool agree = values.Count == 2 && values[0] == values[1];
                string expected = agree ? "https_sources_agree" : values.Count == 2 ? "https_sources_disagree" :
                    values.Count == 1 ? "single_source_only" : "unverified";
                string? suggestion = root.GetProperty("suggested_ipv4").GetString();
                if (root.GetProperty("status").GetString() != expected || suggestion != (agree ? values[0] : null))
                    throw new InvalidDataException("Inconsistent IP suggestion.");
                if (agree && ip.Text.Trim().Length == 0) ip.Text = suggestion!;
                report.Text = string.Join(Environment.NewLine, lines) + Environment.NewLine +
                    "HTTPS observation only. SMTP egress, static assignment and exclusivity are unverified. Existing input is preserved.";
                status.ForeColor = agree && ip.Text.Trim() == suggestion ? Color.SeaGreen : Color.DarkOrange;
                status.Text = agree ? "Both sources agree: " + suggestion + (ip.Text.Trim() != suggestion ? " (entered IP differs)" : "") :
                    "No reliable HTTPS IPv4 suggestion. Enter the verified SMTP egress manually.";
            });
        };
        discoverButton.Click += async (_, _) => await RunAsync("Checking public MX via 1.1.1.1...", async () =>
        {
            using var doc = JsonDocument.Parse(await discover());
            var root = doc.RootElement;
            if (root.GetProperty("version").GetInt32() != 1 || root.GetProperty("domain").GetString() != domain ||
                root.GetProperty("resolver").GetString() != "1.1.1.1") throw new InvalidDataException();
            FalseFlags(root, "tenant_verified", "postfix_modified", "mail_sent");
            string state = root.GetProperty("status").GetString() ?? "";
            string? suggestion = root.GetProperty("recommended_mx").GetString();
            if (state is not ("direct_m365" or "mixed_or_gateway" or "multiple_preferred" or "no_mx" or "null_mx" or "nxdomain" or "dns_unverified" or "dig_missing") ||
                (state == "direct_m365" ? suggestion is null || !ValidMx(suggestion) : suggestion is not null))
                throw new InvalidDataException("Invalid MX suggestion.");
            var records = root.GetProperty("records").EnumerateArray().ToArray();
            if (records.Length > 32) throw new InvalidDataException();
            if (state == "direct_m365")
            {
                var hosts = records.Select(r => (Preference: r.GetProperty("preference").GetInt32(),
                    Host: r.GetProperty("host").GetString() ?? "", M365: r.GetProperty("microsoft365").GetBoolean()))
                    .OrderBy(r => r.Preference).ToArray();
                if (hosts.Length == 0 || hosts.Any(r => r.Preference is < 0 or > 65535 || !r.M365 || !ValidMx(r.Host)) ||
                    hosts[0].Host != suggestion || (hosts.Length > 1 && hosts[0].Preference == hosts[1].Preference))
                    throw new InvalidDataException("Inconsistent direct MX evidence.");
                if (mxField.Text.Trim().Length == 0) mxField.Text = suggestion!;
            }
            report.Text = "DNS result: " + state + Environment.NewLine + "Suggested MX: " + (suggestion ?? "none") +
                Environment.NewLine + "Public DNS does not prove tenant ownership. Existing input is preserved.";
            status.Text = suggestion is not null && mxField.Text.Trim().ToLowerInvariant() == suggestion
                ? "Public MX observed." : "Review tenant MX manually; existing input preserved.";
            status.ForeColor = suggestion is not null && mxField.Text.Trim().ToLowerInvariant() == suggestion ? Color.SeaGreen : Color.DarkOrange;
        });
        tlsButton.Click += async (_, _) => await RunAsync("Testing TCP 25 / verified STARTTLS from Linux...", async () =>
        {
            string target = mxField.Text.Trim().ToLowerInvariant();
            if (!ValidMx(target)) throw new ArgumentException();
            using var doc = JsonDocument.Parse(await diagnose(target));
            var root = doc.RootElement;
            if (root.GetProperty("version").GetInt32() != 1 || root.GetProperty("host").GetString() != target ||
                root.GetProperty("port").GetInt32() != 25) throw new InvalidDataException();
            FalseFlags(root, "client_certificate_loaded", "postfix_process_tested", "mail_sent", "auth_attempted", "exchange_connector_verified");
            var rows = root.GetProperty("observations").EnumerateArray().ToArray();
            if (rows.Length > 2) throw new InvalidDataException();
            bool ipv4Verified = false;
            var lines = new List<string> { "MX: " + target, "DNS: " + root.GetProperty("dns").GetString() };
            foreach (var row in rows)
            {
                string family = row.GetProperty("family").GetString() ?? "";
                string state = row.GetProperty("status").GetString() ?? "";
                string address = row.GetProperty("address").GetString() ?? "";
                if (family is not ("ipv4" or "ipv6") || !IPAddress.TryParse(address, out _)) throw new InvalidDataException();
                if (state == "tls_verified")
                {
                    if (!row.GetProperty("certificate_chain_and_hostname_verified").GetBoolean() ||
                        row.GetProperty("post_tls_ehlo_code").GetInt32() != 250 ||
                        row.GetProperty("protocol").GetString() is not ("TLSv1.2" or "TLSv1.3"))
                        throw new InvalidDataException("Invalid TLS verification evidence.");
                    if (family == "ipv4") ipv4Verified = true;
                }
                lines.Add(family + " " + address + ": " + state);
            }
            lines.Add("No message or AUTH. The Postfix process and its public SMTP NAT address were not tested.");
            report.Text = string.Join(Environment.NewLine, lines);
            status.ForeColor = ipv4Verified ? Color.SeaGreen : Color.DarkOrange;
            status.Text = ipv4Verified ? "Sampled IPv4 STARTTLS verified; public SMTP source identity unverified." :
                "No verified IPv4 STARTTLS sample. Review network or TLS settings.";
        });
        async Task CloudAsync(bool create)
        {
            await RunAsync(create ? "Reviewing new Exchange Connector..." : "Inspecting Exchange Connector...", async () =>
            {
                string chosen = ip.Text.Trim();
                if (!IsPublicIpv4(chosen)) throw new ArgumentException();
                await cloud(this, chosen, create);
                status.Text = "Cloud workflow closed. Review actual tenant state before further changes.";
            });
        }
        inspectButton.Click += async (_, _) => await CloudAsync(false);
        createButton.Click += async (_, _) => await CloudAsync(true);
        ip.TextChanged += (_, _) => Update();
        mxField.TextChanged += (_, _) => { SessionMx = mxField.Text.Trim(); Update(); };
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        layout.Controls.Add(heading, 0, 0);
        layout.Controls.Add(new Label { Text = "Static public IPv4 (manual or observed suggestion)", AutoSize = true }, 0, 1);
        layout.Controls.Add(ip, 0, 2);
        layout.Controls.Add(new Label { Text = "Microsoft 365 MX", AutoSize = true }, 0, 3);
        layout.Controls.Add(mxField, 0, 4);
        layout.Controls.Add(status, 0, 5);
        layout.Controls.Add(report, 0, 6);
        layout.Controls.Add(actions, 0, 7);
        Controls.Add(layout);
        CancelButton = close;
        Update();
    }
}
