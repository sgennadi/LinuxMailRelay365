using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpAcmeIssuanceReviewDialog : Form
{
    internal SmtpAcmeIssuanceReviewDialog(Func<string, Task<string>> review, string acceptedDomain,
        string certificateName, string provider)
    {
        Text = "ACME | Local issuance review";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(680, 500);
        MinimumSize = new Size(440, 340);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1,
            Padding = new Padding(12), RowCount = 10, AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 8; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var environment = new ComboBox { Dock = DockStyle.Top, DropDownStyle = ComboBoxStyle.DropDownList };
        environment.Items.AddRange(["staging", "production"]);
        environment.SelectedIndex = 0;
        var email = new TextBox { Dock = DockStyle.Top, MaxLength = 320 };
        var credential = new TextBox { Dock = DockStyle.Top, MaxLength = 1024,
            PlaceholderText = "/etc/linuxmailrelay365/dns-credentials.ini" };
        var result = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
            ScrollBars = ScrollBars.Vertical, WordWrap = true, MinimumSize = new Size(0, 130) };
        var run = new Button { Text = "Check local readiness", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        bool busy = false;
        void InvalidateReport() { result.Clear(); result.ForeColor = SystemColors.WindowText; }
        email.TextChanged += (_, _) => InvalidateReport();
        credential.TextChanged += (_, _) => InvalidateReport();
        environment.SelectedIndexChanged += (_, _) => InvalidateReport();
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        run.Click += async (_, _) =>
        {
            if (busy) return;
            InvalidateReport();
            string path = credential.Text.Trim(), contact = email.Text.Trim();
            string target = environment.SelectedItem?.ToString() ?? "";
            if (!Regex.IsMatch(path, @"\A/[A-Za-z0-9_./-]{1,1023}\z") ||
                !Regex.IsMatch(contact, @"\A[A-Za-z0-9][A-Za-z0-9._+%-]{0,63}@[A-Za-z0-9.-]{1,253}\z"))
            {
                result.Text = "Enter a valid contact email and absolute Linux credential-file path (ASCII, no spaces). Do not paste DNS secrets.";
                return;
            }
            busy = true;
            run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = false;
            result.Text = "Checking the existing credential file and installed plugin on Linux...";
            try
            {
                using var response = JsonDocument.Parse(await review(JsonSerializer.Serialize(new
                {
                    accepted_domain = acceptedDomain, certificate_name = certificateName,
                    provider, environment = target, email = contact, credentials_path = path
                })));
                var root = response.RootElement;
                string ca = target == "staging" ? "https://acme-staging-v02.api.letsencrypt.org/directory" :
                    "https://acme-v02.api.letsencrypt.org/directory";
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("status").GetString() != "local_review_complete" ||
                    root.GetProperty("accepted_domain").GetString() != acceptedDomain ||
                    root.GetProperty("certificate_name").GetString() != certificateName ||
                    root.GetProperty("provider").GetString() != provider ||
                    root.GetProperty("environment").GetString() != target ||
                    root.GetProperty("ca_directory").GetString() != ca ||
                    root.GetProperty("challenge").GetString() != "_acme-challenge." + certificateName ||
                    !Regex.IsMatch(root.GetProperty("review_sha256").GetString() ?? "", @"\A[a-f0-9]{64}\z"))
                    throw new InvalidDataException("Unexpected issuance review.");
                foreach (string flag in new[] { "api_permissions_verified", "dns_ownership_verified", "ca_client_tls_verified",
                         "accepted_domain_verified", "issuance_supported", "dns_modified", "certificate_issued", "postfix_modified" })
                    if (root.GetProperty(flag).GetBoolean()) throw new InvalidDataException("Unexpected issuance claim.");
                string? file = root.GetProperty("credential_file").GetString();
                string? plugin = root.GetProperty("plugin").GetString();
                bool ready = root.GetProperty("local_preflight_passed").GetBoolean();
                if (file is not ("unverified" or "refused" or "local_structure_passed") ||
                    plugin is not ("unverified" or "not_registered" or "registered") ||
                    ready != (file == "local_structure_passed" && plugin == "registered"))
                    throw new InvalidDataException("Inconsistent preflight result.");
                result.ForeColor = ready ? Color.SeaGreen : Color.DarkOrange;
                result.Text = string.Join(Environment.NewLine, new[] {
                    ready ? "Local preflight passed (not issuance approval)." : "Local preflight incomplete.",
                    "CA: " + ca, "DNS challenge: _acme-challenge." + certificateName,
                    "Credential file: " + file, "Certbot authenticator: " + plugin, "",
                    "The credential check is structural only; DNS API permissions and ownership are not tested.",
                    "CA client-auth eligibility and Exchange accepted-domain status remain unverified.",
                    "Staging is a test environment, not a production SMTP identity.",
                    "No certificate issued, no DNS or Postfix changes. No secrets returned to Windows."
                });
            }
            catch (Exception ex)
            {
                result.ForeColor = Color.DarkOrange;
                result.Text = "Local review unavailable: " + ex.GetType().Name + ". Check the path, root access and installed plugin.";
            }
            finally
            {
                busy = false;
                if (!IsDisposed) run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = true;
            }
        };
        layout.Controls.Add(new Label { Text = "DNS identity: " + certificateName + " | " + provider, AutoSize = true }, 0, 0);
        layout.Controls.Add(new Label { Text = "CA environment (preview only)", AutoSize = true }, 0, 1);
        layout.Controls.Add(environment, 0, 2);
        layout.Controls.Add(new Label { Text = "ACME account contact email", AutoSize = true }, 0, 3);
        layout.Controls.Add(email, 0, 4);
        layout.Controls.Add(new Label { Text = "Existing private credential file on Linux (path only)", AutoSize = true }, 0, 5);
        layout.Controls.Add(credential, 0, 6);
        layout.Controls.Add(run, 0, 7);
        layout.Controls.Add(result, 0, 8);
        layout.Controls.Add(close, 0, 9);
        Controls.Add(layout);
        CancelButton = close;
    }
}
