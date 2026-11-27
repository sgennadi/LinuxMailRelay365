using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpCertificateWizardDialog : Form
{
    private readonly ComboBox identity = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
    private readonly ComboBox source = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
    private readonly Label summary = new() { Dock = DockStyle.Fill, AutoSize = false };
    internal System.Text.Json.JsonElement? SelectedCertificate { get; private set; }
    internal SmtpConnectorIdentity Identity => (SmtpConnectorIdentity)identity.SelectedIndex;
    internal SmtpCertificateSource Source => (SmtpCertificateSource)source.SelectedIndex;

    internal SmtpCertificateWizardDialog(Func<Task<string>> discover, Func<string, string, string, string, Task<string>> validate, Func<System.Security.Cryptography.X509Certificates.X509Certificate2, System.Security.Cryptography.X509Certificates.X509Certificate2Collection, string, Task<string>> transfer, Func<string, Task<string>> inspectAcme, Func<string, string, Task<string>> discoverAcmeProvider, Func<string, string, Task<string>> reviewAcmeIssuance, string acceptedDomain, Func<Task<string>> inspectRenewal, Func<string?, Task<string>> dryRun, Func<string, string?, string?, string?, Task<string>> rotateTls, Func<string, string?, Task<string>> systemd, Func<Form, string, Task> bindExchange, Action<Form> deliveryProbe)
    {
        Text = "SMTP Relay Connector | Setup plan";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(580, 420);
        MinimumSize = new Size(420, 300);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 16, Padding = new Padding(16), AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 4; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        identity.Items.AddRange(new object[] { "Public IP authentication", "TLS certificate authentication" });
        source.Items.AddRange(new object[] { "Existing certificate", "Import certificate", "New ACME certificate" });
        identity.SelectedIndex = 0;
        source.SelectedIndex = 0;
        layout.Controls.Add(new Label { Text = "Connector authentication", AutoSize = true }, 0, 0);
        layout.Controls.Add(identity, 0, 1);
        layout.Controls.Add(new Label { Text = "Certificate source (TLS only)", AutoSize = true }, 0, 2);
        layout.Controls.Add(source, 0, 3);
        layout.Controls.Add(summary, 0, 4);
        var scan = new Button { Text = "Discover existing certificates", AutoSize = true };
        scan.Click += async (_, _) =>
        {
            SelectedCertificate = null;
            scan.Enabled = false;
            try
            {
                using var json = System.Text.Json.JsonDocument.Parse(await discover());
                if (IsDisposed) return;
                var rows = json.RootElement.GetProperty("certificates").EnumerateArray().Select(x => x.Clone()).ToArray();
                if (rows.Length == 0)
                {
                    MessageBox.Show(this, "No standard ACME certificates found.");
                    return;
                }
                using var picker = new Form { Text = "Certificate inventory - eligibility unverified", StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi, ClientSize = new Size(640, 440) };
                var list = new ListBox { Dock = DockStyle.Top, Height = 120 };
                var details = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false };
                var choose = new Button { Dock = DockStyle.Bottom, Text = "Select for validation", Enabled = false };
                foreach (var row in rows) list.Items.Add(row.GetProperty("lineage").GetString() ?? "(unknown)");
                list.SelectedIndexChanged += (_, _) =>
                {
                    if (list.SelectedIndex < 0) { choose.Enabled = false; return; }
                    var row = rows[list.SelectedIndex];
                    choose.Enabled = row.TryGetProperty("certificate", out _) && row.TryGetProperty("key_path", out _) && row.TryGetProperty("chain", out _);
                    details.Text = row.TryGetProperty("metadata", out var metadata) ? metadata.GetString() ?? "" : "Inspection refused";
                };
                choose.Click += (_, _) =>
                {
                    SelectedCertificate = rows[list.SelectedIndex];
                    picker.DialogResult = DialogResult.OK;
                };
                picker.Controls.Add(details);
                picker.Controls.Add(list);
                picker.Controls.Add(choose);
                list.SelectedIndex = 0;
                if (picker.ShowDialog(this) == DialogResult.OK) RefreshPlan();
            }
            catch (Exception ex) { if (!IsDisposed) MessageBox.Show(this, "Discovery failed: " + ex.GetType().Name); }
            finally { if (!IsDisposed) scan.Enabled = true; }
        };
        layout.Controls.Add(scan, 0, 5);
        var domain = new TextBox { Dock = DockStyle.Top, PlaceholderText = "Certificate DNS name (not Linux hostname)" };
        var check = new Button { Text = "Validate Certificate", AutoSize = true };
        check.Click += async (_, _) =>
        {
            if (Identity != SmtpConnectorIdentity.Certificate || Source != SmtpCertificateSource.Existing ||
                SelectedCertificate is not { } cert || Uri.CheckHostName(domain.Text.Trim()) != UriHostNameType.Dns)
            {
                MessageBox.Show(this, "Select an existing TLS certificate and enter its DNS name.");
                return;
            }
            check.Enabled = scan.Enabled = identity.Enabled = source.Enabled = domain.Enabled = false;
            try
            {
                using var report = System.Text.Json.JsonDocument.Parse(await validate(
                    cert.GetProperty("certificate").GetString()!, cert.GetProperty("chain").GetString()!,
                    cert.GetProperty("key_path").GetString()!, domain.Text.Trim()));
                if (IsDisposed) return;
                var root = report.RootElement;
                if (root.GetProperty("status").GetString() != "local_checks_passed")
                    throw new InvalidDataException("Certificate validation refused.");
                MessageBox.Show(this, root.GetProperty("details").GetString() + Environment.NewLine +
                    root.GetProperty("extensions").GetString() + Environment.NewLine +
                    "Local checks passed. Exchange Online acceptance remains unverified.",
                    "Certificate validation", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { if (!IsDisposed) MessageBox.Show(this, "Validation failed: " + ex.GetType().Name, "Certificate validation", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            finally { if (!IsDisposed) { check.Enabled = scan.Enabled = identity.Enabled = domain.Enabled = true; RefreshPlan(); } }
        };
        layout.Controls.Add(domain, 0, 6);
        layout.Controls.Add(check, 0, 7);
        var import = new Button { Text = "Import certificate files", AutoSize = true };
        import.Click += (_, _) =>
        {
            if (Identity != SmtpConnectorIdentity.Certificate || Source != SmtpCertificateSource.Import ||
                Uri.CheckHostName(domain.Text.Trim()) != UriHostNameType.Dns)
            {
                MessageBox.Show(this, "Select TLS certificate import and enter the certificate DNS name.");
                return;
            }
            string name = domain.Text.Trim();
            using var dialog = new SmtpCertificateImportDialog((leaf, chain) => transfer(leaf, chain, name));
            dialog.ShowDialog(this);
        };
        layout.Controls.Add(import, 0, 8);
        var acme = new Button { Text = "Plan ACME and inspect DNS", AutoSize = true };
        acme.Click += (_, _) =>
        {
            if (Identity != SmtpConnectorIdentity.Certificate || Source != SmtpCertificateSource.Acme)
            {
                MessageBox.Show(this, "Select TLS certificate authentication and New ACME certificate.");
                return;
            }
            using var dialog = new SmtpAcmePlanDialog(inspectAcme, discoverAcmeProvider, reviewAcmeIssuance, acceptedDomain, domain.Text.Trim());
            dialog.ShowDialog(this);
        };
        layout.Controls.Add(acme, 0, 9);
        var renewal = new Button { Text = "Inspect certificate renewal", AutoSize = true };
        renewal.Click += (_, _) =>
        {
            if (Identity != SmtpConnectorIdentity.Certificate)
            {
                MessageBox.Show(this, "Select TLS certificate authentication first.");
                return;
            }
            using var dialog = new SmtpRenewalInventoryDialog(inspectRenewal, dryRun);
            dialog.ShowDialog(this);
        };
        layout.Controls.Add(renewal, 0, 10);
        var rotate = new Button { Text = "Review staged TLS deployment", AutoSize = true };
        rotate.Click += (_, _) =>
        {
            if (Identity != SmtpConnectorIdentity.Certificate)
            {
                MessageBox.Show(this, "Select TLS certificate authentication first.");
                return;
            }
            using var dialog = new SmtpTlsRotationDialog(rotateTls, domain.Text.Trim());
            dialog.ShowDialog(this);
        };
        layout.Controls.Add(rotate, 0, 11);
        var scheduler = new Button { Text = "Manage renewal schedule and recovery services", AutoSize = true };
        scheduler.Click += (_, _) =>
        {
            if (Identity != SmtpConnectorIdentity.Certificate)
            {
                MessageBox.Show(this, "Select TLS certificate authentication first.");
                return;
            }
            using var dialog = new SmtpTlsSystemdDialog(systemd);
            dialog.ShowDialog(this);
        };
        layout.Controls.Add(scheduler, 0, 12);
        var binding = new Button { Text = "Verify Exchange certificate binding", AutoSize = true };
        binding.Click += async (_, _) =>
        {
            if (Identity != SmtpConnectorIdentity.Certificate ||
                Uri.CheckHostName(domain.Text.Trim()) != UriHostNameType.Dns)
            {
                MessageBox.Show(this, "Select TLS certificate authentication and enter its exact DNS name.");
                return;
            }
            binding.Enabled = false;
            try { await bindExchange(this, domain.Text.Trim().ToLowerInvariant()); }
            catch (Exception ex) { if (!IsDisposed) MessageBox.Show(this, "Binding review refused: " + ex.GetType().Name); }
            finally { if (!IsDisposed) binding.Enabled = true; }
        };
        layout.Controls.Add(binding, 0, 13);
        var delivery = new Button { Text = "Test delivery through primary Postfix", AutoSize = true };
        delivery.Click += (_, _) => deliveryProbe(this);
        layout.Controls.Add(delivery, 0, 14);
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        layout.Controls.Add(close, 0, 15);
        Controls.Add(layout);
        CancelButton = close;
        identity.SelectedIndexChanged += (_, _) => RefreshPlan();
        source.SelectedIndexChanged += (_, _) => RefreshPlan();
        RefreshPlan();
    }

    private void RefreshPlan()
    {
        source.Enabled = Identity == SmtpConnectorIdentity.Certificate;
        summary.Text = "Planned steps (preview only)" + Environment.NewLine + Environment.NewLine +
            string.Join(Environment.NewLine, SmtpCertificateWizardPlan.Steps(Identity, Source)
                .Select((step, index) => (index + 1) + ". " + step)) +
            Environment.NewLine + Environment.NewLine + (SelectedCertificate is { } cert ? "Selected: " + cert.GetProperty("lineage").GetString() + " (unverified)" + Environment.NewLine : "") + "Import creates protected candidate files on Linux only. Active Postfix and Microsoft 365 configuration remain unchanged.";
    }
}
