using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpCertificateWizardDialog : Form
{
    private readonly ComboBox identity = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
    private readonly ComboBox source = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
    private readonly Label summary = new() { Dock = DockStyle.Top, AutoSize = true };
    internal System.Text.Json.JsonElement? SelectedCertificate { get; private set; }
    internal SmtpConnectorIdentity Identity => (SmtpConnectorIdentity)identity.SelectedIndex;
    internal SmtpCertificateSource Source => (SmtpCertificateSource)source.SelectedIndex;

    internal SmtpCertificateWizardDialog(Func<Task<string>> discover, Func<string, string, string, string, Task<string>> validate, Func<System.Security.Cryptography.X509Certificates.X509Certificate2, System.Security.Cryptography.X509Certificates.X509Certificate2Collection, string, Task<string>> transfer, Func<string, Task<string>> inspectAcme, Func<string, string, Task<string>> discoverAcmeProvider, Func<string, string, Task<string>> reviewAcmeIssuance, string acceptedDomain, Func<Task<string>> inspectRenewal, Func<string?, Task<string>> dryRun, Func<string, string?, string?, string?, Task<string>> rotateTls, Func<string, string?, Task<string>> systemd, Func<Form, string, Task> bindExchange, Action<Form, string> deliveryProbe, string configuredMx = "", Func<Form, string, string, bool, Task>? stagedConnector = null, Func<Form, Task>? manageConnectors = null, Func<Form, string, Task<string>>? publicIpConnector = null)
    {
        Text = "SMTP Relay Connector | Setup plan";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(740, 520);
        MinimumSize = new Size(460, 350);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 18, Padding = new Padding(16), AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 18; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        bool working = false;
        // Event handlers are registered before all controls exist. Assign the
        // complete refresh delegate only after every captured control is initialized.
        Action refreshPlan = () => { };
        void SetWorking(bool value)
        {
            working = value;
            refreshPlan();
        }
        int page = 0;
        string sessionMx = configuredMx;
        FormClosing += (_, e) => { if (working) e.Cancel = true; };
        identity.Items.AddRange(new object[] { "Public IP authentication", "TLS certificate authentication" });
        source.Items.AddRange(new object[] { "Existing certificate", "Import certificate", "New ACME certificate" });
        identity.SelectedIndex = 0;
        source.SelectedIndex = 0;
        var identityLabel = new Label { Text = "Connector authentication", AutoSize = true };
        layout.Controls.Add(identityLabel, 0, 0);
        layout.Controls.Add(identity, 0, 1);
        var sourceLabel = new Label { Text = "Certificate source (TLS only)", AutoSize = true };
        layout.Controls.Add(sourceLabel, 0, 2);
        layout.Controls.Add(source, 0, 3);
        layout.Controls.Add(summary, 0, 4);
        var scan = new Button { Text = "Discover existing certificates", AutoSize = true };
        scan.Click += async (_, _) =>
        {
            if (working) return;
            SelectedCertificate = null;
            SetWorking(true);
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
                if (picker.ShowDialog(this) == DialogResult.OK) refreshPlan();
            }
            catch (Exception ex) { if (!IsDisposed) MessageBox.Show(this, "Discovery failed: " + ex.GetType().Name); }
            finally { if (!IsDisposed) { scan.Enabled = true; SetWorking(false); } }
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
            if (working) return;
            SetWorking(true);
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
            finally { if (!IsDisposed) { check.Enabled = scan.Enabled = identity.Enabled = domain.Enabled = true; SetWorking(false); } }
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
            using var dialog = new SmtpTlsRotationDialog(rotateTls, domain.Text.Trim(), acceptedDomain, sessionMx, stagedConnector);
            dialog.ShowDialog(this);
            sessionMx = dialog.SessionMx;
            domain.Text = dialog.SessionCertificateName;
            refreshPlan();
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
            if (working) return;
            SetWorking(true);
            binding.Enabled = false;
            try { await bindExchange(this, domain.Text.Trim().ToLowerInvariant()); }
            catch (Exception ex) { if (!IsDisposed) MessageBox.Show(this, "Binding review refused: " + ex.GetType().Name); }
            finally { if (!IsDisposed) { binding.Enabled = true; SetWorking(false); } }
        };
        layout.Controls.Add(binding, 0, 13);
        var delivery = new Button { Text = "Test delivery through primary Postfix", AutoSize = true };
        delivery.Click += (_, _) => deliveryProbe(this, sessionMx);
        layout.Controls.Add(delivery, 0, 14);
        var manage = new Button { Text = "Inspect / manage Exchange Connectors", AutoSize = true };
        manage.Click += async (_, _) =>
        {
            if (working || manageConnectors is null) return;
            SetWorking(true);
            try { await manageConnectors(this); }
            catch (Exception ex) { if (!IsDisposed) MessageBox.Show(this, "Connector inventory refused: " + ex.GetType().Name); }
            finally { if (!IsDisposed) SetWorking(false); }
        };
        layout.Controls.Add(manage, 0, 15);
        var publicIp = new Button { Text = "Discover IP / review or create Public IP Connector", AutoSize = true };
        publicIp.Click += async (_, _) =>
        {
            if (working || publicIpConnector is null || Identity != SmtpConnectorIdentity.PublicIp) return;
            SetWorking(true);
            try { sessionMx = await publicIpConnector(this, sessionMx); }
            catch (Exception ex) { if (!IsDisposed) MessageBox.Show(this, "Public IP Connector workflow refused: " + ex.GetType().Name); }
            finally { if (!IsDisposed) SetWorking(false); }
        };
        layout.Controls.Add(publicIp, 0, 16);
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var back = new Button { Text = "Back", AutoSize = true };
        var next = new Button { Text = "Next", AutoSize = true };
        var navigation = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        navigation.Controls.AddRange([back, next, close]);
        layout.Controls.Add(navigation, 0, 17);
        Controls.Add(layout);
        CancelButton = close;

        refreshPlan = () =>
        {
            var stages = SmtpCertificateWizardPlan.Workflow(Identity);
            page = Math.Clamp(page, 0, stages.Length - 1);
            var stage = stages[page];
            bool certificate = Identity == SmtpConnectorIdentity.Certificate;
            bool first = stage == SmtpWorkflowStage.Identity;
            bool material = stage == SmtpWorkflowStage.Certificate;
            bool deployment = stage == SmtpWorkflowStage.Deployment;
            bool exchange = stage == SmtpWorkflowStage.Binding;
            bool maintenance = stage == SmtpWorkflowStage.Maintenance;
            layout.SuspendLayout();
            try
            {
                identityLabel.Visible = identity.Visible = first;
                sourceLabel.Visible = source.Visible = (first || material) && certificate;
                source.Enabled = !working && certificate;
                domain.Visible = material || deployment || exchange || maintenance;
                scan.Visible = check.Visible = material && Source == SmtpCertificateSource.Existing;
                import.Visible = material && Source == SmtpCertificateSource.Import;
                acme.Visible = material && Source == SmtpCertificateSource.Acme;
                rotate.Visible = deployment;
                binding.Visible = exchange;
                delivery.Visible = stage == SmtpWorkflowStage.Delivery;
                renewal.Visible = scheduler.Visible = maintenance;
                manage.Visible = manageConnectors is not null && (first || deployment || exchange);
                publicIp.Visible = publicIpConnector is not null && first && !certificate;
                foreach (Control control in new Control[] { identity, source, domain, scan, check, import,
                    acme, rotate, binding, delivery, renewal, scheduler, manage, publicIp, close })
                    control.Enabled = !working && (control != source || certificate);
                back.Enabled = !working && page > 0;
                next.Enabled = !working && page < stages.Length - 1;
                string heading = stage switch
                {
                    SmtpWorkflowStage.Identity => "Connector identity",
                    SmtpWorkflowStage.Certificate => "Prepare certificate",
                    SmtpWorkflowStage.Deployment => "MX, STARTTLS and Postfix deployment",
                    SmtpWorkflowStage.Binding => "Verify active Exchange certificate binding",
                    SmtpWorkflowStage.Delivery => "Test delivery and message trace",
                    _ => "Certificate maintenance and recovery"
                };
                string guidance = stage switch
                {
                    SmtpWorkflowStage.Identity => certificate
                        ? "Choose the certificate source. The certificate DNS identity is independent of the Linux hostname."
                        : "Public IP authentication does not require a client certificate. Open Discover IP / review or create Public IP Connector to observe HTTPS egress, check MX and SMTP 25, and separately inspect or create the tenant Connector. The actual Postfix route must still be reviewed before sending.",
                    SmtpWorkflowStage.Certificate => Source switch
                    {
                        SmtpCertificateSource.Existing => "Discover and validate an existing certificate. Validation alone does not create a staged candidate; use Import or the ACME staging workflow if a candidate is needed.",
                        SmtpCertificateSource.Import => "Import a certificate and private key into a protected staged generation. No activation occurs here.",
                        _ => "Review DNS, test staging, evaluate production material and stage an eligible certificate. No activation occurs here."
                    },
                    SmtpWorkflowStage.Deployment => "Select a staged generation. Discover MX and test STARTTLS before a separate deployment review and explicit activation. Review or create the tenant Connector for the staged certificate in the deployment dialog before activation; verify the active binding on the next page.",
                    SmtpWorkflowStage.Binding => "Read-only review of the active managed Linux certificate and exact tenant Connector. Use Inspect / manage Exchange Connectors for tenant-owned objects; new certificate connectors are created on the deployment page.",
                    SmtpWorkflowStage.Delivery => "Review the actual primary route, explicitly approve test messages, then refresh the Linux trace and Exchange Message Trace. Local submission or TLS success is not inbox delivery.",
                    _ => "Inspect renewal state, timers and recovery services. Each live action requires its own review."
                };
                string selected = material && Source == SmtpCertificateSource.Existing && SelectedCertificate is { } cert
                    ? Environment.NewLine + "Selected: " + cert.GetProperty("lineage").GetString() + " (selection only)" : "";
                summary.MaximumSize = new Size(Math.Max(200, layout.ClientSize.Width - 48), 0);
                summary.Text = "Step " + (page + 1) + " / " + stages.Length + "  |  " + heading +
                    Environment.NewLine + "Accepted domain: " + (string.IsNullOrWhiteSpace(acceptedDomain) ? "not selected" : acceptedDomain) +
                    Environment.NewLine + "Session MX: " + (string.IsNullOrWhiteSpace(sessionMx) ? "not selected" : sessionMx) +
                    Environment.NewLine + Environment.NewLine + guidance + selected +
                    Environment.NewLine + Environment.NewLine + "Navigation is not approval or evidence that a previous step succeeded.";
                next.Text = page == stages.Length - 1 ? "Next" : "Next >";
            }
            finally { layout.ResumeLayout(true); }
        };
        back.Click += (_, _) => { if (!working && page > 0) { page--; refreshPlan(); } };
        next.Click += (_, _) => { if (!working && page < SmtpCertificateWizardPlan.Workflow(Identity).Length - 1) { page++; refreshPlan(); } };
        identity.SelectedIndexChanged += (_, _) => { page = 0; refreshPlan(); };
        source.SelectedIndexChanged += (_, _) => refreshPlan();
        layout.SizeChanged += (_, _) =>
            summary.MaximumSize = new Size(Math.Max(200, layout.ClientSize.Width - 48), 0);
        refreshPlan();
    }
}
