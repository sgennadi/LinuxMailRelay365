using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpCertificateWizardDialog : Form
{
    private readonly ComboBox identity = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
    private readonly ComboBox source = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
    private readonly Label summary = new() { Dock = DockStyle.Fill, AutoSize = false };
    internal SmtpConnectorIdentity Identity => (SmtpConnectorIdentity)identity.SelectedIndex;
    internal SmtpCertificateSource Source => (SmtpCertificateSource)source.SelectedIndex;

    internal SmtpCertificateWizardDialog(Func<Task<string>> discover)
    {
        Text = "SMTP Relay Connector | Setup plan";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(580, 420);
        MinimumSize = new Size(420, 300);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7, Padding = new Padding(16), AutoScroll = true };
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
            scan.Enabled = false;
            try
            {
                using var json = System.Text.Json.JsonDocument.Parse(await discover());
                if (IsDisposed) return;
                var rows = json.RootElement.GetProperty("certificates").EnumerateArray().Select(x => x.GetProperty("lineage").GetString() + " - unverified").ToArray();
                MessageBox.Show(this, rows.Length == 0 ? "No standard ACME certificates found." : string.Join(Environment.NewLine, rows), "Certificate inventory");
            }
            catch (Exception ex) { if (!IsDisposed) MessageBox.Show(this, "Discovery failed: " + ex.GetType().Name); }
            finally { if (!IsDisposed) scan.Enabled = true; }
        };
        layout.Controls.Add(scan, 0, 5);
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        layout.Controls.Add(close, 0, 6);
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
            Environment.NewLine + Environment.NewLine + "No Linux or Microsoft 365 settings will be changed.";
    }
}
