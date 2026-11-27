using System.Drawing;
using System.Windows.Forms;
using System.Security.Cryptography.X509Certificates;

namespace LinuxMailRelay365;

internal sealed class SmtpCertificateImportDialog : Form
{
    internal SmtpCertificateImportDialog()
    {
        Text = "SMTP certificate import | Local inspection";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(620, 420);
        MinimumSize = new Size(440, 320);
        var panel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(12) };
        var format = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 300 };
        format.Items.AddRange(new object[] { "PEM certificate + key", "PFX / P12" });
        format.SelectedIndex = 0;
        var cert = new TextBox { Width = 350, ReadOnly = true };
        var key = new TextBox { Width = 350, ReadOnly = true };
        var password = new TextBox { Width = 300, UseSystemPasswordChar = true, Enabled = false };
        Button Browse(TextBox target, string filter)
        {
            var button = new Button { Text = "Browse...", AutoSize = true };
            button.Click += (_, _) => { using var file = new OpenFileDialog { Filter = filter, CheckFileExists = true }; if (file.ShowDialog(this) == DialogResult.OK) target.Text = file.FileName; };
            return button;
        }
        var certBrowse = Browse(cert, "Certificate files|*.pem;*.crt;*.cer;*.pfx;*.p12|All files|*.*");
        var keyBrowse = Browse(key, "PEM private keys|*.pem;*.key|All files|*.*");
        format.SelectedIndexChanged += (_, _) => { key.Enabled = keyBrowse.Enabled = format.SelectedIndex == 0; password.Enabled = format.SelectedIndex == 1; password.Clear(); cert.Clear(); key.Clear(); };
        var inspect = new Button { Text = "Inspect locally", AutoSize = true };
        inspect.Click += (_, _) =>
        {
            try
            {
                using var leaf = format.SelectedIndex == 0 ? SmtpCertificateImport.LoadPem(cert.Text, key.Text) : SmtpCertificateImport.LoadPkcs12(cert.Text, password.Text);
                MessageBox.Show(this, leaf.Subject + Environment.NewLine + leaf.Issuer + Environment.NewLine + leaf.NotAfter.ToString("u") + Environment.NewLine + "Private key present. Linux and Exchange Online validation pending.", "Local inspection");
            }
            catch (Exception ex) { MessageBox.Show(this, "Import refused: " + ex.GetType().Name); }
            finally { password.Clear(); }
        };
        foreach (Control control in new Control[] { format, new Label { Text = "Certificate / PFX file", AutoSize = true }, cert, certBrowse, new Label { Text = "PEM private key", AutoSize = true }, key, keyBrowse, new Label { Text = "PFX password", AutoSize = true }, password, inspect }) panel.Controls.Add(control);
        Controls.Add(panel);
    }
}
