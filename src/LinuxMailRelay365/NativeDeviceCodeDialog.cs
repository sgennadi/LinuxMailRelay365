using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Identity.Client;

namespace LinuxMailRelay365;

/// <summary>
/// Non-modal, HiDPI-aware sign-in panel. MSAL continues polling while the
/// user signs in; closing or cancelling aborts the pending request.
/// Inspired by the existing BitKeyBridge DeviceCodeDialog UX.
/// </summary>
internal sealed class NativeDeviceCodeDialog : Form
{
    private readonly Action cancel;
    private readonly TextBox codeBox = new()
    {
        ReadOnly = true, Dock = DockStyle.Fill,
        Font = new Font("Consolas", 15f, FontStyle.Bold),
        TextAlign = HorizontalAlignment.Center,
        AccessibleName = "Temporary Microsoft device sign-in code"
    };
    private readonly TextBox urlBox = new()
    {
        ReadOnly = true, Dock = DockStyle.Fill,
        Font = new Font("Segoe UI", 10f),
        AccessibleName = "Microsoft verification URL"
    };
    private readonly Label description = new()
    {
        Dock = DockStyle.Fill, AutoSize = true,
        Font = new Font("Segoe UI", 10f),
        Text = "Open the Microsoft verification page, enter the temporary code and complete MFA. " +
               "Return to this app after signing in. No mailbox password is entered here."
    };
    private readonly Button copyButton = new()
    {
        Text = "Copy code", AutoSize = true,
        AccessibleName = "Copy temporary sign-in code"
    };
    private readonly Button openButton = new()
    {
        Text = "Open Microsoft sign-in", AutoSize = true,
        AccessibleName = "Open the Microsoft sign-in page"
    };
    private readonly Button cancelButton = new()
    {
        Text = "Cancel sign-in", AutoSize = true,
        AccessibleName = "Cancel Microsoft sign-in"
    };
    private bool completed;
    private string verifiedUrl = "";

    internal NativeDeviceCodeDialog(Action cancel)
    {
        this.cancel = cancel;
        Text = "LinuxMailRelay365 | Microsoft Entra sign-in (C#)";
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        MinimumSize = new Size(540, 295);
        ClientSize = new Size(690, 350);
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 10f);
        BackColor = Color.White;
        FormBorderStyle = FormBorderStyle.Sizable;
        MaximizeBox = true;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, Padding = new Padding(18),
            ColumnCount = 1, RowCount = 6
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 43));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var title = new Label
        {
            Text = "Microsoft Entra | Device Code + MFA",
            Font = new Font("Segoe UI", 12f, FontStyle.Bold),
            AutoSize = true, Dock = DockStyle.Fill,
            Margin = new Padding(0, 0, 0, 14)
        };
        description.MaximumSize = new Size(610, 0);
        description.Margin = new Padding(0, 0, 0, 14);
        codeBox.Margin = new Padding(0, 0, 0, 10);
        urlBox.Margin = new Padding(0, 0, 0, 10);
        root.Controls.Add(title, 0, 0);
        root.Controls.Add(description, 0, 1);
        root.Controls.Add(codeBox, 0, 2);
        root.Controls.Add(urlBox, 0, 3);
        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true,
            WrapContents = true, FlowDirection = FlowDirection.LeftToRight
        };
        buttons.Controls.Add(copyButton);
        buttons.Controls.Add(openButton);
        buttons.Controls.Add(cancelButton);
        root.Controls.Add(buttons, 0, 4);
        root.Controls.Add(new Label
        {
            Text = "The code expires automatically. Only the selected tenant is used for subsequent operations.",
            AutoSize = true, Dock = DockStyle.Fill, ForeColor = Color.DimGray
        }, 0, 5);
        Controls.Add(root);
        copyButton.Click += (_, _) =>
        {
            if (codeBox.Text.Length > 0) Clipboard.SetText(codeBox.Text);
        };
        openButton.Click += (_, _) =>
        {
            if (verifiedUrl.Length == 0) return;
            try { Process.Start(new ProcessStartInfo(verifiedUrl) { UseShellExecute = true }); }
            catch (System.ComponentModel.Win32Exception)
            {
                MessageBox.Show(this, "Open the displayed Microsoft URL in your browser.",
                    "Browser unavailable", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        };
        cancelButton.Click += (_, _) => Close();
    }

    internal void Present(DeviceCodeResult result, Form owner)
    {
        if (IsDisposed) throw new OperationCanceledException("Sign-in window was closed.");
        codeBox.Text = result.UserCode;
        verifiedUrl = IsTrustedMicrosoftVerificationUrl(result.VerificationUrl) ? result.VerificationUrl : "";
        urlBox.Text = verifiedUrl.Length > 0 ? verifiedUrl : "https://microsoft.com/devicelogin";
        if (verifiedUrl.Length == 0) verifiedUrl = "https://microsoft.com/devicelogin";
        if (!Visible) Show(owner);
        Activate();
    }

    internal void Finish()
    {
        completed = true;
        if (!IsDisposed) Close();
    }

    internal static bool IsTrustedMicrosoftVerificationUrl(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out Uri? parsed) &&
        parsed.Scheme == Uri.UriSchemeHttps && parsed.UserInfo.Length == 0 &&
        parsed.Port == 443 &&
        (parsed.Host.Equals("microsoft.com", StringComparison.OrdinalIgnoreCase) ||
         parsed.Host.Equals("www.microsoft.com", StringComparison.OrdinalIgnoreCase) ||
         parsed.Host.Equals("login.microsoftonline.com", StringComparison.OrdinalIgnoreCase));

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!completed) cancel();
        base.OnFormClosing(e);
    }
}
