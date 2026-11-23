using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private readonly ComboBox customSmtpTlsMode = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList,
        Width = 590, Margin = new Padding(0, 3, 0, 12),
        Font = new Font("Segoe UI", 10f),
        AccessibleName = "Custom outbound SMTP transport security"
    };
    private readonly TextBox customSmtpUser = Field("");
    private readonly TextBox customSmtpPassword = new()
    {
        Width = 590, Margin = new Padding(0, 3, 0, 12),
        Font = new Font("Segoe UI", 10f),
        UseSystemPasswordChar = true,
        AccessibleName = "One-use SMTP password (not stored)"
    };
    private CustomSmtpAudit? customSmtpAudit;
    private string? customSmtpAuditContext;
    private string? customSmtpAuditedUser;

    private string CustomSmtpMode()
    {
        if (customSmtpTlsMode.Items.Count == 0)
        {
            customSmtpTlsMode.Items.AddRange([
                "STARTTLS (TLS upgrade with certificate verification)",
                "Implicit TLS (TLS from connection start)",
                "Plaintext diagnostics only (NO password allowed)"
            ]);
            customSmtpTlsMode.SelectedIndex = 0;
        }
        return customSmtpTlsMode.SelectedIndex switch
        {
            0 => "starttls",
            1 => "implicit",
            2 => "plain",
            _ => throw new InvalidDataException("Choose an outbound SMTP TLS mode.")
        };
    }

    private string CurrentCustomSmtpContext() =>
        (TryCurrentIdentity() ?? "") + "|" +
        alternateUpstreamHost.Text.Trim().ToLowerInvariant() + "|" +
        alternateUpstreamPort.Text.Trim() + "|" + CustomSmtpMode();

    private void ShowCustomSmtpChecks(TableLayoutPanel page, int width, int l)
    {
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Проверить SMTP-сервер, выбранный вручную",
            "Inspect a custom SMTP destination",
            "בדוק שרת SMTP מותאם אישית"), true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Проверка выполняется с подключённого Linux-сервера. Она проверяет DNS, TCP, выбранный TLS и SMTP AUTH, но НЕ отправляет письма и НЕ изменяет конфигурацию Linux. Входящий SMTP-порт не меняется.",
            "Diagnostics run on the connected Linux host: DNS, TCP, selected TLS and optional SMTP AUTH. NO mail is sent and NO Linux configuration or inbound SMTP port changes.",
            "בדיקת DNS, TCP ו-TLS משרת Linux ללא שליחת דואר או שינוי הגדרות."),
            width));

        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Безопасность соединения с исходящим SMTP",
            "Outbound SMTP transport security",
            "אבטחת חיבור SMTP יוצא")));
        AddLine(page, customSmtpTlsMode);
        AddAction(page, TranslateMailFlow(l,
            "Проверить DNS, TCP, TLS (без пароля и письма)",
            "Test DNS, TCP and TLS (no password or mail)",
            "בדיקת DNS, TCP ו-TLS ללא סיסמה"),
            () => InspectCustomSmtpAsync(false), false, "check", "custom-smtp-network");

        if (customSmtpAudit is { } report &&
            customSmtpAuditContext == CurrentCustomSmtpContext() &&
            selectedMailTarget == MailFlowIntent.TargetCustom)
        {
            AddLine(page, MailFlowText(
                "SMTP " + report.Host + ":" + report.Port + "  ·  " +
                report.Mode.ToUpperInvariant() + Environment.NewLine +
                "DNS: " + report.Dns + "   TCP: " + report.Tcp +
                "   TLS: " + report.Tls + Environment.NewLine +
                "AUTH capability: " + report.Auth + Environment.NewLine +
                "AUTH result: " + report.AuthResult + Environment.NewLine +
                TranslateMailFlow(l,
                    "Даже успешный SMTP AUTH не подтверждает Send As, разрешённого получателя или фактическую доставку.",
                    "Even successful AUTH does not prove Send As permission, recipient policy or delivery.",
                    "אימות אינו מוכיח הרשאות שליחה או מסירה."),
                width, warning: report.Tls != "verified" ||
                    report.AuthResult is "rejected" or "rejected_or_policy"));
        }

        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Дополнительная разовая проверка SMTP AUTH",
            "Optional one-shot SMTP AUTH",
            "בדיקת SMTP AUTH חד-פעמית"), true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Только для STARTTLS/Implicit TLS, с обязательной проверкой сертификата. Одна попытка AUTH, без отправки письма. Обычный пароль использовать только если это допускает ваш провайдер. Пароль сразу удаляется из интерфейса.",
            "STARTTLS/Implicit TLS only, with certificate verification. Exactly one AUTH attempt and no mail. Use a credential approved by your provider. Password is cleared from the UI immediately.",
            "אימות אחד דרך TLS תקין בלבד וללא שליחת דואר; הסיסמה נמחקת."),
            width, warning: true));
        AddField(page, TranslateMailFlow(l,
            "Логин SMTP (не обязательно адрес почты)",
            "SMTP username (not necessarily an email address)", "שם משתמש SMTP"),
            customSmtpUser);
        AddField(page, TranslateMailFlow(l,
            "Одноразовый SMTP-пароль (не сохраняется)",
            "One-use SMTP password (never saved)", "סיסמת SMTP זמנית"),
            customSmtpPassword);
        if (CustomSmtpMode() != "plain")
            AddAction(page, TranslateMailFlow(l,
                "Проверить SMTP AUTH один раз (без письма)",
                "Test SMTP AUTH once (no mail sent)",
                "בדיקת SMTP AUTH אחת ללא שליחת דואר"),
                () => InspectCustomSmtpAsync(true), false, "shield", "custom-smtp-auth");
        else
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "В режиме без TLS проверка пароля недоступна.",
                "Password authentication is disabled in plaintext mode.",
                "אימות סיסמה אינו זמין ללא TLS."),
                width, warning: true));
        ShowCustomRouteActions(page, width, l);
    }

    private async Task InspectCustomSmtpAsync(bool withAuth)
    {
        if (!HasMailDiscovery() || selectedMailTarget != MailFlowIntent.TargetCustom)
            throw new InvalidOperationException(
                "Complete read-only Linux discovery and choose Custom SMTP first.");
        string identity = TryCurrentIdentity() ??
            throw new InvalidOperationException("Linux SSH identity not confirmed.");
        string host = alternateUpstreamHost.Text.Trim();
        if (!int.TryParse(alternateUpstreamPort.Text.Trim(), out int port))
            throw new InvalidDataException("Enter an outbound TCP port between 1 and 65535.");
        string mode = CustomSmtpMode();
        string selectedContext = CurrentCustomSmtpContext();
        string? username = withAuth ? customSmtpUser.Text : null;
        string? secret = withAuth ? customSmtpPassword.Text : null;
        customSmtpPassword.Clear(); // Do not keep the secret visible after click.
        customSmtpAudit = null;
        customSmtpAuditContext = null;
        customSmtpAuditedUser = null;
        try
        {
            if (withAuth && MessageBox.Show(this,
                TranslateMailFlow(language.SelectedIndex,
                    "Будет ОДНА попытка SMTP AUTH только через проверенный TLS, без отправки письма. Неудачный вход может вызвать блокировку учётной записи. Продолжить?",
                    "Make ONE SMTP AUTH attempt over certificate-verified TLS, with NO mail delivery. Failed logins may trigger account lockout. Continue?",
                    "יתבצע אימות יחיד ב-TLS ללא שליחת דואר. להמשיך?"),
                "LinuxMailRelay365 | Custom SMTP AUTH",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;

            string script = CustomSmtpAudit.BuildScript(
                EmbeddedAssets.CustomSmtpProbe, host, port, mode, username, secret);
            var response = await SshRemote.ExecuteAsync(
                Endpoint(), "bash -s", script, TimeSpan.FromSeconds(65));
            // Never echo stderr; a Python traceback may include the encoded
            // one-shot credential in a line of script text.
            if (response.ExitCode != 0)
                throw new InvalidOperationException(
                    "Custom SMTP diagnostics failed or were refused; no mail was sent.");
            var report = CustomSmtpAudit.Parse(response.StdOut,
                host, port, mode, withAuth);
            if (TryCurrentIdentity() != identity ||
                selectedMailTarget != MailFlowIntent.TargetCustom ||
                CurrentCustomSmtpContext() != selectedContext)
                throw new InvalidOperationException(
                    "Linux or custom SMTP selection changed during diagnostics.");
            customSmtpAudit = report;
            customSmtpAuditContext = selectedContext;
            customSmtpAuditedUser = withAuth && report.AuthResult == "accepted"
                ? username : null;
            WriteLine("Custom SMTP read-only check: TCP=" + report.Tcp +
                "; TLS=" + report.Tls + "; AUTH=" + report.AuthResult +
                "; NO mail sent and NO Linux configuration changed.");
            RenderPage();
        }
        finally
        {
            customSmtpPassword.Clear();
            secret = null;
        }
    }
}
