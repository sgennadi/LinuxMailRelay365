using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    // UI secret is one-shot, never part of MailRoutingPlan, logs, preview,
    // diagnostic journal, Windows Credential Manager or persisted files.
    private readonly TextBox googleMailbox = Field("");
    private readonly TextBox googleAppPassword = new()
    {
        Width = 550, UseSystemPasswordChar = true,
        AccessibleName = "One-use Google SMTP App Password (not saved)",
        ShortcutsEnabled = true
    };
    private readonly TextBox googleOutboundPort = Field("587");
    private GoogleSmtpAudit? googleSmtpAudit;
    private string? googleSmtpAuditIdentity;

    private bool IsGoogleTarget => selectedMailTarget is
        MailFlowIntent.TargetGmail or MailFlowIntent.TargetWorkspace;

    private string GoogleProbeProfile() => selectedMailTarget switch
    {
        MailFlowIntent.TargetGmail => "gmail",
        MailFlowIntent.TargetWorkspace => "workspace",
        _ => throw new InvalidOperationException("Choose Gmail or Google Workspace before testing.")
    };

    private int SelectedGoogleOutboundPort()
    {
        int parsed;
        if (!int.TryParse(googleOutboundPort.Text.Trim(), out parsed) ||
            !GoogleSmtpAudit.PortsFor(GoogleProbeProfile()).Contains(parsed))
            throw new InvalidDataException("Choose a supported Google outbound SMTP port.");
        return parsed;
    }

    private void ShowGoogleSmtpChecks(TableLayoutPanel page)
    {
        if (!HasMailDiscovery() || !IsGoogleTarget) return;
        int l = language.SelectedIndex;
        int width = Math.Max(300, pageHost.ClientSize.Width - 90);
        bool workspace = selectedMailTarget == MailFlowIntent.TargetWorkspace;
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Google SMTP — проверка именно с Linux-сервера",
            "Google SMTP — test from this Linux server",
            "Google SMTP — בדיקה משרת Linux"), true));
        AddLine(page, MailFlowText(workspace
            ? TranslateMailFlow(l,
                "Google Workspace SMTP Relay: smtp-relay.gmail.com · TCP 25/465/587. Для Relay может требоваться разрешённый публичный IP или SMTP AUTH, настроенные в Google Admin. Открытый TCP/TLS не доказывает право Relay.",
                "Google Workspace SMTP relay: smtp-relay.gmail.com · TCP 25/465/587. Google Admin must authorize the sender/IP or SMTP authentication. Open TCP/TLS alone does not prove relay permission.",
                "Google Workspace ממסר: יש לאשר IP או SMTP AUTH ב-Google Admin.")
            : TranslateMailFlow(l,
                "Gmail SMTP: smtp.gmail.com · предпочтительно 587 STARTTLS или 465 TLS. Для проверки входа используйте App Password (если разрешён) или OAuth2; обычный пароль аккаунта не рекомендуется.",
                "Gmail SMTP: smtp.gmail.com · use 587 STARTTLS or 465 TLS. Authenticate with an App Password where available, or OAuth2; do not enter a normal Google account password.",
                "Gmail SMTP: יציאות 587/465, סיסמת אפליקציה או OAuth2."),
            width));

        AddField(page, TranslateMailFlow(l,
            "Исходящий порт Google (не порт локального SMTP)",
            "Google outbound port (NOT the Linux SMTP listener)",
            "יציאת SMTP יוצאת של Google"),
            googleOutboundPort);
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Поддерживаемые порты: ",
            "Supported ports: ", "יציאות נתמכות: ") +
            (workspace ? "25 STARTTLS, 465 implicit TLS, 587 STARTTLS"
                : "465 implicit TLS, 587 STARTTLS"), width));

        AddAction(page, TranslateMailFlow(l,
            "Проверить DNS, TCP-порты и TLS с Linux (без отправки)",
            "Check Google DNS, TCP ports and verified TLS from Linux (no mail)",
            "בדיקת DNS, TCP ו-TLS ללא שליחת דואר"),
            InspectGoogleSmtpPortsAsync, false, "check", "google-ports");

        if (googleSmtpAudit is { } audit &&
            googleSmtpAuditIdentity == TryCurrentIdentity() &&
            audit.Profile == GoogleProbeProfile())
            AddLine(page, MailFlowText(audit.Display(l), width));

        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Необязательная разовая проверка учётных данных",
            "Optional one-time SMTP credential test",
            "בדיקה חד-פעמית של פרטי התחברות"), true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Эта проверка делает только один запрос SMTP AUTH после проверки сертификата TLS. Письмо НЕ отправляется. Пароль сразу очищается из поля, не сохраняется и не записывается в лог.",
            "A single SMTP AUTH attempt is made only after valid TLS certificate verification. NO email is sent. Password is cleared from the field and is never saved or logged.",
            "אימות יחיד דרך TLS תקין, ללא שליחת דואר וללא שמירת הסיסמה."), width));
        AddField(page, TranslateMailFlow(l,
            "Адрес Google / Workspace отправителя",
            "Google / Workspace sender account", "כתובת שולח Google"),
            googleMailbox);
        AddField(page, TranslateMailFlow(l,
            "App Password (временно; НЕ обычный пароль Google)",
            "App Password (one-time; NOT your normal Google password)",
            "סיסמת אפליקציה זמנית"),
            googleAppPassword);
        AddAction(page, TranslateMailFlow(l,
            "Проверить SMTP AUTH на 587/465 (не отправлять письмо)",
            "Check SMTP AUTH via TLS 587/465 (send no mail)",
            "בדיקת SMTP AUTH ללא שליחת דואר"),
            CheckGoogleCredentialsAsync, false, "shield", "google-auth");

        if (workspace)
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Важно: проверка App Password не подтверждает политику SMTP Relay Google Workspace, доверенный IP или адреса отправителей. Их необходимо отдельно проверить в Google Admin.",
                "Important: an App Password check does not verify Workspace SMTP relay settings, authorized public IPs or allowed senders. Inspect these in Google Admin separately.",
                "יש לבדוק בנפרד את הגדרות Google Admin ואת כתובת ה-IP."), width, warning: true));
    }

    private async Task InspectGoogleSmtpPortsAsync()
    {
        if (!HasMailDiscovery()) throw new InvalidOperationException(
            "Run current read-only Linux discovery before Google SMTP tests.");
        string profile = GoogleProbeProfile();
        _ = SelectedGoogleOutboundPort();
        string endpointIdentity = TryCurrentIdentity() ??
            throw new InvalidOperationException("SSH identity not confirmed.");
        googleSmtpAudit = null;
        googleSmtpAuditIdentity = null;
        var code = GoogleSmtpAudit.BuildScript(EmbeddedAssets.GoogleSmtpProbe, profile);
        var report = await SshRemote.ExecuteAsync(Endpoint(), "bash -s", code,
            TimeSpan.FromSeconds(90));
        // Never echo stderr: Python syntax diagnostics can include snippets
        // of the embedded request. Connectivity-only requests are nonsecret,
        // but keep one uniform privacy rule for all Google probes.
        if (report.ExitCode != 0)
            throw new InvalidOperationException("Google SMTP port probe incomplete; no mail was sent.");
        var result = GoogleSmtpAudit.Parse(report.StdOut, profile);
        if (TryCurrentIdentity() != endpointIdentity || GoogleProbeProfile() != profile)
            throw new InvalidOperationException("SSH identity or Google destination changed during test.");
        googleSmtpAudit = result;
        googleSmtpAuditIdentity = endpointIdentity;
        WriteLine(result.Display(1));
        RenderPage();
    }

    private async Task CheckGoogleCredentialsAsync()
    {
        if (!HasMailDiscovery()) throw new InvalidOperationException(
            "Run current read-only Linux discovery before SMTP authentication.");
        string profile = GoogleProbeProfile();
        int selectedPort = SelectedGoogleOutboundPort();
        // Port 25 is a Workspace relay-only option and may use IP-based
        // authentication. Credential testing must use TLS 465/587 instead.
        int authPort = selectedPort == 25 ? 587 : selectedPort;
        string endpointIdentity = TryCurrentIdentity() ??
            throw new InvalidOperationException("SSH identity not confirmed.");
        string mailboxValue = googleMailbox.Text.Trim();
        string ephemeralSecret = googleAppPassword.Text;
        googleAppPassword.Clear();
        try
        {
            if (MessageBox.Show(this, TranslateMailFlow(language.SelectedIndex,
                "Будет выполнена ОДНА попытка входа Google SMTP через проверенный TLS, без отправки письма. Неверные попытки могут вызывать ограничения аккаунта. Продолжить?",
                "Make ONE Google SMTP login attempt over validated TLS; no message will be sent. Failed sign-ins can trigger Google account restrictions. Continue?",
                "תבוצע בדיקת אימות אחת דרך TLS ללא שליחת דואר. להמשיך?"),
                "LinuxMailRelay365 | Google SMTP AUTH",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;
            string code = GoogleSmtpAudit.BuildScript(
                EmbeddedAssets.GoogleSmtpProbe, profile, mailboxValue, ephemeralSecret, authPort);
            var response = await SshRemote.ExecuteAsync(Endpoint(), "bash -s", code,
                TimeSpan.FromSeconds(90));
            // NEVER call EnsureSuccess(): remote stderr might show source code
            // if the runtime crashes, including encoded credential bytes.
            if (response.ExitCode != 0)
                throw new InvalidOperationException(
                    "Google SMTP authentication test did not complete. Credential not logged or saved.");
            var parsed = GoogleSmtpAudit.Parse(response.StdOut, profile);
            if (TryCurrentIdentity() != endpointIdentity || GoogleProbeProfile() != profile)
                throw new InvalidOperationException("SSH identity or destination changed during SMTP AUTH.");
            googleSmtpAudit = parsed;
            googleSmtpAuditIdentity = endpointIdentity;
            WriteLine("Google SMTP AUTH result: " + parsed.AuthResult +
                ". No email sent; no credentials stored.");
            RenderPage();
        }
        finally
        {
            googleAppPassword.Clear();
            ephemeralSecret = "";
        }
    }
}
