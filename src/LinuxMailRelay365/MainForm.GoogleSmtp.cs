using System.Drawing;
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
    private GoogleRoutePreview? googleRoutePreview;
    private string? googleRoutePreviewContext;

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

    private Control BuildGooglePortCards(GoogleSmtpAudit audit)
    {
        int l = language.SelectedIndex;
        int width = Math.Max(310, pageHost.ClientSize.Width - 90);
        int dpi = Math.Max(96, DeviceDpi);
        int columns = (long)width * 96 >= 940L * dpi ? 3 : 1;
        int cardWidth = Math.Max(260, (width - columns * 12) / columns);
        int height = Math.Max(145, 125 * dpi / 96);
        var grid = new TableLayoutPanel
        {
            Width = width, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = columns, RowCount = 0,
            Padding = new Padding(0, 8, 0, 8),
            BackColor = UiTheme.Canvas
        };
        for (int col = 0; col < columns; ++col)
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / columns));
        for (int i = 0; i < audit.Ports.Count; ++i)
        {
            var port = audit.Ports[i];
            bool good = port.Tcp == "reachable" && port.Tls == "verified";
            Color accent = good ? Color.FromArgb(33, 121, 82) :
                port.Tcp == "reachable" ? Color.FromArgb(150, 92, 23) :
                Color.FromArgb(146, 55, 55);
            string tlsName = port.Port == 465 ? "TLS (implicit)" : "STARTTLS";
            string verified = good
                ? TranslateMailFlow(l, "TLS проверен", "TLS verified", "TLS אומת")
                : TranslateMailFlow(l, "Требует проверки", "Not ready", "לא אומת");
            string authName = port.Auth switch
            {
                "plain" => "AUTH PLAIN",
                "login" => "AUTH LOGIN",
                "oauth_only" => "OAuth advertised",
                "none" => "AUTH not advertised",
                _ => "AUTH unverified"
            };
            var card = new Panel
            {
                Width = cardWidth, Height = height,
                Padding = new Padding(9, 8, 9, 8),
                BackColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(2, 3, 9, 9)
            };
            card.Controls.Add(new Label
            {
                Dock = DockStyle.Top, Height = Math.Max(34, 31 * dpi / 96),
                Font = new Font("Segoe UI", 12f, FontStyle.Bold),
                ForeColor = accent, Text = "TCP " + port.Port + " · " + tlsName
            });
            card.Controls.Add(new Label
            {
                Dock = DockStyle.Bottom,
                Height = Math.Max(75, 65 * dpi / 96),
                Font = new Font("Segoe UI", 10f),
                ForeColor = UiTheme.Navy,
                Text = verified + Environment.NewLine +
                    "TCP: " + port.Tcp + "   TLS: " + port.Tls +
                    Environment.NewLine + authName,
                AccessibleName = "Google SMTP port " + port.Port +
                    ", TCP " + port.Tcp + ", TLS " + port.Tls +
                    ", authentication " + port.Auth
            });
            int row = i / columns;
            if (row >= grid.RowCount)
            {
                grid.RowCount++;
                grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            }
            grid.Controls.Add(card, i % columns, row);
        }
        return grid;
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
        {
            AddLine(page, BuildGooglePortCards(audit));
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Результат проверки учётных данных: ",
                "Credential check: ", "בדיקת פרטי התחברות: ") +
                audit.AuthResult + Environment.NewLine +
                TranslateMailFlow(l,
                    "Открытые TCP/TLS-порты не доказывают разрешение отправителя или доставку.",
                    "Open TCP/TLS ports do not prove sender authorization or delivery.",
                    "גישה ל-TCP/TLS אינה הוכחה לאישור משלוח."),
                width, warning: audit.AuthResult is "rejected" or "rejected_or_policy"));
        }

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

        if (selectedMailScenario == MailScenarioPlanner.ReplaceRelay &&
            inspectedMail?.Mta == "postfix" && inspectedHost?.MtaState == "active" &&
            existingSmtpAudit?.SuspectedUnsafeRelay != true)
        {
            AddLine(page, UiTheme.Text(TranslateMailFlow(l,
                "Настройка Google как исходящего relayhost существующего Postfix",
                "Configure Google as the existing Postfix outbound relayhost",
                "הגדרת Google כממסר יוצא של Postfix"), true));
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Изменяется только исходящий маршрут. Входящий localhost:25, локальные пользователи, мастер-конфигурация и очередь сохраняются. Запуск требует точного предварительного SHA-256, пустой очереди, root backup и подтверждения.",
                "Only the outbound upstream changes. Existing local SMTP, local senders and incoming configuration are preserved. Apply requires exact SHA-256 preflight, an empty queue, verified root-only backup and explicit approval.",
                "יש לשמור על קבלת SMTP המקומית ולוודא גיבוי לפני שינוי ניתוב יוצא."),
                width, warning: true));
            if (googleRoutePreview is not null &&
                googleRoutePreviewContext == CurrentGoogleRouteContext(googleRoutePreview.Fingerprint))
            {
                var planned = googleRoutePreview;
                AddLine(page, MailFlowText(TranslateMailFlow(l,
                    "Предварительная проверка: ", "Preflight: ", "בדיקה: ") +
                    "queue=" + planned.Queue + "  ·  " +
                    "sender/transport maps=" + (planned.HasConflictingMaps ? "detected" : "not detected") +
                    "  ·  apply=" + (planned.ApplyAllowed ? "eligible for review" : "blocked") +
                    Environment.NewLine +
                    "Outbound SASL: " + planned.OutboundSasl +
                    "  ·  credential map: " + planned.PasswordMap +
                    "  ·  TLS: " + planned.TlsLevel +
                    Environment.NewLine + TranslateMailFlow(l,
                        "Наличие password map НЕ доказывает действительность пароля.",
                        "A configured password map does NOT prove that its credentials work.",
                        "קובץ אישורים מוגדר אינו הוכחה לתקינות הסיסמה."),
                    width, warning: !planned.ApplyAllowed));
            }
            AddAction(page, TranslateMailFlow(l,
                "Проверить смену relayhost (без изменений)",
                "Preview Google relayhost migration (read-only)",
                "בדיקת שינוי relayhost ללא שינוי"),
                PreviewGoogleRouteAsync, false, "check", "google-route-preview");
            if (googleRoutePreview is { ApplyAllowed: true } plannedRoute &&
                googleRoutePreviewContext == CurrentGoogleRouteContext(plannedRoute.Fingerprint))
            {
                AddAction(page, TranslateMailFlow(l,
                    "Применить Google relayhost с проверенным backup и rollback...",
                    "Apply Google relayhost with verified backup and rollback...",
                    "החל ניתוב Google עם גיבוי ושחזור..."),
                    ApplyGoogleRouteAsync, false, "shield", "google-route-apply");
            }
        }

        if (workspace)
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Важно: проверка App Password не подтверждает политику SMTP Relay Google Workspace, доверенный IP или адреса отправителей. Их необходимо отдельно проверить в Google Admin.",
                "Important: an App Password check does not verify Workspace SMTP relay settings, authorized public IPs or allowed senders. Inspect these in Google Admin separately.",
                "יש לבדוק בנפרד את הגדרות Google Admin ואת כתובת ה-IP."), width, warning: true));
    }


    private string CurrentGoogleRouteContext(string sha) =>
        (TryCurrentIdentity() ?? "") + "|" + selectedMailScenario +
        "|" + selectedMailTarget + "|" + googleOutboundPort.Text.Trim() +
        "|" + (inspectedMail?.ConfigSha256 ?? "") + "|" + sha;

    private void RequireGoogleRoutePreconditions()
    {
        if (!HasMailDiscovery() || !IsGoogleTarget ||
            selectedMailScenario != MailScenarioPlanner.ReplaceRelay ||
            inspectedMail?.Mta != "postfix" || inspectedHost?.MtaState != "active" ||
            existingSmtpAudit?.SuspectedUnsafeRelay == true)
            throw new InvalidOperationException(
                "A healthy, currently inspected Postfix with a selected upstream migration is required.");
        if (googleSmtpAudit is null || googleSmtpAuditIdentity != TryCurrentIdentity() ||
            googleSmtpAudit.Profile != GoogleProbeProfile())
            throw new InvalidOperationException(
                "First test Google DNS, TCP and TLS from this Linux host.");
        int selected = SelectedGoogleOutboundPort();
        var port = googleSmtpAudit.Ports.FirstOrDefault(x => x.Port == selected);
        if (port is null || port.Tcp != "reachable" || port.Tls != "verified")
            throw new InvalidOperationException(
                "Selected outgoing Google port did not pass TLS certificate verification.");
    }

    private async Task PreviewGoogleRouteAsync()
    {
        RequireGoogleRoutePreconditions();
        string profile = GoogleProbeProfile();
        int port = SelectedGoogleOutboundPort();
        var endpoint = Endpoint();
        string id = TryCurrentIdentity() ??
            throw new InvalidOperationException("SSH identity not confirmed.");
        googleRoutePreview = null;
        googleRoutePreviewContext = null;
        string script = GooglePostfixRoute.BuildScript(
            EmbeddedAssets.GooglePostfixRoute, EmbeddedAssets.Recovery, profile, port, "preview");
        var remote = await SshRemote.RunRootScriptAsync(endpoint, script, TimeSpan.FromMinutes(2));
        // Never log arbitrary root-tool stderr, including unexpected tracebacks.
        if (remote.ExitCode != 0)
            throw new InvalidOperationException(
                "Postfix route preflight could not inspect the current configuration.");
        var plan = GooglePostfixRoute.ParsePreview(remote.StdOut, profile, port);
        if (TryCurrentIdentity() != id || GoogleProbeProfile() != profile ||
            SelectedGoogleOutboundPort() != port)
            throw new InvalidOperationException("Selected Linux or Google route changed during preflight.");
        googleRoutePreview = plan;
        googleRoutePreviewContext = CurrentGoogleRouteContext(plan.Fingerprint);
        WriteLine("Read-only Google Postfix relayhost preview: queue=" + plan.Queue +
            "; sender-specific maps=" + (plan.HasConflictingMaps ? "present" : "absent") +
            "; outbound SASL=" + plan.OutboundSasl +
            "; credential map=" + plan.PasswordMap +
            "; guarded apply=" + (plan.ApplyAllowed ? "eligible" : "blocked") + ".");
        RenderPage();
    }

    private async Task ApplyGoogleRouteAsync()
    {
        RequireGoogleRoutePreconditions();
        var plan = googleRoutePreview;
        if (plan is null || !plan.ApplyAllowed ||
            googleRoutePreviewContext != CurrentGoogleRouteContext(plan.Fingerprint))
            throw new InvalidOperationException("Run a fresh, matching Google relayhost preview first.");
        var endpoint = Endpoint();
        string profile = GoogleProbeProfile();
        int port = SelectedGoogleOutboundPort();
        string identity = TryCurrentIdentity() ??
            throw new InvalidOperationException("SSH identity not confirmed.");
        bool personal = profile == "gmail";
        string mailboxValue = googleMailbox.Text.Trim();
        string secret = googleAppPassword.Text;
        googleAppPassword.Clear();
        try
        {
            string caution = personal
                ? "The Gmail App Password will be kept on LINUX in a root-only Postfix hash DB. It is recoverable by root; it is NOT written to Windows. "
                : "Google Workspace must already authorize this Linux server's public IP and sender domain in Admin Console. The IP-authorized mode changes the primary Postfix OUTBOUND smtp_sasl_auth_enable to no; any existing credential map is kept in the protected snapshot but will no longer authenticate this upstream. No new password is stored. ";
            if (!ConfirmDestructive(
                "LinuxMailRelay365 | Replace existing outbound Postfix relay",
                "Change only OUTGOING relayhost to " + GoogleSmtpAudit.HostFor(profile) + ":" + port +
                ". Incoming SMTP listeners and local mail submission remain unchanged. " +
                caution +
                "An exact preflight and EMPTY queue are required. " +
                "A verified backup is created on Linux automatically, with attempted automatic rollback on failure. " +
                "A Postfix reload may briefly interrupt delivery. " +
                "For Gmail, one TLS-verified SMTP AUTH attempt is performed before configuration.",
                "CHANGE_GOOGLE_OUTBOUND_RELAY"))
                return;
            RequireGoogleRoutePreconditions();
            if (googleRoutePreviewContext != CurrentGoogleRouteContext(plan.Fingerprint) ||
                TryCurrentIdentity() != identity || GoogleProbeProfile() != profile ||
                SelectedGoogleOutboundPort() != port)
                throw new InvalidOperationException("Linux or Google route changed after review.");

            if (personal)
            {
                // This tests the SAME one-use value to be installed on Linux.
                // It makes one AUTH attempt only; no MAIL FROM/RCPT/DATA.
                string probeCode = GoogleSmtpAudit.BuildScript(
                    EmbeddedAssets.GoogleSmtpProbe, profile, mailboxValue, secret, port);
                var auth = await SshRemote.ExecuteAsync(endpoint, "bash -s", probeCode,
                    TimeSpan.FromSeconds(95));
                if (auth.ExitCode != 0)
                    throw new InvalidOperationException("Gmail SMTP AUTH preflight incomplete; no route was changed.");
                var live = GoogleSmtpAudit.Parse(auth.StdOut, profile);
                var chosen = live.Ports.FirstOrDefault(x => x.Port == port);
                if (chosen?.Tls != "verified" || live.AuthResult != "accepted")
                    throw new InvalidOperationException(
                        "Gmail App Password or account policy not accepted by Google over verified TLS. No route changed.");
            }

            // Confirm exact SHA again immediately before applying; the Python
            // manager independently rechecks it before its first mutation.
            string previewScript = GooglePostfixRoute.BuildScript(
                EmbeddedAssets.GooglePostfixRoute, EmbeddedAssets.Recovery, profile, port, "preview");
            var fresh = await SshRemote.RunRootScriptAsync(endpoint, previewScript, TimeSpan.FromMinutes(2));
            if (fresh.ExitCode != 0)
                throw new InvalidOperationException("Fresh Postfix preview failed. No changes made.");
            var checkedPlan = GooglePostfixRoute.ParsePreview(fresh.StdOut, profile, port);
            if (!checkedPlan.ApplyAllowed || checkedPlan.Fingerprint != plan.Fingerprint)
                throw new InvalidOperationException(
                    "Mail queue, Postfix routing maps or configuration changed since approval. Nothing applied.");

            string applyScript = GooglePostfixRoute.BuildScript(
                EmbeddedAssets.GooglePostfixRoute, EmbeddedAssets.Recovery,
                profile, port, "apply", plan.Fingerprint,
                personal ? mailboxValue : null, personal ? secret : null);
            googleRoutePreview = null;
            googleRoutePreviewContext = null;
            var response = await SshRemote.RunRootScriptAsync(endpoint,
                applyScript, TimeSpan.FromMinutes(6));
            if (response.ExitCode != 0)
            {
                if (response.StdOut.Contains("GOOGLE_ROUTE_ROLLBACK=failed", StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        "CRITICAL: Google relay apply failed and automatic Postfix rollback ALSO failed. " +
                        "Inspect the root-only Linux backups and restore manually before sending mail.");
                throw new InvalidOperationException(
                    "Google relay migration was refused or failed. Check verified Linux snapshots and existing Postfix route; no email test was sent.");
            }
            var installed = GoogleRouteApplyResult.Parse(response.StdOut, profile, port);
            if (TryCurrentIdentity() != identity)
                throw new InvalidOperationException("SSH identity changed after route application.");
            WriteLine("Google outbound relayhost applied: " + GoogleSmtpAudit.HostFor(profile) +
                ":" + installed.Port + "; verified backup: " + installed.BackupId +
                "; inbound SMTP unchanged. " +
                (installed.StoredRootOnlyCredential ? "Gmail credential stored only in protected Linux Postfix DB." :
                "Workspace IP-based route uses no stored SMTP password."));
            await InspectMailRoutingAsync();
            RenderPage();
        }
        finally
        {
            googleAppPassword.Clear();
            secret = "";
        }
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
