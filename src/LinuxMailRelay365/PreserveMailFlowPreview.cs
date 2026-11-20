using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace LinuxMailRelay365;

// A data-bound preview, NOT a deployment status. No credentials or private keys.
internal sealed record PreserveFlowSnapshot(
    string LinuxHost, string Listener, string SmtpPort, string Mailbox,
    string TenantId, string TrustedCidrs, string? ExistingMta, bool PublicRequested,
    bool ConnectorPlanned = false, bool SenderPolicyPlanned = false, string VerifiedDomain = "",
    string TransportMode = "oauth2", string OAuthSenderMode = "fixed-mailbox",
    string OutboundMx = "", string EopFixedSender = "",
    bool KeepExisting = true, string SenderPolicy = "fixed-mailbox")
{
    private static string OneLine(string? value, int limit = 120)
    {
        var clean = (value ?? "").Replace('\r', ' ').Replace('\n', ' ').Trim();
        return clean.Length <= limit ? clean : clean[..limit] + "...";
    }

    internal bool LocalOnly => string.IsNullOrWhiteSpace(Listener);
    // Connector and Direct Send ARE implemented as separately reviewed EOP routes.
    // Only the multi-mailbox OAuth option is not deployable yet.
    internal bool NotDeployablePlan => MailRoutingGuidance.IsUnimplementedOAuthMultiSender(
        TransportMode, OAuthSenderMode);
    internal string MailRouteTitle => TransportMode switch
    {
        "connector" => "M365 CONNECTOR · TCP 25",
        "direct-send" => "DIRECT SEND · INTERNAL",
        _ => "XOAUTH2 · TCP 587"
    };
    internal string MailRouteHint => TransportMode switch
    {
        "connector" => "Authorized Inbound Connector",
        "direct-send" => "Internal recipients only",
        _ => NotDeployablePlan ? "Multiple mailboxes: PLAN ONLY" : DisplayMailbox
    };
    internal string OutboundDescription => MailRoutingGuidance.Outbound(TransportMode, OutboundMx);
    internal string ServerForClient => LocalOnly ? "127.0.0.1" : OneLine(Listener);
    internal string DisplayHost => string.IsNullOrWhiteSpace(LinuxHost)
        ? "(not entered)" : OneLine(LinuxHost);
    internal string DisplayMailbox => string.IsNullOrWhiteSpace(Mailbox)
        ? "(not selected)" : OneLine(Mailbox);
    internal string DisplayTenant => string.IsNullOrWhiteSpace(TenantId)
        ? "(not selected)" : OneLine(TenantId, 50);
    internal string DisplayPort => int.TryParse(SmtpPort, out var port) && port is >= 1024 and <= 65535
        ? port.ToString() : "(invalid port)";
    internal string ExistingStatus => ExistingMta switch
    {
        "postfix" => "Postfix detected",
        "sendmail" or "exim" => "Detected external MTA: guarded coexistence requires review",
        "none" => "No existing MTA detected",
        "unknown" => "MTA state uncertain",
        _ => "MTA not inspected"
    };

    internal string ExistingStatusLocalized(int language) =>
        language switch
        {
            0 => ExistingMta switch
            {
                "postfix" => "Обнаружен Postfix",
                "exim" or "sendmail" => "Exim/Sendmail: требуется проверка",
                "none" => "Почтовая система не найдена",
                "unknown" => "Состояние MTA неизвестно",
                _ => "MTA ещё не проверен"
            },
            2 => ExistingMta switch
            {
                "postfix" => "Postfix זוהה",
                "exim" or "sendmail" => "נמצא MTA אחר; נדרשת בדיקה",
                "none" => "לא נמצא שרת דואר",
                "unknown" => "מצב MTA לא ידוע",
                _ => "MTA טרם נבדק"
            },
            _ => ExistingStatus
        };

    internal string MailRouteHintLocalized(int language) =>
        language switch
        {
            0 => TransportMode switch
            {
                "connector" => "Проверенный входящий Connector",
                "direct-send" => "Только внутренние получатели",
                _ => NotDeployablePlan ? "Несколько ящиков: только план" :
                    string.IsNullOrWhiteSpace(Mailbox) ? "(ящик не выбран)" : DisplayMailbox
            },
            2 => TransportMode switch
            {
                "connector" => "מחבר נכנס מאושר",
                "direct-send" => "נמענים פנימיים בלבד",
                _ => NotDeployablePlan ? "ריבוי תיבות: תכנון בלבד" :
                    string.IsNullOrWhiteSpace(Mailbox) ? "(תיבה לא נבחרה)" : DisplayMailbox
            },
            _ => MailRouteHint
        };

    internal string ClientInstructions(int lang)
    {
        string route = MailRoutingGuidance.Explain(TransportMode, SenderPolicy,
            OAuthSenderMode, Mailbox, OutboundMx, EopFixedSender,
            VerifiedDomain, SmtpPort, KeepExisting, lang);
        if (NotDeployablePlan)
            return route + "\r\n" + (lang switch
            {
                0 => "НЕ ПЕРЕКЛЮЧАЙТЕ ПРИЛОЖЕНИЯ. Многопользовательский XOAUTH2 только планируется: установка и отправка не разрешены.\r\n",
                2 => "אין לעבור למסלול זה לפני אימות הרשאות ושולחים.\r\n",
                _ => "DO NOT SWITCH APPLICATIONS. Multi-mailbox XOAUTH2 cannot be installed or used yet.\r\n"
            });
        if (TransportMode is "connector" or "direct-send")
        {
            string proposedClientHost = ServerForClient;
            string scope = TransportMode == "direct-send"
                ? (lang == 0 ? "Только внутренние получатели Microsoft 365.\r\n"
                    : lang == 2 ? "רק נמענים פנימיים ב-Microsoft 365.\r\n"
                    : "Microsoft 365 internal recipients ONLY.\r\n")
                : (lang == 0 ? "Внутренние и внешние получатели (только через проверенный Connector).\r\n"
                    : lang == 2 ? "נמענים פנימיים וחיצוניים בכפוף ל-Connector תקין.\r\n"
                    : "Internal and external recipients (verified Connector required).\r\n");
            return route + "\r\n" + (lang switch
            {
                0 => "ПАРАМЕТРЫ ДЛЯ ПРИЛОЖЕНИЙ (план; установка ещё не проверена):\r\n" +
                     "  SMTP Linux: " + proposedClientHost + ":" + DisplayPort + "\r\n" +
                     "  Исходящий Microsoft 365: " + OutboundDescription + "\r\n" +
                     "  Отправитель: " + MailRoutingGuidance.SenderResult(
                         TransportMode, SenderPolicy, OAuthSenderMode, Mailbox, EopFixedSender, lang) + "\r\n" +
                     "  Отдельная очередь: /var/spool/linuxmailrelay365-sidecar\r\n" +
                     "  SMTP AUTH/STARTTLS: включить и проверить отдельно; не предполагать их наличие.\r\n",
                2 => "הגדרות SMTP מוצעות: " + proposedClientHost + ":" + DisplayPort +
                     "\r\nיעד Microsoft 365: " + OutboundDescription +
                     "\r\nיש לבדוק SMTP AUTH/STARTTLS לפני השימוש.\r\n",
                _ => "PROPOSED CLIENT SETTINGS (not verified installed):\r\n" +
                     "  Linux SMTP: " + proposedClientHost + ":" + DisplayPort + "\r\n" +
                     "  Outbound Microsoft 365: " + OutboundDescription + "\r\n" +
                     "  Sender: " + MailRoutingGuidance.SenderResult(
                         TransportMode, SenderPolicy, OAuthSenderMode, Mailbox, EopFixedSender, lang) + "\r\n" +
                     "  Dedicated queue: /var/spool/linuxmailrelay365-sidecar\r\n" +
                     "  SMTP AUTH/STARTTLS: enable and verify separately; never assume enabled.\r\n"
            }) + scope + (lang switch
            {
                0 => "Сначала проверьте установленную конфигурацию, права отправителей и реальную доставку. Не переключайте старые программы автоматически.\r\n",
                2 => "יש לאמת את המסלול וההרשאות לפני שינוי היישומים.\r\n",
                _ => "Verify installed route, sender rights and real delivery first. Never silently switch existing apps.\r\n"
            });
        }
        string listener = ServerForClient;
        string port = DisplayPort;
        string mta = ExistingStatusLocalized(lang);
        string sender = DisplayMailbox;
        string tenant = DisplayTenant;
        string host = DisplayHost;
        string networks = string.IsNullOrWhiteSpace(TrustedCidrs)
            ? "(not specified)" : OneLine(TrustedCidrs, 400);
        if (lang == 1) return
            "LinuxMailRelay365 | Preserve Existing Mail | PROPOSED CONFIGURATION (not confirmed installed)\r\n" +
            "Linux SSH host: " + host + "\r\n" +
            "Detected MTA: " + mta + "\r\n" +
            "EXISTING APPLICATIONS: continue using their existing SMTP server/port, routes and queue.\r\n" +
            "NEW APPLICATIONS (send via Microsoft 365):\r\n" +
            "  SMTP server: " + listener + "\r\n" +
            "  SMTP port: " + port + "\r\n" +
            "  SMTP AUTH: not enabled by default; optional private-sidecar AUTH requires explicit setup.\r\n" +
            "  SMTP TLS to Linux: not enabled by default; mandatory STARTTLS after explicit hardening.\r\n" +
            "  Sender (From/envelope): rewritten to " + sender + "\r\n" +
            "  Recipient (To): preserved; Microsoft 365 routes it normally.\r\n" +
            "  Entra tenant: " + tenant + "\r\n" +
            "  Trusted client CIDRs: " + networks + "\r\n" +
            "  Isolated queue: /var/spool/linuxmailrelay365-sidecar\r\n" +
            "  Linux service: linuxmailrelay365-sidecar.service\r\n" +
            (LocalOnly ? "  The application must run ON THIS LINUX HOST. Remote clients cannot use 127.0.0.1 on a different machine.\r\n" :
                         "  Remote clients must be in a trusted CIDR; an administrator must explicitly allow the selected port through firewall.\r\n") +
            "  Public internet SMTP: NOT SUPPORTED / NOT ENABLED.\r\n" +
            "  Verify installed SMTP AUTH/TLS status before changing client settings.\r\n" +
            "Do not switch an existing application automatically. Verify an actual test message and Exchange delivery first.\r\n";
        if (lang == 2) return
            "LinuxMailRelay365 | שימור דואר קיים | הגדרות מוצעות (טרם אומתו)\r\n" +
            "שרת Linux: " + host + "\r\n" +
            "שרת דואר קיים: " + mta + "\r\n" +
            "יישומים קיימים: אין שינוי ביציאות, בניתוב או בתור הדואר.\r\n" +
            "יישומים חדשים:\r\n  שרת SMTP: " + listener +
            "\r\n  יציאת SMTP: " + port +
            "\r\n  אימות SMTP: כבוי כברירת מחדל (ניתן להפעיל בנפרד)\r\n  STARTTLS: כבוי כברירת מחדל (חובה לאחר הפעלה מפורשת)" +
            "\r\n  כתובת השולח: " + sender + "\r\n  נמען: נשאר ללא שינוי" +
            "\r\n  Tenant: " + tenant + "\r\n  רשתות מהימנות: " + networks +
            "\r\n  תור נפרד: /var/spool/linuxmailrelay365-sidecar\r\n" +
            (LocalOnly ? "גישה מקומית בלבד (127.0.0.1).\r\n" :
                         "יש לאשר גישה רק מהרשתות המהימנות בחומת האש.\r\n") +
            "SMTP ציבורי אינו מופעל. יש לבדוק מסירה בפועל לפני שינוי יישומים.\r\n";
        return
            "LinuxMailRelay365 | Preserve Existing Mail | ПЛАН (установка не подтверждена)\r\n" +
            "Linux (SSH): " + host + "\r\n" +
            "Обнаруженная почтовая система: " + mta + "\r\n" +
            "СТАРЫЕ ПРИЛОЖЕНИЯ: продолжают работать через прежние SMTP, маршруты и очередь.\r\n" +
            "НОВЫЕ ПРИЛОЖЕНИЯ для отправки через Microsoft 365:\r\n" +
            "  SMTP-сервер: " + listener + "\r\n" +
            "  SMTP-порт: " + port + "\r\n" +
            "  SMTP AUTH: по умолчанию выключен; для отдельного Postfix включается явно.\r\n" +
            "  STARTTLS до Linux: по умолчанию выключен; после явного включения обязателен.\r\n" +
            "  Отправитель From/envelope: будет заменён на " + sender + "\r\n" +
            "  Получатель To: остаётся прежним; доставку выполняет Microsoft 365.\r\n" +
            "  Tenant: " + tenant + "\r\n" +
            "  Доверенные сети: " + networks + "\r\n" +
            "  Отдельная очередь: /var/spool/linuxmailrelay365-sidecar\r\n" +
            "  Служба Linux: linuxmailrelay365-sidecar.service\r\n" +
            (LocalOnly
                ? "  Только для приложений НА ЭТОМ Linux! 127.0.0.1 на другом компьютере — это другой компьютер.\r\n"
                : "  Для удалённых приложений нужно разрешить выбранный порт в firewall ТОЛЬКО из доверенных подсетей.\r\n") +
            "  SMTP из всего интернета: НЕ ПОДДЕРЖИВАЕТСЯ / НЕ ОТКРЫВАЕТСЯ.\r\n" +
            "Не переключайте действующие приложения автоматически. Сначала проверьте тестовое письмо и фактическую доставку.\r\n";
    }

    internal static bool SelfTest()
    {
        var sample = new PreserveFlowSnapshot("mx01.example.org", "10.20.30.40",
            "2626", "linux-alerts@example.org", "11111111-1111-1111-1111-111111111111",
            "10.20.30.0/24", "postfix", false);
        string instructions = sample.ClientInstructions(1);
        if (!instructions.Contains("10.20.30.40") || !instructions.Contains("2626") ||
            !instructions.Contains("linux-alerts@example.org") ||
            !instructions.Contains("preserved", StringComparison.OrdinalIgnoreCase)) return false;
        var local = sample with { Listener = "", SmtpPort = "2525", Mailbox = "" };
        var eop = sample with { TransportMode = "connector",
            OutboundMx = "example-org.mail.protection.outlook.com",
            EopFixedSender = "alerts@example.org", SenderPolicy = "preserve-domain" };
        var direct = sample with { TransportMode = "direct-send",
            OutboundMx = "example-org.mail.protection.outlook.com",
            EopFixedSender = "alerts@example.org" };
        var multiple = sample with { OAuthSenderMode = "authorized-multiple-mailboxes" };
        return sample.ExistingStatusLocalized(0).Contains("Postfix") &&
               local.ExistingStatusLocalized(0).Contains("Postfix") &&
               (sample with { ExistingMta = null }).ExistingStatusLocalized(0).Contains("не проверен") &&
               direct.MailRouteHintLocalized(0).Contains("внутренние") &&
               eop.ClientInstructions(1).Contains("Connector") &&
               eop.ClientInstructions(1).Contains("external recipients") &&
               direct.ClientInstructions(1).Contains("internal recipients ONLY") &&
               !direct.ClientInstructions(1).Contains("external recipients (verified Connector") &&
               multiple.NotDeployablePlan && multiple.ClientInstructions(1).Contains("DO NOT SWITCH") &&
               local.ServerForClient == "127.0.0.1" &&
               local.ClientInstructions(0).Contains("НА ЭТОМ Linux") &&
               local.DisplayMailbox == "(not selected)" &&
               local.ClientInstructions(1).Contains("127.0.0.1") &&
               !instructions.Contains("password", StringComparison.OrdinalIgnoreCase);
    }
}

internal sealed class PreserveMailFlowPreview : Control
{
    private PreserveFlowSnapshot state = new("", "", "2525", "", "", "", null, false);
    private int language;

    internal PreserveMailFlowPreview()
    {
        BackColor = Color.White;
        Width = 890;
        Height = 286;
        MinimumSize = new Size(280, 240);
        Margin = new Padding(0, 8, 0, 12);
        Font = new Font("Segoe UI", 10f);
        AccessibleRole = AccessibleRole.Graphic;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
    }

    internal void UpdateData(PreserveFlowSnapshot snapshot, int languageIndex)
    {
        state = snapshot;
        language = languageIndex;
        AccessibleName = language switch
        {
            1 => "Diagram: old mail unchanged, new applications through separate SMTP to Microsoft 365",
            2 => "תרשים דואר קיים ודואר חדש",
            _ => "Схема: существующая почта без изменений, новые приложения через отдельный SMTP в Microsoft 365"
        };
        AccessibleDescription = state.ClientInstructions(languageIndex);
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        if (Width <= 10 || Height <= 10) return;
        var graphics = e.Graphics;
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        graphics.Clear(BackColor);
        if (Width < 790)
        {
            DrawCompact(graphics);
            return;
        }
        var previous = graphics.Save();
        graphics.ScaleTransform(Width / 890f, Height / 286f);
        try
        {
            using var border = new Pen(UiTheme.Border, 1.1f);
            using var background = Rounded(new RectangleF(1, 1, 888, 284), 11);
            graphics.FillPath(Brushes.White, background);
            graphics.DrawPath(border, background);
            DrawText(graphics,
                language switch { 1 => "PRESERVE EXISTING MAIL · LIVE PREVIEW", 2 => "דואר קיים נשמר · תצוגה חיה",
                    _ => "СОХРАНЕНИЕ ПОЧТЫ · СХЕМА ИЗ ВВЕДЁННЫХ ДАННЫХ" },
                new RectangleF(18, 12, 670, 23), 11, UiTheme.Navy, bold: true);
            DrawText(graphics, language switch { 1 => "NOT DEPLOYED", 2 => "טרם הותקן",
                _ => "НЕ ПОДТВЕРЖДЕНО" }, new RectangleF(699, 12, 170, 23), 9, UiTheme.Muted);

            DrawCard(graphics, 18, 48, false, state.KeepExisting
                ? language switch { 1 => "EXISTING APPLICATIONS", 2 => "יישומים קיימים", _ => "СУЩЕСТВУЮЩИЕ ПРОГРАММЫ" }
                : language switch { 1 => "EXISTING APPS · RISK", 2 => "יישומים קיימים", _ => "СТАРЫЕ ПРОГРАММЫ · РИСК" },
                language switch { 1 => "Existing SMTP settings", 2 => "הגדרות קודמות", _ => "Старые настройки SMTP" },
                state.KeepExisting
                    ? language switch { 1 => "No client changes", 2 => "ללא שינוי", _ => "Без изменений" }
                    : language switch { 1 => "Replacement requires approval", 2 => "נדרש אישור", _ => "Замена требует согласия" });
            DrawArrow(graphics, 270, 97, UiTheme.Muted);
            DrawCard(graphics, 322, 48, false, language switch
                { 1 => "PRIMARY MAIL SERVER", 2 => "שרת הדואר הקיים", _ => "ДЕЙСТВУЮЩИЙ MTA" },
                state.ExistingStatusLocalized(language),
                state.KeepExisting
                    ? language switch { 1 => "Current config and queue", 2 => "תצורה ותור קיימים",
                        _ => "Текущие маршруты и очередь" }
                    : language switch { 1 => "Backup before changes", 2 => "גיבוי לפני שינויים",
                        _ => "Перед заменой — backup" });
            DrawArrow(graphics, 574, 97, UiTheme.Muted);
            DrawCard(graphics, 626, 48, false, language switch
                { 1 => "CURRENT DESTINATIONS", 2 => "יעדים קיימים", _ => "ПРЕЖНЯЯ ДОСТАВКА" },
                state.KeepExisting
                    ? language switch { 1 => "Unchanged routing", 2 => "ניתוב ללא שינוי", _ => "Без изменения маршрутов" }
                    : language switch { 1 => "REPLACE: extra review", 2 => "דרוש אישור נוסף",
                        _ => "ЗАМЕНА: нужна проверка" },
                state.KeepExisting
                    ? language switch { 1 => "No rerouting to M365", 2 => "אין העברה אוטומטית",
                        _ => "Не переключаем в 365" }
                    : language switch { 1 => "Service interruption risk", 2 => "סיכון להפרעה",
                        _ => "Риск простоя почты" });

            DrawCard(graphics, 18, 148, true, language switch
                { 1 => "NEW APPLICATIONS", 2 => "יישומים חדשים", _ => "НОВЫЕ ПРИЛОЖЕНИЯ" },
                state.ServerForClient + ":" + state.DisplayPort,
                state.LocalOnly ? language switch
                    { 1 => "Localhost only", 2 => "רק שרת Linux זה", _ => "Только этот Linux" } :
                    language switch { 1 => "Trusted networks only", 2 => "רשתות מהימנות בלבד",
                        _ => "Только доверенные сети" });
            DrawArrow(graphics, 270, 197, UiTheme.Accent);
            DrawCard(graphics, 322, 148, true, language switch
                { 1 => "ISOLATED POSTFIX", 2 => "Postfix נפרד", _ => "ОТДЕЛЬНЫЙ POSTFIX" },
                language switch { 1 => "Dedicated mail queue", 2 => "תור נפרד", _ => "Своя очередь" },
                language switch { 1 => "Separate service, port", 2 => "שירות ויציאה נפרדים",
                    _ => "Отдельная служба и порт" });
            DrawArrow(graphics, 574, 197, UiTheme.Accent);
            DrawCard(graphics, 626, 148, true,
                state.MailRouteTitle,
                state.MailRouteHintLocalized(language),
                state.NotDeployablePlan
                    ? language switch { 1 => "PLAN ONLY · not deployable", 2 => "תכנון בלבד",
                        _ => "ТОЛЬКО ПЛАН" }
                    : state.TransportMode == "direct-send"
                    ? language switch { 1 => "Internal recipients ONLY", 2 => "נמענים פנימיים",
                        _ => "Только внутри M365" }
                    : language switch { 1 => "Recipients preserved", 2 => "הנמען נשמר",
                        _ => "Получатель сохраняется" });

            DrawText(graphics, "Linux: " + state.DisplayHost +
                "    |    " + (language switch { 0 => "Исходящий маршрут: ", 2 => "מסלול יוצא: ",
                    _ => "Outbound: " }) + state.OutboundDescription,
                new RectangleF(18, 251, 694, 20), 9, UiTheme.Muted);
            if (state.PublicRequested)
                DrawText(graphics, language switch {
                    0 => "ПУБЛИЧНЫЙ SMTP: ЗАКРЫТ", 2 => "SMTP ציבורי: חסום",
                    _ => "PUBLIC SMTP: BLOCKED" },
                    new RectangleF(697, 251, 180, 20), 8.6f, Color.FromArgb(154, 52, 49), bold: true);
        }
        finally { graphics.Restore(previous); }
    }

    // Narrow windows use readable vertical lanes rather than shrinking a
    // wide diagram to 30–70% and losing all captions.
    private void DrawCompact(Graphics g)
    {
        using var border = new Pen(UiTheme.Border, 1.1f);
        using var background = Rounded(new RectangleF(1, 1, Width - 2, Height - 2), 10);
        g.FillPath(Brushes.White, background);
        g.DrawPath(border, background);
        DrawText(g, language switch
        {
            0 => "СХЕМА ПОЧТОВЫХ МАРШРУТОВ", 2 => "תרשים מסלולי הדואר",
            _ => "MAIL ROUTES · LIVE PREVIEW"
        }, new RectangleF(15, 10, Width - 30, 22), 10.5f, UiTheme.Navy, bold: true);
        DrawText(g, language switch
        {
            0 => "ПЛАН · НЕ ПОДТВЕРЖДЕНО", 2 => "תכנון בלבד · טרם אומת",
            _ => "PLAN ONLY · NOT VERIFIED"
        }, new RectangleF(15, 34, Width - 30, 17), 8.8f, UiTheme.Muted);
        DrawText(g, language switch
        {
            0 => "ТЕКУЩАЯ ПОЧТА", 2 => "דואר קיים", _ => "EXISTING MAIL"
        }, new RectangleF(16, 57, Width - 32, 18), 10, UiTheme.Navy, bold: true);
        DrawCompactCard(g, 80, false,
            language switch { 0 => "ПРОГРАММЫ", 2 => "יישומים קיימים", _ => "APPLICATIONS" },
            language switch { 0 => "Старые настройки SMTP", 2 => "הגדרות SMTP קודמות",
                _ => "Existing SMTP settings" },
            state.KeepExisting ? (language switch { 0 => "Без изменений",
                2 => "ללא שינוי", _ => "Preserved" }) : (language switch {
                0 => "Изменение требует согласия", 2 => "נדרש אישור לשינוי", _ => "Approval required" }));
        DrawCompactArrow(g, 153, UiTheme.Navy);
        DrawCompactCard(g, 163, false,
            language switch { 0 => "ОСНОВНОЙ MTA", 2 => "שרת הדואר הקיים", _ => "PRIMARY MTA" },
            state.ExistingStatusLocalized(language),
            language switch { 0 => "Действующая конфигурация и очередь",
                2 => "תצורה ותור קיימים", _ => "Current configuration and queue" });
        DrawCompactArrow(g, 236, UiTheme.Navy);
        DrawCompactCard(g, 246, false,
            language switch { 0 => "ДОСТАВКА", 2 => "יעדים קיימים", _ => "DELIVERY" },
            state.KeepExisting ? (language switch { 0 => "Без смены маршрутов",
                2 => "ללא שינוי ניתוב", _ => "Routes unchanged" }) : (language switch {
                0 => "Замена требует проверки", 2 => "שינוי מחייב בדיקה", _ => "Review replacement" }),
            language switch { 0 => "Существующая почта остаётся",
                2 => "הדואר הקיים נשמר", _ => "Existing mail preserved" });
        DrawText(g, language switch
        {
            0 => "НОВЫЙ МАРШРУТ", 2 => "מסלול חדש", _ => "NEW ROUTE"
        }, new RectangleF(16, 330, Width - 32, 18), 10, UiTheme.Accent, bold: true);
        DrawCompactCard(g, 351, true,
            language switch { 0 => "НОВЫЕ ПРОГРАММЫ", 2 => "יישומים חדשים", _ => "NEW APPLICATIONS" },
            state.ServerForClient + ":" + state.DisplayPort,
            state.LocalOnly ? (language switch { 0 => "Только на этом Linux",
                2 => "רק בשרת Linux זה", _ => "Local Linux only" }) :
                (language switch { 0 => "Только доверенные сети",
                2 => "רשתות מאושרות בלבד", _ => "Trusted subnets only" }));
        DrawCompactArrow(g, 424, UiTheme.Accent);
        DrawCompactCard(g, 434, true,
            language switch { 0 => "ОТДЕЛЬНЫЙ POSTFIX", 2 => "Postfix נפרד",
                _ => "ISOLATED POSTFIX" },
            language switch { 0 => "Своя очередь", 2 => "תור דואר נפרד",
                _ => "Independent queue" },
            language switch { 0 => "Отдельный порт и служба",
                2 => "יציאה ושירות נפרדים", _ => "Separate port and service" });
        DrawCompactArrow(g, 507, UiTheme.Accent);
        DrawCompactCard(g, 517, true,
            state.MailRouteTitle, state.MailRouteHintLocalized(language),
            state.NotDeployablePlan ? (language switch {
                0 => "Только план — отправка запрещена",
                2 => "תכנון בלבד, שליחה חסומה", _ => "Plan only, cannot send" }) :
                state.TransportMode == "direct-send" ? (language switch {
                0 => "Только внутренние адресаты", 2 => "נמענים פנימיים",
                _ => "Internal only" }) : (language switch {
                0 => "Получатели сохраняются", 2 => "הנמענים נשמרים",
                _ => "Recipients preserved" }));
        DrawWrappedText(g, (language switch {
            0 => "Исходящий маршрут: ", 2 => "מסלול יוצא: ", _ => "Outbound route: " }) +
            state.OutboundDescription, new RectangleF(16, 603, Width - 32, 39),
            8.8f, UiTheme.Muted);
    }

    private void DrawCompactCard(Graphics g, float y, bool newLane,
        string heading, string main, string detail)
    {
        float width = Math.Max(240, Width - 30);
        var rect = new RectangleF(15, y, width, 69);
        using var background = new SolidBrush(newLane
            ? Color.FromArgb(242, 249, 246) : Color.FromArgb(246, 248, 251));
        using var outline = new Pen(newLane ? Color.FromArgb(175, 207, 193) : UiTheme.Border, 1);
        using var path = Rounded(rect, 8);
        g.FillPath(background, path);
        g.DrawPath(outline, path);
        using var side = new SolidBrush(newLane ? UiTheme.Accent : UiTheme.Navy);
        g.FillRectangle(side, rect.Left + 1, y + 9, 3, 52);
        var color = newLane ? UiTheme.Accent : UiTheme.Muted;
        DrawText(g, heading, new RectangleF(27, y + 4, width - 19, 15),
            8.2f, color, bold: true);
        DrawWrappedText(g, main, new RectangleF(27, y + 20, width - 19, 31),
            10f, UiTheme.Navy, bold: true);
        DrawText(g, detail, new RectangleF(27, y + 52, width - 19, 13),
            8.2f, UiTheme.Muted);
    }

    private void DrawCompactArrow(Graphics g, float y, Color color)
    {
        using var pen = new Pen(color, 1.8f) { StartCap = LineCap.Round };
        float x = Width / 2f;
        g.DrawLine(pen, x, y, x, y + 5);
        using var brush = new SolidBrush(color);
        g.FillPolygon(brush, [new PointF(x - 4, y + 4),
                              new PointF(x + 4, y + 4),
                              new PointF(x, y + 9)]);
    }

    private static void DrawWrappedText(Graphics g, string value, RectangleF bounds,
        float fontSize, Color color, bool bold = false)
    {
        using var font = new Font("Segoe UI", fontSize,
            bold ? FontStyle.Bold : FontStyle.Regular);
        using var brush = new SolidBrush(color);
        using var format = new StringFormat(StringFormat.GenericDefault)
        {
            Trimming = StringTrimming.EllipsisCharacter,
            FormatFlags = StringFormatFlags.LineLimit,
            LineAlignment = StringAlignment.Center
        };
        g.DrawString(value, font, brush, bounds, format);
    }

    private void DrawCard(Graphics g, int x, int y, bool newLane, string heading,
        string main, string detail)
    {
        var bounds = new RectangleF(x, y, 244, 84);
        using var shape = Rounded(bounds, 9);
        using var fill = new SolidBrush(newLane ? Color.FromArgb(242, 249, 246) :
                                         Color.FromArgb(246, 248, 251));
        using var outline = new Pen(newLane ? Color.FromArgb(175, 207, 193) : UiTheme.Border, 1);
        g.FillPath(fill, shape);
        g.DrawPath(outline, shape);
        using var side = new SolidBrush(newLane ? UiTheme.Accent : UiTheme.Navy);
        g.FillRectangle(side, x + 1, y + 12, 3, 59);
        DrawText(g, heading, new RectangleF(x + 11, y + 8, 223, 18), 8.4f,
            newLane ? UiTheme.Accent : UiTheme.Muted, bold: true);
        DrawText(g, main, new RectangleF(x + 11, y + 30, 223, 25), 11, UiTheme.Navy, bold: true);
        DrawText(g, detail, new RectangleF(x + 11, y + 61, 223, 16), 8.4f, UiTheme.Muted);
    }

    private static void DrawArrow(Graphics g, float x, float y, Color color)
    {
        using var pen = new Pen(color, 2.3f) { StartCap = LineCap.Round };
        g.DrawLine(pen, x, y, x + 38, y);
        using var brush = new SolidBrush(color);
        g.FillPolygon(brush, [new PointF(x + 42, y),
                              new PointF(x + 33, y - 6),
                              new PointF(x + 33, y + 6)]);
    }

    private static void DrawText(Graphics g, string value, RectangleF bounds,
        float size, Color color, bool bold = false)
    {
        using var font = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular);
        using var brush = new SolidBrush(color);
        using var format = new StringFormat(StringFormat.GenericTypographic)
        {
            Trimming = StringTrimming.EllipsisCharacter,
            FormatFlags = StringFormatFlags.NoWrap,
            Alignment = StringAlignment.Near,
            LineAlignment = StringAlignment.Center
        };
        g.DrawString(value, font, brush, bounds, format);
    }

    private static GraphicsPath Rounded(RectangleF rect, float radius)
    {
        var path = new GraphicsPath();
        float d = radius * 2;
        path.AddArc(rect.Left, rect.Top, d, d, 180, 90);
        path.AddArc(rect.Right - d, rect.Top, d, d, 270, 90);
        path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
        path.AddArc(rect.Left, rect.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }
}
