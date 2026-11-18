using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace LinuxMailRelay365;

// A data-bound preview, NOT a deployment status. No credentials or private keys.
internal sealed record PreserveFlowSnapshot(
    string LinuxHost, string Listener, string SmtpPort, string Mailbox,
    string TenantId, string TrustedCidrs, string? ExistingMta, bool PublicRequested,
    bool ConnectorPlanned = false, bool SenderPolicyPlanned = false, string VerifiedDomain = "")
{
    private static string OneLine(string? value, int limit = 120)
    {
        var clean = (value ?? "").Replace('\r', ' ').Replace('\n', ' ').Trim();
        return clean.Length <= limit ? clean : clean[..limit] + "...";
    }

    internal bool LocalOnly => string.IsNullOrWhiteSpace(Listener);
    internal bool NotDeployablePlan => ConnectorPlanned || SenderPolicyPlanned;
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
        "sendmail" or "exim" => "Existing MTA not supported by sidecar",
        "none" => "No existing MTA detected",
        "unknown" => "MTA state uncertain",
        _ => "MTA not inspected"
    };

    internal string ClientInstructions(int lang)
    {
        if (NotDeployablePlan)
        {
            string domain = string.IsNullOrWhiteSpace(VerifiedDomain)
                ? "(not specified)" : OneLine(VerifiedDomain);
            return lang switch
            {
                1 => "LinuxMailRelay365 | NOT READY TO DEPLOY\r\n" +
                     "Selected: Microsoft 365 Connector or sender-policy option not yet implemented.\r\n" +
                     "Linux: " + DisplayHost + " | SMTP port: " + DisplayPort +
                     " | Verified domain: " + domain + "\r\n" +
                     "Preserve Existing Mail means old clients stay on existing SMTP; do not switch clients to this planned route.\r\n",
                2 => "LinuxMailRelay365 | תצורה בתכנון, עדיין לא ניתנת להתקנה\r\n" +
                     "שרת: " + DisplayHost + " | יציאה: " + DisplayPort +
                     " | דומיין: " + domain + "\r\nאין לשנות הגדרות של יישומים קיימים.\r\n",
                _ => "LinuxMailRelay365 | ТОЛЬКО ПЛАН, УСТАНОВКА НЕДОСТУПНА\r\n" +
                     "Выбран режим Microsoft 365 Connector или обработки отправителя, ещё не реализованный в этом Preview.\r\n" +
                     "Linux: " + DisplayHost + " | Порт SMTP: " + DisplayPort +
                     " | Проверенный домен: " + domain + "\r\n" +
                     "Существующие приложения остаются на старом SMTP. НЕ переключайте клиентов на этот маршрут.\r\n"
            };
        }
        string listener = ServerForClient;
        string port = DisplayPort;
        string mta = ExistingStatus;
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
            "  SMTP AUTH: not available on the sidecar in this preview.\r\n" +
            "  SMTP TLS to Linux: not available on the sidecar in this preview.\r\n" +
            "  Sender (From/envelope): rewritten to " + sender + "\r\n" +
            "  Recipient (To): preserved; Microsoft 365 routes it normally.\r\n" +
            "  Entra tenant: " + tenant + "\r\n" +
            "  Trusted client CIDRs: " + networks + "\r\n" +
            "  Isolated queue: /var/spool/linuxmailrelay365-sidecar\r\n" +
            "  Linux service: linuxmailrelay365-sidecar.service\r\n" +
            (LocalOnly ? "  The application must run ON THIS LINUX HOST. Remote clients cannot use 127.0.0.1 on a different machine.\r\n" :
                         "  Remote clients must be in a trusted CIDR; an administrator must explicitly allow the selected port through firewall.\r\n") +
            "  Public internet SMTP: NOT SUPPORTED / NOT ENABLED.\r\n" +
            "Do not switch an existing application automatically. Verify an actual test message and Exchange delivery first.\r\n";
        if (lang == 2) return
            "LinuxMailRelay365 | שימור דואר קיים | הגדרות מוצעות (טרם אומתו)\r\n" +
            "שרת Linux: " + host + "\r\n" +
            "שרת דואר קיים: " + mta + "\r\n" +
            "יישומים קיימים: אין שינוי ביציאות, בניתוב או בתור הדואר.\r\n" +
            "יישומים חדשים:\r\n  שרת SMTP: " + listener +
            "\r\n  יציאת SMTP: " + port +
            "\r\n  אימות SMTP: לא זמין בגרסה זו\r\n  TLS נכנס: לא זמין בגרסה זו" +
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
            "  SMTP AUTH: в этом Preview для локального SMTP не реализован.\r\n" +
            "  Входящий TLS до Linux: в этом Preview не реализован.\r\n" +
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
        return local.ServerForClient == "127.0.0.1" &&
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
        MinimumSize = new Size(640, 250);
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
                    _ => "PRESERVE EXISTING MAIL · СХЕМА ИЗ ВВЕДЁННЫХ ДАННЫХ" },
                new RectangleF(18, 12, 670, 23), 11, UiTheme.Navy, bold: true);
            DrawText(graphics, language switch { 1 => "NOT DEPLOYED", 2 => "טרם הותקן",
                _ => "НЕ ПОДТВЕРЖДЕНО" }, new RectangleF(699, 12, 170, 23), 9, UiTheme.Muted);

            DrawCard(graphics, 18, 48, false, language switch
                { 1 => "EXISTING APPLICATIONS", 2 => "יישומים קיימים", _ => "СУЩЕСТВУЮЩИЕ ПРОГРАММЫ" },
                language switch { 1 => "Existing SMTP settings", 2 => "הגדרות קודמות", _ => "Старые настройки SMTP" },
                language switch { 1 => "No client changes", 2 => "ללא שינוי", _ => "Без изменений" });
            DrawArrow(graphics, 270, 97, UiTheme.Muted);
            DrawCard(graphics, 322, 48, false, language switch
                { 1 => "PRIMARY MAIL SERVER", 2 => "שרת הדואר הקיים", _ => "ДЕЙСТВУЮЩИЙ MTA" },
                state.ExistingStatus,
                language switch { 1 => "Current config and queue", 2 => "תצורה ותור קיימים",
                    _ => "Текущие маршруты и очередь" });
            DrawArrow(graphics, 574, 97, UiTheme.Muted);
            DrawCard(graphics, 626, 48, false, language switch
                { 1 => "CURRENT DESTINATIONS", 2 => "יעדים קיימים", _ => "ПРЕЖНЯЯ ДОСТАВКА" },
                language switch { 1 => "Unchanged routing", 2 => "ניתוב ללא שינוי", _ => "Без изменения маршрутов" },
                language switch { 1 => "No rerouting to M365", 2 => "אין העברה אוטומטית",
                    _ => "Не переключаем в 365" });

            DrawCard(graphics, 18, 148, true, language switch
                { 1 => "NEW APPLICATIONS", 2 => "יישומים חדשים", _ => "НОВЫЕ ПРИЛОЖЕНИЯ" },
                state.ServerForClient + ":" + state.DisplayPort,
                state.LocalOnly ? (language == 1 ? "Localhost only" : "Только этот Linux") :
                    (language == 1 ? "Trusted networks only" : "Только доверенные сети"));
            DrawArrow(graphics, 270, 197, UiTheme.Accent);
            DrawCard(graphics, 322, 148, true, language switch
                { 1 => "ISOLATED POSTFIX", 2 => "Postfix נפרד", _ => "ОТДЕЛЬНЫЙ POSTFIX" },
                language switch { 1 => "Dedicated mail queue", 2 => "תור נפרד", _ => "Своя очередь" },
                language switch { 1 => "Separate service, port", 2 => "שירות ויציאה נפרדים",
                    _ => "Отдельная служба и порт" });
            DrawArrow(graphics, 574, 197, UiTheme.Accent);
            DrawCard(graphics, 626, 148, true,
                state.NotDeployablePlan ? "M365 · NOT IMPLEMENTED" : "MICROSOFT 365",
                state.NotDeployablePlan ? "PLANNED ROUTE" : state.DisplayMailbox,
                state.NotDeployablePlan
                    ? (language == 1 ? "Do not switch clients" : "Не переключать клиентов")
                    : (language == 1 ? "Recipient is preserved" : "Получатель сохраняется"));

            DrawText(graphics, (language == 1 ? "Linux: " : "Linux: ") + state.DisplayHost +
                "    |    Tenant: " + state.DisplayTenant,
                new RectangleF(18, 251, 694, 20), 9, UiTheme.Muted);
            if (state.PublicRequested)
                DrawText(graphics, language == 1 ? "PUBLIC SMTP: BLOCKED" : "PUBLIC SMTP: ЗАБЛОКИРОВАН",
                    new RectangleF(697, 251, 180, 20), 8.6f, Color.FromArgb(154, 52, 49), bold: true);
        }
        finally { graphics.Restore(previous); }
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
