namespace LinuxMailRelay365;

/// <summary>
/// Pure explanation of an operator's intended delivery route.  Never reads
/// secrets, contacts Linux/Microsoft 365 or implies that a route is installed.
/// Used by the Wizard and by the data-bound on-screen mail-flow diagram.
/// </summary>
internal static class MailRoutingGuidance
{
    internal static bool IsUnimplementedOAuthMultiSender(string transport, string mode) =>
        transport == "oauth2" && mode == "authorized-multiple-mailboxes";

    internal static string Outbound(string transport, string mx)
    {
        if (transport == "oauth2") return "smtp.office365.com:587 · STARTTLS/XOAUTH2";
        string host = string.IsNullOrWhiteSpace(mx)
            ? "(enter tenant Microsoft 365 MX)" : mx.Trim();
        return host + ":25 · STARTTLS/EOP";
    }

    internal static string SenderResult(string transport, string senderPolicy,
                                        string oauthMode, string mailbox,
                                        string fixedSender, int lang)
    {
        string from = string.IsNullOrWhiteSpace(mailbox) ? "(mailbox not entered)" : mailbox.Trim();
        string eop = string.IsNullOrWhiteSpace(fixedSender) ? "(sender not entered)" : fixedSender.Trim();
        if (transport == "oauth2")
        {
            if (oauthMode == "authorized-multiple-mailboxes")
                return lang switch
                {
                    0 => "Сохранять From каждого пользователя — ТОЛЬКО ПЛАН, отправка заблокирована",
                    2 => "שמירת From לכל שולח — תכנון בלבד, שליחה חסומה",
                    _ => "Preserve each user's From — PLAN ONLY, delivery blocked"
                };
            return lang switch
            {
                0 => "Все From и MAIL FROM будут заменены на " + from,
                2 => "כל כתובות From ו-MAIL FROM יוחלפו ל-" + from,
                _ => "All From and MAIL FROM rewritten to " + from
            };
        }
        if (transport == "direct-send" || senderPolicy == "fixed-mailbox")
            return lang switch
            {
                0 => "Единый разрешённый отправитель: " + eop,
                2 => "שולח מאושר קבוע: " + eop,
                _ => "One approved fixed sender: " + eop
            };
        if (senderPolicy == "masquerade")
            return lang switch
            {
                0 => "Поддоменные адреса маскируются под подтверждённый домен; нужны SMTP AUTH + From Guard",
                2 => "שכתוב שולחים מתת-דומיין מחייב SMTP AUTH והגנת From",
                _ => "Subdomain sender masquerading requires SMTP AUTH + From Guard"
            };
        return lang switch
        {
            0 => "Исходные отправители сохраняются при проверке SMTP-логина и From Guard",
            2 => "שמירת שולח דורשת בדיקת SMTP והגנת From",
            _ => "Preserve original senders with verified SMTP login and From Guard"
        };
    }

    internal static string Explain(string transport, string senderPolicy,
                                   string oauthMode, string mailbox, string mx,
                                   string fixedSender, string acceptedDomain,
                                   string incomingPort, bool preserveExisting, int lang)
    {
        string sender = SenderResult(transport, senderPolicy, oauthMode,
                                     mailbox, fixedSender, lang);
        string outbound = Outbound(transport, mx);
        string from = string.IsNullOrWhiteSpace(acceptedDomain)
            ? "(domain not entered)" : acceptedDomain.Trim();
        string port = string.IsNullOrWhiteSpace(incomingPort) ? "(port not selected)" : incomingPort.Trim();
        string isolation = preserveExisting
            ? lang == 0 ? "Существующий MTA и его очередь не меняются."
              : lang == 2 ? "שרת הדואר הקיים והתור שלו לא משתנים."
              : "Existing MTA and queue remain untouched."
            : lang == 0 ? "Изменение основного MTA требует backup и отдельного подтверждения."
              : lang == 2 ? "שינוי שרת הדואר הראשי דורש גיבוי ואישור."
              : "Changing the primary MTA requires a backup and separate approval.";
        string intro, scope, requirements, warning;
        switch (transport)
        {
            case "connector":
                intro = lang == 0 ? "SMTP Relay через Microsoft 365 Connector"
                    : lang == 2 ? "ממסר SMTP באמצעות Microsoft 365 Connector"
                    : "SMTP Relay through Microsoft 365 Connector";
                scope = lang == 0 ? "Внутренние и внешние получатели."
                    : lang == 2 ? "נמענים פנימיים וחיצוניים."
                    : "Internal and external recipients.";
                requirements = lang == 0
                    ? "Нужны принятый домен " + from + ", проверенный Inbound Connector, публичный исходящий IP или TLS-сертификат и исходящий TCP 25."
                    : lang == 2 ? "נדרש דומיין מאושר, Connector, כתובת IP ציבורית או אישור TLS, ויציאת 25."
                    : "Requires accepted domain " + from + ", verified Inbound Connector, public egress IP or TLS certificate and outbound TCP 25.";
                warning = lang == 0
                    ? "Много отправителей: перед применением обязательно включить SMTP AUTH/STARTTLS, карту владельцев и проверку From (Milter)."
                    : lang == 2 ? "שולחים מרובים מחייבים SMTP AUTH/STARTTLS, מיפוי והרשאות From."
                    : "Multiple senders require SMTP AUTH/STARTTLS, sender-ownership map and RFC5322 From Guard before deployment.";
                break;
            case "direct-send":
                intro = "Direct Send";
                scope = lang == 0 ? "Только внутренние адресаты Microsoft 365. Gmail и внешняя почта заблокированы."
                    : lang == 2 ? "נמענים פנימיים בלבד; דואר חיצוני חסום."
                    : "Microsoft 365 internal recipients ONLY; Gmail and external recipients are blocked.";
                requirements = lang == 0
                    ? "Нужны принятый домен " + from + ", MX Microsoft 365, исходящий TCP 25 и корректные DNS/SPF."
                    : lang == 2 ? "נדרש דומיין מאושר, MX, יציאת 25 ו-SPF תקין."
                    : "Requires accepted domain " + from + ", Microsoft 365 MX, outbound TCP 25 and correct DNS/SPF.";
                warning = lang == 0 ? "Не нужен Entra App, OAuth или Connector; это не универсальная отправка в интернет."
                    : lang == 2 ? "אין צורך ב-OAuth או Connector; זו אינה שליחה לכל האינטרנט."
                    : "No Entra app, OAuth or Connector is needed. Not a general internet relay.";
                break;
            default:
                intro = "XOAUTH2 · Microsoft 365 SMTP AUTH";
                scope = lang == 0 ? "Внутренние и внешние получатели."
                    : lang == 2 ? "נמענים פנימיים וחיצוניים."
                    : "Internal and external recipients.";
                requirements = lang == 0
                    ? "Нужны Entra App, сертификат, SMTP.SendAsApp, разрешения Exchange для конкретного mailbox и исходящие TCP 443/587."
                    : lang == 2 ? "נדרש יישום Entra, אישור, SMTP.SendAsApp, הרשאות תיבה ויציאות 443/587."
                    : "Requires Entra app, certificate, SMTP.SendAsApp, Exchange mailbox permissions and outbound TCP 443/587.";
                warning = IsUnimplementedOAuthMultiSender(transport, oauthMode)
                    ? lang == 0
                        ? "МНОГОПОЛЬЗОВАТЕЛЬСКИЙ XOAUTH2 ЕЩЁ НЕ ПРИМЕНЯЕТСЯ: перед запуском нужны проверка каждой пары SMTP login→From→mailbox, защита подмены заголовка и отдельные Exchange-права. GUI сохраняет только план."
                        : lang == 2
                        ? "XOAUTH2 מרובה שולחים אינו פעיל; נדרש מיפוי ואימות הרשאות."
                        : "MULTI-MAILBOX XOAUTH2 IS NOT DEPLOYABLE YET: sender/login/mailbox authorization, From guard and Exchange grants require verified implementation. The GUI saves a plan only."
                    : lang == 0
                        ? "Текущая реализация работает от имени ОДНОГО mailbox и перезаписывает From. Пароли M365 не нужны."
                        : lang == 2
                        ? "היישום הנוכחי שולח מתיבה אחת ומשכתב את From."
                        : "Current transport sends from ONE mailbox and rewrites From. No M365 mailbox password is required.";
                break;
        }
        string inbound = lang == 0 ? "Входящие программы → Linux SMTP:" + port
            : lang == 2 ? "יישומים → Linux SMTP:" + port
            : "Applications → Linux SMTP:" + port;
        string outboundTitle = lang == 0 ? "Исходящий маршрут: "
            : lang == 2 ? "מסלול יוצא: " : "Outbound route: ";
        string status = lang == 0 ? "ПОКАЗАН ПЛАН — НЕ ПОДТВЕРЖДЕНО, ЧТО СЕРВЕР НАСТРОЕН"
            : lang == 2 ? "תכנון בלבד — לא נבדקה התקנה"
            : "PLAN PREVIEW ONLY — NOT PROOF OF DEPLOYMENT";
        return intro + Environment.NewLine + inbound + Environment.NewLine +
               outboundTitle + outbound + Environment.NewLine + sender +
               Environment.NewLine + scope + Environment.NewLine + requirements +
               Environment.NewLine + warning + Environment.NewLine +
               isolation + Environment.NewLine + status;
    }

    internal static bool SelfTest()
    {
        string single = Explain("oauth2", "fixed-mailbox", "fixed-mailbox",
            "relay@example.org", "", "", "", "2525", true, 0);
        string multi = Explain("oauth2", "fixed-mailbox", "authorized-multiple-mailboxes",
            "relay@example.org", "", "", "", "2525", true, 0);
        string connector = Explain("connector", "preserve-domain", "fixed-mailbox",
            "", "example-org.mail.protection.outlook.com", "alerts@example.org",
            "example.org", "2526", true, 1);
        string direct = Explain("direct-send", "fixed-mailbox", "fixed-mailbox",
            "", "example-org.mail.protection.outlook.com", "alerts@example.org",
            "example.org", "2526", true, 1);
        return single.Contains("From") && single.Contains("587") &&
               single.Contains("relay@example.org") &&
               !IsUnimplementedOAuthMultiSender("oauth2", "fixed-mailbox") &&
               IsUnimplementedOAuthMultiSender("oauth2", "authorized-multiple-mailboxes") &&
               multi.Contains("НЕ ПРИМЕНЯЕТСЯ") &&
               connector.Contains("From Guard") && connector.Contains("25") &&
               connector.Contains("external") &&
               direct.Contains("internal recipients ONLY") &&
               direct.Contains("external recipients are blocked") &&
               !direct.Contains("SMTP.SendAsApp");
    }
}
