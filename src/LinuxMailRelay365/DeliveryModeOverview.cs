namespace LinuxMailRelay365;

/// <summary>
/// Localized operator guidance only. Never claims that a route is installed.
/// The actual deployment gate remains in MailRoutingPlan and Linux auditors.
/// </summary>
internal sealed record DeliveryModeDescription(
    string Name, string Target, string Audience, string Authorization,
    string Sender, string Requirements, string Safety);

internal static class DeliveryModeOverview
{
    internal static DeliveryModeDescription Describe(int mode, int language, bool multiMailbox)
    {
        if (mode is < 0 or > 2)
            throw new ArgumentOutOfRangeException(nameof(mode));
        if (language is < 0 or > 2)
            language = 1;
        return (mode, language) switch
        {
            (0, 0) => new("XOAUTH2 / SMTP AUTH",
                "smtp.office365.com:587 + STARTTLS",
                "Внутренние и внешние адресаты",
                "Приложение Entra и сертификат; пароль почтового ящика не требуется",
                multiMailbox
                    ? "Несколько отправителей — ТОЛЬКО ПЛАН, пересылка заблокирована"
                    : "Один M365 mailbox; From и MAIL FROM заменяются на его адрес",
                "Исходящие TCP 443/587, SMTP.SendAsApp и подтверждённые права Exchange",
                multiMailbox
                    ? "Нельзя применять: ещё нет подтверждённой привязки SMTP login к очереди, отдельного XOAUTH2 mailbox и проверенного Send As"
                    : "После настройки проверьте токен, SMTP AUTH и отдельную тестовую доставку"),
            (0, 2) => new("XOAUTH2 / SMTP AUTH",
                "smtp.office365.com:587 + STARTTLS",
                "נמענים פנימיים וחיצוניים",
                "יישום Entra ואישור; אין צורך בסיסמת תיבת הדואר",
                multiMailbox ? "ריבוי תיבות — תכנון בלבד; המשלוח חסום" : "תיבה אחת; כתובת From תוחלף",
                "יציאות 443/587, SMTP.SendAsApp והרשאות Exchange",
                multiMailbox ? "לא ניתן להפעיל לפני אימות זהות והרשאות" : "יש לבדוק אסימון, אימות SMTP ומשלוח ניסיוני"),
            (0, _) => new("XOAUTH2 / SMTP AUTH",
                "smtp.office365.com:587 + STARTTLS",
                "Internal and external recipients",
                "Entra application and certificate; no mailbox password",
                multiMailbox
                    ? "Multiple sender mailboxes — PLAN ONLY; mail delivery blocked"
                    : "One M365 mailbox: From and envelope MAIL FROM are rewritten",
                "Outbound TCP 443/587, SMTP.SendAsApp and verified Exchange permissions",
                multiMailbox
                    ? "Cannot deploy: queue-bound SMTP login, per-mailbox XOAUTH2 and Exchange Send As are not live verified"
                    : "Verify token, SMTP AUTH and a separately approved test delivery"),
            (1, 0) => new("SMTP Relay / Microsoft 365 Connector",
                "Ваш MX Microsoft 365:25 + EOP",
                "Внутренние и внешние адресаты",
                "Входящий Connector по утверждённому публичному IP или TLS-сертификату",
                "Фиксированный адрес или проверенные отправители (SMTP AUTH + From Guard)",
                "Подтверждённый домен, действующий Inbound Connector, исходящий TCP 25",
                "Отправка наружу только после проверки Connector, правил From и прав ретрансляции"),
            (1, 2) => new("SMTP Relay / Microsoft 365 Connector",
                "Microsoft 365 MX:25 + EOP",
                "נמענים פנימיים וחיצוניים",
                "מחבר מאושר לפי כתובת IP ציבורית או אישור TLS",
                "שולח קבוע או משתמשים מאומתים עם From Guard",
                "דומיין מאושר, Connector פעיל ויציאה 25",
                "לפני ההפעלה יש לבדוק הגדרות Connector והרשאות שליחה"),
            (1, _) => new("SMTP Relay / Microsoft 365 Connector",
                "Your Microsoft 365 MX:25 + EOP",
                "Internal and external recipients",
                "Inbound Connector trusts approved egress public IP or TLS identity",
                "Fixed sender or validated senders with SMTP AUTH and From Guard",
                "Accepted domain, active inbound Connector and outbound TCP 25",
                "Review Connector policy, sender ownership and relay rules before applying"),
            (2, 0) => new("Direct Send",
                "Ваш MX Microsoft 365:25 + EOP",
                "ТОЛЬКО внутренние адресаты Microsoft 365",
                "Без Entra App, SMTP AUTH к Microsoft 365 и Connector",
                "Только разрешённый фиксированный отправитель",
                "Подтверждённый домен, MX, исходящий TCP 25 и правильные DNS/SPF",
                "Внешние получатели блокируются. Это НЕ универсальная отправка в интернет"),
            (2, 2) => new("Direct Send",
                "Microsoft 365 MX:25 + EOP",
                "נמענים פנימיים בלבד",
                "ללא יישום Entra, OAuth או Connector",
                "כתובת שולח קבועה ומאושרת",
                "דומיין מאושר, MX, יציאה 25 ו-DNS/SPF",
                "נמענים חיצוניים חסומים"),
            _ => new("Direct Send",
                "Your Microsoft 365 MX:25 + EOP",
                "Microsoft 365 INTERNAL recipients ONLY",
                "No Entra app, OAuth or Connector",
                "One approved fixed sender",
                "Accepted domain, MX, outbound TCP 25, correct DNS/SPF",
                "External recipients blocked. NOT an internet-wide SMTP relay")
        };
    }

    internal static bool SelfTest()
    {
        var oauth = Describe(0, 1, false);
        var multi = Describe(0, 1, true);
        var connector = Describe(1, 1, false);
        var direct = Describe(2, 1, false);
        var ru = Describe(2, 0, false);
        return oauth.Target.Contains(":587", StringComparison.Ordinal) &&
            oauth.Authorization.Contains("certificate", StringComparison.Ordinal) &&
            multi.Sender.Contains("PLAN ONLY", StringComparison.Ordinal) &&
            multi.Safety.Contains("Cannot deploy", StringComparison.Ordinal) &&
            connector.Target.Contains(":25", StringComparison.Ordinal) &&
            connector.Audience.Contains("external", StringComparison.Ordinal) &&
            direct.Audience.Contains("INTERNAL", StringComparison.Ordinal) &&
            direct.Safety.Contains("External recipients blocked", StringComparison.Ordinal) &&
            ru.Safety.Contains("Внешние", StringComparison.Ordinal);
    }
}
