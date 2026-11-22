namespace LinuxMailRelay365;

// Human-readable, read-only guidance. This never chooses a transport, changes
// a route, authorizes a tenant, or treats observed sockets as verified delivery.
internal sealed record MailDiscoveryFact(string Caption, string Value);

internal sealed record MailDiscoveryBrief(
    string Headline,
    IReadOnlyList<MailDiscoveryFact> Facts,
    string SuggestedNextStep,
    string ReviewWarning,
    string? ExtraNote)
{
    private static string T(int language, string ru, string en, string he) =>
        language == 0 ? ru : language == 2 ? he : en;

    private static string Known(string? value, int language) =>
        string.IsNullOrWhiteSpace(value) || value is "unknown" or "unavailable" or "unverified"
            ? T(language, "не подтверждено", "not verified", "לא אומת")
            : value;

    internal static MailDiscoveryBrief Build(
        MailRoutingInventory? inventory,
        ExistingSmtpAudit? audit,
        MailHostInspection? host,
        bool? isolatedRelay,
        MailServerDiscoveryDecision decision,
        int recipientScope,
        string? proposedPort,
        int language)
    {
        int l = language;
        bool postfix = inventory?.Mta == "postfix";
        string mailServer = inventory?.Mta switch
        {
            "postfix" => "Postfix",
            "sendmail" => "Sendmail",
            "exim" => "Exim",
            "none" => T(l, "не найден", "not detected", "לא זוהה"),
            _ => T(l, "не подтверждён", "unverified", "לא אומת")
        };
        string active = host?.MtaState == "active"
            ? T(l, "работает", "active", "פעיל")
            : T(l, "состояние требуется проверить", "state not verified", "המצב לא אומת");
        string existingRelay = Known(inventory?.CurrentRelay, l);
        string configuredPorts = host?.ConfiguredSmtpPortState ?? "";
        string smtpListener = audit?.PublicBind switch
        {
            "loopback_only" => T(l, "обнаружен только локальный listener", "local-only listener observed", "זוהתה האזנה מקומית בלבד"),
            "potentially_public" => T(l, "возможна внешняя привязка; доступ извне не доказан", "potential external binding; Internet access unverified", "חיבור חיצוני אפשרי; לא אומת"),
            "private_or_other" => T(l, "привязка к внутреннему/другому IP; доступ требует проверки", "private/other binding; access unverified", "האזנה בכתובת פרטית/אחרת"),
            _ => T(l, "фактический listener не подтверждён", "active listener not verified", "האזנה בפועל לא אומתה")
        };
        string inbound = T(l, "Настроены входящие порты: ", "Configured inbound ports: ", "יציאות נכנסות מוגדרות: ") +
            Known(configuredPorts, l) + "; " + smtpListener;
        string hostName = host?.HasFqdn == true ? host.Fqdn : Known(host?.ShortHostname, l);
        string domain = host?.HasDomain == true ? host.Domain :
            T(l, "не подтверждён", "not verified", "לא אומת");
        bool gmail = inventory?.CurrentRelay.Contains("smtp.gmail.com", StringComparison.OrdinalIgnoreCase) == true;

        var facts = new List<MailDiscoveryFact>
        {
            new(T(l, "Работающий MTA", "Mail server", "שרת דואר"), mailServer + " · " + active),
            new(T(l, "Текущая исходящая отправка", "Existing outbound relay", "ממסר יוצא קיים"),
                (gmail ? "Gmail · " : "") + existingRelay),
            new(T(l, "Локальный приём SMTP", "Inbound SMTP", "SMTP נכנס"), inbound),
            new(T(l, "Имя Linux", "Linux host", "שם שרת Linux"), hostName),
            new(T(l, "Домен Linux (не проверен в M365)", "Linux domain (not M365 verified)", "דומיין Linux (לא אומת ב-M365)"), domain)
        };
        if (!string.IsNullOrWhiteSpace(proposedPort))
            facts.Add(new(T(l, "Порт нового Relay (предложение)", "Proposed new relay port", "יציאת ממסר חדשה מוצעת"),
                proposedPort + " · " + T(l, "не считайте работающим", "not evidence of an active listener", "לא מעיד על שירות פעיל")));

        string headline = isolatedRelay == true
            ? T(l, "Отдельный Relay уже обнаружен. Сначала проверьте его.",
                "An isolated relay was detected. Audit it before reinstalling.",
                "זוהה ממסר נפרד. יש לבדוק אותו לפני התקנה.")
            : postfix
                ? T(l, "Postfix уже работает — сохраните текущую почту.",
                    "Postfix is already running — preserve the existing mail flow.",
                    "Postfix כבר פועל — שמרו על תעבורת הדואר הקיימת.")
                : inventory?.Mta is "exim" or "sendmail"
                    ? T(l, "Существующий MTA нельзя автоматически заменять.",
                        "Do not automatically replace the existing MTA.",
                        "אין להחליף אוטומטית את שרת הדואר הקיים.")
                    : T(l, "Сначала подтвердите состояние почтовой службы.",
                        "Verify the existing mail service before configuring a route.",
                        "בדקו תחילה את שירות הדואר.");

        string steps = isolatedRelay == true
            ? T(l, "Проверьте настройки, порт и очередь существующего отдельного Relay. Повторная установка не рекомендуется.",
                "Inspect the existing isolated relay's port, queue and delivery before creating another instance.",
                "בדקו את היציאה, התור והניתוב של הממסר הקיים.")
            : postfix
                ? T(l, "Рассмотрите отдельный Microsoft 365 Relay с собственной очередью и свободным портом. Существующий Postfix и его relayhost оставьте без изменений.",
                    "Consider an independent Microsoft 365 relay with its own queue and an available port. Keep the primary Postfix and its relayhost unchanged.",
                    "שקלו ממסר Microsoft 365 נפרד עם תור ויציאה עצמאיים, ללא שינוי Postfix הקיים.")
                : T(l, "Проверьте текущую почту и возможность отдельного Relay. Основную конфигурацию не изменяйте.",
                    "Inspect current mail delivery and the feasibility of an independent relay. Do not change the primary configuration.",
                    "בדקו ממסר נפרד, ללא שינוי התצורה הקיימת.");

        string audience = recipientScope switch
        {
            1 => T(l,
                "Только внутренние получатели M365: возможен Direct Send (исходящий TCP 25). XOAUTH2 — альтернатива при одобренном почтовом ящике.",
                "Internal M365 recipients only: Direct Send over outbound TCP 25 is a candidate. XOAUTH2 is another option with an approved mailbox.",
                "לנמענים פנימיים ניתן לשקול Direct Send ביציאה 25 או XOAUTH2."),
            2 => T(l,
                "Есть внешние получатели: кандидат — XOAUTH2 от разрешённого ящика через TCP 587. Connector через TCP 25 — альтернатива после проверки tenant и IP/сертификата. Direct Send не подходит.",
                "External recipients: consider XOAUTH2 from an approved mailbox over TCP 587. Connector over TCP 25 requires tenant and IP/certificate approval. Direct Send is unsuitable.",
                "לנמענים חיצוניים: XOAUTH2 או Connector מאושר; Direct Send אינו מתאים."),
            _ => T(l,
                "Укажите, нужны ли внешние получатели: только после этого можно выбирать XOAUTH2, Connector или Direct Send.",
                "Choose whether external recipients are needed before selecting XOAUTH2, Connector or Direct Send.",
                "בחרו אם נדרשים נמענים חיצוניים לפני בחירת שיטה.")
        };

        string warning = decision.Code switch
        {
            "suspected_unsafe_relay" => T(l,
                "Внимание: возможны небезопасные правила Relay. Это не доказательство открытого Relay; выполните проверку перед изменениями.",
                "Possible unsafe relay rules. This does not prove an open relay; audit before making changes.",
                "חשד למדיניות relay לא בטוחה; יש לבדוק לפני שינוי."),
            "postfix_needs_review" or "not_verified" or "conflicting_or_unknown_mta" => T(l,
                "Нужно проверить ограничения Relay и привязку SMTP. Вывод предварительный, установка не разрешена автоматически.",
                "SMTP bindings and relay restrictions need review. This is guidance only, not approval to install.",
                "יש לבדוק הגבלות relay והאזנה. זו המלצה בלבד."),
            _ => T(l,
                "Выбор маршрута не подтверждает доставку, разрешения Microsoft 365 или безопасность SMTP. Изменения не выполнялись.",
                "The route choice does not prove delivery, M365 authorization or SMTP safety. No changes were made.",
                "בחירת מסלול אינה מאשרת משלוח או הרשאות. לא בוצעו שינויים.")
        };
        string? extra = gmail
            ? T(l,
                "Ротация Primary OAuth не переводит текущий Gmail relay на Microsoft 365. Сначала настройте отдельную M365 identity.",
                "Primary OAuth rotation does not migrate the existing Gmail relay to Microsoft 365. Configure a separate M365 identity first.",
                "חידוש OAuth ראשי אינו מעביר ממסר Gmail ל-M365.")
            : null;

        return new MailDiscoveryBrief(headline, facts, steps + Environment.NewLine + audience,
            warning, extra);
    }

    internal static bool SelfTest()
    {
        var active = new MailRoutingInventory("postfix", "[smtp.gmail.com]:587",
            "smtp", new string('a', 64));
        var review = new MailServerDiscoveryDecision("postfix_needs_review", true, true);
        var result = Build(active, null, null, false, review, 2, "2525", 0);
        if (!result.Headline.Contains("сохраните", StringComparison.Ordinal) ||
            !result.Facts.Any(x => x.Value.Contains("[smtp.gmail.com]:587", StringComparison.Ordinal)) ||
            !result.Facts.Any(x => x.Value.Contains("не считайте работающим", StringComparison.Ordinal)) ||
            !result.SuggestedNextStep.Contains("XOAUTH2", StringComparison.Ordinal) ||
            !result.SuggestedNextStep.Contains("Direct Send не подходит", StringComparison.Ordinal) ||
            !result.ReviewWarning.Contains("установка не разрешена", StringComparison.Ordinal) ||
            result.ExtraNote is null) return false;
        var internalOnly = Build(active, null, null, false,
            new MailServerDiscoveryDecision("postfix_active", true, false), 1, "25", 1);
        return internalOnly.SuggestedNextStep.Contains("Direct Send", StringComparison.Ordinal) &&
               internalOnly.Facts.Any(x => x.Caption == "Proposed new relay port" &&
                   x.Value.Contains("not evidence", StringComparison.Ordinal));
    }
}
