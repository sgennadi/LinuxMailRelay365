namespace LinuxMailRelay365;

// Read-only advice based on MTA evidence and user-specified recipients.
// Suggestions never approve a tenant, sender, connector or Linux installation.
internal sealed record DeliveryRouteAdvice(string Code, int? SuggestedMode, bool RequiresReview)
{
    internal string Explain(int language) => Code switch
    {
        "inspect_server" => Local(language,
            "Сначала повторите проверку MTA/SMTP: данные отсутствуют, противоречивы или потенциально небезопасны. Рекомендовать маршрут пока нельзя.",
            "Reinspect MTA/SMTP first: current evidence is incomplete, conflicting or potentially unsafe. No delivery mode can be recommended yet.",
            "יש לבדוק שוב את שרת הדואר לפני המלצה על מסלול."),
        "audit_existing" => Local(language,
            "Уже обнаружены файлы отдельного SMTP Relay. Сначала проверьте действующий порт, маршрут и очередь. Не переустанавливайте его автоматически.",
            "An existing isolated Relay configuration was detected. Audit the port, routing and queue before considering another installation.",
            "נמצאה תצורת ממסר קיימת. בדקו אותה לפני התקנה חוזרת."),
        "choose_recipients" => Local(language,
            "Укажите получателей. Одного обнаружения Postfix/Exim/Sendmail недостаточно, чтобы выбрать XOAUTH2, Connector или Direct Send.",
            "Choose your recipients. Detecting Postfix/Exim/Sendmail is not enough to choose XOAUTH2, Connector or Direct Send.",
            "בחרו נמענים; זיהוי תוכנת הדואר לבדו אינו מספיק."),
        "direct_postfix" => Local(language,
            "Рекомендуемый вариант: Direct Send для внутренних получателей M365. Сохраните основной Postfix и используйте отдельный SMTP-порт и очередь; исходящий TCP 25. Внешние адреса будут отклонены.",
            "Suggested: Direct Send for M365 internal recipients. Preserve primary Postfix and use an isolated SMTP listener/queue; outbound TCP 25. External recipients are rejected.",
            "מומלץ לשקול Direct Send לנמענים פנימיים בלבד, תוך שמירת Postfix."),
        "direct_clean" => Local(language,
            "Вариант: Direct Send. Сначала подтвердите, что Linux чистый, отдельно подготовьте Postfix с отключённым основным сервисом и повторите диагностику. Только внутренние адресаты.",
            "Candidate: Direct Send. First verify a genuinely clean Linux host, prepare Postfix with its primary service disabled, then reinspect. Internal recipients only.",
            "אפשרות Direct Send לאחר בדיקת שרת נקי והכנת Postfix."),
        "direct_foreign" => Local(language,
            "Вариант: Direct Send, сохраняя Exim/Sendmail без изменений. Требуется заранее установленный Postfix и отдельный sidecar с проверкой конфликтов. Только внутренняя почта.",
            "Candidate: Direct Send while preserving Exim/Sendmail. Requires preinstalled Postfix binaries and a guarded independent sidecar. Internal mail only.",
            "אפשרות Direct Send עם Postfix נפרד, ללא שינוי Exim/Sendmail."),
        "oauth_postfix" => Local(language,
            "Рекомендуемый кандидат для внутренних и внешних писем: XOAUTH2 с одним разрешённым ящиком Entra/Exchange и исходящим TCP 587. Альтернатива — Connector, если tenant одобрил IP/сертификат и TCP 25.",
            "Suggested candidate for internal and external recipients: single-mailbox XOAUTH2 with approved Entra/Exchange permissions and outbound TCP 587. Alternative: approved Connector over TCP 25.",
            "מועמד מומלץ: XOAUTH2 לתיבה אחת עם הרשאות Entra ויציאה 587. חלופה: Connector מאושר."),
        "connector_foreign" => Local(language,
            "Кандидат для внешних адресатов: fixed-sender Connector с отдельным Postfix sidecar. Нужны одобренный tenant Connector, публичный IP/сертификат и исходящий TCP 25. Общий XOAUTH2 для Exim/Sendmail здесь не поддерживается.",
            "External-mail candidate: fixed-sender Connector on an isolated Postfix sidecar. Requires an approved tenant Connector, public IP/TLS identity and outbound TCP 25. Generic XOAUTH2 on Exim/Sendmail is unsupported.",
            "לנמענים חיצוניים ניתן לשקול Connector מאושר עם Postfix נפרד."),
        "clean_external_review" => Local(language,
            "Нет безопасной автоматической рекомендации: для внешней почты на чистом Linux сначала проверьте права на Connector или подготовку отдельного XOAUTH2. Установка пакетов не выбирает режим доставки.",
            "No automatic external-mail recommendation on a clean host. First verify tenant Connector authorization or a separately supported XOAUTH2 bootstrap. Package installation alone does not choose a route.",
            "בשרת נקי יש לאמת קודם הרשאות Connector או XOAUTH2."),
        _ => Local(language, "Нужна дополнительная проверка.", "More inspection required.", "נדרשת בדיקה נוספת.")
    };
    private static string Local(int language, string ru, string en, string he) =>
        language == 0 ? ru : language == 2 ? he : en;
}

internal static class MailDeliveryAdvisor
{
    internal static DeliveryRouteAdvice Assess(string scope,
        MailServerDiscoveryDecision discovery, bool? isolatedDetected)
    {
        if (scope is not ("unknown" or "internal-only" or "external-needed"))
            throw new ArgumentOutOfRangeException(nameof(scope));
        if (discovery.Code is "not_verified" or "suspected_unsafe_relay" or
            "conflicting_or_unknown_mta" or "postfix_needs_review" or
            "installed_but_not_active" ||
            (discovery.Code == "postfix_active" && discovery.ManualReviewRequired))
            return new("inspect_server", null, true);
        if (isolatedDetected == true || discovery.Code == "existing_isolated_relay")
            return new("audit_existing", null, true);
        if (scope == "unknown")
            return new("choose_recipients", null, false);
        if (scope == "internal-only")
            return discovery.Code switch
            {
                "postfix_active" => new("direct_postfix", 2, false),
                "no_standard_mta_detected" => new("direct_clean", 2, true),
                "foreign_mta_active" => new("direct_foreign", 2, true),
                _ => new("inspect_server", null, true)
            };
        return discovery.Code switch
        {
            "postfix_active" => new("oauth_postfix", 0, false),
            "foreign_mta_active" => new("connector_foreign", 1, true),
            "no_standard_mta_detected" => new("clean_external_review", null, true),
            _ => new("inspect_server", null, true)
        };
    }

    // An operator's explicit external-recipient requirement is a hard
    // contradiction of Direct Send, even when a local SMTP input is valid.
    internal static bool ConflictsWithRecipients(string scope, int mode) =>
        scope == "external-needed" && mode == 2;

    internal static bool SelfTest()
    {
        var postfix = new MailServerDiscoveryDecision("postfix_active", true, false);
        var publicPostfix = new MailServerDiscoveryDecision("postfix_active", true, true);
        var foreign = new MailServerDiscoveryDecision("foreign_mta_active", true, true);
        var clean = new MailServerDiscoveryDecision("no_standard_mta_detected", false, true);
        var unsafeRelay = new MailServerDiscoveryDecision("suspected_unsafe_relay", true, true);
        var unknown = new MailServerDiscoveryDecision("not_verified", false, true);
        return Assess("internal-only", postfix, false).SuggestedMode == 2 &&
            Assess("external-needed", postfix, false).SuggestedMode == 0 &&
            Assess("external-needed", foreign, false).SuggestedMode == 1 &&
            Assess("external-needed", foreign, false).RequiresReview &&
            Assess("internal-only", clean, false).SuggestedMode == 2 &&
            Assess("external-needed", clean, false).SuggestedMode is null &&
            Assess("external-needed", publicPostfix, false).SuggestedMode is null &&
            Assess("internal-only", postfix, true).Code == "audit_existing" &&
            Assess("internal-only", unsafeRelay, false).SuggestedMode is null &&
            Assess("external-needed", unknown, null).SuggestedMode is null &&
            Assess("unknown", postfix, false).SuggestedMode is null &&
            ConflictsWithRecipients("external-needed", 2) &&
            !ConflictsWithRecipients("internal-only", 2) &&
            !ConflictsWithRecipients("external-needed", 1) &&
            Assess("internal-only", postfix, false).Explain(0).Contains("Direct Send") &&
            Assess("external-needed", postfix, false).Explain(1).Contains("XOAUTH2") &&
            Assess("external-needed", foreign, false).Explain(2).Contains("Connector");
    }
}
