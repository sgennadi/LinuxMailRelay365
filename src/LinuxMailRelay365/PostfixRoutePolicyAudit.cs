using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// RC12: diagnostic only. Postfix transport, sender, and local delivery rules
// have distinct semantics. Declaration states are not map contents.
internal sealed record PostfixRoutePolicyFinding(
    string Code, string English, string Russian, string Hebrew)
{
    internal string Message(int language) =>
        language == 0 ? Russian : language == 2 ? Hebrew : English;
}

internal sealed record PostfixRoutePolicyReview(
    IReadOnlyList<PostfixRoutePolicyFinding> Findings)
{
    internal bool CanApply => false;
    internal bool Contains(string code) => Findings.Any(x => x.Code == code);

    internal string Describe(int language)
    {
        string heading = language == 0
            ? "Проверка маршрутизации Postfix: ТОЛЬКО ЧТЕНИЕ. Apply недоступен."
            : language == 2
                ? "בדיקת ניתוב Postfix לקריאה בלבד. לא ניתן להחיל שינויים."
                : "Postfix routing policy review: READ ONLY. Apply is unavailable.";
        string footer = language == 0
            ? "Содержимое карт, действительный путь, TLS, права отправителя и доставка НЕ проверены."
            : language == 2
                ? "תוכן מפות, ניתוב בפועל, TLS, הרשאות שולח ומסירה לא אומתו."
                : "Map contents, actual routes, TLS, sender rights and delivery are NOT verified.";
        return heading + Environment.NewLine +
            string.Join(Environment.NewLine,
                Findings.Take(18).Select(x => "• " + x.Message(language))) +
            (Findings.Count > 18 ? Environment.NewLine + "…" : "") +
            Environment.NewLine + footer;
    }
}

internal static class PostfixRoutePolicyAudit
{
    internal static PostfixRoutePolicyReview Review(
        MailHostInspection? host, IEnumerable<AdvancedRouteRule> proposedRules)
    {
        var rules = AdvancedRoutePlanner.ValidatePlan(proposedRules);
        var findings = new List<PostfixRoutePolicyFinding>();

        void Add(string code, string en, string ru, string he) =>
            findings.Add(new(code, en, ru, he));

        if (rules.Count == 0)
        {
            Add("empty-plan", "No hypothetical routes to review.",
                "Нет предполагаемых маршрутов для проверки.", "אין נתיבים לבדיקה.");
            return new(findings);
        }
        if (host is null || host.Mta != "postfix")
        {
            Add("unsupported-mta",
                "Postfix was not verified. Exim and Sendmail need their own routing analysis.",
                "Postfix не подтверждён. Для Exim и Sendmail нужен другой анализ.",
                "Postfix לא אומת; Exim ו-Sendmail דורשים ניתוח נפרד.");
            return new(findings);
        }
        if (host.MtaState != "active")
            Add("postfix-not-active",
                "Postfix is not confirmed active; no live route can be inferred.",
                "Postfix не подтверждён как работающий; маршрут неизвестен.",
                "Postfix אינו מאומת כפעיל; הנתיב בפועל אינו ידוע.");

        bool sender = rules.Any(x => x.Kind != AdvancedRouteMatchKind.RecipientDomain);
        bool recipient = rules.Any(x => x.Kind == AdvancedRouteMatchKind.RecipientDomain);
        bool authenticated = rules.Any(x => x.AuthMode == "password");

        void Inspect(string key, string name)
        {
            string state = host.Get("MAIL_HOST_POSTFIX_ROLE_" + key);
            if (state == "not_declared") return;
            if (state == "declared")
                Add("existing-" + key.ToLowerInvariant(),
                    name + " is configured; lookup contents and actual precedence are not examined.",
                    name + " уже настроен; ключи карт и приоритет не исследованы.",
                    name + " מוגדר; תוכן המפות וסדר הקדימות לא נבדקו.");
            else
                Add("unverified-" + key.ToLowerInvariant(),
                    name + " could not be verified. Treat existing routing as unknown.",
                    "Состояние " + name + " неизвестно. Существующую маршрутизацию нельзя исключать.",
                    "המצב של " + name + " לא אומת; הניתוב הקיים אינו ידוע.");
        }

        Inspect("TRANSPORT_MAPS", "transport_maps");
        Inspect("RELAYHOST", "relayhost");
        if (sender)
        {
            Inspect("SENDER_DEPENDENT_RELAYHOST_MAPS", "sender_dependent_relayhost_maps");
            Inspect("SENDER_DEPENDENT_DEFAULT_TRANSPORT_MAPS",
                "sender_dependent_default_transport_maps");
        }
        if (recipient)
        {
            foreach (var key in new[] {
                "VIRTUAL_MAILBOX_DOMAINS", "VIRTUAL_ALIAS_DOMAINS",
                "RELAY_DOMAINS", "LOCAL_TRANSPORT" })
                Inspect(key, key.ToLowerInvariant());
            string destinations = host.Get("MAIL_HOST_POSTFIX_MYDESTINATION");
            if (destinations == "unavailable" || destinations.Contains('$'))
                Add("dynamic-local-domains",
                    "mydestination is dynamic/unverified; local delivery must be preserved.",
                    "mydestination динамический/неизвестный; локальная доставка должна сохраниться.",
                    "mydestination דינמי או לא ידוע; יש לשמר מסירה מקומית.");
            var literalDomains = Regex.Split(destinations, @"[,\s]+")
                .Where(x => x.Length > 0 && x != "unavailable" && !x.Contains('$'))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var domain in rules
                .Where(x => x.Kind == AdvancedRouteMatchKind.RecipientDomain)
                .Select(x => x.Pattern).Distinct(StringComparer.OrdinalIgnoreCase))
                if (literalDomains.Contains(domain))
                    Add("literal-local-domain",
                        "Recipient domain " + domain +
                            " occurs in mydestination: adding transport_maps could redirect local mail.",
                        "Домен " + domain +
                            " указан в mydestination: transport_maps может перенаправить локальную почту.",
                        "הדומיין " + domain + " מופיע ב-mydestination; מפת תעבורה עשויה לשנות מסירה מקומית.");
        }
        if (authenticated)
        {
            Inspect("SMTP_SASL_PASSWORD_MAPS", "smtp_sasl_password_maps");
            Inspect("SMTP_SENDER_DEPENDENT_AUTHENTICATION",
                "smtp_sender_dependent_authentication");
            Inspect("SMTP_SASL_AUTH_ENABLE", "smtp_sasl_auth_enable");
            Add("smtp-auth-unverified",
                "SMTP AUTH credentials, provider sender permissions and TLS policy are NOT validated.",
                "SMTP AUTH, права отправителя и TLS-политика НЕ проверены.",
                "אישורי SMTP AUTH, הרשאות שולח ומדיניות TLS לא אומתו.");
        }
        Inspect("SMTP_TLS_POLICY_MAPS", "smtp_tls_policy_maps");
        if (AdvancedRoutePlanner.PossibleOverlaps(rules).Count > 0)
            Add("overlap",
                "Selectors can overlap; card ordering is NOT Postfix routing precedence.",
                "Условия пересекаются; порядок карточек НЕ является приоритетом Postfix.",
                "התנאים עשויים לחפוף; סדר הכרטיסים אינו סדר הקדימות ב-Postfix.");
        Add("apply-gate",
            "No map-key lookup, ownership proof, atomic rollback or live-delivery acceptance. Apply stays disabled.",
            "Не проверены ключи карт, владение файлами, атомарный откат и доставка. Apply отключён.",
            "לא נבדקו מפתחות, בעלות, שחזור אטומי או מסירה; החלה חסומה.");
        return new(findings);
    }

    internal static bool SelfTest()
    {
        const string reportText = "MAIL_HOST_VERSION=1\nMAIL_HOST_SHORT=mail\n" +
            "MAIL_HOST_FQDN=mail.example.org\nMAIL_HOST_DOMAIN=example.org\n" +
            "MAIL_HOST_MTA=postfix\nMAIL_HOST_MTA_STATE=active\n" +
            "MAIL_HOST_TRUST=os_report_unverified\nMAIL_HOST_CHANGES=no\n" +
            "MAIL_HOST_POSTFIX_MYDESTINATION=mail.example.org,example.org\n";
        var exact = new AdvancedRouteRule(AdvancedRouteMatchKind.ExactEnvelopeSender,
            "user@example.org", "smtp.example.net", 587, "starttls", "password");
        var recipient = new AdvancedRouteRule(AdvancedRouteMatchKind.RecipientDomain,
            "example.org", "smtp.other.net", 25, "starttls", "none");
        var inspected = MailHostInspection.Parse(reportText +
            "MAIL_HOST_POSTFIX_ROLE_TRANSPORT_MAPS=declared\n" +
            "MAIL_HOST_POSTFIX_ROLE_SENDER_DEPENDENT_RELAYHOST_MAPS=not_declared\n" +
            "MAIL_HOST_POSTFIX_ROLE_SENDER_DEPENDENT_DEFAULT_TRANSPORT_MAPS=declared\n" +
            "MAIL_HOST_POSTFIX_ROLE_SMTP_SASL_PASSWORD_MAPS=declared\n" +
            "MAIL_HOST_POSTFIX_ROLE_SMTP_SENDER_DEPENDENT_AUTHENTICATION=not_declared\n" +
            "MAIL_HOST_POSTFIX_ROLE_SMTP_SASL_AUTH_ENABLE=declared\n" +
            "MAIL_HOST_POSTFIX_ROLE_SMTP_TLS_POLICY_MAPS=unverified\n");
        var result = Review(inspected, [exact, recipient]);
        if (result.CanApply ||
            !result.Contains("existing-transport_maps") ||
            !result.Contains("existing-sender_dependent_default_transport_maps") ||
            !result.Contains("existing-smtp_sasl_password_maps") ||
            !result.Contains("existing-smtp_sasl_auth_enable") ||
            !result.Contains("unverified-smtp_tls_policy_maps") ||
            !result.Contains("literal-local-domain") ||
            !result.Contains("overlap") ||
            !result.Describe(1).Contains("READ ONLY", StringComparison.Ordinal))
            return false;
        var dynamic = Review(MailHostInspection.Parse(
            reportText.Replace("mail.example.org,example.org", "$myhostname,localhost.$mydomain")),
            [recipient]);
        if (!dynamic.Contains("dynamic-local-domains") ||
            !dynamic.Contains("unverified-transport_maps") ||
            dynamic.Contains("literal-local-domain") || dynamic.CanApply)
            return false;
        var foreign = Review(MailHostInspection.Parse(
            reportText.Replace("MAIL_HOST_MTA=postfix", "MAIL_HOST_MTA=exim")), [exact]);
        if (!foreign.Contains("unsupported-mta") || foreign.CanApply ||
            !Review(null, [exact]).Contains("unsupported-mta"))
            return false;
        try { Review(inspected, [recipient with { Port = 0 }]); return false; }
        catch (ArgumentException) { return true; }
    }
}
