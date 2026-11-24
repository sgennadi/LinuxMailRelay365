using System.Security.Cryptography;
using System.Text;

namespace LinuxMailRelay365;

// RC13: in-memory candidate key representation ONLY. No path, postmap,
// postconf, file IO, SSH, tenant API or ability to authorize Apply.
internal sealed record PostfixCandidateMapLine(
    string Kind, string Key, string ProposedValue, string Endpoint,
    string TlsMode, string AuthMode, bool NeedsDedicatedTransport)
{
    internal string Printable
    {
        get
        {
            string setting = Kind == "sender" ?
                "sender_dependent_relayhost_maps" : "transport_maps";
            if (NeedsDedicatedTransport)
                return "# " + setting + " " + Key + " -> " + Endpoint +
                    " : IMPLICIT TLS NEEDS A SEPARATE VERIFIED WRAPPER-MODE TRANSPORT";
            return Key + "    " + ProposedValue;
        }
    }
}

internal sealed record PostfixConditionalMapReview(
    string PlanSha256, string InventorySha256,
    IReadOnlyList<PostfixCandidateMapLine> SenderCandidates,
    IReadOnlyList<PostfixCandidateMapLine> RecipientCandidates,
    IReadOnlyList<PostfixRoutePolicyFinding> Warnings,
    bool PostfixDetected)
{
    // The review is not a deployable Postfix configuration. No set of
    // offline conditions may change this flag.
    internal bool CanApply => false;

    internal string Render(int language)
    {
        string en = "Postfix key shapes — review only; NOT an Apply script";
        string ru = "Предлагаемые ключи Postfix — только проверка, НЕ скрипт Apply";
        string he = "מפתחות Postfix מוצעים - לבדיקה בלבד, לא להחלה";
        string heading = language == 0 ? ru : language == 2 ? he : en;
        var lines = new List<string>
        {
            heading,
            "Plan SHA-256 (local): " + PlanSha256,
            "Inventory SHA-256 (read-only report, NOT a server lock): " + InventorySha256,
            "# No files, maps, SMTP listeners, services or cloud objects are changed."
        };
        if (!PostfixDetected)
        {
            lines.Add(language == 0 ?
                "Работающий Postfix не подтверждён. Ключи не формируются." :
                language == 2 ? "Postfix פעיל לא אומת. לא נוצרו מפתחות." :
                "An active Postfix was not confirmed. No map keys are emitted.");
        }
        else
        {
            lines.Add("# sender_dependent_relayhost_maps — PROPOSAL ONLY");
            lines.AddRange(SenderCandidates.Count == 0
                ? ["# (no proposed sender conditions)"]
                : SenderCandidates.Select(x => x.Printable +
                    "    # requested TLS=" + x.TlsMode + "; AUTH=" + x.AuthMode));
            lines.Add("# transport_maps — PROPOSAL ONLY");
            lines.AddRange(RecipientCandidates.Count == 0
                ? ["# (no proposed recipient domains)"]
                : RecipientCandidates.Select(x => x.Printable +
                    "    # requested TLS=" + x.TlsMode + "; AUTH=" + x.AuthMode));
        }
        lines.Add("# REQUIRED REVIEWS (not completed):");
        lines.AddRange(Warnings.Select(x => "# " + x.Message(language)));
        lines.Add("# Actual Postfix lookup precedence, CA/peer verification, " +
                  "client AUTH and mail delivery have NOT been tested.");
        return string.Join(Environment.NewLine, lines);
    }
}

internal static class PostfixConditionalMapPreview
{
    // No existing map contents or sensitive map locations may be inputs.
    private static readonly string[] InventoryKeys =
    [
        "MAIL_HOST_POSTFIX_MYDESTINATION",
        "MAIL_HOST_POSTFIX_ROLE_TRANSPORT_MAPS",
        "MAIL_HOST_POSTFIX_ROLE_SENDER_DEPENDENT_RELAYHOST_MAPS",
        "MAIL_HOST_POSTFIX_ROLE_SENDER_DEPENDENT_DEFAULT_TRANSPORT_MAPS",
        "MAIL_HOST_POSTFIX_ROLE_VIRTUAL_MAILBOX_DOMAINS",
        "MAIL_HOST_POSTFIX_ROLE_VIRTUAL_ALIAS_DOMAINS",
        "MAIL_HOST_POSTFIX_ROLE_RELAY_DOMAINS",
        "MAIL_HOST_POSTFIX_ROLE_SMTP_SASL_PASSWORD_MAPS",
        "MAIL_HOST_POSTFIX_ROLE_SMTP_SENDER_DEPENDENT_AUTHENTICATION",
        "MAIL_HOST_POSTFIX_ROLE_SMTP_TLS_POLICY_MAPS",
        "MAIL_HOST_POSTFIX_ROLE_RELAYHOST",
        "MAIL_HOST_POSTFIX_ROLE_LOCAL_TRANSPORT",
        "MAIL_HOST_POSTFIX_ROLE_SMTP_SASL_AUTH_ENABLE",
        "MAIL_HOST_POSTFIX_MAP_META_TRANSPORT_MAPS",
        "MAIL_HOST_POSTFIX_MAP_META_SENDER_DEPENDENT_RELAYHOST_MAPS",
        "MAIL_HOST_POSTFIX_MAP_META_SENDER_DEPENDENT_DEFAULT_TRANSPORT_MAPS",
        "MAIL_HOST_POSTFIX_MAP_META_SMTP_TLS_POLICY_MAPS"
    ];

    internal static PostfixConditionalMapReview Build(
        MailHostInspection? host, IEnumerable<AdvancedRouteRule> proposed)
    {
        var rules = AdvancedRoutePlanner.ValidatePlan(proposed);
        var policy = PostfixRoutePolicyAudit.Review(host, rules);
        var warnings = new List<PostfixRoutePolicyFinding>(policy.Findings);
        void Warn(string code, string en, string ru, string he) =>
            warnings.Add(new(code, en, ru, he));

        string planHash = AdvancedRoutePlanner.PlanSha256(rules);
        var snapshot = new StringBuilder("LMR365-ROUTE-CANDIDATES-V1\n")
            .Append(host?.Mta ?? "unavailable").Append('\n')
            .Append(host?.MtaState ?? "unavailable").Append('\n')
            .Append(host?.Fqdn ?? "unavailable").Append('\n');
        foreach (string key in InventoryKeys)
        {
            string value = host?.Get(key) ?? "unavailable";
            snapshot.Append(key.Length).Append(':').Append(key)
                .Append('=').Append(value.Length).Append(':').Append(value).Append('\n');
        }
        string inventoryHash = Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(snapshot.ToString()))).ToLowerInvariant();
        bool hasPostfix = host?.Mta == "postfix" && host.MtaState == "active";
        var sender = new List<PostfixCandidateMapLine>();
        var recipient = new List<PostfixCandidateMapLine>();
        if (hasPostfix)
        {
            foreach (var rule in rules)
            {
                string key = rule.Kind switch
                {
                    AdvancedRouteMatchKind.ExactEnvelopeSender => rule.Pattern,
                    AdvancedRouteMatchKind.EnvelopeSenderDomain => "@" + rule.Pattern,
                    AdvancedRouteMatchKind.RecipientDomain => rule.Pattern,
                    _ => throw new ArgumentException("Unsupported selector.")
                };
                bool implicitTls = rule.TlsMode == "implicit";
                string value = rule.Kind == AdvancedRouteMatchKind.RecipientDomain
                    ? "smtp:" + rule.Endpoint
                    : rule.Endpoint;
                var line = new PostfixCandidateMapLine(
                    rule.Kind == AdvancedRouteMatchKind.RecipientDomain
                        ? "recipient" : "sender",
                    key, value, rule.Endpoint, rule.TlsMode,
                    rule.AuthMode, implicitTls);
                if (line.Kind == "recipient") recipient.Add(line);
                else sender.Add(line);
            }
        }
        if (rules.Count > 0)
        {
            Warn("not-a-config",
                "These are illustrative key/value shapes, NOT a valid complete or deployable Postfix configuration.",
                "Это пример формы ключей/значений, НЕ готовая конфигурация Postfix.",
                "אלו דוגמאות בלבד, לא תצורת Postfix מוכנה.");
            Warn("tls-not-bound",
                "The proposed STARTTLS mode does not enforce encryption or certificate verification without separate client policy.",
                "Выбор STARTTLS сам по себе НЕ обеспечивает TLS и проверку сертификата без отдельной политики клиента.",
                "בחירת STARTTLS אינה אוכפת הצפנה ואימות תעודות ללא מדיניות נפרדת.");
            Warn("subdomain-rule",
                "Postfix transport(5) can perform parent-domain and leading-dot lookups; backend/map type must be verified before assuming exact recipient matching.",
                "Postfix transport(5) может проверять родительские домены и записи с ведущей точкой. Без проверки backend нельзя считать совпадение точным.",
                "Postfix transport(5) עשוי לבדוק גם דומיין אב ורשומות עם נקודה; יש לבדוק את סוג המפה.");
            if (rules.Any(x => x.TlsMode == "implicit"))
                Warn("wrapper-mode",
                    "Implicit TLS (often 465) cannot be enabled by a relayhost/transport map line; a dedicated wrapper-mode SMTP transport needs review.",
                    "Implicit TLS (часто порт 465) нельзя настроить одной строкой карты: требуется отдельный проверенный SMTP-транспорт.",
                    "TLS משתמע דורש תעבורה ייעודית במצב wrapper ולא שורת מיפוי בלבד.");
            if (rules.Any(x => x.TlsMode == "plain"))
                Warn("plaintext",
                    "Plaintext SMTP was requested: messages and metadata may be exposed on the network.",
                    "Запрошен SMTP без TLS: содержимое и данные писем могут передаваться открыто.",
                    "SMTP ללא TLS עלול לחשוף תוכן והודעות ברשת.");
            if (rules.Any(x => x.AuthMode == "password"))
                Warn("credentials",
                    "SMTP AUTH is not configured by routing maps. Per-provider credentials and sender authorization need separate verification.",
                    "Карты маршрутизации НЕ настраивают SMTP AUTH. Пароли и права отправителя требуют отдельной проверки.",
                    "מפות ניתוב אינן מגדירות SMTP AUTH; יש לאמת אישורים והרשאות בנפרד.");
            foreach (var set in rules.GroupBy(x => x.Endpoint, StringComparer.Ordinal))
            {
                if (set.Select(x => x.TlsMode + "/" + x.AuthMode)
                    .Distinct(StringComparer.Ordinal).Skip(1).Any())
                    Warn("endpoint-policy-conflict",
                        "Different TLS/AUTH policies were requested for the SAME next-hop " +
                            set.Key + "; a shared SMTP transport cannot assume independent policies.",
                        "Для одного SMTP-адреса " + set.Key +
                            " выбраны разные режимы TLS/AUTH; это требует отдельной политики.",
                        "אותו יעד SMTP קיבל מדיניות TLS/AUTH שונה; יש לאמת הפרדה.");
            }
        }
        return new(planHash, inventoryHash,
            sender, recipient, warnings, hasPostfix);
    }

    internal static bool SelfTest()
    {
        const string hostRecord =
            "MAIL_HOST_VERSION=1\nMAIL_HOST_SHORT=mail\n" +
            "MAIL_HOST_FQDN=mail.example.org\nMAIL_HOST_DOMAIN=example.org\n" +
            "MAIL_HOST_MTA=postfix\nMAIL_HOST_MTA_STATE=active\n" +
            "MAIL_HOST_TRUST=os_report_unverified\nMAIL_HOST_CHANGES=no\n" +
            "MAIL_HOST_POSTFIX_MYDESTINATION=mail.example.org,example.org\n";
        var host = MailHostInspection.Parse(hostRecord);
        var exact = new AdvancedRouteRule(AdvancedRouteMatchKind.ExactEnvelopeSender,
            "USER@EXAMPLE.ORG", "relay.example.net", 587, "starttls", "password");
        var domain = new AdvancedRouteRule(AdvancedRouteMatchKind.EnvelopeSenderDomain,
            "example.org", "alternate.example.net", 25, "starttls", "none");
        var recipient = new AdvancedRouteRule(AdvancedRouteMatchKind.RecipientDomain,
            "external.example.org", "secure.example.net", 465, "implicit", "password");
        var plan = Build(host, [exact, domain, recipient]);
        if (plan.CanApply || !plan.PostfixDetected ||
            plan.SenderCandidates.Count != 2 || plan.RecipientCandidates.Count != 1 ||
            plan.SenderCandidates[0].Key != "user@example.org" ||
            plan.SenderCandidates[0].ProposedValue != "[relay.example.net]:587" ||
            plan.SenderCandidates[1].Key != "@example.org" ||
            plan.RecipientCandidates[0].Key != "external.example.org" ||
            plan.RecipientCandidates[0].ProposedValue != "smtp:[secure.example.net]:465" ||
            !plan.RecipientCandidates[0].NeedsDedicatedTransport ||
            !plan.RecipientCandidates[0].Printable.StartsWith("# ", StringComparison.Ordinal) ||
            plan.PlanSha256.Length != 64 || plan.InventorySha256.Length != 64 ||
            !plan.Warnings.Any(x => x.Code == "wrapper-mode") ||
            !plan.Warnings.Any(x => x.Code == "credentials") ||
            !plan.Render(1).Contains("NOT an Apply script", StringComparison.Ordinal))
            return false;
        var edited = Build(host, [exact with { Port = 25 }, domain, recipient]);
        if (edited.PlanSha256 == plan.PlanSha256 ||
            edited.InventorySha256 != plan.InventorySha256) return false;
        var other = Build(MailHostInspection.Parse(hostRecord.Replace(
            "MAIL_HOST_FQDN=mail.example.org", "MAIL_HOST_FQDN=mail.other.org")),
            [exact, domain, recipient]);
        if (other.PlanSha256 != plan.PlanSha256 ||
            other.InventorySha256 == plan.InventorySha256) return false;
        var noPostfix = Build(MailHostInspection.Parse(hostRecord.Replace(
            "MAIL_HOST_MTA=postfix", "MAIL_HOST_MTA=exim")), [recipient]);
        if (noPostfix.PostfixDetected || noPostfix.CanApply ||
            noPostfix.RecipientCandidates.Count != 0 ||
            !noPostfix.Warnings.Any(x => x.Code == "unsupported-mta")) return false;
        if (!plan.Warnings.Any(x => x.Code == "subdomain-rule") ||
            !plan.Warnings.Any(x => x.Code == "tls-not-bound")) return false;
        var conflicting = Build(host, [exact, exact with {
            Kind = AdvancedRouteMatchKind.EnvelopeSenderDomain, Pattern = "example.org",
            TlsMode = "implicit" }]);
        if (!conflicting.Warnings.Any(x => x.Code == "endpoint-policy-conflict"))
            return false;
        try { Build(host, [exact with { Port = 0 }]); return false; }
        catch (ArgumentException) { return true; }
    }
}
