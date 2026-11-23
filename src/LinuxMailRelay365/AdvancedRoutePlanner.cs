using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// RC11: local what-if planner only. Postfix transport_maps and
// sender_dependent_relayhost_maps are different mechanisms with different
// precedence, so an overlap cannot be interpreted as an actual route.
internal enum AdvancedRouteMatchKind
{
    ExactEnvelopeSender,
    EnvelopeSenderDomain,
    RecipientDomain
}

internal sealed record AdvancedRouteRule(
    AdvancedRouteMatchKind Kind, string Pattern, string Host, int Port,
    string TlsMode, string AuthMode)
{
    internal string Endpoint => "[" + Host + "]:" + Port;
    internal string Selector => Kind switch
    {
        AdvancedRouteMatchKind.ExactEnvelopeSender => "exact-envelope-sender",
        AdvancedRouteMatchKind.EnvelopeSenderDomain => "envelope-sender-domain",
        AdvancedRouteMatchKind.RecipientDomain => "recipient-domain",
        _ => "unsupported"
    };
}

internal sealed record AdvancedRouteSimulation(
    string Status, string Explanation,
    IReadOnlyList<AdvancedRouteRule> Matches, string PlanSha256,
    string SampleSender, string SampleRecipient);

internal sealed record AdvancedRouteOverlap(int FirstRule, int SecondRule, string Reason);

internal static class AdvancedRoutePlanner
{
    internal const int MaximumRules = 24;
    private const string DomainLabel = @"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
    private static readonly Regex Domain = new(
        @"\A" + DomainLabel + @"(?:\." + DomainLabel + @")+\z",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly Regex Mailbox = new(
        @"\A[a-z0-9][a-z0-9._+%-]{0,62}@" + DomainLabel +
        @"(?:\." + DomainLabel + @")+\z",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    internal static string CheckedMailbox(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 254 ||
            value != value.Trim() || !Mailbox.IsMatch(value) ||
            value[..value.IndexOf('@')].Contains("..", StringComparison.Ordinal) ||
            value[..value.IndexOf('@')].EndsWith(".", StringComparison.Ordinal))
            throw new ArgumentException(
                "Use one ASCII envelope address, e.g. user@example.org (no display names).");
        return value.ToLowerInvariant();
    }

    internal static string CheckedDomain(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 253 ||
            value != value.Trim() || !Domain.IsMatch(value))
            throw new ArgumentException(
                "Use one exact domain, e.g. example.org (no wildcard/subdomain matching).");
        return value.ToLowerInvariant();
    }

    internal static AdvancedRouteRule Normalize(AdvancedRouteRule rule)
    {
        if (!Enum.IsDefined(rule.Kind))
            throw new ArgumentException("Unknown conditional routing selector.");
        string pattern = rule.Kind == AdvancedRouteMatchKind.ExactEnvelopeSender
            ? CheckedMailbox(rule.Pattern)
            : CheckedDomain(rule.Pattern);
        string host = CustomSmtpAudit.CheckedHost(rule.Host);
        if (rule.Port is < 1 or > 65535 ||
            rule.TlsMode is not ("starttls" or "implicit" or "plain") ||
            rule.AuthMode is not ("none" or "password") ||
            (rule.TlsMode == "plain" && rule.AuthMode == "password"))
            throw new ArgumentException(
                "Invalid outbound SMTP port or TLS/AUTH combination.");
        return new(rule.Kind, pattern, host, rule.Port, rule.TlsMode, rule.AuthMode);
    }

    internal static IReadOnlyList<AdvancedRouteRule> ValidatePlan(
        IEnumerable<AdvancedRouteRule> rules)
    {
        var items = rules.Take(MaximumRules + 1).Select(Normalize).ToArray();
        if (items.Length > MaximumRules)
            throw new ArgumentException("Maximum 24 route conditions per plan.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rule in items)
            if (!seen.Add(rule.Selector + "|" + rule.Pattern))
                throw new ArgumentException("Duplicate route selector and condition.");
        return items;
    }

    // Possible simultaneous matches are diagnostics only. Real Postfix
    // sender relayhost and recipient transport maps are NOT first-match
    // rules in one common ordered list.
    internal static IReadOnlyList<AdvancedRouteOverlap> PossibleOverlaps(
        IEnumerable<AdvancedRouteRule> rules)
    {
        var items = ValidatePlan(rules);
        var overlaps = new List<AdvancedRouteOverlap>();
        for (int i = 0; i < items.Count; i++)
        {
            for (int j = i + 1; j < items.Count; j++)
            {
                var a = items[i];
                var b = items[j];
                bool senderA = a.Kind != AdvancedRouteMatchKind.RecipientDomain;
                bool senderB = b.Kind != AdvancedRouteMatchKind.RecipientDomain;
                if (senderA != senderB)
                {
                    overlaps.Add(new(i, j, "sender-vs-recipient"));
                    continue;
                }
                if (a.Kind == AdvancedRouteMatchKind.ExactEnvelopeSender &&
                    b.Kind == AdvancedRouteMatchKind.EnvelopeSenderDomain &&
                    a.Pattern.EndsWith("@" + b.Pattern, StringComparison.Ordinal))
                    overlaps.Add(new(i, j, "exact-vs-sender-domain"));
                else if (b.Kind == AdvancedRouteMatchKind.ExactEnvelopeSender &&
                    a.Kind == AdvancedRouteMatchKind.EnvelopeSenderDomain &&
                    b.Pattern.EndsWith("@" + a.Pattern, StringComparison.Ordinal))
                    overlaps.Add(new(i, j, "exact-vs-sender-domain"));
            }
        }
        return overlaps;
    }

    internal static string PlanSha256(IEnumerable<AdvancedRouteRule> rules)
    {
        var items = ValidatePlan(rules);
        var text = new StringBuilder("LMR365-COND-ROUTES-V1\n");
        foreach (var item in items)
            foreach (var field in new[] { item.Selector, item.Pattern, item.Host,
                         item.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                         item.TlsMode, item.AuthMode })
                text.Append(field.Length).Append(':').Append(field).Append('\n');
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            text.ToString()))).ToLowerInvariant();
    }

    internal static AdvancedRouteSimulation Simulate(
        IEnumerable<AdvancedRouteRule> rules, string envelopeFrom, string envelopeTo)
    {
        var items = ValidatePlan(rules);
        string sender = CheckedMailbox(envelopeFrom);
        string recipient = CheckedMailbox(envelopeTo);
        string senderDomain = sender[(sender.IndexOf('@') + 1)..];
        string recipientDomain = recipient[(recipient.IndexOf('@') + 1)..];
        var matches = items.Where(rule => rule.Kind switch
        {
            AdvancedRouteMatchKind.ExactEnvelopeSender => rule.Pattern == sender,
            AdvancedRouteMatchKind.EnvelopeSenderDomain => rule.Pattern == senderDomain,
            AdvancedRouteMatchKind.RecipientDomain => rule.Pattern == recipientDomain,
            _ => false
        }).ToArray();
        string status = matches.Length switch
        {
            0 => "no-match",
            1 => "one-hypothetical-match",
            _ => "overlap-requires-review"
        };
        string explanation = matches.Length switch
        {
            0 => "No proposed rule matches. Actual existing MTA routing is not verified.",
            1 => "One proposed rule matches. Real Postfix precedence and delivery are not verified.",
            _ => "Multiple conditions overlap. Real Postfix map precedence is not modeled; do not Apply."
        };
        return new(status, explanation, matches, PlanSha256(items),
            sender, recipient);
    }

    internal static bool SelfTest()
    {
        var exact = Normalize(new(AdvancedRouteMatchKind.ExactEnvelopeSender,
            "Admin@Example.ORG", "relay-a.example.net", 25, "starttls", "none"));
        var domain = Normalize(new(AdvancedRouteMatchKind.EnvelopeSenderDomain,
            "example.org", "relay-b.example.net", 587, "starttls", "password"));
        var receiver = Normalize(new(AdvancedRouteMatchKind.RecipientDomain,
            "external.example", "relay-c.example.net", 465, "implicit", "password"));
        if (exact.Pattern != "admin@example.org" ||
            exact.Endpoint != "[relay-a.example.net]:25" ||
            Simulate([exact], "admin@example.org", "other@elsewhere.example").Status
                != "one-hypothetical-match" ||
            Simulate([exact, domain], "admin@example.org", "other@elsewhere.example").Status
                != "overlap-requires-review" ||
            Simulate([receiver], "somebody@example.org", "other@external.example")
                .Matches.Single() != receiver ||
            Simulate([receiver], "SOMEBODY@EXAMPLE.ORG", "Other@External.Example")
                .SampleRecipient != "other@external.example" ||
            Simulate([domain], "a@sub.example.org", "other@elsewhere.example").Status
                != "no-match" ||
            PossibleOverlaps([exact, domain]).Single().Reason !=
                "exact-vs-sender-domain" ||
            PossibleOverlaps([domain, receiver]).Single().Reason !=
                "sender-vs-recipient" ||
            PossibleOverlaps([domain, Normalize(new(
                AdvancedRouteMatchKind.EnvelopeSenderDomain,
                "another.example.org", "another.example.net",
                25, "starttls", "none"))]).Count != 0)
            return false;
        var hash = PlanSha256([exact, domain]);
        if (hash.Length != 64 || hash == PlanSha256([domain, exact]))
            return false;
        foreach (Action invalid in new Action[]
        {
            () => Normalize(new(AdvancedRouteMatchKind.RecipientDomain,
                "*.example.org", "relay.example.net", 25, "starttls", "none")),
            () => Normalize(new(AdvancedRouteMatchKind.ExactEnvelopeSender,
                "bad..name@example.org", "relay.example.net", 25, "starttls", "none")),
            () => Normalize(new(AdvancedRouteMatchKind.ExactEnvelopeSender,
                "user@example.org", "relay;id", 25, "starttls", "none")),
            () => Normalize(new(AdvancedRouteMatchKind.RecipientDomain,
                "example.org", "relay.example.net", 0, "starttls", "none")),
            () => Normalize(new(AdvancedRouteMatchKind.RecipientDomain,
                "example.org", "relay.example.net", 587, "plain", "password")),
            () => ValidatePlan([exact, exact]),
            () => ValidatePlan(Enumerable.Repeat(exact, MaximumRules + 1))
        })
        {
            try { invalid(); return false; }
            catch (ArgumentException) { }
        }
        return true;
    }
}
