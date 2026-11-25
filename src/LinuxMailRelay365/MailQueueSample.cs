using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Bounded aggregate evidence only, never an authorization or delivery receipt.
internal sealed record MailQueueSample(string Scope, string Result, string ClientResult,
    int? ClientTotal, IReadOnlyDictionary<string, int?> Counts,
    string DetailResult, int? Frozen, int? EximOldestMinutes,
    int? Groups, int? ClientGroups, string ListingTruncated, string ClientListingTruncated)
{
    internal static readonly string[] QueueKeys =
        ["TOTAL", "ACTIVE", "DEFERRED", "HELD", "INCOMING", "MAILDROP", "OTHER", "OLDEST_MINUTES"];
    internal static readonly string[] ReasonKeys =
        ["AUTH", "TLS", "DNS", "NETWORK", "TEMPORARY", "PERMANENT", "MIXED", "OTHER_REASON", "NO_REASON"];
    internal bool Detailed => (Scope is "postfix" or "sidecar") && Result == "ok";

    internal static MailQueueSample Parse(string output, string scope)
    {
        if (scope is not ("postfix" or "sidecar" or "exim" or "sendmail") ||
            output.Length > 8192 || output.Contains('\0'))
            throw new InvalidDataException("Invalid queue sample context.");
        const string prefix = "MAIL_QUEUE_";
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            int n = line.IndexOf('=');
            if (n <= prefix.Length || !line.StartsWith(prefix, StringComparison.Ordinal) ||
                !fields.TryAdd(line[prefix.Length..n], line[(n + 1)..]))
                throw new InvalidDataException("Malformed or duplicate queue sample field.");
        }
        string Take(string key, string pattern)
        {
            if (!fields.Remove(key, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Missing or invalid queue sample field: " + key);
            return value;
        }
        void Exact(string key, string value) => Take(key, Regex.Escape(value));
        int? Count(string key)
        {
            string value = Take(key, "unknown|0|[1-9][0-9]{0,8}");
            return value == "unknown" ? null : int.Parse(value, CultureInfo.InvariantCulture);
        }
        Exact("VERSION", "2");
        Exact("SCOPE", scope);
        Exact("CHANGES_APPLIED", "no");
        Exact("ATOMIC", "no");
        Exact("DELIVERY_VERIFIED", "no");
        const string states = "ok|tool_unavailable|timeout|output_limit|command_failed|invalid_output|scope_unverified|sample_changed";
        string result = Take("RESULT", states);
        string client = Take("CLIENT_RESULT", scope == "sendmail" ? states : "not_applicable");
        int? clientTotal = Count("CLIENT_TOTAL");
        string detail = Take("DETAIL_RESULT", scope == "exim" && result == "ok" ? states : "not_applicable");
        int? frozen = Count("FROZEN"), eximOldest = Count("EXIM_OLDEST_MINUTES"),
            groups = Count("GROUPS"), clientGroups = Count("CLIENT_GROUPS");
        string truncated = Take("LISTING_TRUNCATED", "unknown|yes|no"),
            clientTruncated = Take("CLIENT_LISTING_TRUNCATED", "unknown|yes|no");
        var counts = QueueKeys.Concat(ReasonKeys).ToDictionary(key => key, Count, StringComparer.Ordinal);
        bool detailed = (scope is "postfix" or "sidecar") && result == "ok";
        if (fields.Count != 0 || (result == "ok") != counts["TOTAL"].HasValue ||
            (client == "ok") != clientTotal.HasValue ||
            counts.Where(x => x.Key != "TOTAL").Any(x => x.Value.HasValue != detailed))
            throw new InvalidDataException("Inconsistent queue sample availability.");
        if (detailed)
        {
            long Sum(IEnumerable<string> keys) => keys.Sum(key => (long)counts[key]!.Value);
            if (counts["TOTAL"] > 50000 ||
                Sum(QueueKeys.Skip(1).Take(6)) != counts["TOTAL"] ||
                Sum(ReasonKeys) != counts["DEFERRED"] ||
                (counts["TOTAL"] == 0 && counts["OLDEST_MINUTES"] != 0))
                throw new InvalidDataException("Inconsistent queue aggregate counts.");
        }
        bool eximDetailed = scope == "exim" && detail == "ok";
        if (frozen.HasValue != eximDetailed || eximOldest.HasValue != eximDetailed ||
            (eximDetailed && (frozen > counts["TOTAL"] ||
                (counts["TOTAL"] == 0 && eximOldest != 0))))
            throw new InvalidDataException("Inconsistent Exim detail evidence.");
        bool ValidGroups(int? groupCount, string printed, string status, int? total)
        {
            if (scope != "sendmail" || status != "ok")
                return groupCount is null && printed == "unknown";
            return groupCount is null ? printed == "unknown" :
                groupCount > 0 && printed is "yes" or "no" &&
                !(total == 0 && printed == "yes");
        }
        if (!ValidGroups(groups, truncated, result, counts["TOTAL"]) ||
            !ValidGroups(clientGroups, clientTruncated, client, clientTotal))
            throw new InvalidDataException("Inconsistent Sendmail group evidence.");
        return new(scope, result, client, clientTotal, counts, detail, frozen, eximOldest,
            groups, clientGroups, truncated, clientTruncated);
    }

    internal static bool SelfTest()
    {
        string Sample(string scope, string result, string client, string total, string clientTotal,
                      bool detailed = false)
        {
            string head = "VERSION=2\nSCOPE=" + scope + "\nRESULT=" + result +
                "\nCLIENT_RESULT=" + client + "\nCLIENT_TOTAL=" + clientTotal +
                "\nCHANGES_APPLIED=no\nATOMIC=no\nDELIVERY_VERIFIED=no\n" +
                "DETAIL_RESULT=" + (scope == "exim" && result == "ok" ? "ok" : "not_applicable") +
                "\nFROZEN=" + (scope == "exim" && result == "ok" ? "0" : "unknown") +
                "\nEXIM_OLDEST_MINUTES=" + (scope == "exim" && result == "ok" ? "0" : "unknown") +
                "\nGROUPS=unknown\nCLIENT_GROUPS=unknown\nLISTING_TRUNCATED=unknown\nCLIENT_LISTING_TRUNCATED=unknown\n";
            var values = QueueKeys.Concat(ReasonKeys).Select(key => key + "=" +
                (key == "TOTAL" ? total : !detailed ? "unknown" :
                 key is "DEFERRED" or "TLS" or "OLDEST_MINUTES" ? "1" : "0"));
            return string.Join("\n", (head + string.Join("\n", values)).Split('\n')
                .Select(line => "MAIL_QUEUE_" + line)) + "\n";
        }
        string postfix = Sample("postfix", "ok", "not_applicable", "1", "unknown", true);
        if (Parse(postfix, "postfix").Counts["TLS"] != 1 ||
            Parse(Sample("exim", "ok", "not_applicable", "0", "unknown"), "exim").Counts["TOTAL"] != 0 ||
            Parse(Sample("sendmail", "timeout", "ok", "unknown", "4"), "sendmail").ClientTotal != 4)
            return false;
        bool Reject(string input, string scope)
        {
            try { Parse(input, scope); return false; }
            catch (InvalidDataException) { return true; }
        }
        if (!Reject(postfix, "sidecar") ||
            !Reject(postfix.Replace("TOTAL=1", "TOTAL=2"), "postfix") ||
            !Reject(postfix.Replace("TLS=1", "TLS=0"), "postfix") ||
            !Reject(postfix.Replace("CHANGES_APPLIED=no", "CHANGES_APPLIED=yes"), "postfix") ||
            !Reject(postfix + "MAIL_QUEUE_TOTAL=1\n", "postfix") ||
            !Reject(postfix + "MAIL_QUEUE_RAW=private\n", "postfix") ||
            !Reject(Sample("exim", "timeout", "not_applicable", "0", "unknown"), "exim"))
            return false;
        string exim = Sample("exim", "ok", "not_applicable", "3", "unknown")
            .Replace("FROZEN=0", "FROZEN=2").Replace("EXIM_OLDEST_MINUTES=0", "EXIM_OLDEST_MINUTES=90");
        if (Parse(exim, "exim").Frozen != 2 ||
            !Reject(exim.Replace("FROZEN=2", "FROZEN=4"), "exim") ||
            !Reject(exim.Replace("DETAIL_RESULT=ok", "DETAIL_RESULT=sample_changed"), "exim"))
            return false;
        string sendmail = Sample("sendmail", "ok", "ok", "2", "0")
            .Replace("MAIL_QUEUE_GROUPS=unknown", "MAIL_QUEUE_GROUPS=1")
            .Replace("MAIL_QUEUE_LISTING_TRUNCATED=unknown", "MAIL_QUEUE_LISTING_TRUNCATED=yes");
        if (Parse(sendmail, "sendmail").Groups != 1 ||
            !Reject(sendmail.Replace("MAIL_QUEUE_GROUPS=1", "MAIL_QUEUE_GROUPS=0"), "sendmail") ||
            !Reject(sendmail.Replace("MAIL_QUEUE_TOTAL=2", "MAIL_QUEUE_TOTAL=0"), "sendmail"))
            return false;
        string bundle = EmbeddedAssets.BuildMailQueueInspectionBundle("sidecar");
        if (!bundle.Contains(" --scope sidecar\n", StringComparison.Ordinal) ||
            bundle.Contains(" --flush ", StringComparison.Ordinal) ||
            bundle.Contains(" --delete ", StringComparison.Ordinal)) return false;
        try { EmbeddedAssets.BuildMailQueueInspectionBundle("sidecar;bad"); return false; }
        catch (ArgumentException) { return true; }
    }
}
