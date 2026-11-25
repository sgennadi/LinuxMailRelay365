using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record QueueMessageRow(int Reference, string State, int AgeMinutes,
    long Bytes, int RecipientCount, string Reason, string Fingerprint = "-");

// No persistent message identity or write authorization is carried by this sample.
internal sealed record QueueMessageInventory(string Scope, string Result, int? Total,
    bool? Truncated, QueueMessageRow[] Rows, long? SampledAt = null, string RetryState = "unverified")
{
    internal const int Limit = 500;
    internal static readonly string[] States =
        ["active", "deferred", "held", "incoming", "maildrop", "other"];
    internal static readonly string[] Reasons =
        ["auth", "tls", "dns", "network", "temporary", "permanent", "mixed", "other_reason", "no_reason", "not_applicable"];

    internal static QueueMessageInventory Parse(string output, string scope, bool requireReviewContext = false)
    {
        if (scope is not ("postfix" or "sidecar") || output.Length > 128 * 1024 || output.Contains('\0'))
            throw new InvalidDataException("Invalid queue message inventory context.");
        const string prefix = "MAIL_ITEMS_";
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        var rows = new List<QueueMessageRow>();
        int? rowFields = null;
        long Number(string value, long max)
        {
            if (!Regex.IsMatch(value, @"\A(?:0|[1-9][0-9]{0,12})\z", RegexOptions.CultureInvariant) ||
                !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long n) || n > max)
                throw new InvalidDataException("Invalid message inventory number.");
            return n;
        }
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            if (line.StartsWith(prefix + "ROW=", StringComparison.Ordinal))
            {
                var parts = line[(prefix.Length + 4)..].Split('|');
                if (parts.Length is not (6 or 7) || (rowFields is not null && rowFields != parts.Length) ||
                    rows.Count >= Limit ||
                    Number(parts[0], Limit) != rows.Count + 1 ||
                    !States.Contains(parts[1], StringComparer.Ordinal) ||
                    !Reasons.Contains(parts[5], StringComparer.Ordinal) ||
                    (parts[1] == "deferred") == (parts[5] == "not_applicable"))
                    throw new InvalidDataException("Invalid queue message row.");
                int age = (int)Number(parts[2], 999999999);
                if (rows.Count > 0 && age > rows[^1].AgeMinutes)
                    throw new InvalidDataException("Queue sample order is inconsistent.");
                rowFields = parts.Length;
                string fingerprint = parts.Length == 7 ? parts[6] : "-";
                if (fingerprint != "-" && (parts[1] != "deferred" || !QueueRetryReview.ValidSha(fingerprint)))
                    throw new InvalidDataException("Invalid Retry fingerprint.");
                rows.Add(new(rows.Count + 1, parts[1], age, Number(parts[3], 1099511627776),
                    (int)Number(parts[4], 10000), parts[5], fingerprint));
                continue;
            }
            int n = line.IndexOf('=');
            if (n <= prefix.Length || !line.StartsWith(prefix, StringComparison.Ordinal) ||
                !fields.TryAdd(line[prefix.Length..n], line[(n + 1)..]))
                throw new InvalidDataException("Malformed or duplicate message inventory field.");
        }
        string Take(string key, string pattern)
        {
            if (!fields.Remove(key, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Missing or invalid message inventory field: " + key);
            return value;
        }
        void Exact(string key, string value) => Take(key, Regex.Escape(value));
        string version = Take("VERSION", requireReviewContext ? "2" : "1|2");
        bool reviewable = version == "2";
        long? sampledAt = reviewable ? Number(Take("SAMPLED_AT", "[1-9][0-9]{0,9}"), 9999999999) : null;
        string retryState = reviewable ? Take("RETRY_STATE", "review_only|long_ids_required|unverified") : "unverified";
        if ((rowFields is not null && rowFields != (reviewable ? 7 : 6)) ||
            (retryState != "review_only" && rows.Any(row => row.Fingerprint != "-")) ||
            rows.Where(row => row.Fingerprint != "-").Select(row => row.Fingerprint).Distinct().Count() !=
                rows.Count(row => row.Fingerprint != "-"))
            throw new InvalidDataException("Inconsistent Retry selection context.");
        Exact("SCOPE", scope);
        Exact("CHANGES_APPLIED", "no");
        Exact("ATOMIC", "no");
        Exact("DELIVERY_VERIFIED", "no");
        Exact("REFERENCE_KIND", "sample_ordinal_only");
        string result = Take("RESULT", "ok|tool_unavailable|timeout|output_limit|command_failed|invalid_output|scope_unverified|sample_changed");
        string rawTotal = Take("TOTAL", "unknown|0|[1-9][0-9]{0,4}");
        int? total = rawTotal == "unknown" ? null : (int)Number(rawTotal, 50000);
        int listed = (int)Number(Take("LISTED", "0|[1-9][0-9]{0,2}"), Limit);
        string rawTruncated = Take("TRUNCATED", "yes|no|unknown");
        bool? truncated = rawTruncated == "unknown" ? null : rawTruncated == "yes";
        if (fields.Count != 0 || rows.Count != listed || (result == "ok") != total.HasValue ||
            (total is null && (listed != 0 || truncated is not null)) ||
            (total is int count && (listed != Math.Min(count, Limit) || truncated != (count > Limit))))
            throw new InvalidDataException("Inconsistent queue message inventory.");
        if (result != "ok" && retryState != "unverified")
            throw new InvalidDataException("Failed inventory cannot carry Retry context.");
        return new(scope, result, total, truncated, rows.ToArray(), sampledAt, retryState);
    }

    internal IEnumerable<QueueMessageRow> Filter(string? state, string? reason, int minimumAge, int? reference = null)
        => Rows.Where(row => (state is null || row.State == state) &&
            (reason is null || row.Reason == reason) && row.AgeMinutes >= minimumAge &&
            (reference is null || row.Reference == reference));

    internal static bool SelfTest()
    {
        string Receipt(string result, string total, int listed, string truncated) =>
            "MAIL_ITEMS_VERSION=1\nMAIL_ITEMS_SCOPE=postfix\nMAIL_ITEMS_RESULT=" + result +
            "\nMAIL_ITEMS_TOTAL=" + total + "\nMAIL_ITEMS_LISTED=" + listed +
            "\nMAIL_ITEMS_TRUNCATED=" + truncated +
            "\nMAIL_ITEMS_CHANGES_APPLIED=no\nMAIL_ITEMS_ATOMIC=no\nMAIL_ITEMS_DELIVERY_VERIFIED=no\n" +
            "MAIL_ITEMS_REFERENCE_KIND=sample_ordinal_only\n";
        string sample = Receipt("ok", "2", 2, "no") +
            "MAIL_ITEMS_ROW=1|deferred|15|1024|1|tls\nMAIL_ITEMS_ROW=2|active|3|2048|2|not_applicable\n";
        var inventory = Parse(sample, "postfix");
        if (inventory.Filter("deferred", "tls", 10).Single().Reference != 1 ||
            inventory.Filter(null, null, 0, 2).Single().Bytes != 2048 ||
            inventory.Filter("active", null, 10).Any() ||
            Parse(Receipt("timeout", "unknown", 0, "unknown"), "postfix").Total is not null ||
            Parse(Receipt("ok", "0", 0, "no"), "postfix").Rows.Length != 0)
            return false;
        string capped = Receipt("ok", "600", Limit, "yes") +
            string.Concat(Enumerable.Range(1, Limit).Select(i =>
                "MAIL_ITEMS_ROW=" + i + "|active|0|20|1|not_applicable\n"));
        if (Parse(capped, "postfix") is not { Total: 600, Truncated: true, Rows.Length: Limit })
            return false;
        bool Reject(string value, string scope = "postfix")
        {
            try { Parse(value, scope); return false; }
            catch (InvalidDataException) { return true; }
        }
        if (!Reject(sample, "sidecar") || !Reject(sample.Replace("TOTAL=2", "TOTAL=3")) ||
            !Reject(sample.Replace("ROW=2", "ROW=1")) ||
            !Reject(sample.Replace("|active|3|", "|active|16|")) ||
            !Reject(sample.Replace("|tls", "|private@example.invalid")) ||
            !Reject(sample.Replace("|tls", "|not_applicable")) ||
            !Reject(sample.Replace("|not_applicable", "|tls")) ||
            !Reject(sample.Replace("CHANGES_APPLIED=no", "CHANGES_APPLIED=yes")) ||
            !Reject(sample + "MAIL_ITEMS_RAW=message\n") ||
            !Reject(sample.Replace("|1024|", "|1099511627777|")) ||
            !Reject(Receipt("timeout", "0", 0, "no")))
            return false;
        string bundle = EmbeddedAssets.BuildMailQueueInspectionBundle("postfix", messages: true);
        if (!bundle.Contains(" --scope postfix --messages\n", StringComparison.Ordinal)) return false;
        try { EmbeddedAssets.BuildMailQueueInspectionBundle("sendmail", messages: true); return false; }
        catch (ArgumentException) { return true; }
    }
}
