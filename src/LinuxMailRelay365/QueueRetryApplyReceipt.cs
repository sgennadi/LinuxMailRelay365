using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record PreparedQueueRetry(QueueRetryReview Review, long? PreparedAt, string? PlanSha);
internal sealed record QueueRetryOutcome(string Outcome, string Reason);

internal static class QueueRetryApplyReceipt
{
    internal const string Confirmation = "RETRY_SELECTED_DEFERRED_MESSAGE";

    internal static PreparedQueueRetry ParsePrepare(string output, string scope, long sampledAt, QueueMessageRow row)
    {
        if (output.Length > 4096 || output.Contains('\0'))
            throw new InvalidDataException("Invalid Retry preparation.");
        string? time = null, sha = null;
        var review = new List<string>();
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            if (line.StartsWith("MAIL_RETRY_PREPARED_AT=", StringComparison.Ordinal))
            {
                if (time is not null) throw new InvalidDataException("Duplicate Retry preparation time.");
                time = line["MAIL_RETRY_PREPARED_AT=".Length..];
            }
            else if (line.StartsWith("MAIL_RETRY_PLAN_SHA256=", StringComparison.Ordinal))
            {
                if (sha is not null) throw new InvalidDataException("Duplicate Retry plan.");
                sha = line["MAIL_RETRY_PLAN_SHA256=".Length..];
            }
            else review.Add(line);
        }
        var parsed = QueueRetryReview.Parse(string.Join("\n", review), scope, sampledAt, row);
        if (!parsed.Candidate)
        {
            if (time is not null || sha is not null) throw new InvalidDataException("Refused Retry carries approval data.");
            return new(parsed, null, null);
        }
        if (!long.TryParse(time, NumberStyles.None, CultureInfo.InvariantCulture, out long preparedAt) ||
            time != preparedAt.ToString(CultureInfo.InvariantCulture) ||
            preparedAt < sampledAt || preparedAt > 9999999999 || preparedAt - sampledAt > 300 ||
            !QueueRetryReview.ValidSha(sha))
            throw new InvalidDataException("Invalid Retry plan context.");
        return new(parsed, preparedAt, sha);
    }

    internal static QueueRetryOutcome ParseApply(string output, string scope, long sampledAt,
        string fingerprint, long preparedAt, string planSha)
    {
        if (output.Length > 4096 || output.Contains('\0') ||
            scope is not ("postfix" or "sidecar") || !QueueRetryReview.ValidSha(fingerprint) ||
            !QueueRetryReview.ValidSha(planSha) || sampledAt < 1 || preparedAt < sampledAt ||
            preparedAt > 9999999999 || preparedAt - sampledAt > 300)
            throw new InvalidDataException("Invalid selected Retry result context.");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            int n = line.IndexOf('=');
            if (n <= 0 || !fields.TryAdd(line[..n], line[(n + 1)..]))
                throw new InvalidDataException("Malformed or duplicate Retry result field.");
        }
        string Take(string key, string pattern)
        {
            if (!fields.Remove("MAIL_RETRY_APPLY_" + key, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Invalid Retry result field: " + key);
            return value;
        }
        void Exact(string key, string expected) => Take(key, Regex.Escape(expected));
        Exact("VERSION", "1");
        Exact("SCOPE", scope);
        Exact("FINGERPRINT", fingerprint);
        Exact("SAMPLED_AT", sampledAt.ToString(CultureInfo.InvariantCulture));
        Exact("PREPARED_AT", preparedAt.ToString(CultureInfo.InvariantCulture));
        Exact("PLAN_SHA256", planSha);
        foreach (string flag in new[] { "DELIVERY_VERIFIED", "ATOMIC", "SERVICE_CHANGED",
            "CONFIG_CHANGED", "NEW_MESSAGE_SUBMITTED", "DELETE_REQUESTED", "FLUSH_REQUESTED" })
            Exact(flag, "no");
        string outcome = Take("OUTCOME", "request_accepted|not_requested|outcome_unknown");
        string reason = outcome switch
        {
            "request_accepted" => Take("REASON", "none"),
            "outcome_unknown" => Take("REASON", "native_result_unconfirmed"),
            _ => Take("REASON", "expired|plan_changed|long_ids_required|tool_unavailable|timeout|output_limit|command_failed|invalid_output|scope_unverified|sample_changed")
        };
        Exact("REQUEST_COUNT", outcome == "request_accepted" ? "1" : outcome == "not_requested" ? "0" : "unknown");
        if (fields.Count != 0) throw new InvalidDataException("Unexpected Retry result fields.");
        return new(outcome, reason);
    }

    internal static bool SelfTest()
    {
        string fingerprint = new('a', 64), digest = new('b', 64), nonce = new('c', 64);
        var selected = new QueueMessageRow(1, "deferred", 5, 1024, 1, "tls", fingerprint);
        string review = "MAIL_RETRY_VERSION=1\nMAIL_RETRY_SCOPE=postfix\nMAIL_RETRY_FINGERPRINT=" + fingerprint +
            "\nMAIL_RETRY_SAMPLED_AT=1000\nMAIL_RETRY_RESULT=candidate_review_only\n" +
            "MAIL_RETRY_CHANGES_APPLIED=no\nMAIL_RETRY_APPLY_AUTHORIZED=no\nMAIL_RETRY_DELIVERY_VERIFIED=no\n" +
            "MAIL_RETRY_ROW=deferred|6|1024|1|tls\n";
        string prepared = review + "MAIL_RETRY_PREPARED_AT=1060\nMAIL_RETRY_PLAN_SHA256=" + digest + "\n";
        if (ParsePrepare(prepared, "postfix", 1000, selected).PlanSha != digest) return false;
        string Prefix(string text) => string.Join("\n", text.Split('\n').Select(x => "MAIL_RETRY_APPLY_" + x)) + "\n";
        string result = Prefix("VERSION=1\nSCOPE=postfix\nFINGERPRINT=" + fingerprint +
            "\nSAMPLED_AT=1000\nPREPARED_AT=1060\nPLAN_SHA256=" + digest +
            "\nOUTCOME=request_accepted\nREASON=none\nREQUEST_COUNT=1\nDELIVERY_VERIFIED=no\nATOMIC=no" +
            "\nSERVICE_CHANGED=no\nCONFIG_CHANGED=no\nNEW_MESSAGE_SUBMITTED=no\nDELETE_REQUESTED=no\nFLUSH_REQUESTED=no");
        QueueRetryOutcome Parse(string s) => ParseApply(s, "postfix", 1000, fingerprint, 1060, digest);
        if (Parse(result).Outcome != "request_accepted" ||
            Parse(result.Replace("request_accepted", "outcome_unknown").Replace("REASON=none", "REASON=native_result_unconfirmed")
                .Replace("REQUEST_COUNT=1", "REQUEST_COUNT=unknown")).Outcome != "outcome_unknown" ||
            Parse(result.Replace("request_accepted", "not_requested").Replace("REASON=none", "REASON=expired")
                .Replace("REQUEST_COUNT=1", "REQUEST_COUNT=0")).Outcome != "not_requested")
            return false;
        bool Reject(Action action)
        {
            try { action(); return false; }
            catch (InvalidDataException) { return true; }
        }
        foreach (var bad in new[] { result.Replace("REQUEST_COUNT=1", "REQUEST_COUNT=0"),
            result.Replace("DELIVERY_VERIFIED=no", "DELIVERY_VERIFIED=yes"),
            result.Replace("FLUSH_REQUESTED=no", "FLUSH_REQUESTED=yes"), result.Replace(digest, nonce),
            result + "MAIL_RETRY_APPLY_OUTCOME=request_accepted\n" })
            if (!Reject(() => Parse(bad))) return false;
        if (!Reject(() => ParsePrepare(prepared.Replace("PREPARED_AT=1060", "PREPARED_AT=1301"), "postfix", 1000, selected)) ||
            !Reject(() => ParsePrepare(prepared + "MAIL_RETRY_PLAN_SHA256=" + digest + "\n", "postfix", 1000, selected)))
            return false;
        var bundle = EmbeddedAssets.BuildQueueRetryApplyBundle("postfix", nonce, 1000, fingerprint, 1060, digest);
        if (!bundle.Contains(" --retry-apply " + fingerprint + " --prepared-at 1060 --approve-sha256 " +
            digest + " --confirm " + Confirmation + "\n", StringComparison.Ordinal))
            return false;
        try { EmbeddedAssets.BuildQueueRetryApplyBundle("sendmail", nonce, 1000, fingerprint, 1060, digest); return false; }
        catch (ArgumentException) { return true; }
    }
}
