using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// A read-only correlation result, never a write approval.
internal sealed record QueueRetryReview(string Result)
{
    internal bool Candidate => Result == "candidate_review_only";
    internal static bool ValidSha(string? value) => value is not null &&
        Regex.IsMatch(value, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant);

    internal static QueueRetryReview Parse(string output, string scope, long sampledAt, QueueMessageRow selected)
    {
        if (output.Length > 4096 || output.Contains('\0') ||
            scope is not ("postfix" or "sidecar") || selected.State != "deferred" || !ValidSha(selected.Fingerprint))
            throw new InvalidDataException("Invalid Retry review context.");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            int pos = line.IndexOf('=');
            if (pos <= 0 || !fields.TryAdd(line[..pos], line[(pos + 1)..]))
                throw new InvalidDataException("Duplicate or malformed Retry review field.");
        }
        string Take(string key, string pattern)
        {
            if (!fields.Remove("MAIL_RETRY_" + key, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Invalid Retry review field: " + key);
            return value;
        }
        void Exact(string key, string value) => Take(key, Regex.Escape(value));
        Exact("VERSION", "1");
        Exact("SCOPE", scope);
        Exact("FINGERPRINT", selected.Fingerprint);
        Exact("SAMPLED_AT", sampledAt.ToString(CultureInfo.InvariantCulture));
        Exact("CHANGES_APPLIED", "no");
        Exact("APPLY_AUTHORIZED", "no");
        Exact("DELIVERY_VERIFIED", "no");
        string result = Take("RESULT", "candidate_review_only|expired|long_ids_required|tool_unavailable|timeout|output_limit|command_failed|invalid_output|scope_unverified|sample_changed");
        if (result == "candidate_review_only")
        {
            string row = Take("ROW", @"deferred\|(?:0|[1-9][0-9]{0,8})\|(?:0|[1-9][0-9]{0,12})\|(?:0|[1-9][0-9]{0,4})\|(?:auth|tls|dns|network|temporary|permanent|mixed|other_reason|no_reason)");
            // The complete fixed shape is checked below. The reason may
            // legitimately change while the same deferred message remains.
            var parts = row.Split('|');
            if (parts.Length != 5 || !int.TryParse(parts[1], out int age) || age < selected.AgeMinutes ||
                parts[2] != selected.Bytes.ToString(CultureInfo.InvariantCulture) ||
                parts[3] != selected.RecipientCount.ToString(CultureInfo.InvariantCulture) ||
                !QueueMessageInventory.Reasons.Contains(parts[4], StringComparer.Ordinal) ||
                parts[4] == "not_applicable")
                throw new InvalidDataException("Retry review differs from selected metadata.");
        }
        if (fields.Count != 0)
            throw new InvalidDataException("Unexpected Retry review fields.");
        return new(result);
    }

    internal static bool SelfTest()
    {
        string nonce = new('a', 64), fingerprint = new('b', 64);
        var row = new QueueMessageRow(1, "deferred", 5, 1024, 1, "tls", fingerprint);
        string sample = "MAIL_RETRY_VERSION=1\nMAIL_RETRY_SCOPE=postfix\nMAIL_RETRY_FINGERPRINT=" + fingerprint +
            "\nMAIL_RETRY_SAMPLED_AT=1000\nMAIL_RETRY_RESULT=candidate_review_only\n" +
            "MAIL_RETRY_CHANGES_APPLIED=no\nMAIL_RETRY_APPLY_AUTHORIZED=no\nMAIL_RETRY_DELIVERY_VERIFIED=no\n" +
            "MAIL_RETRY_ROW=deferred|6|1024|1|tls\n";
        if (!Parse(sample, "postfix", 1000, row).Candidate ||
            Parse(sample.Replace("candidate_review_only", "expired").Replace("MAIL_RETRY_ROW=deferred|6|1024|1|tls\n", ""),
                "postfix", 1000, row).Candidate)
            return false;
        foreach (string bad in new[] { sample.Replace(fingerprint, nonce), sample.Replace("SCOPE=postfix", "SCOPE=sidecar"),
            sample.Replace("SAMPLED_AT=1000", "SAMPLED_AT=999"), sample.Replace("APPLY_AUTHORIZED=no", "APPLY_AUTHORIZED=yes"),
            sample.Replace("|1024|", "|2048|"), sample.Replace("|6|", "|4|"), sample + "MAIL_RETRY_EXTRA=x\n" })
        {
            try { Parse(bad, "postfix", 1000, row); return false; }
            catch (InvalidDataException) { }
        }
        string bundle = EmbeddedAssets.BuildQueueRetryReviewBundle("postfix", nonce, 1000, fingerprint);
        if (!bundle.Contains(" --scope postfix --selection-nonce " + nonce + " --sampled-at 1000 --retry-plan " + fingerprint + "\n", StringComparison.Ordinal))
            return false;
        try { EmbeddedAssets.BuildQueueRetryReviewBundle("postfix", nonce, 1000, "bad;id"); return false; }
        catch (ArgumentException) { return true; }
    }
}
