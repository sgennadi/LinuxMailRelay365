using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record ConditionalOfflineReview(string TransactionSha, string EvidenceSha,
    int TlsDestinations);

internal static class ConditionalOfflineClient
{
    internal const string MaintenancePhrase =
        "I_HAVE_PREVENTED_CONCURRENT_MAIL_AND_CONFIG_CHANGES";
    internal const string ApplyPhrase = "APPLY_STOPPED_POSTFIX_SENDER_MAP";
    internal const string RestorePhrase = "RESTORE_STOPPED_POSTFIX_SENDER_MAP";

    internal static bool IsSha(string? value) => value is not null &&
        Regex.IsMatch(value, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant);

    internal static int EligibleDestinations(IEnumerable<AdvancedRouteRule> rules)
    {
        var items = ConditionalStageClient.Eligible(rules);
        if (items.Any(x => x.Kind == AdvancedRouteMatchKind.RecipientDomain))
            throw new InvalidOperationException("Experimental activation is sender-only.");
        int count = items.Select(x => (x.Host, x.Port)).Distinct().Count();
        if (count is < 1 or > 4)
            throw new InvalidOperationException("Maximum four TLS destinations.");
        return count;
    }

    internal static string Build(string stage, string transaction, string preflight,
        string manager, string operation, string maintenance,
        string? plan = null, string? compiled = null,
        ConditionalOfflineReview? review = null, string? backup = null,
        string? confirmation = null)
    {
        if (maintenance != MaintenancePhrase)
            throw new ArgumentException("Exclusive maintenance confirmation required.");
        string args;
        if (operation == "restore")
        {
            if (!IsSha(backup) || plan is not null || compiled is not null ||
                review is not null || confirmation != RestorePhrase)
                throw new ArgumentException("Exact backup and restore approval required.");
            args = "--restore " + backup + " --confirm " + RestorePhrase;
        }
        else
        {
            if (!IsSha(plan) || !IsSha(compiled) || backup is not null)
                throw new ArgumentException("Exact candidate digests required.");
            string common = " --plan-sha256 " + plan + " --compiled-sha256 " + compiled;
            if (operation == "review" && review is null && confirmation is null)
                args = "--review" + common;
            else if (operation == "apply" && review is not null &&
                IsSha(review.TransactionSha) && IsSha(review.EvidenceSha) &&
                review.TlsDestinations is >= 1 and <= 4 && confirmation == ApplyPhrase)
                args = "--apply" + common +
                    " --approve-transaction-sha256 " + review.TransactionSha +
                    " --approve-evidence-sha256 " + review.EvidenceSha +
                    " --confirm " + ApplyPhrase;
            else throw new ArgumentException("Invalid offline operation or approval.");
        }
        string script = "set +x\nset -Eeuo pipefail\numask 077\n" +
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n" +
            "work=$(mktemp -d /tmp/lmr365-offline.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n";
        foreach (var (name, data) in new[] {
            ("stage-conditional-postfix-maps.py", stage),
            ("conditional-postfix-transaction.py", transaction),
            ("inspect-conditional-postfix-activation.py", preflight),
            ("manage-conditional-postfix-offline.py", manager)
        })
        {
            if (string.IsNullOrWhiteSpace(data) || data.Contains('\0'))
                throw new ArgumentException("Invalid embedded offline module.");
            script += "base64 -d > \"$work/" + name +
                "\" <<'LMR365_OFFLINE_SOURCE'\n" +
                Convert.ToBase64String(Encoding.UTF8.GetBytes(data)) +
                "\nLMR365_OFFLINE_SOURCE\n";
        }
        return script + "python3 -I -B \"$work/manage-conditional-postfix-offline.py\" " +
            args + " --maintenance-confirmation " + MaintenancePhrase + "\n";
    }

    private static Dictionary<string, string> Fields(string output, int count)
    {
        if (output.Length > 4096)
            throw new InvalidDataException("Oversized offline receipt.");
        const string prefix = "CONDITIONAL_OFFLINE_";
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            int at = line.IndexOf('=');
            if (at <= prefix.Length || !line.StartsWith(prefix, StringComparison.Ordinal) ||
                !result.TryAdd(line[prefix.Length..at], line[(at + 1)..]))
                throw new InvalidDataException("Malformed offline receipt.");
        }
        if (result.Count != count ||
            result.GetValueOrDefault("SERVICE_STARTED") != "no" ||
            result.GetValueOrDefault("MAIL_SENT") != "no" ||
            result.GetValueOrDefault("QUEUE_MODIFIED") != "no")
            throw new InvalidDataException("Unverified offline receipt.");
        return result;
    }

    internal static ConditionalOfflineReview ParseReview(string output, int expected)
    {
        var fields = Fields(output, 8);
        string? txn = fields.GetValueOrDefault("TRANSACTION_SHA256");
        string? proof = fields.GetValueOrDefault("EVIDENCE_SHA256");
        if (fields.GetValueOrDefault("STATUS") != "reviewed_offline_experimental" ||
            fields.GetValueOrDefault("POSTFIX_CHANGED") != "no" ||
            !IsSha(txn) || !IsSha(proof) ||
            !int.TryParse(fields.GetValueOrDefault("TLS_DESTINATIONS"), NumberStyles.None,
                CultureInfo.InvariantCulture, out int count) ||
            count != expected || count is < 1 or > 4)
            throw new InvalidDataException("Invalid offline review.");
        return new(txn!, proof!, count);
    }

    internal static void VerifyMutation(string output, string operation, string sha)
    {
        var fields = Fields(output, 6);
        var expected = operation switch {
            "apply" => ("applied_offline_not_started", "yes"),
            "restore" => ("restored_offline_not_started", "restored"),
            _ => throw new ArgumentException("Unknown mutation.")
        };
        if (!IsSha(sha) || fields.GetValueOrDefault("BACKUP_SHA256") != sha ||
            fields.GetValueOrDefault("STATUS") != expected.Item1 ||
            fields.GetValueOrDefault("POSTFIX_CHANGED") != expected.Item2)
            throw new InvalidDataException("Unverified offline write result.");
    }

    internal static bool SelfTest()
    {
        string a = new('a', 64), b = new('b', 64), c = new('c', 64), d = new('d', 64);
        const string common = "CONDITIONAL_OFFLINE_SERVICE_STARTED=no\n" +
            "CONDITIONAL_OFFLINE_MAIL_SENT=no\nCONDITIONAL_OFFLINE_QUEUE_MODIFIED=no\n";
        string report = "CONDITIONAL_OFFLINE_STATUS=reviewed_offline_experimental\n" +
            "CONDITIONAL_OFFLINE_TRANSACTION_SHA256=" + a + "\n" +
            "CONDITIONAL_OFFLINE_EVIDENCE_SHA256=" + b + "\n" +
            "CONDITIONAL_OFFLINE_TLS_DESTINATIONS=2\n" +
            "CONDITIONAL_OFFLINE_POSTFIX_CHANGED=no\n" + common;
        var review = ParseReview(report, 2);
        if (review != new ConditionalOfflineReview(a, b, 2)) return false;
        string applied = "CONDITIONAL_OFFLINE_STATUS=applied_offline_not_started\n" +
            "CONDITIONAL_OFFLINE_BACKUP_SHA256=" + a + "\n" +
            "CONDITIONAL_OFFLINE_POSTFIX_CHANGED=yes\n" + common;
        VerifyMutation(applied, "apply", a);
        VerifyMutation(applied.Replace("applied_offline", "restored_offline")
            .Replace("POSTFIX_CHANGED=yes", "POSTFIX_CHANGED=restored"), "restore", a);
        if (!Build("s", "t", "p", "m", "apply", MaintenancePhrase, c, d, review,
                confirmation: ApplyPhrase).Contains("--approve-evidence-sha256 " + b) ||
            !Build("s", "t", "p", "m", "restore", MaintenancePhrase,
                backup: a, confirmation: RestorePhrase).Contains("--restore " + a))
            return false;
        foreach (string bad in new[] {
            report.Replace("TLS_DESTINATIONS=2", "TLS_DESTINATIONS=3"),
            report.Replace("MAIL_SENT=no", "MAIL_SENT=yes"),
            report + "CONDITIONAL_OFFLINE_STATUS=reviewed_offline_experimental\n"
        })
        {
            try { ParseReview(bad, 2); return false; }
            catch (InvalidDataException) { }
        }
        try { VerifyMutation(applied, "apply", b); return false; }
        catch (InvalidDataException) { }
        try { Build("s", "t", "p", "m", "apply", MaintenancePhrase, c, d, review); return false; }
        catch (ArgumentException) { }
        try { Build("s", "t", "p", "m", "review", "", c, d); return false; }
        catch (ArgumentException) { }
        return true;
    }
}
