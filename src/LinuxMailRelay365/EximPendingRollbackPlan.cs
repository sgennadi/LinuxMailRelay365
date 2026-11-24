using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// These receipts are valid only for the experimental schema-3 Exim CLI.
internal sealed record EximPendingRollbackPlan(string SafetyId, string TargetId,
    string SafetySha, string TargetSha, string Sha, int Changed, int Total)
{
    internal const string Confirmation = "ROLLBACK_INTERRUPTED_EXIM_CONFIG";
    private const string Prefix = "FOREIGN_PENDING_ROLLBACK_";
    private const string IdPattern = "[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}";
    private const string ShaPattern = "[a-f0-9]{64}";

    private sealed class Receipt
    {
        private readonly Dictionary<string, string> fields = new(StringComparer.Ordinal);
        internal Receipt(string output, string status)
        {
            if (output.Length > 4096 || output.Contains('\0'))
                throw new InvalidDataException("Invalid Exim rollback receipt.");
            foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
            {
                if (line.Length == 0) continue;
                int n = line.IndexOf('=');
                if (n <= Prefix.Length || !line.StartsWith(Prefix, StringComparison.Ordinal) ||
                    !fields.TryAdd(line[Prefix.Length..n], line[(n + 1)..]))
                    throw new InvalidDataException("Malformed or duplicate Exim rollback field.");
            }
            Exact("VERSION", "1");
            Exact("MTA", "exim");
            Exact("STATUS", status);
            Exact("QUEUE_CHANGED", "no");
            Exact("SERVICE_CHANGED", "no");
        }
        internal string Take(string key, string pattern)
        {
            if (!fields.Remove(key, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Invalid or missing Exim rollback field.");
            return value;
        }
        internal void Exact(string key, string value) => Take(key, Regex.Escape(value));
        internal int Count(string key) => int.Parse(Take(key, "0|[1-9][0-9]{0,3}"), CultureInfo.InvariantCulture);
        internal void Complete()
        {
            if (fields.Count != 0)
                throw new InvalidDataException("Unexpected Exim rollback receipt fields.");
        }
    }

    internal static EximPendingRollbackPlan Parse(string output)
    {
        var r = new Receipt(output, "preview_only");
        r.Exact("CONFIG_CHANGED", "no");
        string safety = r.Take("SAFETY_ID", IdPattern), target = r.Take("TARGET_ID", IdPattern);
        string safetySha = r.Take("SAFETY_SHA256", ShaPattern), targetSha = r.Take("TARGET_SHA256", ShaPattern);
        string sha = r.Take("PLAN_SHA256", ShaPattern);
        int changed = r.Count("CHANGED_FILES"), total = r.Count("FILE_COUNT");
        if (safety == target || total is < 1 or > 4096 || changed > total)
            throw new InvalidDataException("Inconsistent Exim rollback plan.");
        r.Complete();
        return new(safety, target, safetySha, targetSha, sha, changed, total);
    }

    internal void VerifyApplied(string output)
    {
        var r = new Receipt(output, "original_verified_service_not_started");
        r.Exact("SAFETY_ID", SafetyId);
        r.Exact("TARGET_ID", TargetId);
        r.Exact("PLAN_SHA256", Sha);
        r.Exact("MARKER_CLEARED", "yes");
        r.Exact("NATIVE_STATIC_CHECK", "passed_partial_parse_only");
        if (r.Count("CHANGED_FILES") != Changed || r.Count("FILE_COUNT") != Total)
            throw new InvalidDataException("Exim rollback result differs from the reviewed plan.");
        r.Complete();
    }

    internal static bool SelfTest()
    {
        string Wrap(string text) => string.Join("\n", text.Split('\n')
            .Where(x => x.Length > 0).Select(x => Prefix + x)) + "\n";
        const string common = "VERSION=1\nMTA=exim\nQUEUE_CHANGED=no\nSERVICE_CHANGED=no\n";
        const string safety = "20261121T005501Z-abcdef012345", target = "20261121T005502Z-012345abcdef";
        string sha = new string('a', 64);
        string ids = "SAFETY_ID=" + safety + "\nTARGET_ID=" + target + "\nPLAN_SHA256=" + sha +
            "\nCHANGED_FILES=1\nFILE_COUNT=2\n";
        string preview = common + ids + "STATUS=preview_only\nCONFIG_CHANGED=no\nSAFETY_SHA256=" +
            new string('b', 64) + "\nTARGET_SHA256=" + new string('c', 64) + "\n";
        string applied = common + ids + "STATUS=original_verified_service_not_started\n" +
            "MARKER_CLEARED=yes\nNATIVE_STATIC_CHECK=passed_partial_parse_only\n";
        var plan = Parse(Wrap(preview));
        plan.VerifyApplied(Wrap(applied));
        if (plan.Changed != 1 || plan.Total != 2 ||
            Parse(Wrap(preview.Replace("CHANGED_FILES=1", "CHANGED_FILES=0"))).Changed != 0)
            return false;
        foreach (string bad in new[] { preview.Replace("MTA=exim", "MTA=sendmail"),
            preview.Replace("CHANGED_FILES=1", "CHANGED_FILES=3"),
            preview.Replace("CONFIG_CHANGED=no", "CONFIG_CHANGED=yes"),
            preview.Replace(target, safety), preview + "FILE_COUNT=2\n" })
        {
            try { Parse(Wrap(bad)); return false; }
            catch (InvalidDataException) { }
        }
        foreach (string bad in new[] { applied.Replace("MARKER_CLEARED=yes", "MARKER_CLEARED=no"),
            applied.Replace("SERVICE_CHANGED=no", "SERVICE_CHANGED=yes"),
            applied.Replace(sha, new string('0', 64)), applied.Replace(safety, target),
            applied.Replace("CHANGED_FILES=1", "CHANGED_FILES=0"), applied + "EXTRA=yes\n" })
        {
            try { plan.VerifyApplied(Wrap(bad)); return false; }
            catch (InvalidDataException) { }
        }
        string read = EmbeddedAssets.BuildEximPendingRollbackPlanBundle();
        string write = EmbeddedAssets.BuildEximPendingRollbackApplyBundle(sha);
        if (!read.Contains(" --pending-rollback-plan\n", StringComparison.Ordinal) ||
            read.Contains(" --pending-rollback-apply ", StringComparison.Ordinal) ||
            read.Contains(" --confirm ", StringComparison.Ordinal) ||
            !write.Contains(" --pending-rollback-apply --approve-sha256 " + sha +
                " --confirm " + Confirmation + "\n", StringComparison.Ordinal))
            return false;
        try { EmbeddedAssets.BuildEximPendingRollbackApplyBundle(sha + "; echo bad"); return false; }
        catch (ArgumentException) { }
        return true;
    }
}
