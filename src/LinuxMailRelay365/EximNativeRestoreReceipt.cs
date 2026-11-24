using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Experimental offline Exim Restore only. Never authorize service startup.
internal sealed record EximNativeRestoreReceipt(string SafetyId, string SafetySha)
{
    internal const string Confirmation = "RESTORE_STOPPED_FOREIGN_MTA_CONFIG";

    internal static bool CanApply(ForeignRestorePlan plan) =>
        plan.Gate == "offline_candidate_manual_recovery_only" &&
        plan.Service == "stopped_declared" && plan.Processes == "none_observed" &&
        plan.Queue == "empty_reported" && plan.Listener == "none_observed" &&
        plan.Total is >= 1 and <= 4096 && plan.Changed >= 0 && plan.Changed <= plan.Total;

    internal static EximNativeRestoreReceipt Parse(string output, string selectedId, ForeignRestorePlan plan)
    {
        if (!CanApply(plan) || output.Length > 4096 || output.Contains('\0'))
            throw new InvalidDataException("Invalid Exim Restore receipt context.");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            int n = line.IndexOf('=');
            if (n <= 0 || !fields.TryAdd(line[..n], line[(n + 1)..]))
                throw new InvalidDataException("Duplicate or malformed Exim Restore field.");
        }
        string Take(string key, string pattern)
        {
            if (!fields.Remove("FOREIGN_RESTORE_" + key, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Missing or invalid Exim Restore field.");
            return value;
        }
        void Exact(string key, string value) => Take(key, Regex.Escape(value));
        Exact("APPLY_VERSION", "1");
        Exact("APPLY_MTA", "exim");
        Exact("APPLY_SNAPSHOT", selectedId);
        Exact("APPLY_PLAN_SHA256", plan.Sha);
        Exact("APPLY_SNAPSHOT_SHA256", plan.SnapshotSha);
        Exact("STATUS", "config_replaced_service_not_started");
        Exact("QUEUE_CHANGED", "no");
        Exact("SERVICE_CHANGED", "no");
        Exact("MARKER_CLEARED", "yes");
        Exact("NATIVE_STATIC_CHECK", "passed_partial_parse_only");
        Exact("FILE_COUNT", plan.Total.ToString(CultureInfo.InvariantCulture));
        Exact("CHANGED_FILES", plan.Changed.ToString(CultureInfo.InvariantCulture));
        string safety = Take("SAFETY_BACKUP_ID", "[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}");
        string sha = Take("SAFETY_SHA256", "[a-f0-9]{64}");
        if (safety == selectedId || fields.Count != 0)
            throw new InvalidDataException("Inconsistent Exim Restore recovery evidence.");
        return new(safety, sha);
    }

    internal static bool SelfTest()
    {
        const string id = "20261121T005501Z-abcdef012345", safety = "20261121T005502Z-012345abcdef";
        string planSha = new string('a', 64), archiveSha = new string('b', 64), safetySha = new string('c', 64);
        var plan = new ForeignRestorePlan(planSha, 1, 2, "stopped_declared", "none_observed",
            "empty_reported", "none_observed", "offline_candidate_manual_recovery_only", archiveSha);
        string receipt = "APPLY_VERSION=1\nAPPLY_MTA=exim\nAPPLY_SNAPSHOT=" + id +
            "\nAPPLY_PLAN_SHA256=" + planSha + "\nAPPLY_SNAPSHOT_SHA256=" + archiveSha +
            "\nSAFETY_BACKUP_ID=" + safety + "\nSAFETY_SHA256=" + safetySha +
            "\nSTATUS=config_replaced_service_not_started\nQUEUE_CHANGED=no\nSERVICE_CHANGED=no\n" +
            "MARKER_CLEARED=yes\nNATIVE_STATIC_CHECK=passed_partial_parse_only\nFILE_COUNT=2\nCHANGED_FILES=1\n";
        string Wrap(string s) => string.Join("\n", s.Split('\n').Where(x => x.Length > 0)
            .Select(x => "FOREIGN_RESTORE_" + x)) + "\n";
        if (Parse(Wrap(receipt), id, plan).SafetyId != safety ||
            CanApply(plan with { Queue = "nonempty_reported" }) ||
            CanApply(plan with { Service = "running" }) ||
            CanApply(plan with { Gate = "blocked_unverified" }))
            return false;
        foreach (string bad in new[] { receipt.Replace("APPLY_MTA=exim", "APPLY_MTA=sendmail"),
            receipt.Replace(planSha, new string('d', 64)), receipt.Replace(archiveSha, safetySha),
            receipt.Replace("MARKER_CLEARED=yes", "MARKER_CLEARED=no"),
            receipt.Replace("SERVICE_CHANGED=no", "SERVICE_CHANGED=yes"),
            receipt.Replace("CHANGED_FILES=1", "CHANGED_FILES=2"), receipt.Replace(safety, id),
            receipt + "FILE_COUNT=2\n", receipt + "UNEXPECTED=yes\n" })
        {
            try { Parse(Wrap(bad), id, plan); return false; }
            catch (InvalidDataException) { }
        }
        string bundle = EmbeddedAssets.BuildEximNativeRestoreApplyBundle(id, planSha);
        if (!bundle.Contains(" --mta exim --apply " + id + " --approve-sha256 " + planSha +
                " --confirm " + Confirmation + "\n", StringComparison.Ordinal))
            return false;
        try { EmbeddedAssets.BuildEximNativeRestoreApplyBundle("../etc", planSha); return false; }
        catch (ArgumentException) { }
        try { EmbeddedAssets.BuildEximNativeRestoreApplyBundle(id, planSha + "; echo bad"); return false; }
        catch (ArgumentException) { }
        return true;
    }
}
