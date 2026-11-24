using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Read-only receipt; this type never grants permission to restore.
internal sealed record ForeignRestorePlan(string Sha, int Changed, int Total,
    string Service, string Processes, string Queue, string Listener, string Gate)
{
    internal static ForeignRestorePlan Parse(string text, string mta, string id)
    {
        if (mta is not ("exim" or "sendmail") ||
            !Regex.IsMatch(id, @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z") ||
            text.Length > 4096 || text.Contains('\0'))
            throw new InvalidDataException("Invalid native Restore Plan context.");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in text.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            int n = line.IndexOf('=');
            if (n <= 0 || !fields.TryAdd(line[..n], line[(n + 1)..]))
                throw new InvalidDataException("Duplicate or malformed native Restore Plan field.");
        }
        string Take(string key, string pattern)
        {
            if (!fields.Remove(key, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Missing or invalid native Restore Plan field.");
            return value;
        }
        void Exact(string key, string value) => Take(key, Regex.Escape(value));
        Exact("FOREIGN_RESTORE_PLAN_VERSION", "1");
        Exact("FOREIGN_RESTORE_PLAN_MTA", mta);
        Exact("FOREIGN_RESTORE_PLAN_SNAPSHOT", id);
        Exact("FOREIGN_RESTORE_PLAN_CONFIG_CHANGED", "no");
        Exact("FOREIGN_RESTORE_STATUS", "preview_only");
        Exact("FOREIGN_RESTORE_QUEUE_CHANGED", "no");
        Exact("FOREIGN_RESTORE_SERVICE_CHANGED", "no");
        string sha = Take("FOREIGN_RESTORE_PLAN_SHA256", "[a-f0-9]{64}");
        int changed = int.Parse(Take("FOREIGN_RESTORE_CHANGED_FILES", "[0-9]{1,4}"), CultureInfo.InvariantCulture);
        int total = int.Parse(Take("FOREIGN_RESTORE_FILE_COUNT", "[0-9]{1,4}"), CultureInfo.InvariantCulture);
        string service = Take("FOREIGN_RESTORE_PREFLIGHT_SERVICE", "running|stopped_declared|unverified");
        string processes = Take("FOREIGN_RESTORE_PREFLIGHT_PROCESSES", "running|none_observed|unverified");
        string queue = Take("FOREIGN_RESTORE_PREFLIGHT_QUEUE", "empty_reported|nonempty_reported|unverified");
        string listener = Take("FOREIGN_RESTORE_PREFLIGHT_LISTENER", "running|none_observed|unverified");
        string gate = Take("FOREIGN_RESTORE_PREFLIGHT_GATE",
            "blocked_running|blocked_nonempty_queue|blocked_unverified|offline_candidate_manual_recovery_only");
        string expected = service == "running" || processes == "running" || listener == "running"
            ? "blocked_running" : queue == "nonempty_reported" ? "blocked_nonempty_queue"
            : service != "stopped_declared" || processes != "none_observed" ||
              queue != "empty_reported" || listener != "none_observed"
                ? "blocked_unverified" : "offline_candidate_manual_recovery_only";
        if (total is < 1 or > 4096 || changed > total || fields.Count != 0 ||
            (gate != expected && !(expected == "offline_candidate_manual_recovery_only" && gate == "blocked_unverified")))
            throw new InvalidDataException("Inconsistent native Restore Plan receipt.");
        return new(sha, changed, total, service, processes, queue, listener, gate);
    }

    internal static bool SelfTest()
    {
        const string id = "20261121T005501Z-abcdef012345";
        string sample = "FOREIGN_RESTORE_PLAN_VERSION=1\nFOREIGN_RESTORE_PLAN_MTA=exim\n" +
            "FOREIGN_RESTORE_PLAN_SNAPSHOT=" + id + "\nFOREIGN_RESTORE_PLAN_CONFIG_CHANGED=no\n" +
            "FOREIGN_RESTORE_PLAN_SHA256=" + new string('a', 64) + "\n" +
            "FOREIGN_RESTORE_CHANGED_FILES=1\nFOREIGN_RESTORE_FILE_COUNT=3\n" +
            "FOREIGN_RESTORE_PREFLIGHT_SERVICE=stopped_declared\nFOREIGN_RESTORE_PREFLIGHT_PROCESSES=none_observed\n" +
            "FOREIGN_RESTORE_PREFLIGHT_QUEUE=empty_reported\nFOREIGN_RESTORE_PREFLIGHT_LISTENER=none_observed\n" +
            "FOREIGN_RESTORE_PREFLIGHT_GATE=offline_candidate_manual_recovery_only\n" +
            "FOREIGN_RESTORE_STATUS=preview_only\nFOREIGN_RESTORE_QUEUE_CHANGED=no\nFOREIGN_RESTORE_SERVICE_CHANGED=no\n";
        if (Parse(sample, "exim", id).Changed != 1 ||
            Parse(sample.Replace("stopped_declared", "running").Replace("offline_candidate_manual_recovery_only", "blocked_running"),
                "exim", id).Gate != "blocked_running") return false;
        foreach (string bad in new[] { sample.Replace("stopped_declared", "running"),
            sample.Replace("CHANGED_FILES=1", "CHANGED_FILES=4"),
            sample.Replace("CONFIG_CHANGED=no", "CONFIG_CHANGED=yes"),
            sample.Replace("MTA=exim", "MTA=sendmail"),
            sample + "FOREIGN_RESTORE_STATUS=preview_only\n",
            sample + "FOREIGN_RESTORE_APPLY=yes\n" })
        {
            try { Parse(bad, "exim", id); return false; }
            catch (InvalidDataException) { }
        }
        string bundle = EmbeddedAssets.BuildForeignMtaRestorePlanBundle("exim", id);
        if (!bundle.Contains(" --plan " + id, StringComparison.Ordinal) ||
            bundle.Contains(" --apply ", StringComparison.Ordinal) ||
            bundle.Contains(" --approve-sha256 ", StringComparison.Ordinal) ||
            bundle.Contains(" --confirm ", StringComparison.Ordinal)) return false;
        try { EmbeddedAssets.BuildForeignMtaRestorePlanBundle("exim", "../etc"); return false; }
        catch (ArgumentException) { }
        try { EmbeddedAssets.BuildForeignMtaRestorePlanBundle("postfix", id); return false; }
        catch (ArgumentException) { }
        return true;
    }
}
