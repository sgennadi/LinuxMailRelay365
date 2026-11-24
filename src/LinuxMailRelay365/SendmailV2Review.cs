using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Observational receipt only; no method grants write or service-start permission.
internal sealed record SendmailV2Review(
    string ArchiveSha, string ManifestSha, string PlanSha, string Gate,
    int FileCount, int CompiledTargets, int CompiledChanged, int OtherChanged,
    int Missing, int Extra, int MetadataChanged, int ObjectDrift,
    string Service, string Processes, string Queue, string Listener, string OfflineGate)
{
    internal bool IsCandidate => Gate == "compiled_files_review_candidate_only";

    internal static SendmailV2Review Parse(string output, string selectedId, string verifiedArchiveSha)
    {
        const string shaPattern = "[a-f0-9]{64}";
        if (!Regex.IsMatch(selectedId, @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z") ||
            !Regex.IsMatch(verifiedArchiveSha, @"\A" + shaPattern + @"\z") ||
            output.Length > 8192 || output.Contains('\0'))
            throw new InvalidDataException("Invalid Sendmail v2 review context.");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            int n = line.IndexOf('=');
            if (n <= 0 || !fields.TryAdd(line[..n], line[(n + 1)..]))
                throw new InvalidDataException("Duplicate or malformed Sendmail v2 field.");
        }
        string Take(string name, string pattern)
        {
            if (!fields.Remove("SENDMAIL_V2_PLAN_" + name, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Missing or invalid Sendmail v2 review field.");
            return value;
        }
        void Exact(string name, string value) => Take(name, Regex.Escape(value));
        int Count(string name) => int.Parse(Take(name, "0|[1-9][0-9]{0,3}"), CultureInfo.InvariantCulture);

        Exact("VERSION", "1");
        Exact("STATUS", "review_only");
        Exact("SNAPSHOT", selectedId);
        Exact("ARCHIVE_SHA256", verifiedArchiveSha);
        foreach (string field in new[] { "CONFIG_CHANGED", "QUEUE_CHANGED", "SERVICE_CHANGED", "APPLY_AUTHORIZED" })
            Exact(field, "no");
        string manifest = Take("MANIFEST_SHA256", shaPattern);
        string plan = Take("PLAN_SHA256", shaPattern);
        string gate = Take("GATE", "compiled_files_review_candidate_only|blocked_inventory_drift|blocked_offline_preflight|blocked_untrusted_write_scope");
        int total = Count("FILE_COUNT"), targets = Count("COMPILED_TARGETS"), changed = Count("COMPILED_CHANGED"),
            other = Count("OTHER_CHANGED"), missing = Count("MISSING"), extra = Count("EXTRA"),
            metadata = Count("METADATA_CHANGED"), objects = Count("OBJECT_DRIFT");
        string service = Take("OFFLINE_SERVICE", "running|stopped_declared|unverified");
        string processes = Take("OFFLINE_PROCESSES", "running|none_observed|unverified");
        string queue = Take("OFFLINE_QUEUE", "empty_reported|nonempty_reported|unverified");
        string listener = Take("OFFLINE_LISTENER", "running|none_observed|unverified");
        string offline = Take("OFFLINE_GATE", "blocked_running|blocked_nonempty_queue|blocked_unverified|offline_candidate_manual_recovery_only");

        int shared = total - missing;
        if (total is < 1 or > 4096 || missing > total || extra > 4096 || shared + extra > 4096 ||
            targets > 2 || targets > shared || changed > targets || other > shared - targets ||
            metadata > shared || objects > 8192 || fields.Count != 0)
            throw new InvalidDataException("Impossible Sendmail v2 inventory counts.");
        string expectedOffline = service == "running" || processes == "running" || listener == "running"
            ? "blocked_running" : queue == "nonempty_reported" ? "blocked_nonempty_queue"
            : service != "stopped_declared" || processes != "none_observed" ||
              queue != "empty_reported" || listener != "none_observed" ? "blocked_unverified"
            : "offline_candidate_manual_recovery_only";
        if (offline != expectedOffline &&
            !(expectedOffline == "offline_candidate_manual_recovery_only" && offline == "blocked_unverified"))
            throw new InvalidDataException("Inconsistent Sendmail v2 offline evidence.");
        bool drift = targets != 2 || other != 0 || missing != 0 || extra != 0 || metadata != 0 || objects != 0;
        // A blocked preflight is conservative even when visible fields appear clean.
        if (gate != "blocked_offline_preflight" &&
            (offline != "offline_candidate_manual_recovery_only" ||
             (drift != (gate == "blocked_inventory_drift"))))
            throw new InvalidDataException("Inconsistent Sendmail v2 review gate.");
        return new(verifiedArchiveSha, manifest, plan, gate, total, targets, changed, other,
            missing, extra, metadata, objects, service, processes, queue, listener, offline);
    }

    internal static bool SelfTest()
    {
        const string id = "20261121T005501Z-abcdef012345";
        string archive = new('a', 64), manifest = new('b', 64), plan = new('c', 64);
        string sample = "VERSION=1\nSTATUS=review_only\nSNAPSHOT=" + id +
            "\nARCHIVE_SHA256=" + archive + "\nMANIFEST_SHA256=" + manifest + "\nPLAN_SHA256=" + plan +
            "\nGATE=compiled_files_review_candidate_only\nFILE_COUNT=4\nCOMPILED_TARGETS=2\nCOMPILED_CHANGED=1\n" +
            "OTHER_CHANGED=0\nMISSING=0\nEXTRA=0\nMETADATA_CHANGED=0\nOBJECT_DRIFT=0\n" +
            "OFFLINE_SERVICE=stopped_declared\nOFFLINE_PROCESSES=none_observed\nOFFLINE_QUEUE=empty_reported\n" +
            "OFFLINE_LISTENER=none_observed\nOFFLINE_GATE=offline_candidate_manual_recovery_only\n" +
            "CONFIG_CHANGED=no\nQUEUE_CHANGED=no\nSERVICE_CHANGED=no\nAPPLY_AUTHORIZED=no\n";
        string Wrap(string s) => string.Join("\n", s.Split('\n').Where(x => x.Length > 0)
            .Select(x => "SENDMAIL_V2_PLAN_" + x)) + "\n";
        var review = Parse(Wrap(sample), id, archive);
        if (!review.IsCandidate || review.CompiledChanged != 1 || review.ManifestSha != manifest ||
            Parse(Wrap(sample.Replace("OTHER_CHANGED=0", "OTHER_CHANGED=1")
                .Replace("compiled_files_review_candidate_only", "blocked_inventory_drift")), id, archive).IsCandidate ||
            Parse(Wrap(sample.Replace("stopped_declared", "running")
                .Replace("offline_candidate_manual_recovery_only", "blocked_running")
                .Replace("compiled_files_review_candidate_only", "blocked_offline_preflight")), id, archive).IsCandidate)
            return false;
        foreach (string bad in new[] { sample.Replace(archive, manifest), sample.Replace(id, "other"),
            sample.Replace("APPLY_AUTHORIZED=no", "APPLY_AUTHORIZED=yes"), sample.Replace("QUEUE_CHANGED=no", "QUEUE_CHANGED=yes"),
            sample.Replace("COMPILED_CHANGED=1", "COMPILED_CHANGED=3"), sample.Replace("OTHER_CHANGED=0", "OTHER_CHANGED=1"),
            sample.Replace("MISSING=0", "MISSING=5"), sample.Replace("EXTRA=0", "EXTRA=4096"),
            sample.Replace("METADATA_CHANGED=0", "METADATA_CHANGED=5"), sample.Replace("stopped_declared", "running"),
            sample.Replace("MANIFEST_SHA256=" + manifest + "\n", ""), sample + "UNEXPECTED=no\n", sample + "FILE_COUNT=4\n" })
        {
            try { Parse(Wrap(bad), id, archive); return false; }
            catch (InvalidDataException) { }
        }
        string bundle = EmbeddedAssets.BuildSendmailV2ReviewBundle(id);
        if (!bundle.Contains(" --mta sendmail --sendmail-v2-plan " + id + "\n", StringComparison.Ordinal) ||
            bundle.Contains(" --apply ", StringComparison.Ordinal) || bundle.Contains(" --confirm ", StringComparison.Ordinal) ||
            bundle.Contains(" --approve-sha256 ", StringComparison.Ordinal)) return false;
        try { EmbeddedAssets.BuildSendmailV2ReviewBundle("../etc"); return false; }
        catch (ArgumentException) { }
        return true;
    }
}
