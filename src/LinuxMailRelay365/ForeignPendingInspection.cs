using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record ForeignPendingCounts(int Total, int Original, int Target,
    int Both, int Other, int Missing, int Extra);

// A sampled informational receipt only. It cannot authorize any write.
internal sealed record ForeignPendingInspection(bool IsClear, string? Mta = null,
    string? SafetyId = null, string? TargetId = null, string? SafetySha = null,
    string? TargetSha = null, ForeignPendingCounts? Counts = null)
{
    internal static ForeignPendingInspection Parse(string output)
    {
        if (output.Length > 4096 || output.Contains('\0'))
            throw new InvalidDataException("Invalid pending Restore receipt.");
        const string prefix = "FOREIGN_PENDING_INSPECT_";
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            int n = line.IndexOf('=');
            if (n <= prefix.Length || !line.StartsWith(prefix, StringComparison.Ordinal) ||
                !fields.TryAdd(line[prefix.Length..n], line[(n + 1)..]))
                throw new InvalidDataException("Duplicate or malformed pending Restore field.");
        }
        string Take(string key, string pattern)
        {
            if (!fields.Remove(key, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Missing or invalid pending Restore field.");
            return value;
        }
        void Exact(string key, string value) => Take(key, Regex.Escape(value));
        int Count(string key) => int.Parse(Take(key, "0|[1-9][0-9]{0,3}"), CultureInfo.InvariantCulture);
        void Complete()
        {
            if (fields.Count != 0)
                throw new InvalidDataException("Unexpected pending Restore fields.");
        }
        Exact("VERSION", "1");
        Exact("CONFIG_CHANGED", "no");
        Exact("QUEUE_CHANGED", "no");
        Exact("SERVICE_CHANGED", "no");
        Exact("RESUME_AUTHORIZED", "no");
        if (Take("STATUS", "clear|manual_recovery_required") == "clear")
        {
            Complete();
            return new(true);
        }
        const string idPattern = "[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}";
        string mta = Take("MTA", "exim|sendmail");
        string safety = Take("SAFETY_ID", idPattern);
        string target = Take("TARGET_ID", idPattern);
        if (safety == target)
            throw new InvalidDataException("Pending Restore archives are not independent.");
        string safetySha = Take("SAFETY_SHA256", "[a-f0-9]{64}");
        string comparison = Take("COMPARISON", "unavailable_legacy_target_unbound|verified_sampled_content_only");
        if (comparison == "unavailable_legacy_target_unbound")
        {
            Complete();
            return new(false, mta, safety, target, safetySha);
        }
        string targetSha = Take("TARGET_SHA256", "[a-f0-9]{64}");
        int total = Count("FILE_COUNT"), original = Count("ORIGINAL_ONLY"),
            restored = Count("TARGET_ONLY"), both = Count("BOTH"), other = Count("OTHER"),
            missing = Count("MISSING"), extra = Count("EXTRA");
        if (total is < 1 or > 4096 || original + restored + both + other + missing != total ||
            extra > 4096 || total - missing + extra > 4096)
            throw new InvalidDataException("Inconsistent pending Restore file counts.");
        Complete();
        return new(false, mta, safety, target, safetySha, targetSha,
            new(total, original, restored, both, other, missing, extra));
    }

    internal static bool SelfTest()
    {
        string Fields(string lines) => string.Join("\n", lines.Split('\n')
            .Where(x => x.Length > 0).Select(x => "FOREIGN_PENDING_INSPECT_" + x)) + "\n";
        const string guards = "VERSION=1\nCONFIG_CHANGED=no\nQUEUE_CHANGED=no\nSERVICE_CHANGED=no\nRESUME_AUTHORIZED=no\n";
        const string safety = "20261121T005501Z-abcdef012345", target = "20261121T005502Z-012345abcdef";
        string head = guards + "STATUS=manual_recovery_required\nMTA=sendmail\nSAFETY_ID=" + safety +
            "\nTARGET_ID=" + target + "\nSAFETY_SHA256=" + new string('a', 64) + "\n";
        string legacy = head + "COMPARISON=unavailable_legacy_target_unbound\n";
        string full = head + "COMPARISON=verified_sampled_content_only\nTARGET_SHA256=" +
            new string('b', 64) + "\nFILE_COUNT=4\nORIGINAL_ONLY=1\nTARGET_ONLY=1\nBOTH=1\nOTHER=0\nMISSING=1\nEXTRA=2\n";
        string clear = guards + "STATUS=clear\n";
        if (!Parse(Fields(clear)).IsClear || Parse(Fields(legacy)).Counts is not null ||
            Parse(Fields(full)).Counts is not { Total: 4, Original: 1, Target: 1, Missing: 1, Extra: 2 } ||
            Parse(Fields(full)).Mta != "sendmail" || Parse(Fields(full)).TargetId != target)
            return false;
        foreach (string bad in new[] { full.Replace("RESUME_AUTHORIZED=no", "RESUME_AUTHORIZED=yes"),
            full.Replace("FILE_COUNT=4", "FILE_COUNT=5"), full.Replace("EXTRA=2", "EXTRA=4096"),
            full.Replace("MISSING=1", "MISSING=-1"), full.Replace("MTA=sendmail", "MTA=postfix"),
            full.Replace(target, safety), full + "STATUS=clear\n",
            legacy + "FILE_COUNT=4\n", clear + "MTA=exim\n",
            full.Replace("SAFETY_SHA256=", "UNKNOWN_SHA256=") })
        {
            try { Parse(Fields(bad)); return false; }
            catch (InvalidDataException) { }
        }
        string bundle = EmbeddedAssets.BuildForeignMtaPendingInspectBundle();
        return bundle.Contains(" --pending-inspect\n", StringComparison.Ordinal) &&
            !bundle.Contains(" --apply ", StringComparison.Ordinal) &&
            !bundle.Contains(" --approve-sha256 ", StringComparison.Ordinal) &&
            !bundle.Contains(" --confirm ", StringComparison.Ordinal);
    }
}
