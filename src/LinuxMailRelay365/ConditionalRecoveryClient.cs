using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record ConditionalRecoveryEntry(string Sha, string State);

internal static class ConditionalRecoveryClient
{
    private static readonly HashSet<string> States = new(StringComparer.Ordinal)
    {
        "different_config_directory", "unexpected_source_file", "config_drift",
        "original_no_map", "configured_map_missing", "map_ownership_unproven",
        "map_identity_or_content_changed", "original_owned_map", "configured_owned_map",
        "invalid_or_missing_backup", "unstable_observation", "state_unverified"
    };

    private static bool IsSha(string value) =>
        Regex.IsMatch(value, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant);

    internal static string Build(string stage, string transaction, string preflight,
        string manager, string recovery)
    {
        string script = "set +x\nset -Eeuo pipefail\numask 077\n" +
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n" +
            "work=$(mktemp -d /tmp/lmr365-recovery.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n";
        foreach (var (name, content) in new[]
        {
            ("stage-conditional-postfix-maps.py", stage),
            ("conditional-postfix-transaction.py", transaction),
            ("inspect-conditional-postfix-activation.py", preflight),
            ("manage-conditional-postfix-offline.py", manager),
            ("inspect-conditional-postfix-recovery.py", recovery)
        })
        {
            if (string.IsNullOrWhiteSpace(content) || content.Contains('\0'))
                throw new ArgumentException("Invalid embedded recovery source.");
            script += "base64 -d > \"$work/" + name +
                "\" <<'LMR365_RECOVERY_SOURCE'\n" +
                Convert.ToBase64String(Encoding.UTF8.GetBytes(content)) +
                "\nLMR365_RECOVERY_SOURCE\n";
        }
        return script + "python3 -I -B \"$work/inspect-conditional-postfix-recovery.py\" --list\n";
    }

    internal static IReadOnlyList<ConditionalRecoveryEntry> Parse(string output)
    {
        if (output.Length > 16384)
            throw new InvalidDataException("Oversized recovery inventory.");
        const string prefix = "CONDITIONAL_RECOVERY_";
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        var entries = new List<ConditionalRecoveryEntry>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            int at = line.IndexOf('=');
            if (at <= prefix.Length || !line.StartsWith(prefix, StringComparison.Ordinal))
                throw new InvalidDataException("Malformed recovery inventory.");
            string key = line[prefix.Length..at], value = line[(at + 1)..];
            if (key == "ENTRY")
            {
                var parts = value.Split(':');
                if (parts.Length != 2 || !IsSha(parts[0]) || !States.Contains(parts[1]) ||
                    !seen.Add(parts[0]) || entries.Count >= 64)
                    throw new InvalidDataException("Invalid recovery entry.");
                entries.Add(new(parts[0], parts[1]));
            }
            else if (!fields.TryAdd(key, value))
                throw new InvalidDataException("Duplicate recovery field.");
        }
        if (fields.Count != 4 || fields.GetValueOrDefault("STATUS") != "observed_read_only" ||
            fields.GetValueOrDefault("WRITE_ALLOWED") != "no" ||
            fields.GetValueOrDefault("POSTFIX_CHANGED") != "no" ||
            !int.TryParse(fields.GetValueOrDefault("COUNT"), NumberStyles.None,
                CultureInfo.InvariantCulture, out int count) || count != entries.Count)
            throw new InvalidDataException("Unverified recovery inventory.");
        return entries;
    }

    internal static bool SelfTest()
    {
        string sha = new('a', 64);
        string result = "CONDITIONAL_RECOVERY_STATUS=observed_read_only\n" +
            "CONDITIONAL_RECOVERY_COUNT=1\nCONDITIONAL_RECOVERY_ENTRY=" +
            sha + ":original_owned_map\nCONDITIONAL_RECOVERY_WRITE_ALLOWED=no\n" +
            "CONDITIONAL_RECOVERY_POSTFIX_CHANGED=no\n";
        if (Parse(result).Single() != new ConditionalRecoveryEntry(sha, "original_owned_map") ||
            Parse(result.Replace("COUNT=1", "COUNT=0")
                .Replace("CONDITIONAL_RECOVERY_ENTRY=" + sha + ":original_owned_map\n", "")).Count != 0 ||
            !Build("s", "t", "p", "m", "r").Contains(
                "inspect-conditional-postfix-recovery.py\" --list", StringComparison.Ordinal))
            return false;
        foreach (string bad in new[]
        {
            result.Replace("COUNT=1", "COUNT=2"),
            result.Replace("WRITE_ALLOWED=no", "WRITE_ALLOWED=yes"),
            result.Replace("original_owned_map", "restore_allowed"),
            result.Replace(sha, "invalid"),
            result + "CONDITIONAL_RECOVERY_ENTRY=" + sha + ":original_owned_map\n"
        })
        {
            try { Parse(bad); return false; }
            catch (InvalidDataException) { }
        }
        return true;
    }
}
