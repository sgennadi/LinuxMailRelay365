using System.Globalization;
using System.Text;
using System.Text.Json;

namespace LinuxMailRelay365;

internal sealed record MultiTransportReview(string Plan, string Evidence, string Backend, int Destinations);
internal sealed record MultiTransportRecovery(string Revision, string State);
internal sealed record MultiTransportMutation(string Revision, string Status);

internal static class MultiTransportClient
{
    internal const string ApplyPhrase = "APPLY_NEW_STOPPED_POSTFIX_TRANSPORTS";
    internal const string RestorePhrase = "RESTORE_STOPPED_POSTFIX_TRANSPORTS";
    internal static IReadOnlyList<AdvancedRouteRule> Eligible(IEnumerable<AdvancedRouteRule> rules)
    {
        var items = AdvancedRoutePlanner.ValidatePlan(rules);
        if (items.Count is < 1 or > 8 || items.Any(r =>
            r.Kind == AdvancedRouteMatchKind.RecipientDomain ||
            r.TlsMode is not ("starttls" or "implicit")) ||
            AdvancedRoutePlanner.PossibleOverlaps(items).Count != 0)
            throw new ArgumentException("Use 1–8 non-overlapping sender rules with verified TLS.");
        return items;
    }

    internal static int Destinations(IEnumerable<AdvancedRouteRule> rules) =>
        rules.Select(r => (r.Host, r.Port, r.TlsMode)).Distinct().Count();

    internal static bool ValidCredential(string user, string secret) =>
        user.Length is >= 1 and <= 254 && secret.Length is >= 1 and <= 256 &&
        !user.Contains(':') && user.All(c => c >= 33 && c <= 126) &&
        secret.All(c => c >= 33 && c <= 126);

    internal static string Build(string operation, string? maintenance = null,
        IEnumerable<AdvancedRouteRule>? rules = null, MultiTransportReview? review = null,
        IReadOnlyList<(string User, string Secret)?>? credentials = null,
        string? revision = null, string? confirmation = null)
    {
        if (operation != "scan" && maintenance != ConditionalOfflineClient.MaintenancePhrase)
            throw new ArgumentException("Exclusive maintenance approval required.");
        string args, file = "manage-conditional-transports-offline.py";
        string? payload = null;
        if (operation is "review" or "apply")
        {
            var items = Eligible(rules ?? throw new ArgumentException("Missing route plan."));
            string plan = AdvancedRoutePlanner.PlanSha256(items);
            var wire = items.Select(r => new { selector = r.Selector, pattern = r.Pattern,
                host = r.Host, port = r.Port, tls = r.TlsMode, auth = r.AuthMode }).ToArray();
            if (revision is not null) throw new ArgumentException("Unexpected revision.");
            if (operation == "review" && credentials is null && review is null && confirmation is null)
            {
                args = "--review";
                payload = JsonSerializer.Serialize(wire);
            }
            else if (operation == "apply" && review is not null && review.Plan == plan &&
                     ConditionalOfflineClient.IsSha(review.Evidence) &&
                     review.Backend is "hash" or "lmdb" &&
                     review.Destinations == Destinations(items) &&
                     confirmation == ApplyPhrase && credentials is not null && credentials.Count == items.Count)
            {
                var slots = new object?[items.Count];
                for (int i = 0; i < items.Count; i++)
                {
                    var entry = credentials[i];
                    if (items[i].AuthMode == "none" && entry is null) continue;
                    if (items[i].AuthMode != "password" || entry is null ||
                        !ValidCredential(entry.Value.User, entry.Value.Secret))
                        throw new ArgumentException("Invalid credential slot.");
                    slots[i] = new { username = entry.Value.User, password = entry.Value.Secret };
                }
                args = "--apply --backend " + review.Backend +
                    " --approve-plan-sha256 " + plan + " --approve-review-sha256 " +
                    review.Evidence + " --confirm " + ApplyPhrase;
                payload = JsonSerializer.Serialize(new { rules = wire, credentials = slots });
            }
            else throw new ArgumentException("Invalid review or Apply approval.");
        }
        else if (operation == "restore" && ConditionalOfflineClient.IsSha(revision) &&
                 confirmation == RestorePhrase && rules is null && review is null && credentials is null)
            args = "--restore " + revision + " --confirm " + RestorePhrase;
        else if (operation == "scan" && maintenance is null && rules is null && review is null &&
                 credentials is null && revision is null && confirmation is null)
        {
            file = "inspect-conditional-transport-recovery.py";
            args = "";
        }
        else throw new ArgumentException("Invalid transport operation.");
        if (operation != "scan")
            args += " --maintenance-confirmation " + ConditionalOfflineClient.MaintenancePhrase;

        // Fixed modules only are written to scratch. Request JSON is sent by
        // a shell builtin into a pipe; never an external command argument,
        // environment variable, persistent request file or activity message.
        string script = "set +x\nset -Eeuo pipefail\numask 077\n" +
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n" +
            "work=$(mktemp -d /tmp/lmr365-multi.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n";
        foreach (var (name, source) in new[] {
            ("stage-conditional-postfix-maps.py", EmbeddedAssets.ConditionalStageManager),
            ("conditional-postfix-transaction.py", EmbeddedAssets.ConditionalTransactionManager),
            ("inspect-conditional-postfix-activation.py", EmbeddedAssets.ConditionalActivationPreflight),
            ("manage-conditional-postfix-offline.py", EmbeddedAssets.ConditionalOfflineManager),
            ("compile-conditional-transports.py", EmbeddedAssets.ConditionalTransportCompiler),
            ("conditional-transport-recovery.py", EmbeddedAssets.ConditionalTransportSnapshot),
            ("conditional-transport-transaction.py", EmbeddedAssets.ConditionalTransportTransaction),
            ("manage-conditional-transports-offline.py", EmbeddedAssets.ConditionalTransportHost),
            ("inspect-conditional-transport-recovery.py", EmbeddedAssets.ConditionalTransportRecovery)
        })
            script += "base64 -d > \"$work/" + name + "\" <<'LMR365_MULTI_SOURCE'\n" +
                Convert.ToBase64String(Encoding.UTF8.GetBytes(source)) + "\nLMR365_MULTI_SOURCE\n";
        string run = "python3 -I -B \"$work/" + file + "\" " + args + "\n";
        if (payload is null) return script + run;
        return script + "builtin printf '%s' '" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)) + "' | base64 -d | " + run;
    }

    private static Dictionary<string,string> Fields(string output, string prefix, int count)
    {
        if (output.Length > 4096) throw new InvalidDataException("Oversized receipt.");
        var fields = new Dictionary<string,string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            int i = line.IndexOf('=');
            if (i <= prefix.Length || !line.StartsWith(prefix, StringComparison.Ordinal) ||
                !fields.TryAdd(line[prefix.Length..i], line[(i+1)..]))
                throw new InvalidDataException("Malformed receipt.");
        }
        if (fields.Count != count || fields.GetValueOrDefault("SERVICE_STARTED") != "no" ||
            fields.GetValueOrDefault("MAIL_SENT") != "no" ||
            fields.GetValueOrDefault("QUEUE_MODIFIED") != "no")
            throw new InvalidDataException("Unverified operation.");
        return fields;
    }

    internal static MultiTransportReview ParseReview(string output, string plan, int count)
    {
        var f = Fields(output, "MULTI_TRANSPORT_", 9);
        string? evidence = f.GetValueOrDefault("REVIEW_SHA256"), backend = f.GetValueOrDefault("BACKEND");
        if (!ConditionalOfflineClient.IsSha(plan) || f.GetValueOrDefault("PLAN_SHA256") != plan ||
            !ConditionalOfflineClient.IsSha(evidence) || backend is not ("hash" or "lmdb") ||
            f.GetValueOrDefault("STATUS") != "reviewed_experimental" ||
            f.GetValueOrDefault("POSTFIX_CHANGED") != "no" ||
            count is < 1 or > 8 ||
            f.GetValueOrDefault("TLS_DESTINATIONS") != count.ToString(CultureInfo.InvariantCulture))
            throw new InvalidDataException("Unverified transport review.");
        return new(plan, evidence!, backend!, count);
    }

    internal static MultiTransportMutation ParseMutation(string output, string operation, string? revision)
    {
        var f = Fields(output, "MULTI_TRANSPORT_", 6);
        string? id = f.GetValueOrDefault("RECOVERY_REVISION"), status = f.GetValueOrDefault("STATUS");
        if (!ConditionalOfflineClient.IsSha(id) ||
            (operation == "restore" && id != revision))
            throw new InvalidDataException("Invalid recovery ID.");
        bool valid = (operation, status, f.GetValueOrDefault("POSTFIX_CHANGED")) switch {
            ("apply", "applied_offline_not_started", "yes") => true,
            ("restore", "restored_offline_not_started", "restored") => true,
            ("apply", "rolled_back", "restored") => true,
            ("apply", "manual_recovery_required", "unknown") => true,
            _ => false
        };
        if (!valid) throw new InvalidDataException("Unverified transport write.");
        return new(id!, status!);
    }

    internal static IReadOnlyList<MultiTransportRecovery> ParseInventory(string output)
    {
        if (output.Length > 16384) throw new InvalidDataException("Oversized recovery inventory.");
        const string prefix = "MULTI_RECOVERY_";
        var fields = new Dictionary<string,string>(StringComparer.Ordinal);
        var entries = new List<MultiTransportRecovery>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            int i = line.IndexOf('=');
            if (i <= prefix.Length || !line.StartsWith(prefix, StringComparison.Ordinal))
                throw new InvalidDataException("Malformed recovery inventory.");
            string key = line[prefix.Length..i], value = line[(i+1)..];
            if (key != "ENTRY")
            {
                if (!fields.TryAdd(key, value)) throw new InvalidDataException("Duplicate field.");
                continue;
            }
            var parts = value.Split(':');
            if (parts.Length != 2 || !ConditionalOfflineClient.IsSha(parts[0]) ||
                entries.Count >= 64 || !seen.Add(parts[0]) ||
                parts[1] is not ("snapshot_only" or "publication_unverified" or
                    "different_config_directory" or "configuration_drift" or
                    "original_owned_maps" or "original_no_maps" or "configured_owned_maps" or
                    "configured_maps_missing" or "partial_configuration" or "unverified" or "unstable"))
                throw new InvalidDataException("Invalid recovery entry.");
            entries.Add(new(parts[0], parts[1]));
        }
        if (fields.Count != 4 || fields.GetValueOrDefault("STATUS") != "observed_read_only" ||
            fields.GetValueOrDefault("WRITE_ALLOWED") != "no" ||
            fields.GetValueOrDefault("POSTFIX_CHANGED") != "no" ||
            fields.GetValueOrDefault("COUNT") != entries.Count.ToString(CultureInfo.InvariantCulture))
            throw new InvalidDataException("Unverified recovery inventory.");
        return entries;
    }

    internal static bool SelfTest()
    {
        string a = new('a',64), b = new('b',64);
        const string common = "MULTI_TRANSPORT_SERVICE_STARTED=no\nMULTI_TRANSPORT_MAIL_SENT=no\nMULTI_TRANSPORT_QUEUE_MODIFIED=no\n";
        string review = "MULTI_TRANSPORT_STATUS=reviewed_experimental\nMULTI_TRANSPORT_PLAN_SHA256=" + a +
            "\nMULTI_TRANSPORT_REVIEW_SHA256=" + b + "\nMULTI_TRANSPORT_BACKEND=hash\n" +
            "MULTI_TRANSPORT_TLS_DESTINATIONS=2\nMULTI_TRANSPORT_POSTFIX_CHANGED=no\n" + common;
        if (ParseReview(review,a,2) != new MultiTransportReview(a,b,"hash",2)) return false;
        string mutation = "MULTI_TRANSPORT_STATUS=rolled_back\nMULTI_TRANSPORT_RECOVERY_REVISION=" +
            a + "\nMULTI_TRANSPORT_POSTFIX_CHANGED=restored\n" + common;
        if (ParseMutation(mutation,"apply",null).Revision != a) return false;
        string inventory = "MULTI_RECOVERY_STATUS=observed_read_only\nMULTI_RECOVERY_COUNT=1\n" +
            "MULTI_RECOVERY_ENTRY=" + a + ":snapshot_only\nMULTI_RECOVERY_WRITE_ALLOWED=no\nMULTI_RECOVERY_POSTFIX_CHANGED=no\n";
        if (ParseInventory(inventory).Single().Revision != a ||
            !ValidCredential("fixture","synthetic") || ValidCredential("bad:user","x") ||
            ValidCredential("user","space here")) return false;
        try { ParseReview(review,a,1); return false; } catch (InvalidDataException) {}
        try { ParseInventory(inventory.Replace("WRITE_ALLOWED=no","WRITE_ALLOWED=yes")); return false; }
        catch (InvalidDataException) {}
        try { ParseMutation(mutation,"restore",b); return false; } catch (InvalidDataException) {}
        return Build("scan").Contains("inspect-conditional-transport-recovery.py",StringComparison.Ordinal);
    }
}
