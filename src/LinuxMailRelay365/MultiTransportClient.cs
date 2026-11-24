using System.Globalization;
using System.Text;
using System.Text.Json;

namespace LinuxMailRelay365;

internal sealed record MultiTransportReview(string Plan, string Evidence, string Backend, int Destinations);
internal sealed record MultiTransportRecovery(string Revision, string State);
internal sealed record MultiTransportMutation(string Revision, string Status);

internal sealed record MultiTransportInstalled(string Status, string? Revision, string? Plan,
    string? Backend, IReadOnlyList<AdvancedRouteRule> Rules);

// Read-only comparison; these records are never a Linux write authorization.
internal sealed record MultiTransportEditItem(string Change, int? OldIndex, int? NewIndex,
    AdvancedRouteRule? Before, AdvancedRouteRule? After, string CredentialIntent);
internal sealed record MultiTransportEditPreview(string Revision, string CurrentPlan,
    string DraftPlan, IReadOnlyList<MultiTransportEditItem> Items);

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

    internal static MultiTransportEditPreview PreviewEdit(MultiTransportInstalled installed,
        IEnumerable<AdvancedRouteRule> draft)
    {
        if (installed.Status != "installed_owned" ||
            !ConditionalOfflineClient.IsSha(installed.Revision) ||
            !ConditionalOfflineClient.IsSha(installed.Plan) ||
            installed.Backend is not ("hash" or "lmdb"))
            throw new ArgumentException("An owned installed set is required.");
        var current = Eligible(installed.Rules);
        if (!current.SequenceEqual(installed.Rules) ||
            AdvancedRoutePlanner.PlanSha256(current) != installed.Plan)
            throw new ArgumentException("Installed plan no longer matches.");
        // Empty drafts are useful to review removal of all rules, but are
        // never eligible for the first-install Apply or an edit transaction.
        var requested = AdvancedRoutePlanner.ValidatePlan(draft);
        var next = requested.Count == 0 ? requested : Eligible(requested);
        var oldByKey = current.Select((rule, i) => (Rule: rule, Index: i + 1))
            .ToDictionary(x => (x.Rule.Kind, x.Rule.Pattern));
        var newKeys = new HashSet<(AdvancedRouteMatchKind, string)>();
        var items = new List<MultiTransportEditItem>();
        for (int i = 0; i < next.Count; i++)
        {
            var rule = next[i];
            var key = (rule.Kind, rule.Pattern);
            newKeys.Add(key);
            if (oldByKey.TryGetValue(key, out var old))
            {
                bool same = old.Rule == rule;
                // Never infer that a credential is appropriate for a new
                // endpoint, changed TLS, different selector or new auth mode.
                // Even an unchanged candidate is NOT read, copied or approved.
                string intent = rule.AuthMode == "none" ? "none" :
                    same ? "existing_candidate_only" : "new_credential_required";
                items.Add(new(same ? (old.Index == i + 1 ? "unchanged" : "moved") : "modified",
                    old.Index, i + 1, old.Rule, rule, intent));
            }
            else
                items.Add(new("added", null, i + 1, null, rule,
                    rule.AuthMode == "password" ? "new_credential_required" : "none"));
        }
        for (int i = 0; i < current.Count; i++)
        {
            var rule = current[i];
            if (!newKeys.Contains((rule.Kind, rule.Pattern)))
                items.Add(new("removed", i + 1, null, rule, null,
                    rule.AuthMode == "password" ? "remove_reference_only" : "none"));
        }
        return new(installed.Revision!, installed.Plan!,
            AdvancedRoutePlanner.PlanSha256(next), items.AsReadOnly());
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
        if (operation is not ("scan" or "installed") && maintenance != ConditionalOfflineClient.MaintenancePhrase)
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
        else if (operation is "scan" or "installed" && maintenance is null && rules is null && review is null &&
                 credentials is null && revision is null && confirmation is null)
        {
            file = "inspect-conditional-transport-recovery.py";
            args = operation == "installed" ? "--installed" : "";
        }
        else throw new ArgumentException("Invalid transport operation.");
        if (operation is not ("scan" or "installed"))
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
                    "configured_maps_missing" or "partial_configuration" or "credential_rotation_pending" or
                    "unverified" or "unstable"))
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

    private static void ExactProperties(JsonElement element, params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Invalid installed transport object.");
        var names = element.EnumerateObject().Select(x => x.Name).ToArray();
        if (names.Length != expected.Length || !names.ToHashSet(StringComparer.Ordinal)
                .SetEquals(expected))
            throw new InvalidDataException("Unexpected installed transport fields.");
    }

    internal static MultiTransportInstalled ParseInstalled(string output)
    {
        const string prefix = "MULTI_INSTALLED_JSON=";
        string line = output.TrimEnd('\r', '\n');
        if (line.Length > 16384 || !line.StartsWith(prefix, StringComparison.Ordinal) ||
            line.Contains('\n') || line.Contains('\r'))
            throw new InvalidDataException("Malformed installed transport receipt.");
        using var doc = JsonDocument.Parse(line[prefix.Length..]);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("status", out var statusElement))
            throw new InvalidDataException("Missing installed status.");
        string? status = statusElement.GetString();
        if (status is "no_effective_transport_map" or "external_or_unverified")
        {
            ExactProperties(root, "status");
            return new(status, null, null, null, Array.Empty<AdvancedRouteRule>());
        }
        ExactProperties(root, "status", "revision", "plan", "backend", "rules");
        string? revision = root.GetProperty("revision").GetString();
        string? plan = root.GetProperty("plan").GetString();
        string? backend = root.GetProperty("backend").GetString();
        var array = root.GetProperty("rules");
        if (status != "installed_owned" || !ConditionalOfflineClient.IsSha(revision) ||
            !ConditionalOfflineClient.IsSha(plan) || backend is not ("hash" or "lmdb") ||
            array.ValueKind != JsonValueKind.Array || array.GetArrayLength() is < 1 or > 8)
            throw new InvalidDataException("Unverified installed transport receipt.");
        var rules = new List<AdvancedRouteRule>();
        foreach (var entry in array.EnumerateArray())
        {
            ExactProperties(entry, "selector", "pattern", "host", "port", "tls", "auth");
            var kind = entry.GetProperty("selector").GetString() switch
            {
                "exact-envelope-sender" => AdvancedRouteMatchKind.ExactEnvelopeSender,
                "envelope-sender-domain" => AdvancedRouteMatchKind.EnvelopeSenderDomain,
                _ => throw new InvalidDataException("Unsupported installed selector.")
            };
            rules.Add(new(kind, entry.GetProperty("pattern").GetString() ?? "",
                entry.GetProperty("host").GetString() ?? "", entry.GetProperty("port").GetInt32(),
                entry.GetProperty("tls").GetString() ?? "", entry.GetProperty("auth").GetString() ?? ""));
        }
        var normalized = Eligible(rules);
        if (!rules.SequenceEqual(normalized) || AdvancedRoutePlanner.PlanSha256(normalized) != plan)
            throw new InvalidDataException("Installed plan hash mismatch.");
        return new(status, revision, plan, backend, normalized);
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
        var rule = new AdvancedRouteRule(AdvancedRouteMatchKind.ExactEnvelopeSender,
            "user@example.org", "relay.example.net", 587, "starttls", "password");
        string plan = AdvancedRoutePlanner.PlanSha256(new[] { rule });
        string installed = "MULTI_INSTALLED_JSON=" + JsonSerializer.Serialize(new {
            status = "installed_owned", revision = a, plan, backend = "hash",
            rules = new[] { new { selector = rule.Selector, pattern = rule.Pattern,
                host = rule.Host, port = rule.Port, tls = rule.TlsMode, auth = rule.AuthMode } }
        });
        if (ParseInstalled(installed).Rules.Single() != rule ||
            ParseInstalled("MULTI_INSTALLED_JSON={\"status\":\"no_effective_transport_map\"}").Rules.Count != 0)
            return false;
        try { ParseInstalled(installed.Replace(plan,b)); return false; }
        catch (InvalidDataException) {}
        try { ParseInstalled(installed.Replace("\"auth\":", "\"secret\":\"x\",\"auth\":")); return false; }
        catch (InvalidDataException) {}
        var observation = ParseInstalled(installed);
        var noAuth = rule with { Pattern = "other@example.org", AuthMode = "none", Port = 25 };
        var password = rule with { Pattern = "third@example.org" };
        var modified = rule with { Port = 465, TlsMode = "implicit" };
        var originalRules = new[] { rule, noAuth };
        var original = observation with { Rules = originalRules,
            Plan = AdvancedRoutePlanner.PlanSha256(originalRules) };
        var unchanged = PreviewEdit(original, originalRules);
        if (unchanged.CurrentPlan != unchanged.DraftPlan ||
            unchanged.Items.Any(x => x.Change != "unchanged") ||
            unchanged.Items[0].CredentialIntent != "existing_candidate_only") return false;
        var moved = PreviewEdit(original, new[] { noAuth, rule });
        if (moved.CurrentPlan == moved.DraftPlan || moved.Items.Any(x => x.Change != "moved") ||
            moved.Items[1].OldIndex != 1 || moved.Items[1].NewIndex != 2 ||
            moved.Items[1].CredentialIntent != "existing_candidate_only") return false;
        var changed = PreviewEdit(original, new[] { modified, password });
        if (changed.Items.Select(x => x.Change).SequenceEqual(new[] { "modified", "added", "removed" }) == false ||
            changed.Items[0].CredentialIntent != "new_credential_required" ||
            changed.Items[1].CredentialIntent != "new_credential_required" ||
            changed.Items[2].CredentialIntent != "none") return false;
        var empty = PreviewEdit(original, Array.Empty<AdvancedRouteRule>());
        if (empty.Items.Count != 2 || empty.Items.Any(x => x.Change != "removed") ||
            empty.Items[0].CredentialIntent != "remove_reference_only") return false;
        var renamed = PreviewEdit(observation, new[] { password });
        if (renamed.Items.Count != 2 || renamed.Items[0].Change != "added" ||
            renamed.Items[0].CredentialIntent != "new_credential_required" ||
            renamed.Items[1].Change != "removed") return false;
        var disabled = PreviewEdit(observation, new[] { rule with { AuthMode = "none" } });
        if (disabled.Items.Single().CredentialIntent != "none") return false;
        try { PreviewEdit(original with { Plan = b }, originalRules); return false; }
        catch (ArgumentException) {}
        try { PreviewEdit(original with { Status = "external_or_unverified" }, originalRules); return false; }
        catch (ArgumentException) {}
        try { PreviewEdit(original, new[] { rule, rule }); return false; }
        catch (ArgumentException) {}
        try { PreviewEdit(original, new[] { rule with { Kind = AdvancedRouteMatchKind.RecipientDomain,
            Pattern = "example.org" } }); return false; }
        catch (ArgumentException) {}
        return Build("scan").Contains("inspect-conditional-transport-recovery.py",StringComparison.Ordinal)
            && Build("installed").Contains("inspect-conditional-transport-recovery.py\" --installed",StringComparison.Ordinal);
    }
}
