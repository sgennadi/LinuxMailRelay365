using System.Globalization;
using System.Text;
using System.Text.Json;

namespace LinuxMailRelay365;

internal sealed record TransportEditReview(string OldRevision, string OldPlan, string NewPlan,
    string Backend, string Evidence, int Destinations, IReadOnlyList<int> RetainIndices);

internal sealed record TransportEditRecovery(string OldRevision, string NewRevision, string OldPlan,
    string NewPlan, string Backend, string Phase, string Layout, string Evidence,
    bool CanCommit, bool CanRollback);

internal sealed record TransportEditSlot(bool Retain, string? User = null, string? Secret = null);

internal static class TransportEditClient
{
    internal const string SwitchPhrase = "SWITCH_STOPPED_POSTFIX_TRANSPORTS";
    internal const string CommitPhrase = "COMMIT_STOPPED_POSTFIX_TRANSPORT_EDIT";
    internal const string RollbackPhrase = "ROLLBACK_STOPPED_POSTFIX_TRANSPORT_EDIT";
    private const string Prefix = "EDIT_";
    private static bool Sha(string? value) => ConditionalOfflineClient.IsSha(value);

    private static int[] RetainIndices(MultiTransportInstalled installed, IReadOnlyList<AdvancedRouteRule> draft)
    {
        var preview = MultiTransportClient.PreviewEdit(installed, draft);
        if (draft.Count == 0 || preview.CurrentPlan == preview.DraftPlan)
            throw new ArgumentException("A changed nonempty route plan is required.");
        return preview.Items.Where(x => x.NewIndex.HasValue).OrderBy(x => x.NewIndex)
            .Select(x => x.CredentialIntent == "existing_candidate_only" ? x.OldIndex!.Value : 0).ToArray();
    }

    private static bool ValidReview(TransportEditReview review, MultiTransportInstalled installed,
        IReadOnlyList<AdvancedRouteRule> draft) =>
        review.OldRevision == installed.Revision && review.OldPlan == installed.Plan &&
        review.NewPlan == AdvancedRoutePlanner.PlanSha256(draft) && review.Backend == installed.Backend &&
        Sha(review.Evidence) && review.Destinations == MultiTransportClient.Destinations(draft) &&
        review.RetainIndices.SequenceEqual(RetainIndices(installed, draft));

    private static bool ValidRecovery(TransportEditRecovery r) =>
        Sha(r.OldRevision) && Sha(r.NewRevision) && r.OldRevision != r.NewRevision &&
        Sha(r.OldPlan) && Sha(r.NewPlan) && r.OldPlan != r.NewPlan && Sha(r.Evidence) &&
        r.Backend is "hash" or "lmdb" &&
        (r.Phase switch
        {
            "pending" => r.CanRollback && (r.Layout is "old" or "new" or "mixed") &&
                (!r.CanCommit || r.Layout == "new"),
            "commit" => r.CanCommit && !r.CanRollback && r.Layout == "new",
            "rollback" => r.CanRollback && !r.CanCommit && r.Layout == "old",
            _ => false
        });

    internal static string Build(string operation, string maintenance,
        MultiTransportInstalled? installed = null, IEnumerable<AdvancedRouteRule>? draft = null,
        TransportEditReview? review = null, IReadOnlyList<TransportEditSlot?>? slots = null,
        TransportEditRecovery? recovery = null, string? confirmation = null)
    {
        if (maintenance != ConditionalOfflineClient.MaintenancePhrase)
            throw new ArgumentException("Exclusive maintenance approval required.");
        string args;
        string? payload = null;
        if (operation is "review" or "switch")
        {
            if (installed is null || draft is null || recovery is not null)
                throw new ArgumentException("An owned installed set and draft are required.");
            var rules = MultiTransportClient.Eligible(draft);
            var retain = RetainIndices(installed, rules);
            var wire = rules.Select(r => new { selector = r.Selector, pattern = r.Pattern,
                host = r.Host, port = r.Port, tls = r.TlsMode, auth = r.AuthMode }).ToArray();
            args = "--" + operation + " " + installed.Revision;
            if (operation == "review" && review is null && slots is null && confirmation is null)
                payload = JsonSerializer.Serialize(wire);
            else if (operation == "switch" && review is not null && ValidReview(review, installed, rules) &&
                     slots is not null && slots.Count == rules.Count && confirmation == SwitchPhrase)
            {
                var credentials = new object?[rules.Count];
                for (int i = 0; i < rules.Count; i++)
                {
                    var slot = slots[i];
                    if (rules[i].AuthMode == "none" && slot is null) continue;
                    if (rules[i].AuthMode != "password" || slot is null)
                        throw new ArgumentException("An explicit credential choice is required.");
                    if (slot.Retain)
                    {
                        if (retain[i] == 0 || slot.User is not null || slot.Secret is not null)
                            throw new ArgumentException("Credential reuse is not allowed for this rule.");
                        credentials[i] = new { mode = "retain" };
                    }
                    else
                    {
                        if (slot.User is null || slot.Secret is null ||
                            !MultiTransportClient.ValidCredential(slot.User, slot.Secret))
                            throw new ArgumentException("Valid new credentials required.");
                        credentials[i] = new { mode = "new", credential = new {
                            username = slot.User, password = slot.Secret } };
                    }
                }
                args += " --approve-plan-sha256 " + review.NewPlan +
                    " --approve-review-sha256 " + review.Evidence + " --confirm " + SwitchPhrase;
                payload = JsonSerializer.Serialize(new { rules = wire, credentials });
            }
            else throw new ArgumentException("Invalid edit review or switch request.");
        }
        else if (installed is null && draft is null && review is null && slots is null)
        {
            if (operation == "review-recovery" && recovery is null && confirmation is null)
                args = "--review-recovery";
            else if ((operation is "commit" or "rollback") && recovery is not null && ValidRecovery(recovery) &&
                     (operation == "commit" ? recovery.CanCommit : recovery.CanRollback) &&
                     confirmation == (operation == "commit" ? CommitPhrase : RollbackPhrase))
                args = "--" + operation + " " + recovery.NewRevision +
                    " --approve-review-sha256 " + recovery.Evidence + " --confirm " + confirmation;
            else throw new ArgumentException("Invalid edit recovery request.");
        }
        else throw new ArgumentException("Unexpected edit recovery arguments.");

        args += " --maintenance-confirmation " + ConditionalOfflineClient.MaintenancePhrase;
        string script = "set +x\nset -Eeuo pipefail\numask 077\n" +
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n" +
            "work=$(mktemp -d /tmp/lmr365-edit.XXXXXXXX)\n" +
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
            ("inspect-conditional-transport-recovery.py", EmbeddedAssets.ConditionalTransportRecovery),
            ("conditional-transport-rotation.py", EmbeddedAssets.ConditionalTransportRotation),
            ("conditional-transport-edit.py", EmbeddedAssets.ConditionalTransportEdit),
            ("conditional-transport-edit-transaction.py", EmbeddedAssets.ConditionalTransportEditTransaction),
            ("manage-conditional-transport-edit.py", EmbeddedAssets.ConditionalTransportEditHost)
        })
        {
            if (string.IsNullOrWhiteSpace(source) || source.Contains('\0'))
                throw new InvalidDataException("Invalid embedded edit module.");
            script += "base64 -d > \"$work/" + name + "\" <<'LMR365_EDIT_SOURCE'\n" +
                Convert.ToBase64String(Encoding.UTF8.GetBytes(source)) + "\nLMR365_EDIT_SOURCE\n";
        }
        string command = "python3 -I -B \"$work/manage-conditional-transport-edit.py\" " + args + "\n";
        // Only the SSH stdin contains the secret-bearing script. Input auditing
        // may still record it. Never persist or log the payload.
        return payload is null ? script + command : script + "builtin printf '%s' '" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)) + "' | base64 -d | " + command;
    }

    private static Dictionary<string, string> Fields(string output, int exitCode)
    {
        if (exitCode != 0 || output.Length > 4096)
            throw new InvalidDataException("Unverified edit operation.");
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            int at = line.IndexOf('=');
            if (at <= Prefix.Length || !line.StartsWith(Prefix, StringComparison.Ordinal) ||
                !result.TryAdd(line[Prefix.Length..at], line[(at + 1)..]))
                throw new InvalidDataException("Malformed edit receipt.");
        }
        foreach (string flag in new[] { "SERVICE_STARTED", "MAIL_SENT", "QUEUE_MODIFIED", "SMTP_AUTH_ATTEMPTED" })
            if (result.GetValueOrDefault(flag) != "no")
                throw new InvalidDataException("Unverified edit safety flags.");
        return result;
    }

    private static void Exact(Dictionary<string, string> f, params string[] extra)
    {
        var fields = new HashSet<string>(extra, StringComparer.Ordinal)
        { "STATUS", "POSTFIX_CHANGED", "SERVICE_STARTED", "MAIL_SENT", "QUEUE_MODIFIED", "SMTP_AUTH_ATTEMPTED" };
        if (!fields.SetEquals(f.Keys)) throw new InvalidDataException("Unexpected edit receipt fields.");
    }

    private static int Number(string value, int min, int max)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int n) ||
            n < min || n > max || value != n.ToString(CultureInfo.InvariantCulture))
            throw new InvalidDataException("Invalid edit receipt number.");
        return n;
    }

    private static bool Flag(string value) => value switch
    {
        "yes" => true, "no" => false, _ => throw new InvalidDataException("Invalid edit flag.")
    };

    internal static TransportEditReview ParseReview(string output, int exitCode,
        MultiTransportInstalled installed, IReadOnlyList<AdvancedRouteRule> draft)
    {
        var f = Fields(output, exitCode);
        Exact(f, "OLD_REVISION", "OLD_PLAN", "NEW_PLAN", "BACKEND", "REVIEW_SHA256",
            "TLS_DESTINATIONS", "RETAIN_INDICES");
        var review = new TransportEditReview(f["OLD_REVISION"], f["OLD_PLAN"], f["NEW_PLAN"],
            f["BACKEND"], f["REVIEW_SHA256"], Number(f["TLS_DESTINATIONS"], 1, 8),
            Array.AsReadOnly(f["RETAIN_INDICES"].Split(',').Select(v => Number(v, 0, 8)).ToArray()));
        if (f["STATUS"] != "reviewed_experimental" || f["POSTFIX_CHANGED"] != "no" ||
            !ValidReview(review, installed, draft))
            throw new InvalidDataException("Unverified edit review.");
        return review;
    }

    internal static TransportEditRecovery? ParseRecovery(string output, int exitCode)
    {
        var f = Fields(output, exitCode);
        if (f.GetValueOrDefault("STATUS") == "no_pending_edit")
        {
            Exact(f);
            if (f["POSTFIX_CHANGED"] != "no") throw new InvalidDataException("Unverified recovery scan.");
            return null;
        }
        Exact(f, "OLD_REVISION", "NEW_REVISION", "OLD_PLAN", "NEW_PLAN", "BACKEND", "PHASE",
            "LAYOUT", "REVIEW_SHA256", "COMMIT_CANDIDATE", "ROLLBACK_CANDIDATE");
        var recovery = new TransportEditRecovery(f["OLD_REVISION"], f["NEW_REVISION"],
            f["OLD_PLAN"], f["NEW_PLAN"], f["BACKEND"], f["PHASE"], f["LAYOUT"],
            f["REVIEW_SHA256"], Flag(f["COMMIT_CANDIDATE"]), Flag(f["ROLLBACK_CANDIDATE"]));
        if (f["STATUS"] != "recovery_reviewed_experimental" || f["POSTFIX_CHANGED"] != "no" ||
            !ValidRecovery(recovery)) throw new InvalidDataException("Unverified edit recovery review.");
        return recovery;
    }

    internal static string ParseSwitch(string output, int exitCode, TransportEditReview review)
    {
        var f = Fields(output, exitCode);
        Exact(f, "OLD_REVISION", "NEW_REVISION");
        if (f["STATUS"] != "switched_pending_resolution" || f["POSTFIX_CHANGED"] != "pending" ||
            f["OLD_REVISION"] != review.OldRevision || !Sha(f["NEW_REVISION"]) ||
            f["NEW_REVISION"] == review.OldRevision)
            throw new InvalidDataException("Unverified edit switch result.");
        return f["NEW_REVISION"];
    }

    internal static string ParseResolution(string output, int exitCode, TransportEditRecovery review, string operation)
    {
        var f = Fields(output, exitCode);
        Exact(f, "KEPT_REVISION");
        if (!ValidRecovery(review) || operation is not ("commit" or "rollback") ||
            !(operation == "commit" ? review.CanCommit : review.CanRollback) ||
            f["STATUS"] != (operation == "commit" ? "committed_offline_not_started" : "rolled_back_offline_not_started") ||
            f["POSTFIX_CHANGED"] != "resolved" ||
            f["KEPT_REVISION"] != (operation == "commit" ? review.NewRevision : review.OldRevision))
            throw new InvalidDataException("Unverified edit resolution result.");
        return f["KEPT_REVISION"];
    }

    internal static bool SelfTest()
    {
        string a = new('a',64), b = new('b',64), c = new('c',64);
        var rule = new AdvancedRouteRule(AdvancedRouteMatchKind.ExactEnvelopeSender,
            "first@example.org", "smtp.example.net", 587, "starttls", "password");
        var second = rule with { Pattern = "second@example.org" };
        var old = new[] { rule, second };
        var draft = new[] { second with { Port = 465, TlsMode = "implicit" }, rule };
        var installed = new MultiTransportInstalled("installed_owned", a,
            AdvancedRoutePlanner.PlanSha256(old), "hash", old);
        string plan = AdvancedRoutePlanner.PlanSha256(draft);
        const string flags = "EDIT_SERVICE_STARTED=no\nEDIT_MAIL_SENT=no\nEDIT_QUEUE_MODIFIED=no\nEDIT_SMTP_AUTH_ATTEMPTED=no\n";
        string common = "EDIT_OLD_REVISION=" + a + "\nEDIT_OLD_PLAN=" + installed.Plan +
            "\nEDIT_NEW_PLAN=" + plan + "\nEDIT_BACKEND=hash\nEDIT_REVIEW_SHA256=" + c + "\nEDIT_POSTFIX_CHANGED=no\n" + flags;
        string receipt = "EDIT_STATUS=reviewed_experimental\n" + common +
            "EDIT_TLS_DESTINATIONS=2\nEDIT_RETAIN_INDICES=0,1\n";
        var review = ParseReview(receipt, 0, installed, draft);
        string pending = "EDIT_STATUS=recovery_reviewed_experimental\n" + common +
            "EDIT_NEW_REVISION=" + b + "\nEDIT_PHASE=pending\nEDIT_LAYOUT=new\nEDIT_COMMIT_CANDIDATE=yes\nEDIT_ROLLBACK_CANDIDATE=yes\n";
        var recovery = ParseRecovery(pending, 0);
        if (recovery is null || !recovery.CanCommit || !recovery.CanRollback ||
            ParseRecovery("EDIT_STATUS=no_pending_edit\nEDIT_POSTFIX_CHANGED=no\n" + flags, 0) is not null)
            return false;
        string switched = "EDIT_STATUS=switched_pending_resolution\nEDIT_OLD_REVISION=" + a +
            "\nEDIT_NEW_REVISION=" + b + "\nEDIT_POSTFIX_CHANGED=pending\n" + flags;
        string committed = "EDIT_STATUS=committed_offline_not_started\nEDIT_KEPT_REVISION=" + b +
            "\nEDIT_POSTFIX_CHANGED=resolved\n" + flags;
        if (ParseSwitch(switched, 0, review) != b || ParseResolution(committed, 0, recovery, "commit") != b)
            return false;
        foreach (var bad in new[] { receipt.Replace("0,1","1,1"), receipt.Replace("MAIL_SENT=no","MAIL_SENT=yes"),
            receipt + "EDIT_SECRET=fixture\n", receipt.Replace("TLS_DESTINATIONS=2","TLS_DESTINATIONS=02") })
        {
            try { ParseReview(bad, 0, installed, draft); return false; }
            catch (InvalidDataException) {}
        }
        try { ParseRecovery(pending.Replace("LAYOUT=new","LAYOUT=mixed"), 0); return false; }
        catch (InvalidDataException) {}
        try { ParseSwitch(switched, 2, review); return false; } catch (InvalidDataException) {}
        try { ParseResolution(committed, 0, recovery, "rollback"); return false; } catch (InvalidDataException) {}
        string maintenance = ConditionalOfflineClient.MaintenancePhrase;
        var slots = new TransportEditSlot?[] { new(false, "fixture", "synthetic"), new(true) };
        string script = Build("switch", maintenance, installed, draft, review, slots, confirmation: SwitchPhrase);
        if (!script.Contains("--switch " + a, StringComparison.Ordinal) || script.Contains("synthetic", StringComparison.Ordinal) ||
            Build("commit", maintenance, recovery: recovery, confirmation: CommitPhrase).Contains("builtin printf", StringComparison.Ordinal))
            return false;
        try { Build("switch", maintenance, installed, draft, review,
            new TransportEditSlot?[] { new(true), new(true) }, confirmation: SwitchPhrase); return false; }
        catch (ArgumentException) {}
        return true;
    }
}
