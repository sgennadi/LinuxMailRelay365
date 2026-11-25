using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record QueueMaintenanceReceipt(string Outcome, string Reason, long PreparedAt,
    string PlanSha, string Detail)
{
    internal static string Confirmation(string action) => action switch
    {
        "flush" => "FLUSH_SELECTED_POSTFIX_INSTANCE",
        "hold" => "HOLD_SELECTED_DEFERRED_MESSAGE",
        "release" => "RELEASE_SELECTED_HELD_MESSAGE",
        _ => throw new ArgumentException("Invalid queue maintenance action.")
    };

    internal static void ValidateContext(string scope, string action, string nonce, long sampledAt, string fingerprint)
    {
        if (scope is not ("postfix" or "sidecar") || action is not ("flush" or "hold" or "release") ||
            !QueueRetryReview.ValidSha(nonce) ||
            (action == "flush" ? sampledAt != 0 || fingerprint != "-" :
                sampledAt is < 1 or > 9999999999 || !QueueRetryReview.ValidSha(fingerprint)))
            throw new ArgumentException("Invalid scoped maintenance selection.");
    }

    internal static QueueMaintenanceReceipt Parse(string output, string scope, string action,
        string nonce, long sampledAt, QueueMessageRow? selected, long? expectedPrepared = null, string? expectedSha = null)
    {
        string fingerprint = selected?.Fingerprint ?? "-";
        ValidateContext(scope, action, nonce, sampledAt, fingerprint);
        if ((action == "flush") != (selected is null) ||
            (selected is not null && selected.State != (action == "hold" ? "deferred" : "held")) ||
            (expectedPrepared is null) != (expectedSha is null) || output.Length > 4096 || output.Contains('\0'))
            throw new InvalidDataException("Invalid maintenance receipt context.");
        bool apply = expectedPrepared.HasValue;
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            int n = line.IndexOf('=');
            if (n <= 0 || !fields.TryAdd(line[..n], line[(n + 1)..]))
                throw new InvalidDataException("Malformed or duplicate maintenance field.");
        }
        string Take(string key, string pattern)
        {
            if (!fields.Remove("MAIL_MAINT_" + key, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Invalid maintenance field: " + key);
            return value;
        }
        void Exact(string key, string expected) => Take(key, Regex.Escape(expected));
        long Number(string value, long max)
        {
            if (!Regex.IsMatch(value, @"\A(?:0|[1-9][0-9]{0,12})\z") ||
                !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long n) || n > max)
                throw new InvalidDataException("Invalid maintenance numeric evidence.");
            return n;
        }
        Exact("VERSION", "1");
        Exact("ACTION", action);
        Exact("SCOPE", scope);
        Exact("NONCE", nonce);
        Exact("SAMPLED_AT", sampledAt.ToString(CultureInfo.InvariantCulture));
        Exact("FINGERPRINT", fingerprint);
        Exact("PHASE", apply ? "apply" : "prepare");
        long prepared = Number(Take("PREPARED_AT", "[1-9][0-9]{0,9}"), 9999999999);
        string outcome = Take("OUTCOME", apply ? "command_completed|not_requested|outcome_unknown" : "candidate|not_requested");
        string digest = Take("PLAN_SHA256", apply || outcome == "candidate" ? "[a-f0-9]{64}" : "-");
        if (apply && (prepared != expectedPrepared || digest != expectedSha) ||
            ((apply || outcome == "candidate") && action != "flush" &&
                (prepared < sampledAt || prepared - sampledAt > 300)))
            throw new InvalidDataException("Maintenance approval context changed.");
        string reason = outcome switch
        {
            "candidate" or "command_completed" => Take("REASON", "none"),
            "outcome_unknown" => Take("REASON", "native_result_unconfirmed"),
            _ => Take("REASON", "expired|plan_changed|no_deferred_messages|long_ids_required|tool_unavailable|timeout|output_limit|command_failed|invalid_output|scope_unverified|sample_changed")
        };
        string detail = Take("DETAIL", outcome != "candidate" ? "-" : "[a-z0-9|]{1,150}");
        if (outcome == "candidate")
        {
            string[] parts = detail.Split('|');
            if (action == "flush")
            {
                if (parts.Length != 7) throw new InvalidDataException("Invalid Flush counts.");
                var counts = parts.Select(x => Number(x, 50000)).ToArray();
                if (counts[0] != counts.Skip(1).Sum() || counts[2] == 0)
                    throw new InvalidDataException("Inconsistent Flush counts.");
            }
            else if (parts.Length != 3 || parts[0] != selected!.State ||
                     Number(parts[1], 1099511627776) != selected.Bytes ||
                     Number(parts[2], 10000) != selected.RecipientCount)
                throw new InvalidDataException("Maintenance target changed.");
        }
        Exact("COMMAND_COUNT", outcome == "command_completed" ? "1" : outcome == "outcome_unknown" ? "unknown" : "0");
        foreach (string flag in new[] { "EFFECT_VERIFIED", "DELIVERY_VERIFIED", "ATOMIC",
            "CONFIG_CHANGED", "SERVICE_CHANGED", "DELETE_REQUESTED", "NEW_MESSAGE_SUBMITTED" })
            Exact(flag, "no");
        if (fields.Count != 0) throw new InvalidDataException("Unexpected maintenance evidence.");
        return new(outcome, reason, prepared, digest, detail);
    }

    internal static bool SelfTest()
    {
        string nonce = new('a', 64), sha = new('b', 64), fingerprint = new('c', 64);
        string Make(string action, string token, long sampled, string phase, string outcome, string detail, string reason) =>
            string.Join("\n", ("VERSION=1\nACTION=" + action + "\nSCOPE=sidecar\nNONCE=" + nonce +
                "\nSAMPLED_AT=" + sampled + "\nFINGERPRINT=" + token + "\nPHASE=" + phase +
                "\nPREPARED_AT=1060\nPLAN_SHA256=" + sha + "\nOUTCOME=" + outcome +
                "\nDETAIL=" + detail + "\nREASON=" + reason + "\nCOMMAND_COUNT=" +
                (outcome == "command_completed" ? "1" : "0") +
                "\nEFFECT_VERIFIED=no\nDELIVERY_VERIFIED=no\nATOMIC=no\nCONFIG_CHANGED=no\nSERVICE_CHANGED=no\nDELETE_REQUESTED=no\nNEW_MESSAGE_SUBMITTED=no")
                .Split('\n').Select(x => "MAIL_MAINT_" + x)) + "\n";
        string flush = Make("flush", "-", 0, "prepare", "candidate", "3|1|1|1|0|0|0", "none");
        var held = new QueueMessageRow(1, "held", 5, 1024, 1, "not_applicable", fingerprint);
        string release = Make("release", fingerprint, 1000, "prepare", "candidate", "held|1024|1", "none");
        string apply = Make("release", fingerprint, 1000, "apply", "command_completed", "-", "none");
        if (Parse(flush, "sidecar", "flush", nonce, 0, null).Outcome != "candidate" ||
            Parse(release, "sidecar", "release", nonce, 1000, held).PlanSha != sha ||
            Parse(apply, "sidecar", "release", nonce, 1000, held, 1060, sha).Outcome != "command_completed")
            return false;
        bool Reject(Action fn) { try { fn(); return false; } catch (InvalidDataException) { return true; } }
        if (!Reject(() => Parse(flush.Replace("3|1|1|1", "4|1|1|1"), "sidecar", "flush", nonce, 0, null)) ||
            !Reject(() => Parse(release.Replace("1024", "2048"), "sidecar", "release", nonce, 1000, held)) ||
            !Reject(() => Parse(apply.Replace("EFFECT_VERIFIED=no", "EFFECT_VERIFIED=yes"), "sidecar", "release", nonce, 1000, held, 1060, sha)) ||
            !Reject(() => Parse(apply.Replace("COMMAND_COUNT=1", "COMMAND_COUNT=0"), "sidecar", "release", nonce, 1000, held, 1060, sha)))
            return false;
        string bundle = EmbeddedAssets.BuildQueueMaintenanceBundle("sidecar", "release", nonce, 1000, fingerprint, 1060, sha);
        return bundle.Contains(" --maintenance release ", StringComparison.Ordinal) &&
               bundle.Contains(" --confirm RELEASE_SELECTED_HELD_MESSAGE\n", StringComparison.Ordinal);
    }
}
