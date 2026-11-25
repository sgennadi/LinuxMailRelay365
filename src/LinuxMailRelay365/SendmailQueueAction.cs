using System.Globalization;

namespace LinuxMailRelay365;

internal sealed record SendmailQueueAction(string Outcome, string Reason, long PreparedAt, string PlanSha, int? TargetCount)
{
    internal static string Confirmation(string action) => action switch
    {
        "retry" => "RETRY_SELECTED_SENDMAIL_MESSAGE",
        "flush" => "RUN_SELECTED_SENDMAIL_QUEUE_ONCE",
        _ => throw new ArgumentException("Invalid Sendmail action.")
    };
    internal static void Validate(string queue, string action, string nonce, long sampled, string fingerprint)
    {
        if (queue is not ("mta" or "msp") || action is not ("retry" or "flush") ||
            !QueueRetryReview.ValidSha(nonce) || (action == "flush" ? sampled != 0 || fingerprint != "-" :
                sampled is < 1 or > 9999999999 || !QueueRetryReview.ValidSha(fingerprint)))
            throw new ArgumentException("Invalid Sendmail queue action context.");
    }
    internal static SendmailQueueAction Parse(string output, string queue, string action, string nonce,
        long sampled, string fingerprint, long? expectedTime = null, string? expectedSha = null)
    {
        Validate(queue, action, nonce, sampled, fingerprint);
        if ((expectedTime is null) != (expectedSha is null)) throw new ArgumentException("Invalid approval.");
        bool apply = expectedTime.HasValue;
        var f = new EximQueueFields(output, "SENDMAIL_ACTION_");
        f.Exact("VERSION", "1"); f.Exact("SCOPE", "sendmail"); f.Exact("QUEUE", queue);
        f.Exact("ACTION", action); f.Exact("NONCE", nonce);
        f.Exact("SAMPLED_AT", sampled.ToString(CultureInfo.InvariantCulture));
        f.Exact("FINGERPRINT", fingerprint); f.Exact("PHASE", apply ? "apply" : "prepare");
        long prepared = EximQueueFields.Number(f.Take("PREPARED_AT", "[1-9][0-9]{0,9}"), 9999999999);
        string outcome = f.Take("OUTCOME", apply ? "command_completed|not_requested|outcome_unknown" : "candidate|not_requested");
        string sha = f.Take("PLAN_SHA256", apply || outcome == "candidate" ? "[a-f0-9]{64}" : "-");
        if ((apply && (prepared != expectedTime || sha != expectedSha)) ||
            ((apply || outcome == "candidate") && action == "retry" && (prepared < sampled || prepared - sampled > 300)))
            throw new InvalidDataException("Sendmail approval changed.");
        string reason = f.Take("REASON", outcome is "candidate" or "command_completed" ? "none" :
            outcome == "outcome_unknown" ? "native_result_unconfirmed" :
            "expired|plan_changed|no_queued_messages|" + EximQueueFields.Failures);
        string raw = f.Take("TARGET_COUNT", outcome == "candidate" ? "[1-9][0-9]{0,4}" : "unknown");
        int? count = raw == "unknown" ? null : (int)EximQueueFields.Number(raw, 50000);
        if (outcome == "candidate" && action == "retry" && count != 1)
            throw new InvalidDataException("Selected Retry must target one message.");
        f.Exact("COMMAND_COUNT", outcome == "command_completed" ? "1" : outcome == "outcome_unknown" ? "unknown" : "0");
        foreach (string flag in new[] {"DELIVERY_VERIFIED", "EFFECT_VERIFIED", "ATOMIC", "DELETE_REQUESTED",
            "QUARANTINE_CHANGED", "CONFIG_CHANGED", "SERVICE_CHANGED"}) f.Exact(flag, "no");
        f.End();
        return new(outcome, reason, prepared, sha, count);
    }

    internal static bool SelfTest()
    {
        string nonce = new('a', 64), token = new('b', 64), sha = new('c', 64);
        string Make(string phase, string outcome, string count, string command) =>
            string.Join("\n", ("VERSION=1\nSCOPE=sendmail\nQUEUE=msp\nACTION=retry\nNONCE=" + nonce +
                "\nSAMPLED_AT=1000\nFINGERPRINT=" + token + "\nPHASE=" + phase +
                "\nPREPARED_AT=1060\nPLAN_SHA256=" + sha + "\nOUTCOME=" + outcome +
                "\nREASON=none\nTARGET_COUNT=" + count + "\nCOMMAND_COUNT=" + command +
                "\nDELIVERY_VERIFIED=no\nEFFECT_VERIFIED=no\nATOMIC=no\nDELETE_REQUESTED=no\nQUARANTINE_CHANGED=no\nCONFIG_CHANGED=no\nSERVICE_CHANGED=no")
                .Split('\n').Select(x => "SENDMAIL_ACTION_" + x)) + "\n";
        string preview = Make("prepare", "candidate", "1", "0"),
            apply = Make("apply", "command_completed", "unknown", "1");
        if (Parse(preview, "msp", "retry", nonce, 1000, token).TargetCount != 1 ||
            Parse(apply, "msp", "retry", nonce, 1000, token, 1060, sha).Outcome != "command_completed") return false;
        bool Reject(Action fn) { try { fn(); return false; } catch (InvalidDataException) { return true; } }
        if (!Reject(() => Parse(preview.Replace("TARGET_COUNT=1", "TARGET_COUNT=2"), "msp", "retry", nonce, 1000, token)) ||
            !Reject(() => Parse(preview, "mta", "retry", nonce, 1000, token)) ||
            !Reject(() => Parse(apply.Replace("DELIVERY_VERIFIED=no", "DELIVERY_VERIFIED=yes"), "msp", "retry", nonce, 1000, token, 1060, sha))) return false;
        string bundle = EmbeddedAssets.BuildSendmailQueueActionBundle("msp", "retry", nonce, 1000, token, 1060, sha);
        return bundle.Contains(" --sendmail-action retry --sendmail-queue msp ", StringComparison.Ordinal) &&
            bundle.Contains(" --confirm RETRY_SELECTED_SENDMAIL_MESSAGE\n", StringComparison.Ordinal);
    }
}
