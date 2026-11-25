using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record EximQueueRow(int Reference, string State, int AgeMinutes,
    string NativeSize, int PendingLines, int DeliveredLines, string Fingerprint);

internal sealed class EximQueueFields
{
    internal const string Failures = "tool_unavailable|timeout|output_limit|command_failed|invalid_output|scope_unverified|sample_changed";
    private readonly Dictionary<string, string> fields = new(StringComparer.Ordinal);
    internal List<string> Rows { get; } = new();
    internal EximQueueFields(string output, string prefix, bool rows = false)
    {
        if (output.Length > (rows ? 128 * 1024 : 4096) || output.Contains('\0'))
            throw new InvalidDataException("Invalid Exim queue receipt.");
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            int pos = line.IndexOf('=');
            if (!line.StartsWith(prefix, StringComparison.Ordinal) || pos <= prefix.Length)
                throw new InvalidDataException("Invalid Exim queue field.");
            string key = line[prefix.Length..pos], value = line[(pos + 1)..];
            if (rows && key == "ROW")
            {
                if (Rows.Count >= 500) throw new InvalidDataException("Too many Exim rows.");
                Rows.Add(value);
            }
            else if (!fields.TryAdd(key, value))
                throw new InvalidDataException("Duplicate Exim queue field.");
        }
    }
    internal string Take(string key, string pattern)
    {
        if (!fields.Remove(key, out string? value) ||
            !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
            throw new InvalidDataException("Invalid Exim queue field: " + key);
        return value;
    }
    internal void Exact(string key, string value) => Take(key, Regex.Escape(value));
    internal void End()
    {
        if (fields.Count != 0) throw new InvalidDataException("Unexpected Exim queue fields.");
    }
    internal static long Number(string value, long max)
    {
        if (!Regex.IsMatch(value, @"\A(?:0|[1-9][0-9]{0,9})\z") ||
            !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long number) || number > max)
            throw new InvalidDataException("Invalid Exim queue number.");
        return number;
    }
}

internal sealed record EximQueueInventory(string Result, long SampledAt, int? Total,
    bool? Truncated, bool ContextVerified, EximQueueRow[] Rows)
{
    internal static EximQueueInventory Parse(string output, string nonce)
    {
        if (!QueueRetryReview.ValidSha(nonce)) throw new ArgumentException("Invalid Exim nonce.");
        var f = new EximQueueFields(output, "EXIM_ITEMS_", rows: true);
        f.Exact("VERSION", "1"); f.Exact("SCOPE", "exim"); f.Exact("NONCE", nonce);
        f.Exact("CHANGES_APPLIED", "no"); f.Exact("ATOMIC", "no"); f.Exact("DELIVERY_VERIFIED", "no");
        string result = f.Take("RESULT", "ok|" + EximQueueFields.Failures);
        long sampled = EximQueueFields.Number(f.Take("SAMPLED_AT", "[1-9][0-9]{0,9}"), 9999999999);
        string count = f.Take("TOTAL", "unknown|0|[1-9][0-9]{0,4}");
        int? total = count == "unknown" ? null : (int)EximQueueFields.Number(count, 50000);
        int listed = (int)EximQueueFields.Number(f.Take("LISTED", "0|[1-9][0-9]{0,2}"), 500);
        string truncatedRaw = f.Take("TRUNCATED", "yes|no|unknown");
        bool? truncated = truncatedRaw == "unknown" ? null : truncatedRaw == "yes";
        bool verified = f.Take("CONTEXT", "verified|unverified") == "verified";
        f.End();
        if ((result == "ok") != total.HasValue || f.Rows.Count != listed ||
            (total is null && (listed != 0 || truncated is not null || verified)) ||
            (total is int n && (listed != Math.Min(n, 500) || truncated != (n > 500))))
            throw new InvalidDataException("Inconsistent Exim inventory.");
        var rows = new List<EximQueueRow>();
        var tokens = new HashSet<string>(StringComparer.Ordinal);
        foreach (string line in f.Rows)
        {
            string[] p = line.Split('|');
            if (p.Length != 7 || EximQueueFields.Number(p[0], 500) != rows.Count + 1 ||
                p[1] is not ("queued" or "frozen") ||
                !Regex.IsMatch(p[3], @"\A[0-9]{1,12}(?:\.[0-9]{1,3})?[KMGT]?\z") ||
                (verified ? !QueueRetryReview.ValidSha(p[6]) || !tokens.Add(p[6]) : p[6] != "-"))
                throw new InvalidDataException("Invalid Exim message row.");
            int age = (int)EximQueueFields.Number(p[2], 999999999),
                pending = (int)EximQueueFields.Number(p[4], 10000),
                delivered = (int)EximQueueFields.Number(p[5], 10000);
            if (pending + delivered > 10000 || (rows.Count > 0 && age > rows[^1].AgeMinutes))
                throw new InvalidDataException("Invalid Exim row ordering/counts.");
            rows.Add(new(rows.Count + 1, p[1], age, p[3], pending, delivered, p[6]));
        }
        return new(result, sampled, total, truncated, verified, rows.ToArray());
    }

    internal static bool SelfTest()
    {
        string nonce = new('a', 64), token = new('b', 64), digest = new('c', 64);
        string sample = "EXIM_ITEMS_VERSION=1\nEXIM_ITEMS_SCOPE=exim\nEXIM_ITEMS_NONCE=" + nonce +
            "\nEXIM_ITEMS_RESULT=ok\nEXIM_ITEMS_SAMPLED_AT=1000\nEXIM_ITEMS_TOTAL=1\nEXIM_ITEMS_LISTED=1\n" +
            "EXIM_ITEMS_TRUNCATED=no\nEXIM_ITEMS_CONTEXT=verified\nEXIM_ITEMS_CHANGES_APPLIED=no\n" +
            "EXIM_ITEMS_ATOMIC=no\nEXIM_ITEMS_DELIVERY_VERIFIED=no\nEXIM_ITEMS_ROW=1|frozen|12|2.9K|1|0|" + token + "\n";
        var inventory = Parse(sample, nonce);
        if (inventory.Rows.Single().State != "frozen" || inventory.Rows[0].NativeSize != "2.9K") return false;
        bool Reject(Action fn) { try { fn(); return false; } catch (InvalidDataException) { return true; } }
        if (!Reject(() => Parse(sample.Replace("TOTAL=1", "TOTAL=2"), nonce)) ||
            !Reject(() => Parse(sample.Replace("CONTEXT=verified", "CONTEXT=unverified"), nonce)) ||
            !Reject(() => Parse(sample.Replace("2.9K", "private@example.invalid"), nonce))) return false;
        string Make(string phase, string outcome, string count) =>
            string.Join("\n", ("VERSION=1\nSCOPE=exim\nACTION=thaw\nNONCE=" + nonce +
                "\nSAMPLED_AT=1000\nFINGERPRINT=" + token + "\nPHASE=" + phase +
                "\nPREPARED_AT=1060\nPLAN_SHA256=" + digest + "\nOUTCOME=" + outcome +
                "\nREASON=none\nCOMMAND_COUNT=" + count +
                "\nEFFECT_VERIFIED=no\nDELIVERY_VERIFIED=no\nATOMIC=no\nDELETE_REQUESTED=no\nNEW_MESSAGE_SUBMITTED=no\nCONFIG_CHANGED=no\nSERVICE_CHANGED=no")
                .Split('\n').Select(x => "EXIM_ACTION_" + x)) + "\n";
        var row = inventory.Rows[0];
        string preview = Make("prepare", "candidate", "0"), apply = Make("apply", "command_completed", "1");
        if (EximQueueAction.Parse(preview, "thaw", nonce, 1000, row).PlanSha != digest ||
            EximQueueAction.Parse(apply, "thaw", nonce, 1000, row, 1060, digest).Outcome != "command_completed" ||
            !Reject(() => EximQueueAction.Parse(apply.Replace("EFFECT_VERIFIED=no", "EFFECT_VERIFIED=yes"),
                "thaw", nonce, 1000, row, 1060, digest)) ||
            !Reject(() => EximQueueAction.Parse(preview, "freeze", nonce, 1000, row))) return false;
        return EmbeddedAssets.BuildEximQueueActionBundle("thaw", nonce, 1000, token, 1060, digest)
            .Contains(" --confirm THAW_SELECTED_EXIM_MESSAGE\n", StringComparison.Ordinal);
    }
}

internal sealed record EximQueueAction(string Outcome, string Reason, long PreparedAt, string PlanSha)
{
    internal static string Confirmation(string action) => action switch
    {
        "freeze" => "FREEZE_SELECTED_EXIM_MESSAGE",
        "thaw" => "THAW_SELECTED_EXIM_MESSAGE",
        _ => throw new ArgumentException("Invalid Exim action.")
    };
    internal static EximQueueAction Parse(string output, string action, string nonce, long sampled,
        EximQueueRow row, long? expectedTime = null, string? expectedSha = null)
    {
        if (action is not ("freeze" or "thaw") || row.State != (action == "freeze" ? "queued" : "frozen") ||
            !QueueRetryReview.ValidSha(nonce) || !QueueRetryReview.ValidSha(row.Fingerprint) ||
            sampled is < 1 or > 9999999999 || (expectedTime is null) != (expectedSha is null))
            throw new InvalidDataException("Invalid Exim action context.");
        bool apply = expectedTime.HasValue;
        var f = new EximQueueFields(output, "EXIM_ACTION_");
        f.Exact("VERSION", "1"); f.Exact("SCOPE", "exim"); f.Exact("ACTION", action);
        f.Exact("NONCE", nonce); f.Exact("SAMPLED_AT", sampled.ToString(CultureInfo.InvariantCulture));
        f.Exact("FINGERPRINT", row.Fingerprint); f.Exact("PHASE", apply ? "apply" : "prepare");
        long prepared = EximQueueFields.Number(f.Take("PREPARED_AT", "[1-9][0-9]{0,9}"), 9999999999);
        string outcome = f.Take("OUTCOME", apply ? "command_completed|not_requested|outcome_unknown" : "candidate|not_requested");
        string sha = f.Take("PLAN_SHA256", apply || outcome == "candidate" ? "[a-f0-9]{64}" : "-");
        if ((apply && (prepared != expectedTime || sha != expectedSha)) ||
            ((apply || outcome == "candidate") && (prepared < sampled || prepared - sampled > 300)))
            throw new InvalidDataException("Exim plan context changed.");
        string reason = f.Take("REASON", outcome is "candidate" or "command_completed" ? "none" :
            outcome == "outcome_unknown" ? "native_result_unconfirmed" : "expired|plan_changed|" + EximQueueFields.Failures);
        f.Exact("COMMAND_COUNT", outcome == "command_completed" ? "1" : outcome == "outcome_unknown" ? "unknown" : "0");
        foreach (string key in new[] { "EFFECT_VERIFIED", "DELIVERY_VERIFIED", "ATOMIC", "DELETE_REQUESTED",
            "NEW_MESSAGE_SUBMITTED", "CONFIG_CHANGED", "SERVICE_CHANGED" }) f.Exact(key, "no");
        f.End();
        return new(outcome, reason, prepared, sha);
    }
}
