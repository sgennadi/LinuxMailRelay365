using System.Globalization;
using System.Text;
using System.Text.Json;

namespace LinuxMailRelay365;

internal sealed record CredentialRotationReview(string Revision, string Plan, int Index,
    string Backend, string Evidence, string Retained)
{
    internal bool IsRecovery => Retained != "rotation_ready";
}

internal sealed record CredentialRotationResult(string Revision, string Status, string? Generation,
    string? Retained);

internal static class CredentialRotationClient
{
    internal const string RotatePhrase = "ROTATE_ONE_STOPPED_POSTFIX_CREDENTIAL";
    internal const string RecoverPhrase = "RECOVER_ONE_STOPPED_POSTFIX_CREDENTIAL";
    private const string Prefix = "ROTATION_";

    private static bool Sha(string? value) => ConditionalOfflineClient.IsSha(value);
    private static bool Retained(string? value) => value is "old_retained" or "new_retained" or "old_restored";

    private static bool ValidReview(CredentialRotationReview r) => Sha(r.Revision) && Sha(r.Plan) &&
        Sha(r.Evidence) && r.Index is >= 1 and <= 8 && r.Backend is "hash" or "lmdb" &&
        (r.Retained == "rotation_ready" || Retained(r.Retained));

    internal static string Build(string operation, string revision, int? index, string maintenance,
        CredentialRotationReview? reviewed = null, (string User, string Secret)? credential = null,
        string? confirmation = null)
    {
        if (!Sha(revision) || maintenance != ConditionalOfflineClient.MaintenancePhrase)
            throw new ArgumentException("Exact revision and maintenance approval required.");
        string args;
        string? payload = null;
        if (operation is "review-rotation" or "review-recovery")
        {
            if (reviewed is not null || credential is not null || confirmation is not null ||
                (operation == "review-rotation" ? index is not (>= 1 and <= 8) : index is not null))
                throw new ArgumentException("Invalid rotation review request.");
            args = "--" + operation + " " + revision;
            if (index is int n) args += " --index " + n.ToString(CultureInfo.InvariantCulture);
        }
        else if (operation is "rotate" or "recover")
        {
            if (reviewed is null || !ValidReview(reviewed) || reviewed.Revision != revision ||
                reviewed.IsRecovery != (operation == "recover") ||
                confirmation != (operation == "rotate" ? RotatePhrase : RecoverPhrase))
                throw new ArgumentException("Exact reviewed operation and write approval required.");
            args = "--" + operation + " " + revision;
            if (operation == "rotate")
            {
                if (index != reviewed.Index || credential is not { } value ||
                    !MultiTransportClient.ValidCredential(value.User, value.Secret))
                    throw new ArgumentException("One valid selected account is required.");
                args += " --index " + reviewed.Index.ToString(CultureInfo.InvariantCulture);
                payload = JsonSerializer.Serialize(new { username = value.User, password = value.Secret });
            }
            else if (index is not null || credential is not null)
                throw new ArgumentException("Recovery never accepts credentials or an index override.");
            args += " --approve-plan-sha256 " + reviewed.Plan +
                    " --approve-review-sha256 " + reviewed.Evidence + " --confirm " + confirmation;
        }
        else throw new ArgumentException("Unknown rotation operation.");
        args += " --maintenance-confirmation " + ConditionalOfflineClient.MaintenancePhrase;
        string script = "set +x\nset -Eeuo pipefail\numask 077\n" +
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n" +
            "work=$(mktemp -d /tmp/lmr365-rotation.XXXXXXXX)\n" +
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
            ("manage-conditional-transport-rotation.py", EmbeddedAssets.ConditionalTransportRotationHost)
        })
        {
            if (string.IsNullOrWhiteSpace(source) || source.Contains('\0'))
                throw new InvalidDataException("Invalid embedded rotation module.");
            script += "base64 -d > \"$work/" + name + "\" <<'LMR365_ROTATION_SOURCE'\n" +
                Convert.ToBase64String(Encoding.UTF8.GetBytes(source)) + "\nLMR365_ROTATION_SOURCE\n";
        }
        string command = "python3 -I -B \"$work/manage-conditional-transport-rotation.py\" " + args + "\n";
        // The credential JSON is sent on the encrypted SSH stdin. It is never
        // a process argument, environment variable, or a persistent request file.
        // Shell/sudo/SSH input auditing can still record it; the GUI warns the operator.
        return payload is null ? script + command : script + "builtin printf '%s' '" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)) + "' | base64 -d | " + command;
    }

    private static Dictionary<string, string> Fields(string output)
    {
        if (output.Length > 4096) throw new InvalidDataException("Oversized rotation receipt.");
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            int at = line.IndexOf('=');
            if (at <= Prefix.Length || !line.StartsWith(Prefix, StringComparison.Ordinal) ||
                !result.TryAdd(line[Prefix.Length..at], line[(at + 1)..]))
                throw new InvalidDataException("Malformed rotation receipt.");
        }
        foreach (string flag in new[] { "SERVICE_STARTED", "MAIL_SENT", "QUEUE_MODIFIED", "SMTP_AUTH_ATTEMPTED" })
            if (result.GetValueOrDefault(flag) != "no")
                throw new InvalidDataException("Unverified rotation safety flags.");
        return result;
    }

    private static void Exact(Dictionary<string, string> f, params string[] extra)
    {
        var fields = new HashSet<string>(extra, StringComparer.Ordinal)
        { "STATUS", "POSTFIX_CHANGED", "SERVICE_STARTED", "MAIL_SENT", "QUEUE_MODIFIED", "SMTP_AUTH_ATTEMPTED" };
        if (!fields.SetEquals(f.Keys)) throw new InvalidDataException("Unexpected rotation receipt fields.");
    }

    private static int Index(string? value)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int index) ||
            index is < 1 or > 8 || value != index.ToString(CultureInfo.InvariantCulture))
            throw new InvalidDataException("Invalid reviewed transport index.");
        return index;
    }

    internal static CredentialRotationReview ParseReview(string output, string revision,
        bool recovery, int? index = null, string? plan = null, string? backend = null)
    {
        var f = Fields(output);
        Exact(f, "REVISION", "PLAN_SHA256", "INDEX", "BACKEND", "REVIEW_SHA256", "RETAINED");
        var review = new CredentialRotationReview(f["REVISION"], f["PLAN_SHA256"], Index(f["INDEX"]),
            f["BACKEND"], f["REVIEW_SHA256"], f["RETAINED"]);
        if (f["STATUS"] != "reviewed_experimental" || f["POSTFIX_CHANGED"] != "no" ||
            !ValidReview(review) || review.Revision != revision || review.IsRecovery != recovery ||
            (!recovery && index != review.Index) || (recovery && index is not null) ||
            (plan is not null && review.Plan != plan) || (backend is not null && review.Backend != backend))
            throw new InvalidDataException("Unverified rotation review.");
        return review;
    }

    internal static CredentialRotationResult ParseResult(string output, CredentialRotationReview review, int exitCode)
    {
        if (!ValidReview(review)) throw new InvalidDataException("Invalid review context.");
        var f = Fields(output);
        string status = f.GetValueOrDefault("STATUS") ?? "";
        if (status is "rolled_back" or "manual_recovery_required")
        {
            Exact(f, "REVISION");
            if (review.IsRecovery || exitCode == 0 || f["REVISION"] != review.Revision ||
                f["POSTFIX_CHANGED"] != (status == "rolled_back" ? "restored" : "unknown"))
                throw new InvalidDataException("Unverified rotation failure receipt.");
            return new(review.Revision, status, null, null);
        }
        if (!review.IsRecovery)
        {
            Exact(f, "REVISION", "INDEX", "GENERATION");
            if (exitCode != 0 || status != "rotated_offline_not_started" || f["REVISION"] != review.Revision ||
                f["POSTFIX_CHANGED"] != "credential_only" || Index(f["INDEX"]) != review.Index || !Sha(f["GENERATION"]))
                throw new InvalidDataException("Unverified credential rotation result.");
            return new(review.Revision, status, f["GENERATION"], null);
        }
        Exact(f, "REVISION", "RETAINED");
        if (exitCode != 0 || status != "reconciled_offline_not_started" || f["REVISION"] != review.Revision ||
            f["POSTFIX_CHANGED"] != "ownership_record_only" || f["RETAINED"] != review.Retained)
            throw new InvalidDataException("Unverified credential recovery result.");
        return new(review.Revision, status, null, f["RETAINED"]);
    }

    internal static bool SelfTest()
    {
        string a = new('a', 64), b = new('b', 64), c = new('c', 64);
        const string flags = "ROTATION_SERVICE_STARTED=no\nROTATION_MAIL_SENT=no\n" +
            "ROTATION_QUEUE_MODIFIED=no\nROTATION_SMTP_AUTH_ATTEMPTED=no\n";
        string rev = "ROTATION_REVISION=" + a + "\n";
        string review = "ROTATION_STATUS=reviewed_experimental\n" + rev + "ROTATION_PLAN_SHA256=" + b +
            "\nROTATION_INDEX=2\nROTATION_BACKEND=hash\nROTATION_REVIEW_SHA256=" + c +
            "\nROTATION_RETAINED=rotation_ready\nROTATION_POSTFIX_CHANGED=no\n" + flags;
        var checkedReview = ParseReview(review, a, false, 2, b, "hash");
        var recovery = ParseReview(review.Replace("rotation_ready", "new_retained"), a, true);
        string rotated = "ROTATION_STATUS=rotated_offline_not_started\n" + rev +
            "ROTATION_INDEX=2\nROTATION_GENERATION=" + c + "\nROTATION_POSTFIX_CHANGED=credential_only\n" + flags;
        string recovered = "ROTATION_STATUS=reconciled_offline_not_started\n" + rev +
            "ROTATION_RETAINED=new_retained\nROTATION_POSTFIX_CHANGED=ownership_record_only\n" + flags;
        string failed = "ROTATION_STATUS=rolled_back\n" + rev + "ROTATION_POSTFIX_CHANGED=restored\n" + flags;
        if (ParseResult(rotated, checkedReview, 0).Generation != c ||
            ParseResult(recovered, recovery, 0).Retained != "new_retained" ||
            ParseResult(failed, checkedReview, 2).Status != "rolled_back") return false;
        foreach (string bad in new[] { review.Replace("INDEX=2", "INDEX=02"),
            review.Replace("MAIL_SENT=no", "MAIL_SENT=yes"), review.Replace("rotation_ready", "new_retained"),
            review + "ROTATION_INDEX=2\n", review + "ROTATION_PASSWORD=secret\n" })
        {
            try { ParseReview(bad, a, false, 2, b, "hash"); return false; }
            catch (InvalidDataException) { }
        }
        try { ParseResult(rotated, checkedReview, 2); return false; } catch (InvalidDataException) { }
        try { ParseResult(failed, checkedReview, 0); return false; } catch (InvalidDataException) { }
        try { ParseResult(recovered.Replace("new_retained", "old_retained"), recovery, 0); return false; }
        catch (InvalidDataException) { }
        string maintenance = ConditionalOfflineClient.MaintenancePhrase;
        string script = Build("rotate", a, 2, maintenance, checkedReview, ("fixture", "synthetic"), RotatePhrase);
        string reconcile = Build("recover", a, null, maintenance, recovery, confirmation: RecoverPhrase);
        if (!script.Contains("--rotate " + a + " --index 2", StringComparison.Ordinal) ||
            script.Contains("synthetic", StringComparison.Ordinal) || reconcile.Contains("builtin printf", StringComparison.Ordinal)) return false;
        try { Build("rotate", a, 3, maintenance, checkedReview, ("fixture", "synthetic"), RotatePhrase); return false; }
        catch (ArgumentException) { }
        try { Build("recover", a, null, maintenance, recovery, ("fixture", "synthetic"), RecoverPhrase); return false; }
        catch (ArgumentException) { }
        return true;
    }
}
