using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Strict, operation-specific receipts. No recovery approval is persisted.
internal sealed record SendmailV2Evidence(string TargetId, string SafetyId,
    string TargetSha, string SafetySha, string TargetManifest, string SafetyManifest, string RestorePlanSha);

internal sealed record SendmailV2RollbackReview(SendmailV2Evidence Evidence, string Sha, int Changed);

internal static class SendmailV2RecoveryReceipt
{
    internal const string RestoreConfirmation = "RESTORE_STOPPED_SENDMAIL_V2_COMPILED_CONFIG";
    internal const string RollbackConfirmation = "ROLLBACK_INTERRUPTED_SENDMAIL_V2_CONFIG";
    private const string IdPattern = "[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}";
    private const string ShaPattern = "[a-f0-9]{64}";

    private sealed class Receipt
    {
        private readonly Dictionary<string, string> fields = new(StringComparer.Ordinal);
        internal Receipt(string output)
        {
            if (output.Length > 8192 || output.Contains('\0'))
                throw new InvalidDataException("Invalid Sendmail recovery receipt.");
            foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
            {
                if (line.Length == 0) continue;
                int n = line.IndexOf('=');
                if (n <= 0 || !fields.TryAdd(line[..n], line[(n + 1)..]))
                    throw new InvalidDataException("Malformed or duplicate Sendmail recovery field.");
            }
        }
        internal string Take(string key, string pattern)
        {
            if (!fields.Remove(key, out string? value) ||
                !Regex.IsMatch(value, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Invalid or missing Sendmail recovery field: " + key);
            return value;
        }
        internal void Exact(string key, string value) => Take(key, Regex.Escape(value));
        internal int Changed(string key) => int.Parse(Take(key, "[012]"), CultureInfo.InvariantCulture);
        internal void Complete()
        {
            if (fields.Count != 0)
                throw new InvalidDataException("Unexpected Sendmail recovery receipt fields.");
        }
        internal SendmailV2Evidence Evidence()
        {
            Exact("SENDMAIL_V2_EVIDENCE_VERSION", "4");
            Exact("SENDMAIL_V2_EVIDENCE_MTA", "sendmail");
            Exact("SENDMAIL_V2_QUEUE_CHANGED", "no");
            Exact("SENDMAIL_V2_SERVICE_CHANGED", "no");
            var evidence = new SendmailV2Evidence(
                Take("SENDMAIL_V2_EVIDENCE_TARGET", IdPattern), Take("SENDMAIL_V2_EVIDENCE_SAFETY", IdPattern),
                Take("SENDMAIL_V2_EVIDENCE_TARGET_SHA256", ShaPattern), Take("SENDMAIL_V2_EVIDENCE_SAFETY_SHA256", ShaPattern),
                Take("SENDMAIL_V2_EVIDENCE_TARGET_MANIFEST_SHA256", ShaPattern), Take("SENDMAIL_V2_EVIDENCE_SAFETY_MANIFEST_SHA256", ShaPattern),
                Take("SENDMAIL_V2_EVIDENCE_PLAN_SHA256", ShaPattern));
            if (evidence.TargetId == evidence.SafetyId)
                throw new InvalidDataException("Sendmail safety archive is not independent.");
            return evidence;
        }
    }

    internal static string VerifyArchive(string output)
    {
        var r = new Receipt(output);
        r.Exact("FOREIGN_BACKUP_STATUS", "verified");
        r.Exact("FOREIGN_BACKUP_MTA", "sendmail");
        r.Exact("FOREIGN_BACKUP_FORMAT", "v2_package_metadata");
        foreach (string field in new[] { "PRIMARY_CONFIG_CHANGED", "MAIL_QUEUE_CHANGED", "SERVICE_CHANGED", "RESTORE_ENABLED" })
            r.Exact("FOREIGN_BACKUP_" + field, "no");
        string sha = r.Take("FOREIGN_BACKUP_ARCHIVE_SHA256", ShaPattern);
        r.Complete();
        return sha;
    }

    internal static bool CanRestore(SendmailV2Review plan) =>
        plan.IsCandidate && plan.CompiledTargets == 2 && plan.CompiledChanged is 1 or 2 &&
        plan.OtherChanged == 0 && plan.Missing == 0 && plan.Extra == 0 &&
        plan.MetadataChanged == 0 && plan.ObjectDrift == 0 &&
        plan.Service == "stopped_declared" && plan.Processes == "none_observed" &&
        plan.Queue == "empty_reported" && plan.Listener == "none_observed" &&
        plan.OfflineGate == "offline_candidate_manual_recovery_only";

    internal static SendmailV2Evidence VerifyRestore(string output, string id, SendmailV2Review plan)
    {
        if (!CanRestore(plan)) throw new InvalidDataException("Sendmail Restore plan is not eligible.");
        var r = new Receipt(output);
        var evidence = r.Evidence();
        r.Exact("SENDMAIL_V2_RECOVERY_SAFETY_ID", evidence.SafetyId);
        r.Exact("SENDMAIL_V2_RECOVERY_STATUS", "config_replaced_service_not_started");
        r.Exact("SENDMAIL_V2_RECOVERY_NATIVE_STATIC_CHECK", "passed_partial_parse_only");
        r.Exact("SENDMAIL_V2_RECOVERY_MARKER_CLEARED", "yes");
        if (r.Changed("SENDMAIL_V2_RECOVERY_CHANGED_FILES") != plan.CompiledChanged ||
            evidence.TargetId != id || evidence.TargetSha != plan.ArchiveSha ||
            evidence.TargetManifest != plan.ManifestSha || evidence.RestorePlanSha != plan.PlanSha)
            throw new InvalidDataException("Sendmail Restore result differs from approved plan.");
        r.Complete();
        return evidence;
    }

    internal static SendmailV2RollbackReview ParseRollbackPlan(string output)
    {
        var r = new Receipt(output);
        var evidence = r.Evidence();
        r.Exact("SENDMAIL_V2_ROLLBACK_STATUS", "review_only");
        r.Exact("SENDMAIL_V2_ROLLBACK_CONFIG_CHANGED", "no");
        string sha = r.Take("SENDMAIL_V2_ROLLBACK_PLAN_SHA256", ShaPattern);
        int changed = r.Changed("SENDMAIL_V2_ROLLBACK_CHANGED_FILES");
        r.Complete();
        return new(evidence, sha, changed);
    }

    internal static void VerifyRollback(string output, SendmailV2RollbackReview plan)
    {
        var r = new Receipt(output);
        var evidence = r.Evidence();
        r.Exact("SENDMAIL_V2_RECOVERY_STATUS", "original_verified_service_not_started");
        r.Exact("SENDMAIL_V2_ROLLBACK_APPROVED_SHA256", plan.Sha);
        r.Exact("SENDMAIL_V2_RECOVERY_NATIVE_STATIC_CHECK", "passed_partial_parse_only");
        r.Exact("SENDMAIL_V2_RECOVERY_MARKER_CLEARED", "yes");
        if (evidence != plan.Evidence || r.Changed("SENDMAIL_V2_RECOVERY_CHANGED_FILES") != plan.Changed)
            throw new InvalidDataException("Sendmail rollback result differs from approved plan.");
        r.Complete();
    }

    internal static bool SelfTest()
    {
        const string id = "20261121T005501Z-abcdef012345", safety = "20261121T005502Z-012345abcdef";
        string a = new('a', 64), b = new('b', 64), c = new('c', 64),
            d = new('d', 64), e = new('e', 64), f = new('f', 64);
        var plan = new SendmailV2Review(a, b, c, "compiled_files_review_candidate_only",
            4, 2, 1, 0, 0, 0, 0, 0, "stopped_declared", "none_observed", "empty_reported",
            "none_observed", "offline_candidate_manual_recovery_only");
        string common = "SENDMAIL_V2_EVIDENCE_VERSION=4\nSENDMAIL_V2_EVIDENCE_MTA=sendmail\n" +
            "SENDMAIL_V2_EVIDENCE_TARGET=" + id + "\nSENDMAIL_V2_EVIDENCE_SAFETY=" + safety +
            "\nSENDMAIL_V2_EVIDENCE_TARGET_SHA256=" + a + "\nSENDMAIL_V2_EVIDENCE_SAFETY_SHA256=" + d +
            "\nSENDMAIL_V2_EVIDENCE_TARGET_MANIFEST_SHA256=" + b + "\nSENDMAIL_V2_EVIDENCE_SAFETY_MANIFEST_SHA256=" + e +
            "\nSENDMAIL_V2_EVIDENCE_PLAN_SHA256=" + c + "\nSENDMAIL_V2_QUEUE_CHANGED=no\nSENDMAIL_V2_SERVICE_CHANGED=no\n";
        const string done = "SENDMAIL_V2_RECOVERY_CHANGED_FILES=1\nSENDMAIL_V2_RECOVERY_NATIVE_STATIC_CHECK=passed_partial_parse_only\nSENDMAIL_V2_RECOVERY_MARKER_CLEARED=yes\n";
        string applied = common + done + "SENDMAIL_V2_RECOVERY_STATUS=config_replaced_service_not_started\nSENDMAIL_V2_RECOVERY_SAFETY_ID=" + safety + "\n";
        string preview = common + "SENDMAIL_V2_ROLLBACK_STATUS=review_only\nSENDMAIL_V2_ROLLBACK_CONFIG_CHANGED=no\n" +
            "SENDMAIL_V2_ROLLBACK_PLAN_SHA256=" + f + "\nSENDMAIL_V2_ROLLBACK_CHANGED_FILES=1\n";
        string rolled = common + done + "SENDMAIL_V2_RECOVERY_STATUS=original_verified_service_not_started\nSENDMAIL_V2_ROLLBACK_APPROVED_SHA256=" + f + "\n";
        var review = ParseRollbackPlan(preview);
        if (!CanRestore(plan) || CanRestore(plan with { CompiledChanged = 0 }) ||
            CanRestore(plan with { OtherChanged = 1 }) || VerifyRestore(applied, id, plan) != review.Evidence)
            return false;
        VerifyRollback(rolled, review);
        string verify = "FOREIGN_BACKUP_STATUS=verified\nFOREIGN_BACKUP_MTA=sendmail\nFOREIGN_BACKUP_FORMAT=v2_package_metadata\n" +
            "FOREIGN_BACKUP_PRIMARY_CONFIG_CHANGED=no\nFOREIGN_BACKUP_MAIL_QUEUE_CHANGED=no\nFOREIGN_BACKUP_SERVICE_CHANGED=no\nFOREIGN_BACKUP_RESTORE_ENABLED=no\nFOREIGN_BACKUP_ARCHIVE_SHA256=" + a + "\n";
        if (VerifyArchive(verify) != a) return false;
        bool Reject(Action action)
        {
            try { action(); return false; }
            catch (InvalidDataException) { return true; }
        }
        foreach (string bad in new[] { applied.Replace("VERSION=4", "VERSION=3"), applied.Replace("MTA=sendmail", "MTA=exim"),
            applied.Replace(a, d), applied.Replace(b, e), applied.Replace(c, f), applied.Replace(safety, id),
            applied.Replace("CHANGED_FILES=1", "CHANGED_FILES=2"), applied.Replace("QUEUE_CHANGED=no", "QUEUE_CHANGED=yes"),
            applied.Replace("MARKER_CLEARED=yes", "MARKER_CLEARED=no"), applied + "EXTRA=yes\n",
            applied + "SENDMAIL_V2_QUEUE_CHANGED=no\n" })
            if (!Reject(() => VerifyRestore(bad, id, plan))) return false;
        foreach (string bad in new[] { rolled.Replace(f, c), rolled.Replace(e, d), rolled.Replace("SERVICE_CHANGED=no", "SERVICE_CHANGED=yes"),
            rolled.Replace("CHANGED_FILES=1", "CHANGED_FILES=0"), rolled + "SENDMAIL_V2_RECOVERY_SAFETY_ID=" + safety + "\n" })
            if (!Reject(() => VerifyRollback(bad, review))) return false;
        if (!Reject(() => ParseRollbackPlan(preview.Replace("CONFIG_CHANGED=no", "CONFIG_CHANGED=yes"))) ||
            !Reject(() => ParseRollbackPlan(preview.Replace("CHANGED_FILES=1", "CHANGED_FILES=3"))) ||
            !Reject(() => VerifyArchive(verify.Replace("v2_package_metadata", "v1_regular_files")))) return false;

        string restore = EmbeddedAssets.BuildSendmailV2RestoreApplyBundle(id, c);
        string rollback = EmbeddedAssets.BuildSendmailV2RollbackApplyBundle(f);
        string readOnly = EmbeddedAssets.BuildSendmailV2RollbackPlanBundle();
        if (!restore.Contains(" --mta sendmail --sendmail-v2-apply " + id + " --approve-sha256 " + c + " --confirm " + RestoreConfirmation + "\n", StringComparison.Ordinal) ||
            !rollback.Contains(" --mta sendmail --sendmail-v2-rollback-apply --approve-sha256 " + f + " --confirm " + RollbackConfirmation + "\n", StringComparison.Ordinal) ||
            !readOnly.Contains(" --mta sendmail --sendmail-v2-rollback-plan\n", StringComparison.Ordinal) ||
            readOnly.Contains(" --confirm ", StringComparison.Ordinal) || readOnly.Contains(" --approve-sha256 ", StringComparison.Ordinal))
            return false;
        try { EmbeddedAssets.BuildSendmailV2RestoreApplyBundle("../bad", c); return false; }
        catch (ArgumentException) { }
        try { EmbeddedAssets.BuildSendmailV2RollbackApplyBundle(f + ";bad"); return false; }
        catch (ArgumentException) { }
        return true;
    }
}
