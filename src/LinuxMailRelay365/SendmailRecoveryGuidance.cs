namespace LinuxMailRelay365;

// Presentation only. A candidate is not an approval; the actual write path
// still uses its independent exact-plan, connection and confirmation gates.
internal enum SendmailRecoveryDisposition { Blocked, NoChanges, SeparateApprovalRequired }

internal sealed record SendmailRecoveryGuidance(SendmailRecoveryDisposition Disposition, string[] Reasons)
{
    internal static SendmailRecoveryGuidance From(SendmailV2Review plan)
    {
        if (SendmailV2RecoveryReceipt.CanRestore(plan))
            return new(SendmailRecoveryDisposition.SeparateApprovalRequired, []);
        var reasons = new List<string>();
        if (plan.Service != "stopped_declared")
            reasons.Add(plan.Service == "running" ? "service_running" : "service_unknown");
        if (plan.Processes != "none_observed")
            reasons.Add(plan.Processes == "running" ? "process_running" : "process_unknown");
        if (plan.Queue != "empty_reported")
            reasons.Add(plan.Queue == "nonempty_reported" ? "queue_nonempty" : "queue_unknown");
        if (plan.Listener != "none_observed")
            reasons.Add(plan.Listener == "running" ? "listener_running" : "listener_unknown");
        if (plan.CompiledTargets != 2) reasons.Add("compiled_targets");
        if (plan.OtherChanged != 0) reasons.Add("other_content");
        if (plan.Missing != 0 || plan.Extra != 0) reasons.Add("file_set");
        if (plan.MetadataChanged != 0) reasons.Add("metadata");
        if (plan.ObjectDrift != 0) reasons.Add("objects");
        if (plan.Gate == "blocked_untrusted_write_scope") reasons.Add("write_scope");
        if (plan.Gate == "blocked_offline_preflight" && reasons.Count == 0)
            reasons.Add("offline_unknown");
        if (plan.Gate == "blocked_inventory_drift" && reasons.Count == 0)
            reasons.Add("inventory_unknown");
        if (reasons.Count == 0 && plan.IsCandidate &&
            plan.CompiledChanged == 0 && plan.OfflineGate == "offline_candidate_manual_recovery_only")
            return new(SendmailRecoveryDisposition.NoChanges, []);
        if (reasons.Count == 0) reasons.Add("unknown");
        return new(SendmailRecoveryDisposition.Blocked, reasons.ToArray());
    }

    internal static bool SelfTest()
    {
        string a = new('a', 64), b = new('b', 64), c = new('c', 64);
        var plan = new SendmailV2Review(a, b, c, "compiled_files_review_candidate_only",
            4, 2, 1, 0, 0, 0, 0, 0, "stopped_declared", "none_observed",
            "empty_reported", "none_observed", "offline_candidate_manual_recovery_only");
        if (From(plan).Disposition != SendmailRecoveryDisposition.SeparateApprovalRequired ||
            From(plan with { CompiledChanged = 0 }).Disposition != SendmailRecoveryDisposition.NoChanges)
            return false;
        bool Blocked(SendmailV2Review review, params string[] reasons)
        {
            var result = From(review);
            return result.Disposition == SendmailRecoveryDisposition.Blocked &&
                result.Reasons.SequenceEqual(reasons);
        }
        var offline = plan with { Gate = "blocked_offline_preflight", OfflineGate = "blocked_unverified" };
        var inventory = plan with { Gate = "blocked_inventory_drift" };
        return Blocked(offline, "offline_unknown") &&
            Blocked(offline with { Service = "running", Processes = "running", Listener = "running",
                OfflineGate = "blocked_running" }, "service_running", "process_running", "listener_running") &&
            Blocked(offline with { Service = "unverified", Processes = "unverified",
                Queue = "unverified", Listener = "unverified" },
                "service_unknown", "process_unknown", "queue_unknown", "listener_unknown") &&
            Blocked(offline with { Queue = "nonempty_reported", OfflineGate = "blocked_nonempty_queue" },
                "queue_nonempty") &&
            Blocked(inventory with { CompiledTargets = 1, OtherChanged = 1, Missing = 1, Extra = 1,
                MetadataChanged = 1, ObjectDrift = 1 }, "compiled_targets", "other_content",
                "file_set", "metadata", "objects") &&
            Blocked(plan with { Gate = "blocked_untrusted_write_scope" }, "write_scope") &&
            Blocked(offline with { CompiledChanged = 0 }, "offline_unknown");
    }
}
