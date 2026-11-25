namespace LinuxMailRelay365;

internal enum NativeRecoverySampleState { Unknown, Clear, Exim, Sendmail, ManualOnly }

// Presentation only. The global inspection receipt does not attest the
// rollback schema or authorize a write. Full tools remain explicitly accessible.
internal sealed record NativeRecoveryVisibility(NativeRecoverySampleState State, bool ShowExim, bool ShowSendmail)
{
    internal static NativeRecoveryVisibility From(ForeignPendingInspection? sample, bool expanded)
    {
        var state = sample switch
        {
            null => NativeRecoverySampleState.Unknown,
            { IsClear: true } => NativeRecoverySampleState.Clear,
            { Mta: "exim", Counts: not null } => NativeRecoverySampleState.Exim,
            { Mta: "sendmail", Counts: not null } => NativeRecoverySampleState.Sendmail,
            _ => NativeRecoverySampleState.ManualOnly
        };
        return new(state, expanded || state == NativeRecoverySampleState.Exim,
            expanded || state == NativeRecoverySampleState.Sendmail);
    }

    internal static bool SelfTest()
    {
        var counts = new ForeignPendingCounts(4, 1, 1, 2, 0, 0, 0);
        var exim = new ForeignPendingInspection(false, "exim", Counts: counts);
        var sendmail = exim with { Mta = "sendmail" };
        var legacy = exim with { Counts = null };
        return From(null, false) == new NativeRecoveryVisibility(NativeRecoverySampleState.Unknown, false, false) &&
            From(new ForeignPendingInspection(true), false) == new NativeRecoveryVisibility(NativeRecoverySampleState.Clear, false, false) &&
            From(exim, false) == new NativeRecoveryVisibility(NativeRecoverySampleState.Exim, true, false) &&
            From(sendmail, false) == new NativeRecoveryVisibility(NativeRecoverySampleState.Sendmail, false, true) &&
            From(legacy, false) == new NativeRecoveryVisibility(NativeRecoverySampleState.ManualOnly, false, false) &&
            new ForeignPendingInspection?[] { null, new(true), exim, sendmail, legacy }.All(
                sample => From(sample, true) is { ShowExim: true, ShowSendmail: true });
    }
}
