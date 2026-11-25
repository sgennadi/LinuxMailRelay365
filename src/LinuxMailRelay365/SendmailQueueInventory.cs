using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record SendmailQueueRow(int Reference, int Group, string State,
    long Bytes, string NativeTime, string Reason);

// Normal-queue metadata only. Native IDs and reusable write handles are absent.
internal sealed record SendmailQueueInventory(string Queue, string Result, int? Total,
    int? Groups, int? NativeListed, bool? NativeTruncated, bool? DisplayTruncated,
    SendmailQueueRow[] Rows)
{
    internal static readonly string[] States = ["queued", "processing_mark", "load_limited", "too_young"];
    internal static readonly string[] Reasons = ["auth", "tls", "dns", "network", "temporary",
        "permanent", "mixed", "other_reason", "no_reason"];

    internal static SendmailQueueInventory Parse(string output, string queue, string nonce)
    {
        if (queue is not ("mta" or "msp") || !QueueRetryReview.ValidSha(nonce))
            throw new ArgumentException("Invalid Sendmail queue request.");
        var f = new EximQueueFields(output, "SENDMAIL_ITEMS_", rows: true);
        f.Exact("VERSION", "1"); f.Exact("SCOPE", "sendmail");
        f.Exact("QUEUE", queue); f.Exact("NONCE", nonce);
        f.Exact("REFERENCE_KIND", "sample_ordinal_only");
        f.Exact("QUEUE_CLASS", "normal"); f.Exact("DATE_KIND", "native_local_no_year");
        f.Exact("CHANGES_APPLIED", "no"); f.Exact("ATOMIC", "no");
        f.Exact("DELIVERY_VERIFIED", "no");
        string result = f.Take("RESULT", "ok|" + EximQueueFields.Failures);
        int? Count(string key)
        {
            string value = f.Take(key, "unknown|0|[1-9][0-9]{0,4}");
            return value == "unknown" ? null : (int)EximQueueFields.Number(value, 50000);
        }
        bool? Flag(string key)
        {
            string value = f.Take(key, "unknown|yes|no");
            return value == "unknown" ? null : value == "yes";
        }
        int? total = Count("TOTAL"), groups = Count("GROUPS"), native = Count("NATIVE_LISTED");
        bool? nativeTruncated = Flag("NATIVE_TRUNCATED"), displayTruncated = Flag("DISPLAY_TRUNCATED");
        int listed = (int)EximQueueFields.Number(f.Take("LISTED", "0|[1-9][0-9]{0,2}"), 500);
        f.End();
        bool ok = result == "ok";
        if (listed != f.Rows.Count || ok != total.HasValue || ok != groups.HasValue ||
            ok != native.HasValue || ok != nativeTruncated.HasValue || ok != displayTruncated.HasValue ||
            (!ok && listed != 0) ||
            (ok && (groups < 1 || native > total || listed != Math.Min(native!.Value, 500) ||
                nativeTruncated != (native < total) || displayTruncated != (native > listed))))
            throw new InvalidDataException("Inconsistent Sendmail queue counts.");
        var rows = new List<SendmailQueueRow>();
        foreach (string line in f.Rows)
        {
            string[] p = line.Split('|');
            if (p.Length != 6 || EximQueueFields.Number(p[0], 500) != rows.Count + 1 ||
                !States.Contains(p[2], StringComparer.Ordinal) ||
                !Regex.IsMatch(p[3], @"\A(?:0|[1-9][0-9]{0,12})\z") ||
                !long.TryParse(p[3], NumberStyles.None, CultureInfo.InvariantCulture, out long bytes) ||
                bytes > 1099511627776 || !ValidNativeTime(p[4]) ||
                !Reasons.Contains(p[5], StringComparer.Ordinal))
                throw new InvalidDataException("Invalid Sendmail metadata row.");
            int group = (int)EximQueueFields.Number(p[1], groups!.Value);
            if (group < 1 || (rows.Count > 0 && group < rows[^1].Group))
                throw new InvalidDataException("Invalid Sendmail queue group order.");
            rows.Add(new(rows.Count + 1, group, p[2], bytes, p[4], p[5]));
        }
        return new(queue, result, total, groups, native, nativeTruncated, displayTruncated, rows.ToArray());
    }

    private static bool ValidNativeTime(string value)
    {
        if (!Regex.IsMatch(value, @"\A(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?:[1-9]|[12][0-9]|3[01]) (?:[01][0-9]|2[0-3]):[0-5][0-9]\z"))
            return false;
        var parts = value.Split(' ');
        int day = int.Parse(parts[2], CultureInfo.InvariantCulture);
        int limit = parts[1] switch { "Feb" => 29, "Apr" or "Jun" or "Sep" or "Nov" => 30, _ => 31 };
        return day <= limit;
    }

    internal IEnumerable<SendmailQueueRow> Filter(string? state, int? group, string? reason)
        => Rows.Where(row => (state is null || row.State == state) &&
            (group is null || row.Group == group) && (reason is null || row.Reason == reason));

    internal static bool SelfTest()
    {
        string nonce = new('a', 64);
        string sample = "SENDMAIL_ITEMS_VERSION=1\nSENDMAIL_ITEMS_SCOPE=sendmail\nSENDMAIL_ITEMS_QUEUE=msp\n" +
            "SENDMAIL_ITEMS_NONCE=" + nonce + "\nSENDMAIL_ITEMS_RESULT=ok\nSENDMAIL_ITEMS_TOTAL=3\n" +
            "SENDMAIL_ITEMS_GROUPS=2\nSENDMAIL_ITEMS_NATIVE_LISTED=2\nSENDMAIL_ITEMS_NATIVE_TRUNCATED=yes\n" +
            "SENDMAIL_ITEMS_LISTED=2\nSENDMAIL_ITEMS_DISPLAY_TRUNCATED=no\nSENDMAIL_ITEMS_REFERENCE_KIND=sample_ordinal_only\n" +
            "SENDMAIL_ITEMS_QUEUE_CLASS=normal\nSENDMAIL_ITEMS_DATE_KIND=native_local_no_year\n" +
            "SENDMAIL_ITEMS_CHANGES_APPLIED=no\nSENDMAIL_ITEMS_ATOMIC=no\nSENDMAIL_ITEMS_DELIVERY_VERIFIED=no\n" +
            "SENDMAIL_ITEMS_ROW=1|1|too_young|1024|Mon Nov 25 10:00|tls\n" +
            "SENDMAIL_ITEMS_ROW=2|2|processing_mark|42|Tue Feb 29 01:00|no_reason\n";
        var parsed = Parse(sample, "msp", nonce);
        if (parsed.Total != 3 || parsed.NativeTruncated != true || parsed.DisplayTruncated != false ||
            parsed.Filter("processing_mark", 2, null).Single().Bytes != 42) return false;
        bool Reject(Action fn) { try { fn(); return false; } catch (InvalidDataException) { return true; } }
        foreach (string bad in new[] { sample.Replace("NATIVE_TRUNCATED=yes", "NATIVE_TRUNCATED=no"),
            sample.Replace("NATIVE_LISTED=2", "NATIVE_LISTED=1"), sample.Replace("Feb 29", "Feb 30"),
            sample.Replace("ROW=2|2", "ROW=2|3"), sample.Replace("|tls", "|private@example.invalid"),
            sample.Replace("CHANGES_APPLIED=no", "CHANGES_APPLIED=yes"),
            sample.Replace("processing_mark", "active"), sample + "SENDMAIL_ITEMS_RAW=message\n" })
            if (!Reject(() => Parse(bad, "msp", nonce))) return false;
        if (!Reject(() => Parse(sample, "mta", nonce))) return false;
        string bundle = EmbeddedAssets.BuildSendmailQueueInventoryBundle("msp", nonce);
        return bundle.Contains(" --scope sendmail --sendmail-inventory msp --selection-nonce " + nonce + "\n",
            StringComparison.Ordinal);
    }
}
