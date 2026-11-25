using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Lists identify verified remote archives, not approval or proof of live delivery.
internal sealed record VerifiedArchiveListing(string[] Ids, int Total)
{
    internal static bool ValidId(string id) =>
        Regex.IsMatch(id, @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z", RegexOptions.CultureInvariant);

    internal static VerifiedArchiveListing Parse(string output, bool sidecar)
    {
        if (output.Length > 512 * 1024 || output.Contains('\0'))
            throw new InvalidDataException("Archive inventory too large or malformed.");
        string prefix = sidecar ? "SIDECAR_BACKUP_" : "BACKUP_";
        string invalidPrefix = sidecar ? "SIDECAR_INVALID_BACKUP_ID=" : "BACKUP_INVALID_ID=";
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var invalid = new HashSet<string>(StringComparer.Ordinal);
        int? total = null;
        bool unchanged = false;
        foreach (string line in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0) continue;
            if (line.StartsWith(prefix + "ID=", StringComparison.Ordinal))
            {
                string id = line[(prefix.Length + 3)..];
                if (!ValidId(id) || invalid.Contains(id) || !ids.Add(id))
                    throw new InvalidDataException("Invalid or duplicate verified archive ID.");
            }
            else if (line.StartsWith(invalidPrefix, StringComparison.Ordinal))
            {
                string id = line[invalidPrefix.Length..];
                if (!ValidId(id) || ids.Contains(id) || !invalid.Add(id))
                    throw new InvalidDataException("Invalid or duplicate rejected archive ID.");
            }
            else if (line.StartsWith(prefix + "COUNT=", StringComparison.Ordinal))
            {
                string value = line[(prefix.Length + 6)..];
                if (total is not null || !Regex.IsMatch(value, @"\A(?:0|[1-9][0-9]{0,5})\z") ||
                    !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed))
                    throw new InvalidDataException("Invalid archive count.");
                total = parsed;
            }
            else if (sidecar && line == "CHANGES_APPLIED=no" && !unchanged)
                unchanged = true;
            else
                throw new InvalidDataException("Unexpected archive inventory field.");
        }
        if (total is null || (sidecar && !unchanged) ||
            ids.Count != (sidecar ? Math.Min(total.Value, 256) : total.Value))
            throw new InvalidDataException("Incomplete or inconsistent archive listing.");
        return new(ids.OrderByDescending(x => x, StringComparer.Ordinal).ToArray(), total.Value);
    }

    internal static bool SelfTest()
    {
        const string a = "20261124T120000Z-abcdef012345", b = "20261125T120000Z-012345abcdef";
        const string badId = "20261123T120000Z-aaaaaaaaaaaa";
        string plain = "BACKUP_ID=" + a + "\nBACKUP_ID=" + b + "\nBACKUP_INVALID_ID=" + badId + "\nBACKUP_COUNT=2\n";
        var list = Parse(plain, false);
        if (list.Total != 2 || !list.Ids.SequenceEqual(new[] { b, a }) ||
            Parse("BACKUP_COUNT=0\n", false).Ids.Length != 0 ||
            Parse("SIDECAR_BACKUP_COUNT=0\nCHANGES_APPLIED=no\n", true).Total != 0)
            return false;
        string sidecar = "SIDECAR_BACKUP_ID=" + a + "\nSIDECAR_INVALID_BACKUP_ID=" + badId +
            "\nSIDECAR_BACKUP_COUNT=1\nCHANGES_APPLIED=no\n";
        if (Parse(sidecar, true).Ids.Single() != a) return false;
        string capped = string.Concat(Enumerable.Range(0, 256).Select(i =>
            "SIDECAR_BACKUP_ID=20261124T120000Z-" + i.ToString("x12", CultureInfo.InvariantCulture) + "\n")) +
            "SIDECAR_BACKUP_COUNT=300\nCHANGES_APPLIED=no\n";
        if (Parse(capped, true) is not { Total: 300, Ids.Length: 256 }) return false;
        bool Reject(string value, bool isSidecar)
        {
            try { Parse(value, isSidecar); return false; }
            catch (InvalidDataException) { return true; }
        }
        return Reject(plain.Replace("COUNT=2", "COUNT=3"), false) &&
            Reject(plain + "BACKUP_COUNT=2\n", false) &&
            Reject(plain + "BACKUP_ID=" + a + "\n", false) &&
            Reject(plain.Replace(badId, a), false) &&
            Reject(plain.Replace(a, "../etc"), false) &&
            Reject(sidecar.Replace("CHANGES_APPLIED=no\n", ""), true) &&
            Reject(sidecar.Replace("CHANGES_APPLIED=no", "CHANGES_APPLIED=yes"), true) &&
            Reject(sidecar.Replace("COUNT=1", "COUNT=257"), true);
    }
}
