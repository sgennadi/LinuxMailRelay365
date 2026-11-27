using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private static ConnectorSettingsEdit ReadConnectorRestoreSnapshot(string path, Guid tenantId, CloudConnectorObject connector)
    {
        if (!CanEditConnectorSettings(connector))
            throw new InvalidOperationException("Restore requires a disabled managed connector with one identity mode.");
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Restore source cannot be a reparse point.");
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > 65536)
            throw new InvalidDataException("Invalid connector snapshot size.");
        using var json = JsonDocument.Parse(file, new JsonDocumentOptions { MaxDepth = 8 });
        var root = json.RootElement;
        static void ExactFields(JsonElement obj, params string[] names)
        {
            if (obj.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("Expected a snapshot object.");
            var fields = obj.EnumerateObject().Select(p => p.Name).ToArray();
            if (fields.Length != names.Length || fields.Distinct(StringComparer.Ordinal).Count() != fields.Length ||
                fields.Except(names, StringComparer.Ordinal).Any())
                throw new InvalidDataException("Unknown, duplicate or missing snapshot fields.");
        }
        static string ReadString(JsonElement obj, string name, int limit)
        {
            string value = obj.GetProperty(name).GetString() ?? throw new InvalidDataException("Missing snapshot string.");
            if (value.Length > limit || value.Any(char.IsControl))
                throw new InvalidDataException("Invalid snapshot string.");
            return value;
        }
        static string[] Rows(JsonElement obj, string name, int max, Func<string, string> normalize)
        {
            var array = obj.GetProperty(name);
            if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > max)
                throw new InvalidDataException("Invalid snapshot list.");
            var rows = array.EnumerateArray().Select(x => normalize(x.GetString() ??
                throw new InvalidDataException("Invalid snapshot entry."))).OrderBy(x => x, StringComparer.Ordinal).ToArray();
            if (rows.Distinct(StringComparer.Ordinal).Count() != rows.Length)
                throw new InvalidDataException("Duplicate snapshot entries.");
            return rows;
        }
        static string Dns(string value)
        {
            value = value.ToLowerInvariant();
            if (value.Length is < 4 or > 253 || Uri.CheckHostName(value) != UriHostNameType.Dns ||
                !Regex.IsMatch(value, @"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z"))
                throw new InvalidDataException("Snapshot requires an exact DNS identity.");
            return value;
        }
        static string Ip(string value)
        {
            if (value.EndsWith("/32", StringComparison.Ordinal)) value = value[..^3];
            if (!Regex.IsMatch(value, @"\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z") ||
                !System.Net.IPAddress.TryParse(value, out var ip) || ip.ToString() != value)
                throw new InvalidDataException("Snapshot requires exact IPv4 addresses.");
            return value;
        }
        static ConnectorSettingsEdit Settings(JsonElement obj)
        {
            var domains = Rows(obj, "senderDomains", 40, Dns);
            var ips = Rows(obj, "senderIps", 24, Ip);
            string cert = ReadString(obj, "certificateName", 253);
            if (cert.Length > 0) cert = Dns(cert);
            if (domains.Length == 0 || (ips.Length > 0) == (cert.Length > 0))
                throw new InvalidDataException("Ambiguous or empty snapshot settings.");
            return new ConnectorSettingsEdit(string.Join(",", domains), string.Join(",", ips), cert);
        }
        ExactFields(root, "schema", "tenantId", "reviewedSha256", "utc", "identity", "name", "before", "proposed");
        if (ReadString(root, "schema", 80) != "linuxmailrelay365-connector-settings-backup/v1" ||
            ReadString(root, "tenantId", 36) != tenantId.ToString("D") ||
            ReadString(root, "identity", 256) != connector.Identity ||
            ReadString(root, "name", 90) != connector.Name ||
            !Regex.IsMatch(ReadString(root, "reviewedSha256", 64), @"\A[a-f0-9]{64}\z") ||
            !DateTimeOffset.TryParse(ReadString(root, "utc", 50), out _))
            throw new InvalidDataException("Snapshot does not match the selected tenant and connector.");
        var before = root.GetProperty("before");
        var proposed = root.GetProperty("proposed");
        string[] flagNames = ["requireTls", "restrictDomainsToIPAddresses", "restrictDomainsToCertificate",
            "cloudServicesMailEnabled", "treatMessagesAsInternal"];
        ExactFields(before, ["enabled", "senderDomains", "senderIps", "certificateName", .. flagNames]);
        ExactFields(proposed, "senderDomains", "senderIps", "certificateName");
        if (before.GetProperty("enabled").GetBoolean())
            throw new InvalidDataException("Snapshot was not taken from a disabled connector.");
        var previous = Settings(before);
        var expectedCurrent = Settings(proposed);
        var current = new ConnectorSettingsEdit(
            string.Join(",", connector.SenderDomains.Select(Dns).OrderBy(x => x, StringComparer.Ordinal)),
            string.Join(",", connector.SenderIps.Select(Ip).OrderBy(x => x, StringComparer.Ordinal)),
            connector.TlsCertificateName.Length == 0 ? "" : Dns(connector.TlsCertificateName));
        if (current != expectedCurrent || previous == current ||
            (previous.Ips.Length > 0) != (current.Ips.Length > 0))
            throw new InvalidDataException("Current settings do not match the snapshot proposal; refresh or review manually.");
        string flags = string.Concat(flagNames.Select(k => before.GetProperty(k).GetBoolean() ? "1" : "0"));
        if (flags[3] != '0' || flags[4] != '0' || (previous.Certificate.Length > 0 && flags[0] != '1'))
            throw new InvalidDataException("Snapshot security policy requires manual review.");
        return previous with { ExpectedSecurityFlags = flags };
    }

    private async Task<bool> RestoreCloudConnectorSettingsAsync(Form owner, CloudObjectsInventory inventory,
        CloudConnectorObject connector, Action contextGuard)
    {
        contextGuard();
        using var picker = new OpenFileDialog
        {
            Title = "Select connector settings backup (JSON)",
            InitialDirectory = dataDirectory,
            Filter = "Connector settings backups (connector-settings-backup-*.json)|connector-settings-backup-*.json|JSON files (*.json)|*.json",
            CheckFileExists = true, Multiselect = false, RestoreDirectory = true
        };
        if (picker.ShowDialog(owner) != DialogResult.OK) return false;
        string path = Path.GetFullPath(picker.FileName);
        var edit = ReadConnectorRestoreSnapshot(path, inventory.Tenant, connector);
        contextGuard();
        return await ApplyReviewedConnectorSettingsAsync(owner, inventory, connector, edit, contextGuard, path);
    }
}
