using System.Text.Json;

namespace LinuxMailRelay365;

// Pure parser for an allowlisted local result written by the embedded PowerShell discovery script.
// Neither passwords nor tokens are ever returned from tenant discovery.
internal sealed record TenantOption(Guid Id, string Name, string Domain, string Category)
{
    public override string ToString() =>
        $"{Name}  |  {(string.IsNullOrEmpty(Domain) ? "no domain" : Domain)}  |  {Id}";
}

internal static class TenantDiscovery
{
    internal const string Schema = "linux-mail-relay-tenant-discovery/v1";

    // Accept only a fixed diagnostic code. Never surface raw Azure exceptions,
    // usernames, tokens, or arbitrary strings from the child PowerShell process.
    internal static string FailureCode(string json)
    {
        if (json.Length > 256_000) return "invalid_result";
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 12 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schema", out var schema) ||
                schema.ValueKind != JsonValueKind.String ||
                schema.GetString() != Schema ||
                !root.TryGetProperty("status", out var status) ||
                status.ValueKind != JsonValueKind.String ||
                status.GetString() != "error" ||
                !root.TryGetProperty("errorCode", out var error) ||
                error.ValueKind != JsonValueKind.String)
                return "invalid_result";
            return error.GetString() switch
            {
                "az_module_install_failed" => "az_module_install_failed",
                "az_module_import_failed" => "az_module_import_failed",
                "device_sign_in_failed" => "device_sign_in_failed",
                "tenant_enumeration_failed" => "tenant_enumeration_failed",
                "result_write_failed" => "result_write_failed",
                "discovery_failed" => "discovery_failed",
                _ => "invalid_result"
            };
        }
        catch (JsonException) { return "invalid_result"; }
    }

    internal static IReadOnlyList<TenantOption> Parse(string json)
    {
        if (json.Length > 256_000) throw new InvalidDataException("Tenant discovery result too large.");
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 12 });
        var root = document.RootElement;
        if (!root.TryGetProperty("schema", out var schema) || schema.GetString() != Schema)
            throw new InvalidDataException("Unrecognized tenant discovery response schema.");
        if (!root.TryGetProperty("tenants", out var tenants) || tenants.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Tenant discovery response is incomplete.");
        if (tenants.GetArrayLength() > 100)
            throw new InvalidDataException("Tenant discovery returned too many entries.");
        var result = new List<TenantOption>();
        var used = new HashSet<Guid>();
        foreach (var candidate in tenants.EnumerateArray())
        {
            if (candidate.ValueKind != JsonValueKind.Object ||
                !candidate.TryGetProperty("tenantId", out var identifier) ||
                identifier.ValueKind != JsonValueKind.String ||
                !Guid.TryParse(identifier.GetString(), out var id) || id == Guid.Empty)
                continue;
            if (!used.Add(id)) continue;
            string name = candidate.TryGetProperty("displayName", out var n) && n.ValueKind == JsonValueKind.String
                ? n.GetString() ?? "" : "";
            string domain = candidate.TryGetProperty("primaryDomain", out var d) && d.ValueKind == JsonValueKind.String
                ? d.GetString() ?? "" : "";
            string category = candidate.TryGetProperty("category", out var c) && c.ValueKind == JsonValueKind.String
                ? c.GetString() ?? "" : "";
            if (name.Length > 128 || domain.Length > 253 || category.Length > 32)
                throw new InvalidDataException("Unexpected tenant metadata size.");
            result.Add(new TenantOption(id, string.IsNullOrWhiteSpace(name) ? "Microsoft Entra tenant" : name.Trim(),
                domain.Trim(), category.Trim()));
        }
        return result.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Id).ToArray();
    }

    internal static bool SelfTest()
    {
        var t1 = "11111111-1111-4111-8111-111111111111";
        var t2 = "22222222-2222-4222-8222-222222222222";
        var json = "{\"schema\":\"" + Schema + "\",\"tenants\":[" +
            "{\"tenantId\":\"" + t2 + "\",\"displayName\":\"Zebra\",\"primaryDomain\":\"zebra.example\"}," +
            "{\"tenantId\":\"" + t1 + "\",\"displayName\":\"Alpha\",\"primaryDomain\":\"alpha.example\"}," +
            "{\"tenantId\":\"" + t1 + "\",\"displayName\":\"Duplicate\"}]}";
        var choices = Parse(json);
        if (choices.Count != 2 || choices[0].Name != "Alpha" || choices[1].Id.ToString() != t2 ||
            !choices[0].ToString().Contains("alpha.example", StringComparison.Ordinal)) return false;
        try { Parse("{\"schema\":\"invalid\",\"tenants\":[]}"); return false; }
        catch (InvalidDataException) { return true; }
    }
}
