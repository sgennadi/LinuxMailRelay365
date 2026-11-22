using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Identity.Client;

namespace Microsoft365Auth;

/// <summary>Read-only Graph inventory: no directory write scopes, no key bytes.</summary>
public static class EntraGraphInventoryClient
{
    private const int MaxBytes = 256_000;

    public static async Task<EntraApplicationInventory> InspectAsync(
        Guid tenantId, Guid appId, Guid? bootstrapPublicClientId,
        Func<DeviceCodeResult, Task> showDeviceCode, CancellationToken ct)
    {
        if (tenantId == Guid.Empty || appId == Guid.Empty)
            throw new EntraDiscoveryException("invalid_graph_selection");
        Guid signInApp = bootstrapPublicClientId is { } supplied && supplied != Guid.Empty
            ? supplied : EntraTenantDiscoveryClient.DefaultGraphClientId;
        string token = await EntraTenantDiscoveryClient.AcquireGraphReadTokenAsync(
            tenantId, signInApp, showDeviceCode, ct).ConfigureAwait(false);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(25),
            MaxResponseContentBufferSize = MaxBytes
        };

        var url = "https://graph.microsoft.com/v1.0/applications(appId='" +
                  appId.ToString("D") + "')?$select=id,appId,displayName,keyCredentials";
        using var app = await GetJsonAsync(http, url, token, false, ct).ConfigureAwait(false)
            ?? throw new EntraDiscoveryException("application_not_found");
        var root = app.RootElement;
        if (GuidProperty(root, "appId") != appId)
            throw new EntraDiscoveryException("application_id_mismatch");
        Guid objectId = GuidProperty(root, "id");
        string name = LimitedString(root, "displayName", 128);
        var certificates = new List<EntraCertificateMetadata>();
        if (!root.TryGetProperty("keyCredentials", out var keys) ||
            keys.ValueKind != JsonValueKind.Array || keys.GetArrayLength() > 64)
            throw new EntraDiscoveryException("application_credentials_not_verified");
        foreach (var cert in keys.EnumerateArray())
        {
            if (cert.ValueKind != JsonValueKind.Object)
                throw new EntraDiscoveryException("invalid_certificate_metadata");
            Guid keyId = GuidProperty(cert, "keyId");
            string label = LimitedString(cert, "displayName", 128);
            string type = LimitedString(cert, "type", 32);
            string usage = LimitedString(cert, "usage", 32);
            if (!DateTimeOffset.TryParse(LimitedString(cert, "startDateTime", 64), out var from) ||
                !DateTimeOffset.TryParse(LimitedString(cert, "endDateTime", 64), out var until) ||
                until <= from)
                throw new EntraDiscoveryException("invalid_certificate_dates");
            certificates.Add(new(keyId, label, type, usage, from.ToUniversalTime(), until.ToUniversalTime()));
        }

        Guid? enterpriseId = null;
        string enterpriseStatus = "unverified";
        var spUrl = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='" +
                    appId.ToString("D") + "')?$select=id,appId";
        using (var sp = await GetJsonAsync(http, spUrl, token, true, ct).ConfigureAwait(false))
        {
            if (sp is not null)
            {
                if (GuidProperty(sp.RootElement, "appId") != appId)
                    throw new EntraDiscoveryException("enterprise_application_mismatch");
                enterpriseId = GuidProperty(sp.RootElement, "id");
                enterpriseStatus = "found";
            }
        }
        return new EntraApplicationInventory(appId, objectId, name,
            enterpriseStatus, enterpriseId, certificates);
    }

    private static async Task<JsonDocument?> GetJsonAsync(
        HttpClient http, string url, string token, bool allowNotFound, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await http.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (allowNotFound && response.StatusCode == HttpStatusCode.NotFound)
            return null;
        if (response.StatusCode == HttpStatusCode.Unauthorized ||
            response.StatusCode == HttpStatusCode.Forbidden)
            throw new EntraDiscoveryException("graph_application_read_denied");
        if (response.StatusCode == HttpStatusCode.NotFound)
            throw new EntraDiscoveryException("application_not_found");
        if (!response.IsSuccessStatusCode)
            throw new EntraDiscoveryException("graph_application_http_failed");
        if (response.Content.Headers.ContentLength > MaxBytes)
            throw new EntraDiscoveryException("graph_result_too_large");
        try
        {
            await response.Content.LoadIntoBufferAsync(MaxBytes, ct).ConfigureAwait(false);
            return JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false),
                new JsonDocumentOptions { MaxDepth = 16 });
        }
        catch (JsonException) { throw new EntraDiscoveryException("invalid_graph_json"); }
        catch (HttpRequestException) { throw new EntraDiscoveryException("graph_connection_failed"); }
    }

    private static Guid GuidProperty(JsonElement root, string key)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty(key, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            !Guid.TryParse(value.GetString(), out Guid parsed) || parsed == Guid.Empty)
            throw new EntraDiscoveryException("invalid_graph_object_id");
        return parsed;
    }

    private static string LimitedString(JsonElement root, string key, int max)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty(key, out var value) || value.ValueKind != JsonValueKind.String)
            return "";
        var text = value.GetString() ?? "";
        if (text.Length > max || text.Any(char.IsControl))
            throw new EntraDiscoveryException("invalid_graph_metadata");
        return text;
    }

    public static bool SelfTest() =>
        EntraTenantDiscoveryClient.DefaultGraphClientId != Guid.Empty &&
        GuidProperty(JsonDocument.Parse("{\"id\":\"11111111-1111-4111-8111-111111111111\"}")
            .RootElement, "id") != Guid.Empty;
}

public sealed record EntraCertificateMetadata(
    Guid KeyId, string Label, string Type, string Usage,
    DateTimeOffset ValidFrom, DateTimeOffset ValidUntil);

public sealed record EntraApplicationInventory(
    Guid ClientId, Guid AppObjectId, string DisplayName,
    string EnterpriseStatus, Guid? EnterpriseObjectId,
    IReadOnlyList<EntraCertificateMetadata> Certificates);
