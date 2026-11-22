using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Identity.Client;

namespace Microsoft365Auth;

/// <summary>
/// C#-native, session-only Microsoft Entra discovery. Based on the Device Code
/// model used by BitKeyBridge, but backed by the supported MSAL.NET client.
/// No PowerShell, persisted OAuth tokens, client secrets or tenant mutations.
/// </summary>
public static class EntraTenantDiscoveryClient
{
    public static readonly Guid DefaultGraphClientId =
        Guid.Parse("14d82eec-204b-4c2f-b7e8-296a70dab67e"); // Microsoft Graph Command Line Tools
    public const string GraphScope = "https://graph.microsoft.com/User.Read";
    public const string ArmScope = "https://management.azure.com/user_impersonation";
    private const int MaxResponseBytes = 512_000;
    private static readonly ConcurrentDictionary<Guid, IPublicClientApplication> Clients = new();

    public static async Task<IReadOnlyList<EntraTenantEntry>> DiscoverAsync(
        Guid? approvedArmClientId, bool allAccessibleTenants,
        Func<DeviceCodeResult, Task> showDeviceCode, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(showDeviceCode);
        if (allAccessibleTenants && (approvedArmClientId is null || approvedArmClientId == Guid.Empty))
            throw new EntraDiscoveryException("approved_public_client_id_required");
        Guid clientId = allAccessibleTenants ? approvedArmClientId!.Value :
            (approvedArmClientId is { } supplied && supplied != Guid.Empty ? supplied : DefaultGraphClientId);
        string[] scopes = [allAccessibleTenants ? ArmScope : GraphScope];
        AuthenticationResult credential;
        try
        {
            var app = Clients.GetOrAdd(clientId, id =>
                PublicClientApplicationBuilder.Create(id.ToString("D"))
                    .WithAuthority(AzureCloudInstance.AzurePublic, "organizations").Build());
            credential = await AcquireSessionTokenAsync(app, scopes, showDeviceCode, ct)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (MsalException) { throw new EntraDiscoveryException("device_sign_in_failed"); }

        if (!Guid.TryParse(credential.TenantId, out var loggedIn) || loggedIn == Guid.Empty)
            throw new EntraDiscoveryException("signed_in_tenant_unverified");

        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(25),
            MaxResponseContentBufferSize = MaxResponseBytes
        };
        string token = credential.AccessToken;
        try
        {
            return allAccessibleTenants
                ? await ListArmTenantsAsync(http, token, ct).ConfigureAwait(false)
                : await GetGraphTenantAsync(http, token, loggedIn, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (EntraDiscoveryException) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or IOException or
                                   JsonException or TaskCanceledException or InvalidOperationException)
        {
            throw new EntraDiscoveryException("tenant_enumeration_failed");
        }
    }

    // Shared in-process token acquisition for read-only and separately
    // operator-approved Graph writes. Tokens never leave this library and its
    // MSAL cache is volatile only. The exact tenant is independently checked.
    internal static Task<string> AcquireGraphReadTokenAsync(
        Guid exactTenant, Guid approvedClientId,
        Func<DeviceCodeResult, Task> showDeviceCode, CancellationToken ct) =>
        AcquireGraphTokenAsync(exactTenant, approvedClientId,
            "https://graph.microsoft.com/Application.Read.All", showDeviceCode, ct);

    internal static Task<string> AcquireGraphWriteTokenAsync(
        Guid exactTenant, Guid approvedClientId,
        Func<DeviceCodeResult, Task> showDeviceCode, CancellationToken ct) =>
        AcquireGraphTokenAsync(exactTenant, approvedClientId,
            "https://graph.microsoft.com/Application.ReadWrite.All", showDeviceCode, ct);

    private static async Task<string> AcquireGraphTokenAsync(
        Guid exactTenant, Guid approvedClientId, string exactScope,
        Func<DeviceCodeResult, Task> showDeviceCode, CancellationToken ct)
    {
        if (exactTenant == Guid.Empty || approvedClientId == Guid.Empty)
            throw new EntraDiscoveryException("invalid_graph_tenant_or_public_client");
        if (exactScope is not ("https://graph.microsoft.com/Application.Read.All" or
                              "https://graph.microsoft.com/Application.ReadWrite.All"))
            throw new EntraDiscoveryException("invalid_graph_scope");
        var app = Clients.GetOrAdd(approvedClientId, id =>
            PublicClientApplicationBuilder.Create(id.ToString("D"))
                .WithAuthority(AzureCloudInstance.AzurePublic, "organizations").Build());
        AuthenticationResult? credential = null;
        try
        {
            foreach (var account in await app.GetAccountsAsync().ConfigureAwait(false))
            {
                try
                {
                    var silent = await app.AcquireTokenSilent([exactScope], account)
                        .WithTenantId(exactTenant.ToString("D"))
                        .ExecuteAsync(ct).ConfigureAwait(false);
                    if (Guid.TryParse(silent.TenantId, out var found) && found == exactTenant)
                    {
                        credential = silent;
                        break;
                    }
                }
                catch (MsalUiRequiredException) { }
            }
            credential ??= await app.AcquireTokenWithDeviceCode([exactScope], showDeviceCode)
                .WithTenantId(exactTenant.ToString("D"))
                .ExecuteAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (MsalException) { throw new EntraDiscoveryException("graph_device_sign_in_failed"); }
        if (!Guid.TryParse(credential.TenantId, out Guid received) || received != exactTenant)
            throw new EntraDiscoveryException("graph_wrong_tenant");
        return credential.AccessToken;
    }

    private static async Task<AuthenticationResult> AcquireSessionTokenAsync(
        IPublicClientApplication app, string[] scopes,
        Func<DeviceCodeResult, Task> showDeviceCode, CancellationToken ct)
    {
        // MSAL cache is IN MEMORY only. Never persist access/refresh tokens on disk.
        // A cached account is a convenience, not tenant authorization.
        foreach (var account in await app.GetAccountsAsync().ConfigureAwait(false))
        {
            try
            {
                return await app.AcquireTokenSilent(scopes, account)
                    .ExecuteAsync(ct).ConfigureAwait(false);
            }
            catch (MsalUiRequiredException) { }
        }
        return await app.AcquireTokenWithDeviceCode(scopes, showDeviceCode)
            .ExecuteAsync(ct).ConfigureAwait(false);
    }

    private static async Task<JsonDocument> ReadJsonAsync(
        HttpClient http, string uri, string bearer, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct)
            .ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new EntraDiscoveryException("tenant_read_permission_denied");
        if (response.StatusCode != HttpStatusCode.OK)
            throw new EntraDiscoveryException("tenant_read_http_failed");
        if (response.Content.Headers.ContentLength > MaxResponseBytes)
            throw new EntraDiscoveryException("tenant_response_too_large");
        await response.Content.LoadIntoBufferAsync(MaxResponseBytes, ct).ConfigureAwait(false);
        return JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false),
            new JsonDocumentOptions { MaxDepth = 18 });
    }

    private static async Task<IReadOnlyList<EntraTenantEntry>> GetGraphTenantAsync(
        HttpClient http, string bearer, Guid loggedIn, CancellationToken ct)
    {
        const string url = "https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains";
        using var json = await ReadJsonAsync(http, url, bearer, ct).ConfigureAwait(false);
        var root = json.RootElement;
        if (!root.TryGetProperty("value", out var rows) || rows.ValueKind != JsonValueKind.Array ||
            rows.GetArrayLength() != 1)
            throw new EntraDiscoveryException("graph_organization_unverified");
        var item = rows[0];
        if (!item.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String ||
            !Guid.TryParse(id.GetString(), out var tenantId) || tenantId != loggedIn)
            throw new EntraDiscoveryException("tenant_mismatch");
        string name = GetSafeText(item, "displayName", 128, "Microsoft Entra tenant");
        string domain = "";
        if (item.TryGetProperty("verifiedDomains", out var verified) &&
            verified.ValueKind == JsonValueKind.Array)
        {
            foreach (var candidate in verified.EnumerateArray())
            {
                if (candidate.ValueKind != JsonValueKind.Object) continue;
                bool preferred = candidate.TryGetProperty("isDefault", out var isDefault) &&
                    isDefault.ValueKind == JsonValueKind.True;
                string candidateDomain = GetSafeText(candidate, "name", 253, "");
                if (candidateDomain.Length == 0) continue;
                if (domain.Length == 0) domain = candidateDomain;
                if (preferred) { domain = candidateDomain; break; }
            }
        }
        return [new EntraTenantEntry(tenantId, name, domain, "SignedIn")];
    }

    private static async Task<IReadOnlyList<EntraTenantEntry>> ListArmTenantsAsync(
        HttpClient http, string bearer, CancellationToken ct)
    {
        string? next = "https://management.azure.com/tenants?api-version=2022-12-01";
        var visited = new HashSet<string>(StringComparer.Ordinal);
        var byId = new Dictionary<Guid, EntraTenantEntry>();
        for (int page = 0; next is not null && page < 5; page++)
        {
            if (!IsExpectedArmUrl(next) || !visited.Add(next))
                throw new EntraDiscoveryException("unexpected_arm_pagination");
            using var doc = await ReadJsonAsync(http, next, bearer, ct).ConfigureAwait(false);
            var root = doc.RootElement;
            if (!root.TryGetProperty("value", out var values) ||
                values.ValueKind != JsonValueKind.Array ||
                values.GetArrayLength() > 100)
                throw new EntraDiscoveryException("invalid_arm_tenant_response");
            foreach (var item in values.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object ||
                    !item.TryGetProperty("tenantId", out var rawId) ||
                    rawId.ValueKind != JsonValueKind.String ||
                    !Guid.TryParse(rawId.GetString(), out var id) || id == Guid.Empty)
                    continue;
                byId.TryAdd(id, new EntraTenantEntry(id,
                    GetSafeText(item, "displayName", 128, "Microsoft Entra tenant"),
                    GetSafeText(item, "defaultDomain", 253, ""),
                    GetSafeText(item, "tenantCategory", 32, "")));
            }
            if (byId.Count > 100)
                throw new EntraDiscoveryException("too_many_tenants");
            next = root.TryGetProperty("nextLink", out var more) && more.ValueKind == JsonValueKind.String
                ? more.GetString() : null;
        }
        if (next is not null)
            throw new EntraDiscoveryException("too_many_tenant_pages");
        return byId.Values.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Id).ToArray();
    }

    internal static bool IsExpectedArmUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var parsed) &&
        parsed.Scheme == Uri.UriSchemeHttps &&
        parsed.Host.Equals("management.azure.com", StringComparison.OrdinalIgnoreCase) &&
        parsed.Port == 443 &&
        parsed.AbsolutePath.Equals("/tenants", StringComparison.Ordinal) &&
        parsed.Query.Contains("api-version=2022-12-01", StringComparison.Ordinal) &&
        parsed.UserInfo.Length == 0 &&
        parsed.Fragment.Length == 0;

    private static string GetSafeText(JsonElement item, string property, int max, string fallback)
    {
        if (!item.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.String)
            return fallback;
        string text = (value.GetString() ?? "").Trim();
        if (text.Length > max || text.Any(char.IsControl))
            throw new EntraDiscoveryException("invalid_tenant_metadata");
        return text.Length == 0 ? fallback : text;
    }

    public static bool SelfTest() =>
        IsExpectedArmUrl("https://management.azure.com/tenants?api-version=2022-12-01") &&
        !IsExpectedArmUrl("http://management.azure.com/tenants?api-version=2022-12-01") &&
        !IsExpectedArmUrl("https://management.azure.com.evil.test/tenants?api-version=2022-12-01") &&
        !IsExpectedArmUrl("https://management.azure.com.evil.test@evil.test/tenants?api-version=2022-12-01") &&
        !IsExpectedArmUrl("https://management.azure.com/other?api-version=2022-12-01");
}

public sealed record EntraTenantEntry(Guid Id, string Name, string Domain, string Category);

/// <summary>Allowlisted code only: no bearer tokens, user email or Entra challenge text.</summary>
public sealed class EntraDiscoveryException(string code) : Exception(code)
{
    public string Code { get; } = code;
}
