using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Identity.Client;

namespace Microsoft365Auth;

/// <summary>
/// Exact-tenant, read-only Graph capability probe. Equivalent to the legacy
/// Test-LinuxMailRelay365Security.ps1 without launching PowerShell or storing
/// tokens, sign-in logs, usernames, licensing details, or Graph responses.
/// </summary>
public static class EntraGraphSecurityReadClient
{
    private const int ResponseLimit = 256_000;
    private const string GraphBase = "https://graph.microsoft.com/v1.0/";

    public static async Task<EntraSecurityReadResult> InspectAsync(
        Guid tenantId, Guid approvedPublicClientId,
        Func<DeviceCodeResult, Task> deviceCode, CancellationToken cancellation)
    {
        if (tenantId == Guid.Empty || approvedPublicClientId == Guid.Empty)
            throw new EntraDiscoveryException("invalid_graph_security_tenant_or_client");
        string token = await EntraTenantDiscoveryClient.AcquireGraphSecurityReadTokenAsync(
            tenantId, approvedPublicClientId, deviceCode, cancellation).ConfigureAwait(false);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(25),
            MaxResponseContentBufferSize = ResponseLimit
        };
        string ca = await CanReadArrayAsync(http, token,
            "identity/conditionalAccess/policies?$top=1", cancellation).ConfigureAwait(false)
            ? "accessible" : "not_accessible_or_insufficient_rights";
        string log = await CanReadArrayAsync(http, token,
            "auditLogs/signIns?$top=1", cancellation).ConfigureAwait(false)
            ? "accessible" : "not_accessible_or_insufficient_rights";
        string license = await CanReadArrayAsync(http, token,
            "subscribedSkus?$select=skuPartNumber,capabilityStatus", cancellation).ConfigureAwait(false)
            ? "manual_license_verification_required" : "not_verified";
        return new EntraSecurityReadResult(tenantId, ca, log, license,
            "not_checked", ChangesApplied: false);
    }

    private static async Task<bool> CanReadArrayAsync(
        HttpClient http, string token, string fixedPath, CancellationToken ct)
    {
        // No user-supplied URI, no redirects, and no returned tenant records.
        if (!AllowedPath(fixedPath))
            throw new EntraDiscoveryException("unapproved_security_graph_path");
        using var request = new HttpRequestMessage(HttpMethod.Get, GraphBase + fixedPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        try
        {
            using var response = await http.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode ||
                response.Content.Headers.ContentLength > ResponseLimit) return false;
            await response.Content.LoadIntoBufferAsync(ResponseLimit, ct).ConfigureAwait(false);
            using var parsed = JsonDocument.Parse(
                await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false),
                new JsonDocumentOptions { MaxDepth = 15 });
            return parsed.RootElement.ValueKind == JsonValueKind.Object &&
                   parsed.RootElement.TryGetProperty("value", out var values) &&
                   values.ValueKind == JsonValueKind.Array;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return false; }
        catch (HttpRequestException) { return false; }
        catch (IOException) { return false; }
        catch (JsonException) { return false; }
    }

    private static bool AllowedPath(string path) =>
        path is "identity/conditionalAccess/policies?$top=1" or
                "auditLogs/signIns?$top=1" or
                "subscribedSkus?$select=skuPartNumber,capabilityStatus";

    public static bool SelfTest() =>
        AllowedPath("identity/conditionalAccess/policies?$top=1") &&
        AllowedPath("auditLogs/signIns?$top=1") &&
        AllowedPath("subscribedSkus?$select=skuPartNumber,capabilityStatus") &&
        !AllowedPath("https://evil.test/") &&
        !AllowedPath("identity/conditionalAccess/policies?$top=9999") &&
        !AllowedPath("subscribedSkus?update=true") &&
        !new EntraSecurityReadResult(Guid.NewGuid(), "not_verified", "not_verified",
            "not_verified", "not_checked", false).ChangesApplied;
}

public sealed record EntraSecurityReadResult(
    Guid TenantId, string ConditionalAccessPolicyRead, string SignInLogRead,
    string WorkloadIdPremium, string IpPolicyConfigured, bool ChangesApplied);
