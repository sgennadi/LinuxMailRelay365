using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Identity.Client;

namespace Microsoft365Auth;

/// <summary>
/// Native delegated Graph app provisioning. Requires explicit UI confirmation
/// before entry. No Exchange Online commands, client secrets, Graph Mail.Send,
/// private-key export, app-wide SMTP grants or destructive rollbacks.
/// </summary>
public static class EntraGraphProvisioner
{
    private const int MaxResponseBytes = 256_000;
    private const int MaxRequestBytes = 160_000;
    private const string GraphRoot = "https://graph.microsoft.com/v1.0/";

    public static async Task<EntraProvisionResult> ProvisionAsync(
        Guid tenantId, Guid publicSignInClientId, Guid? reuseAppId,
        string applicationName, string certificateLabel, string publicCertificatePem,
        Func<DeviceCodeResult, Task> showDeviceCode, CancellationToken ct)
    {
        if (tenantId == Guid.Empty || publicSignInClientId == Guid.Empty ||
            reuseAppId == Guid.Empty || !IsSafeLabel(applicationName, 90) ||
            !IsSafeLabel(certificateLabel, 90))
            throw new EntraDiscoveryException("invalid_entra_provisioning_selection");
        ArgumentNullException.ThrowIfNull(showDeviceCode);
        using var cert = ParsePublicCertificate(publicCertificatePem);
        string certificateSha256 = Convert.ToHexString(SHA256.HashData(cert.RawData));
        string publicDer = Convert.ToBase64String(cert.RawData);
        var newKey = new PublicKeyEntry(null, "AsymmetricX509Cert", "Verify",
            certificateLabel, publicDer, cert.NotBefore.ToUniversalTime().ToString("o"),
            cert.NotAfter.ToUniversalTime().ToString("o"), null);

        string token = await EntraTenantDiscoveryClient.AcquireGraphWriteTokenAsync(
            tenantId, publicSignInClientId, showDeviceCode, ct).ConfigureAwait(false);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = MaxResponseBytes
        };
        Guid clientId;
        Guid applicationObjectId;
        string verifiedAppName;
        bool newApp = false;
        bool newCertificate = false;

        if (reuseAppId is { } exactApp)
        {
            var before = await GetAppAsync(http, token, exactApp, ct).ConfigureAwait(false);
            var existing = ReadPublicKeys(before);
            if (existing.Count > 32)
                throw new EntraDiscoveryException("too_many_existing_public_keys");
            clientId = exactApp;
            applicationObjectId = ReadGuid(before, "id");
            verifiedAppName = ReadLabel(before, "displayName", 90);
            bool alreadyPresent = existing.Any(k =>
                string.Equals(KeySha(k), certificateSha256, StringComparison.OrdinalIgnoreCase));
            if (!alreadyPresent)
            {
                // Re-read immediately before PATCH to avoid overwriting a known
                // changed certificate set. This is a drift guard, not a tenant-wide lock.
                var recent = await GetAppAsync(http, token, exactApp, ct).ConfigureAwait(false);
                var latest = ReadPublicKeys(recent);
                if (ReadGuid(recent, "id") != applicationObjectId ||
                    !SameKeySet(existing, latest))
                    throw new EntraDiscoveryException("app_credentials_changed_review_again");
                var combined = latest.Concat([newKey]).ToArray();
                await RequestAsync(http, token, HttpMethod.Patch,
                    "applications/" + applicationObjectId.ToString("D"),
                    new { keyCredentials = combined }, false, ct).ConfigureAwait(false);
                newCertificate = true;
                await VerifyKeySetAsync(http, token, clientId, combined, ct).ConfigureAwait(false);
            }
            else
            {
                await VerifyKeySetAsync(http, token, clientId, existing, ct)
                    .ConfigureAwait(false);
            }
        }
        else
        {
            using var created = await RequestAsync(http, token, HttpMethod.Post,
                "applications",
                new
                {
                    displayName = applicationName,
                    signInAudience = "AzureADMyOrg",
                    keyCredentials = new[] { newKey }
                }, false, ct).ConfigureAwait(false)
                ?? throw new EntraDiscoveryException("application_create_missing_body");
            clientId = ReadGuid(created.RootElement, "appId");
            applicationObjectId = ReadGuid(created.RootElement, "id");
            verifiedAppName = applicationName;
            newApp = true;
            newCertificate = true;
            // A newly-created certificate is not considered registered until
            // Graph returns the exact public-key thumbprint on single-app GET.
            await VerifyKeySetAsync(http, token, clientId, [newKey], ct)
                .ConfigureAwait(false);
        }

        var spPath = "servicePrincipals(appId='" + clientId.ToString("D") + "')" +
                     "?$select=id,appId";
        Guid enterpriseId;
        bool newSp = false;
        using (var existingSp = await RequestAsync(http, token, HttpMethod.Get,
                   spPath, null, true, ct).ConfigureAwait(false))
        {
            if (existingSp is not null)
            {
                if (ReadGuid(existingSp.RootElement, "appId") != clientId)
                    throw new EntraDiscoveryException("wrong_enterprise_app");
                enterpriseId = ReadGuid(existingSp.RootElement, "id");
            }
            else
            {
                using var createdSp = await RequestAsync(http, token, HttpMethod.Post,
                    "servicePrincipals", new { appId = clientId.ToString("D") },
                    false, ct).ConfigureAwait(false)
                    ?? throw new EntraDiscoveryException("service_principal_create_missing_body");
                if (ReadGuid(createdSp.RootElement, "appId") != clientId)
                    throw new EntraDiscoveryException("created_enterprise_app_mismatch");
                enterpriseId = ReadGuid(createdSp.RootElement, "id");
                newSp = true;
            }
        }

        // Exact postcheck: a created/reused SP must point to the chosen AppId.
        // A transient 404 after creation may be retried, never interpreted as
        // permission to create a second SP.
        bool verified = false;
        for (int attempt = 0; attempt < 4; attempt++)
        {
            using var check = await RequestAsync(http, token, HttpMethod.Get,
                spPath, null, true, ct).ConfigureAwait(false);
            if (check is not null)
            {
                if (ReadGuid(check.RootElement, "appId") != clientId ||
                    ReadGuid(check.RootElement, "id") != enterpriseId)
                    throw new EntraDiscoveryException("enterprise_app_postcheck_mismatch");
                verified = true;
                break;
            }
            if (attempt < 3) await Task.Delay(900, ct).ConfigureAwait(false);
        }
        if (!verified)
            throw new EntraDiscoveryException("enterprise_app_not_yet_visible");
        return new EntraProvisionResult(tenantId, clientId, applicationObjectId,
            enterpriseId, verifiedAppName, certificateSha256,
            cert.NotAfter.ToUniversalTime(), newApp, newSp, newCertificate);
    }

    private static X509Certificate2 ParsePublicCertificate(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem) || pem.Length > 48_000 ||
            pem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new EntraDiscoveryException("public_certificate_only");
        try
        {
            var certificate = X509Certificate2.CreateFromPem(pem);
            if (certificate.HasPrivateKey ||
                certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow.AddDays(3) ||
                certificate.NotAfter.ToUniversalTime() >
                    certificate.NotBefore.ToUniversalTime().AddDays(366) ||
                certificate.RawData.Length is < 500 or > 32_768)
            {
                certificate.Dispose();
                throw new EntraDiscoveryException("unsafe_public_certificate_validity");
            }
            using var rsa = certificate.GetRSAPublicKey();
            if (rsa is null || rsa.KeySize < 2048)
            {
                certificate.Dispose();
                throw new EntraDiscoveryException("rsa_public_certificate_required");
            }
            return certificate;
        }
        catch (CryptographicException)
        {
            throw new EntraDiscoveryException("invalid_public_x509_certificate");
        }
    }

    private static async Task<JsonElement> GetAppAsync(
        HttpClient http, string token, Guid appId, CancellationToken ct)
    {
        string path = "applications(appId='" + appId.ToString("D") + "')" +
                      "?$select=id,appId,displayName,keyCredentials";
        using var doc = await RequestAsync(http, token, HttpMethod.Get,
            path, null, false, ct).ConfigureAwait(false)
            ?? throw new EntraDiscoveryException("app_registration_not_found");
        if (ReadGuid(doc.RootElement, "appId") != appId)
            throw new EntraDiscoveryException("wrong_entra_app_id");
        return doc.RootElement.Clone();
    }

    private static List<PublicKeyEntry> ReadPublicKeys(JsonElement app)
    {
        if (!app.TryGetProperty("keyCredentials", out var keys) ||
            keys.ValueKind != JsonValueKind.Array || keys.GetArrayLength() > 32)
            throw new EntraDiscoveryException("existing_key_material_incomplete");
        var all = new List<PublicKeyEntry>();
        foreach (var entry in keys.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
                throw new EntraDiscoveryException("invalid_existing_key_entry");
            string type = ReadLabel(entry, "type", 32);
            string usage = ReadLabel(entry, "usage", 32);
            string key = ReadLabel(entry, "key", 48000);
            string keyId = ReadLabel(entry, "keyId", 36);
            string name = ReadLabel(entry, "displayName", 128);
            string from = ReadLabel(entry, "startDateTime", 64);
            string until = ReadLabel(entry, "endDateTime", 64);
            string? custom = null;
            if (entry.TryGetProperty("customKeyIdentifier", out var identifier))
            {
                if (identifier.ValueKind == JsonValueKind.String)
                {
                    custom = ReadLabel(entry, "customKeyIdentifier", 256);
                    try { _ = Convert.FromBase64String(custom); }
                    catch (FormatException)
                    {
                        throw new EntraDiscoveryException("invalid_existing_custom_key_identifier");
                    }
                }
                else if (identifier.ValueKind != JsonValueKind.Null)
                    throw new EntraDiscoveryException("invalid_existing_custom_key_identifier");
            }
            if (type != "AsymmetricX509Cert" || usage != "Verify" ||
                !Guid.TryParse(keyId, out _) || key.Length < 500 ||
                from.Length == 0 || until.Length == 0)
                throw new EntraDiscoveryException("existing_public_key_bytes_missing");
            // Ensure existing keys are actual parseable X.509 public certificates
            // before a PATCH could ever replace this entire collection.
            try
            {
                var bytes = Convert.FromBase64String(key);
                using var existingCert = X509CertificateLoader.LoadCertificate(bytes);
                if (existingCert.HasPrivateKey)
                    throw new EntraDiscoveryException("private_key_in_existing_graph_credential");
            }
            catch (FormatException)
            {
                throw new EntraDiscoveryException("invalid_existing_public_key");
            }
            catch (CryptographicException)
            {
                throw new EntraDiscoveryException("invalid_existing_public_key");
            }
            all.Add(new PublicKeyEntry(keyId, type, usage, name, key, from, until, custom));
        }
        if (all.Select(k => k.KeyId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != all.Count)
            throw new EntraDiscoveryException("duplicate_graph_key_identifiers");
        return all;
    }

    private static string KeySha(PublicKeyEntry key) =>
        Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(key.Key)));

    // Compare every credential attribute, not merely the public-key digest.
    // This detects concurrent changes to validity, labels or custom IDs
    // before a replacement-style Graph PATCH.
    private static bool SameKeySet(IEnumerable<PublicKeyEntry> first, IEnumerable<PublicKeyEntry> second) =>
        first.Select(k => JsonSerializer.Serialize(k)).Order(StringComparer.Ordinal)
            .SequenceEqual(second.Select(k => JsonSerializer.Serialize(k)).Order(StringComparer.Ordinal));

    private static async Task VerifyKeySetAsync(
        HttpClient http, string token, Guid appId, IReadOnlyList<PublicKeyEntry> expected,
        CancellationToken ct)
    {
        var actualApp = await GetAppAsync(http, token, appId, ct).ConfigureAwait(false);
        var actual = ReadPublicKeys(actualApp);
        if (actual.Count != expected.Count ||
            !actual.Select(KeySha).Order(StringComparer.Ordinal)
                   .SequenceEqual(expected.Select(KeySha).Order(StringComparer.Ordinal)))
            throw new EntraDiscoveryException("certificate_postcheck_failed_review_entra");
        // Old keys must retain exact metadata including custom identifier.
        foreach (var preserved in expected.Where(k => k.KeyId is not null))
        {
            var matching = actual.Where(k =>
                string.Equals(k.KeyId, preserved.KeyId, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matching.Length != 1 || !SameKeySet([preserved], matching))
                throw new EntraDiscoveryException("existing_certificate_metadata_changed_review_entra");
        }
    }

    private static async Task<JsonDocument?> RequestAsync(
        HttpClient http, string token, HttpMethod method, string path,
        object? data, bool allowNotFound, CancellationToken ct)
    {
        // All Graph paths are built from fixed segments and prevalidated GUIDs.
        if (path.Contains("://", StringComparison.Ordinal) || path.Contains("..", StringComparison.Ordinal))
            throw new EntraDiscoveryException("unexpected_graph_path");
        using var request = new HttpRequestMessage(method, GraphRoot + path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (data is not null)
        {
            string serialized = JsonSerializer.Serialize(data, new JsonSerializerOptions
            {
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            });
            if (Encoding.UTF8.GetByteCount(serialized) > MaxRequestBytes)
                throw new EntraDiscoveryException("graph_request_too_large");
            request.Content = new StringContent(serialized, Encoding.UTF8, "application/json");
        }
        try
        {
            using var response = await http.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (allowNotFound && response.StatusCode == HttpStatusCode.NotFound)
                return null;
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new EntraDiscoveryException("graph_application_write_denied");
            if (response.StatusCode == HttpStatusCode.NotFound)
                throw new EntraDiscoveryException("graph_exact_object_not_found");
            if (!response.IsSuccessStatusCode)
                throw new EntraDiscoveryException("graph_write_or_read_http_failed");
            if (response.StatusCode == HttpStatusCode.NoContent)
                return null;
            if (response.Content.Headers.ContentLength > MaxResponseBytes)
                throw new EntraDiscoveryException("graph_response_too_large");
            await response.Content.LoadIntoBufferAsync(MaxResponseBytes, ct).ConfigureAwait(false);
            return JsonDocument.Parse(
                await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false),
                new JsonDocumentOptions { MaxDepth = 20 });
        }
        catch (HttpRequestException)
        {
            throw new EntraDiscoveryException("graph_https_connection_failed");
        }
        catch (JsonException)
        {
            throw new EntraDiscoveryException("graph_json_response_invalid");
        }
    }

    private static Guid ReadGuid(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            !Guid.TryParse(value.GetString(), out var guid) || guid == Guid.Empty)
            throw new EntraDiscoveryException("graph_object_guid_unverified");
        return guid;
    }

    private static string ReadLabel(JsonElement obj, string name, int maximum)
    {
        if (!obj.TryGetProperty(name, out var field) || field.ValueKind != JsonValueKind.String)
            return "";
        string value = field.GetString() ?? "";
        if (value.Length > maximum || value.Any(char.IsControl))
            throw new EntraDiscoveryException("graph_object_unexpected_text");
        return value;
    }

    private static bool IsSafeLabel(string name, int length) =>
        name.Length is >= 3 &&
        name.Length <= length &&
        !name.Any(char.IsControl);

    private sealed record PublicKeyEntry(
        [property: System.Text.Json.Serialization.JsonPropertyName("keyId")]
        string? KeyId,
        [property: System.Text.Json.Serialization.JsonPropertyName("type")]
        string Type,
        [property: System.Text.Json.Serialization.JsonPropertyName("usage")]
        string Usage,
        [property: System.Text.Json.Serialization.JsonPropertyName("displayName")]
        string DisplayName,
        [property: System.Text.Json.Serialization.JsonPropertyName("key")]
        string Key,
        [property: System.Text.Json.Serialization.JsonPropertyName("startDateTime")]
        string StartDateTime,
        [property: System.Text.Json.Serialization.JsonPropertyName("endDateTime")]
        string EndDateTime,
        [property: System.Text.Json.Serialization.JsonPropertyName("customKeyIdentifier")]
        string? CustomKeyIdentifier);

    public static bool SelfTest() =>
        IsSafeLabel("Linux Mail Relay 365", 90) &&
        !IsSafeLabel("X", 90) &&
        !IsSafeLabel("app\nsecret", 90) &&
        !SameKeySet(
            [new PublicKeyEntry("1", "AsymmetricX509Cert", "Verify", "A",
                Convert.ToBase64String([1,2,3]), "2026", "2027", "AA==")],
            [new PublicKeyEntry("1", "AsymmetricX509Cert", "Verify", "A",
                Convert.ToBase64String([4,5,6]), "2026", "2027", "AA==")]);
}

public sealed record EntraProvisionResult(
    Guid TenantId,
    Guid ClientId,
    Guid ApplicationObjectId,
    Guid EnterpriseApplicationObjectId,
    string DisplayName,
    string CertificateSha256,
    DateTime CertificateExpiresUtc,
    bool AppCreated,
    bool EnterpriseAppCreated,
    bool PublicCertificateAdded);
