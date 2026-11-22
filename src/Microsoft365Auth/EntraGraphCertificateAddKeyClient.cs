using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Identity.Client;

namespace Microsoft365Auth;

/// <summary>
/// Native C# Microsoft Graph addKey workflow for pre-staged Linux OAuth
/// public certificates. It does not create/delete applications, PATCH any
/// credentials, export Linux private keys, or send mail. The PS1 implementation
/// remains available as an explicit operator-selected compatibility path.
/// </summary>
public static class EntraGraphCertificateAddKeyClient
{
    private const int MaxResponseBytes = 256_000;
    private const int MaxRequestBytes = 45_000;
    private const string GraphRoot = "https://graph.microsoft.com/v1.0/";
    private const string ProofAudience = "00000002-0000-0000-c000-000000000000";
    private static readonly Regex Hash = new(@"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex JwtShape = new(@"\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z", RegexOptions.CultureInvariant);
    private const string ReportPrefix =
        "ENTRA_CERT_VERSION=1\nENTRA_CERT_TENANT=exact_match\nENTRA_CERT_APP=exact_client_id\n";

    public static async Task<string> PreviewAsync(
        EntraCertificateEvidence evidence, Guid signInClientId,
        Func<DeviceCodeResult, Task> deviceCode, CancellationToken cancellation)
    {
        using var oldCert = ParseAndValidate(evidence, out var newCert);
        using (newCert)
        {
            string token = await EntraTenantDiscoveryClient.AcquireGraphReadTokenAsync(
                evidence.TenantId, signInClientId, deviceCode, cancellation).ConfigureAwait(false);
            using var http = CreateHttpClient();
            var (objectId, keys) = await GetApplicationAsync(
                http, token, evidence.ClientId, cancellation).ConfigureAwait(false);
            var plan = MakePlan(evidence, objectId, keys, oldCert, newCert);
            return Report(plan, added: false);
        }
    }

    // Sign in BEFORE the existing Linux host signs the short-lived proof JWT.
    // No Graph mutation and no JWT file is created at this step.
    public static async Task PrepareWriteSignInAsync(Guid tenantId, Guid signInClientId,
        Func<DeviceCodeResult, Task> deviceCode, CancellationToken cancellation)
    {
        _ = await EntraTenantDiscoveryClient.AcquireGraphWriteTokenAsync(
            tenantId, signInClientId, deviceCode, cancellation).ConfigureAwait(false);
    }

    public static async Task<string> AddAsync(
        EntraCertificateEvidence evidence, Guid signInClientId, string expectedPlanSha256,
        string ephemeralProof, Func<DeviceCodeResult, Task> deviceCode,
        CancellationToken cancellation)
    {
        if (!Hash.IsMatch(expectedPlanSha256))
            throw new EntraDiscoveryException("reviewed_entra_certificate_sha_required");
        using var oldCert = ParseAndValidate(evidence, out var newCert);
        using (newCert)
        {
            // This token is kept in memory by MSAL; never handed to PowerShell.
            string token = await EntraTenantDiscoveryClient.AcquireGraphWriteTokenAsync(
                evidence.TenantId, signInClientId, deviceCode, cancellation).ConfigureAwait(false);
            using var http = CreateHttpClient();
            var (objectId, keys) = await GetApplicationAsync(
                http, token, evidence.ClientId, cancellation).ConfigureAwait(false);
            var plan = MakePlan(evidence, objectId, keys, oldCert, newCert);
            if (!string.Equals(plan.Hash, expectedPlanSha256, StringComparison.Ordinal))
                throw new EntraDiscoveryException("graph_inventory_changed_since_preview");
            VerifyProof(ephemeralProof, objectId, oldCert);

            // addKey appends one public key. Unlike PATCH, it cannot silently
            // replace an omitted key. Never use removeKey or overwrite keys.
            var credential = new
            {
                type = "AsymmetricX509Cert",
                usage = "Verify",
                key = Convert.ToBase64String(newCert.RawData),
                displayName = "LinuxMailRelay365 Hardware OAuth",
                startDateTime = newCert.NotBefore.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                endDateTime = newCert.NotAfter.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)
            };
            var body = new { keyCredential = credential, passwordCredential = (object?)null, proof = ephemeralProof };
            // From this point onward, ANY failure is possibly post-mutation.
            try
            {
                using var addKeyResult = await RequestAsync(http, token, HttpMethod.Post,
                    "applications/" + objectId.ToString("D") + "/addKey", body, cancellation)
                    .ConfigureAwait(false);
                var (verifiedObject, updated) = await GetApplicationAsync(
                    http, token, evidence.ClientId, cancellation).ConfigureAwait(false);
                if (verifiedObject != objectId || updated.Count != keys.Count + 1 ||
                    !keys.All(k => updated.Count(x => x.Id == k.Id && x == k) == 1) ||
                    updated.Count(x => x.Thumbprint == plan.NewThumb &&
                        x.Type == "AsymmetricX509Cert" && x.Usage == "Verify") != 1)
                    throw new EntraDiscoveryException("graph_addkey_postcheck_manual_review_required");
            }
            catch (OperationCanceledException)
            {
                // Cancellation during POST or read-back cannot disprove a
                // completed addKey. Surface possible partial success.
                throw new EntraDiscoveryException("graph_addkey_may_have_succeeded_verify_manually");
            }
            catch (EntraDiscoveryException) { throw new EntraDiscoveryException("graph_addkey_may_have_succeeded_verify_manually"); }
            catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException or
                                      InvalidOperationException or TaskCanceledException)
            {
                throw new EntraDiscoveryException("graph_addkey_may_have_succeeded_verify_manually");
            }
            return Report(plan, added: true);
        }
    }

    private static HttpClient CreateHttpClient() =>
        new(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(25),
            MaxResponseContentBufferSize = MaxResponseBytes
        };

    private static X509Certificate2 ParseAndValidate(EntraCertificateEvidence evidence, out X509Certificate2 newCert)
    {
        newCert = null!;
        if (evidence.TenantId == Guid.Empty || evidence.ClientId == Guid.Empty ||
            !new[] { evidence.ActiveSha, evidence.StageSha, evidence.ActiveCertSha, evidence.CandidateCertSha }
                .All(x => x is not null && Hash.IsMatch(x)))
            throw new EntraDiscoveryException("invalid_linux_certificate_evidence");
        var active = LoadPublic(evidence.ActiveDer, evidence.ActiveCertSha);
        try
        {
            newCert = LoadPublic(evidence.CandidateDer, evidence.CandidateCertSha);
            var now = DateTimeOffset.UtcNow;
            if (active.NotBefore.ToUniversalTime() > now ||
                active.NotAfter.ToUniversalTime() <= now.AddMinutes(10))
                throw new EntraDiscoveryException("active_certificate_expired");
            if (newCert.NotBefore.ToUniversalTime() > now.AddMinutes(5) ||
                newCert.NotAfter.ToUniversalTime() <= now.AddDays(1) ||
                newCert.NotAfter.ToUniversalTime() >
                    newCert.NotBefore.ToUniversalTime().AddDays(366) ||
                string.Equals(active.Thumbprint, newCert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                throw new EntraDiscoveryException("invalid_candidate_certificate");
            return active;
        }
        catch
        {
            newCert?.Dispose();
            active.Dispose();
            throw;
        }
    }

    private static X509Certificate2 LoadPublic(string value, string digest)
    {
        if (value.Length is < 350 or > 32768)
            throw new EntraDiscoveryException("invalid_public_certificate_base64");
        byte[] raw;
        try { raw = Convert.FromBase64String(value); }
        catch (FormatException) { throw new EntraDiscoveryException("invalid_public_certificate_base64"); }
        if (raw.Length is < 250 or > 24576 ||
            !Convert.ToHexString(SHA256.HashData(raw)).Equals(digest, StringComparison.OrdinalIgnoreCase))
            throw new EntraDiscoveryException("public_certificate_sha_mismatch");
        try
        {
            var cert = X509CertificateLoader.LoadCertificate(raw);
            using var rsa = cert.GetRSAPublicKey();
            if (cert.HasPrivateKey || rsa is null || rsa.KeySize < 2048)
            {
                cert.Dispose();
                throw new EntraDiscoveryException("rsa_public_certificate_required");
            }
            return cert;
        }
        catch (CryptographicException)
        {
            throw new EntraDiscoveryException("invalid_public_x509_certificate");
        }
    }

    private static async Task<(Guid Id, List<GraphKey> Keys)> GetApplicationAsync(
        HttpClient http, string token, Guid exactClientId, CancellationToken ct)
    {
        string path = "applications(appId='" + exactClientId.ToString("D") + "')" +
                      "?$select=id,appId,keyCredentials";
        using var document = await RequestAsync(http, token, HttpMethod.Get, path, null, ct)
            .ConfigureAwait(false);
        var app = document.RootElement;
        if (!Guid.TryParse(GetText(app, "appId"), out var clientId) || clientId != exactClientId ||
            !Guid.TryParse(GetText(app, "id"), out var objectId) || objectId == Guid.Empty)
            throw new EntraDiscoveryException("graph_wrong_app");
        if (!app.TryGetProperty("keyCredentials", out var raw) ||
            raw.ValueKind != JsonValueKind.Array || raw.GetArrayLength() > 40)
            throw new EntraDiscoveryException("graph_key_inventory_incomplete");
        var rows = new List<GraphKey>();
        var ids = new HashSet<Guid>();
        foreach (var key in raw.EnumerateArray())
        {
            if (key.ValueKind != JsonValueKind.Object ||
                !Guid.TryParse(GetText(key, "keyId"), out var keyId) ||
                keyId == Guid.Empty || !ids.Add(keyId))
                throw new EntraDiscoveryException("invalid_graph_key_id");
            var thumbBytes = ParseBase64(GetText(key, "customKeyIdentifier"));
            if (thumbBytes.Length != 20 ||
                !DateTimeOffset.TryParse(GetText(key, "startDateTime"), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var start) ||
                !DateTimeOffset.TryParse(GetText(key, "endDateTime"), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var end))
                throw new EntraDiscoveryException("invalid_graph_key_metadata");
            string type = GetText(key, "type");
            string usage = GetText(key, "usage");
            if (type.Length > 64 || usage.Length > 64)
                throw new EntraDiscoveryException("invalid_graph_key_metadata");
            rows.Add(new GraphKey(keyId, type, usage,
                Convert.ToHexString(thumbBytes).ToLowerInvariant(),
                start.ToUniversalTime(), end.ToUniversalTime()));
        }
        return (objectId, rows.OrderBy(x => x.Id).ToList());
    }

    private static CertificatePlan MakePlan(EntraCertificateEvidence evidence,
        Guid objectId, IReadOnlyList<GraphKey> keys,
        X509Certificate2 oldCert, X509Certificate2 newCert)
    {
        string oldThumb = oldCert.Thumbprint.ToLowerInvariant();
        string newThumb = newCert.Thumbprint.ToLowerInvariant();
        var now = DateTimeOffset.UtcNow;
        if (keys.Count == 0 ||
            !keys.Any(x => x.Thumbprint == oldThumb && x.Type == "AsymmetricX509Cert" &&
                           x.Usage == "Verify" && x.Start <= now && x.End > now.AddMinutes(10)))
            throw new EntraDiscoveryException("current_certificate_not_valid_in_entra");
        if (keys.Any(x => x.Thumbprint == newThumb))
            throw new EntraDiscoveryException("new_certificate_already_registered");
        var basis = new List<string>
        {
            "lmr365-entra-cert/v1",
            evidence.TenantId.ToString("D"), evidence.ClientId.ToString("D"),
            objectId.ToString("D"), evidence.ActiveSha, evidence.StageSha,
            evidence.ActiveCertSha, evidence.CandidateCertSha, oldThumb, newThumb
        };
        basis.AddRange(keys.Select(k =>
            k.Id.ToString("D") + "|" + k.Type + "|" + k.Usage + "|" + k.Thumbprint + "|" +
            k.Start.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture) + "|" +
            k.End.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture))
            .OrderBy(x => x, StringComparer.Ordinal));
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", basis)));
        return new CertificatePlan(objectId, Convert.ToHexString(digest).ToLowerInvariant(), newThumb);
    }

    private static string Report(CertificatePlan plan, bool added) =>
        ReportPrefix + "ENTRA_CERT_OBJECT_ID=" + plan.ObjectId.ToString("D") + "\n" +
        "ENTRA_CERT_PLAN_SHA256=" + plan.Hash + "\n" +
        "ENTRA_CERT_ACTIVE_KEY=valid\nENTRA_CERT_CANDIDATE=not_registered\n" +
        "ENTRA_CERT_EXISTING_KEYS_PRESERVED=yes\n" +
        "ENTRA_CERT_PRIVATE_KEY_EXPORTED=no\nENTRA_CERT_DELETE_EXISTING_KEYS=no\n" +
        "ENTRA_CERT_ADDED=" + (added ? "yes" : "no") + "\n" +
        "CHANGES_APPLIED=" + (added ? "entra_addkey_only" : "no") + "\n";

    private static async Task<JsonDocument> RequestAsync(
        HttpClient http, string token, HttpMethod method, string relative,
        object? body, CancellationToken ct)
    {
        if (relative.Contains("://", StringComparison.Ordinal) ||
            relative.Contains("..", StringComparison.Ordinal))
            throw new EntraDiscoveryException("invalid_graph_path");
        using var request = new HttpRequestMessage(method, GraphRoot + relative);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (body is not null)
        {
            string encoded = JsonSerializer.Serialize(body);
            if (Encoding.UTF8.GetByteCount(encoded) > MaxRequestBytes)
                throw new EntraDiscoveryException("graph_addkey_request_too_large");
            request.Content = new StringContent(encoded, Encoding.UTF8, "application/json");
        }
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new EntraDiscoveryException("graph_delegated_permission_denied");
            if (response.StatusCode == HttpStatusCode.NotFound)
                throw new EntraDiscoveryException("graph_exact_app_not_found");
            if (!response.IsSuccessStatusCode)
                throw new EntraDiscoveryException("graph_request_failed");
            if (response.Content.Headers.ContentLength > MaxResponseBytes)
                throw new EntraDiscoveryException("graph_response_too_large");
            await response.Content.LoadIntoBufferAsync(MaxResponseBytes, ct).ConfigureAwait(false);
            byte[] data = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            // addKey returns JSON, never need it; do not store the response.
            if (method == HttpMethod.Post) return JsonDocument.Parse("{}");
            return JsonDocument.Parse(data, new JsonDocumentOptions { MaxDepth = 20 });
        }
        catch (HttpRequestException) { throw new EntraDiscoveryException("graph_connection_failed"); }
        catch (JsonException) { throw new EntraDiscoveryException("graph_response_invalid"); }
    }

    private static void VerifyProof(string proof, Guid appObjectId, X509Certificate2 active)
    {
        if (proof.Length is < 300 or > 12000 || !JwtShape.IsMatch(proof))
            throw new EntraDiscoveryException("invalid_graph_proof");
        string[] chunks = proof.Split('.');
        try
        {
            using var header = JsonDocument.Parse(FromUrl64(chunks[0]), new JsonDocumentOptions { MaxDepth = 5 });
            using var body = JsonDocument.Parse(FromUrl64(chunks[1]), new JsonDocumentOptions { MaxDepth = 5 });
            if (GetText(header.RootElement, "alg") != "RS256" ||
                GetText(header.RootElement, "typ") != "JWT" ||
                GetText(body.RootElement, "aud") != ProofAudience ||
                GetText(body.RootElement, "iss") != appObjectId.ToString("D"))
                throw new EntraDiscoveryException("graph_proof_claims_invalid");
            byte[] thumb = FromUrl64(GetText(header.RootElement, "x5t"));
            if (thumb.Length != 20 ||
                !CryptographicOperations.FixedTimeEquals(thumb, SHA1.HashData(active.RawData)))
                throw new EntraDiscoveryException("graph_proof_wrong_active_key");
            var claims = body.RootElement;
            if (!claims.TryGetProperty("nbf", out var nbfRaw) || !nbfRaw.TryGetInt64(out var nbf) ||
                !claims.TryGetProperty("exp", out var expRaw) || !expRaw.TryGetInt64(out var exp))
                throw new EntraDiscoveryException("graph_proof_time_missing");
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (exp - nbf != 600 || nbf > now || exp <= now)
                throw new EntraDiscoveryException("graph_proof_expired");
            byte[] signature = FromUrl64(chunks[2]);
            using var rsa = active.GetRSAPublicKey();
            if (rsa is null || !rsa.VerifyData(
                    Encoding.ASCII.GetBytes(chunks[0] + "." + chunks[1]), signature,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                throw new EntraDiscoveryException("graph_proof_signature_invalid");
        }
        catch (EntraDiscoveryException) { throw; }
        catch (Exception ex) when (ex is JsonException or FormatException or CryptographicException or
                                   InvalidOperationException or ArgumentException)
        {
            throw new EntraDiscoveryException("invalid_graph_proof");
        }
    }

    private static byte[] FromUrl64(string input)
    {
        if (input.Length is < 1 or > 12_000 || input.Any(x =>
            !(char.IsAsciiLetterOrDigit(x) || x is '-' or '_')))
            throw new EntraDiscoveryException("invalid_base64url");
        string s = input.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }

    private static byte[] ParseBase64(string input)
    {
        if (input.Length is < 4 or > 1000)
            throw new EntraDiscoveryException("invalid_graph_base64");
        try { return Convert.FromBase64String(input); }
        catch (FormatException) { throw new EntraDiscoveryException("invalid_graph_base64"); }
    }

    private static string GetText(JsonElement obj, string key)
    {
        if (obj.ValueKind != JsonValueKind.Object ||
            !obj.TryGetProperty(key, out var value) || value.ValueKind != JsonValueKind.String)
            throw new EntraDiscoveryException("graph_required_field_missing");
        string text = value.GetString() ?? "";
        if (text.Length > 1000 || text.Any(char.IsControl))
            throw new EntraDiscoveryException("graph_invalid_text_field");
        return text;
    }

    public static bool SelfTest()
    {
        try
        {
            if (Report(new CertificatePlan(Guid.Parse("11111111-1111-4111-8111-111111111111"),
                new string('a', 64), new string('b', 40)), false).Contains("CHANGES_APPLIED=entra_addkey_only",
                    StringComparison.Ordinal)) return false;
            if (Report(new CertificatePlan(Guid.Parse("11111111-1111-4111-8111-111111111111"),
                new string('a', 64), new string('b', 40)), true).Contains("CHANGES_APPLIED=no\n",
                    StringComparison.Ordinal)) return false;
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=LinuxMailRelay365-selftest", key,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(14));
            var id = Guid.Parse("11111111-1111-4111-8111-111111111111");
            long nbf = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 3;
            static string B64(byte[] x) => Convert.ToBase64String(x).TrimEnd('=').Replace('+','-').Replace('/','_');
            string header = B64(JsonSerializer.SerializeToUtf8Bytes(new
            {
                alg = "RS256", typ = "JWT", x5t = B64(SHA1.HashData(cert.RawData))
            }));
            string payload = B64(JsonSerializer.SerializeToUtf8Bytes(new
            {
                aud = ProofAudience, iss = id.ToString("D"), nbf, exp = nbf + 600
            }));
            string signing = header + "." + payload;
            string proof = signing + "." + B64(key.SignData(Encoding.ASCII.GetBytes(signing),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            VerifyProof(proof, id, cert);
            try
            {
                VerifyProof(proof, Guid.NewGuid(), cert);
                return false;
            }
            catch (EntraDiscoveryException) { }
            try
            {
                VerifyProof(proof + "x", id, cert);
                return false;
            }
            catch (EntraDiscoveryException) { }
            return true;
        }
        catch { return false; }
    }

    private sealed record GraphKey(Guid Id, string Type, string Usage, string Thumbprint,
                                   DateTimeOffset Start, DateTimeOffset End);
    private sealed record CertificatePlan(Guid ObjectId, string Hash, string NewThumb);
}

public sealed record EntraCertificateEvidence(
    Guid TenantId, Guid ClientId,
    string ActiveSha, string StageSha,
    string ActiveCertSha, string CandidateCertSha,
    string ActiveDer, string CandidateDer);
