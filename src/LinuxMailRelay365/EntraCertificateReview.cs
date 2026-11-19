using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Public DER certificate only. Never hold/export PEM, TPM blobs, HSM PIN,
// Graph access tokens or mail content. Proof JWT is short-lived and must
// NEVER be included in a diagnostic report, log, exception or command line.
internal sealed record EntraCertificateReview(
    Guid TenantId, Guid ClientId,
    string ActiveSha, string StagedSha,
    string ActiveCertificateSha, string CandidateCertificateSha,
    string ActiveDerBase64, string CandidateDerBase64)
{
    private static readonly Regex Hash = new(@"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant);

    private static Dictionary<string, string> Lines(string raw)
    {
        if (raw.Length > 90_000 || raw.Contains('\0'))
            throw new InvalidDataException("Unsafe Entra public certificate inventory.");
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in raw.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.TrimEnd('\r');
            var pos = trimmed.IndexOf('=');
            if (pos < 1 || !trimmed.StartsWith("ENTRA_OAUTH_", StringComparison.Ordinal))
                throw new InvalidDataException("Malformed Entra certificate inventory.");
            if (!map.TryAdd(trimmed[..pos], trimmed[(pos + 1)..]))
                throw new InvalidDataException("Duplicate Entra public certificate inventory entry.");
        }
        return map;
    }

    private static string Get(Dictionary<string, string> map, string key)
    {
        if (!map.TryGetValue("ENTRA_OAUTH_" + key, out var value) || string.IsNullOrEmpty(value))
            throw new InvalidDataException("Incomplete Entra certificate inventory (" + key + ").");
        return value;
    }

    internal static EntraCertificateReview Parse(string raw)
    {
        var map = Lines(raw);
        if (Get(map, "VERSION") != "1" ||
            Get(map, "PRIVATE_KEY_EXPORTED") != "no" ||
            Get(map, "ACTIVE_OAUTH_CHANGED") != "no" ||
            Get(map, "ENTRA_CONTACTED") != "no" ||
            Get(map, "ROUTING_IDENTITY_UNCHANGED") != "yes")
            throw new InvalidDataException("Linux certificate inventory did not prove a read-only operation.");
        if (!Guid.TryParse(Get(map, "TENANT_ID"), out var tenant) || tenant == Guid.Empty ||
            !Guid.TryParse(Get(map, "CLIENT_ID"), out var client) || client == Guid.Empty)
            throw new InvalidDataException("Invalid Entra client or tenant GUID.");
        var active = Get(map, "ACTIVE_SHA256");
        var staged = Get(map, "STAGED_SHA256");
        var oldSha = Get(map, "ACTIVE_CERT_SHA256");
        var newSha = Get(map, "CANDIDATE_CERT_SHA256");
        if (!new[] { active, staged, oldSha, newSha }.All(x => Hash.IsMatch(x)))
            throw new InvalidDataException("Invalid certificate SHA256 evidence.");
        var oldDer = Get(map, "ACTIVE_CERT_DER_BASE64");
        var newDer = Get(map, "CANDIDATE_CERT_DER_BASE64");
        static void VerifyCertificate(string base64, string sha)
        {
            if (base64.Length > 32768)
                throw new InvalidDataException("Public certificate too large.");
            byte[] der;
            try { der = Convert.FromBase64String(base64); }
            catch (FormatException) { throw new InvalidDataException("Invalid public certificate Base64."); }
            if (der.Length is < 250 or > 24576 ||
                !string.Equals(Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant(),
                               sha, StringComparison.Ordinal))
                throw new InvalidDataException("Public certificate SHA256 does not match Linux inventory.");
            using var cert = new X509Certificate2(der);
            using var rsa = cert.GetRSAPublicKey();
            if (rsa is null || rsa.KeySize < 2048)
                throw new InvalidDataException("Entra public certificate must contain RSA2048+ key.");
        }
        VerifyCertificate(oldDer, oldSha);
        VerifyCertificate(newDer, newSha);
        if (oldSha == newSha)
            throw new InvalidDataException("Staged public certificate must differ from active.");
        return new(tenant, client, active, staged, oldSha, newSha, oldDer, newDer);
    }

    internal string Context(string endpointIdentity, string target) =>
        string.Join("|", endpointIdentity, target, TenantId.ToString("D"), ClientId.ToString("D"),
                    ActiveSha, StagedSha, ActiveCertificateSha, CandidateCertificateSha);

    internal string PayloadJson(string? ephemeralProof = null)
    {
        if (ephemeralProof is not null && (ephemeralProof.Length is < 300 or > 12000 ||
            !Regex.IsMatch(ephemeralProof,
                @"\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z",
                RegexOptions.CultureInvariant)))
            throw new ArgumentException("Invalid ephemeral Graph addKey proof.", nameof(ephemeralProof));
        var result = new Dictionary<string, string>
        {
            ["schema"] = "lmr365-entra-oauth-cert/v1",
            ["tenantId"] = TenantId.ToString("D"),
            ["clientId"] = ClientId.ToString("D"),
            ["activeSha"] = ActiveSha,
            ["stageSha"] = StagedSha,
            ["activeCertSha"] = ActiveCertificateSha,
            ["candidateCertSha"] = CandidateCertificateSha,
            ["activeDer"] = ActiveDerBase64,
            ["candidateDer"] = CandidateDerBase64
        };
        if (ephemeralProof is not null)
            result["proof"] = ephemeralProof;
        return JsonSerializer.Serialize(result);
    }

    internal static string ParseProof(string raw)
    {
        var map = Lines(raw);
        if (Get(map, "PROOF_VERSION") != "1" ||
            Get(map, "PRIVATE_KEY_EXPORTED") != "no" ||
            Get(map, "ENTRA_CONTACTED") != "no" ||
            Get(map, "MAIL_SENT") != "no")
            throw new InvalidDataException("Linux proof signing returned an unverified status.");
        string proof = Get(map, "PROOF_JWT");
        if (proof.Length is < 300 or > 12000 ||
            !Regex.IsMatch(proof, @"\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z"))
            throw new InvalidDataException("Invalid proof signing result.");
        return proof;
    }

    internal static bool SelfTest()
    {
        try
        {
            Parse("ENTRA_OAUTH_VERSION=1\nENTRA_OAUTH_VERSION=1\n");
            return false;
        }
        catch (InvalidDataException) { }
        try
        {
            var fake = new EntraCertificateReview(Guid.NewGuid(), Guid.NewGuid(),
                new string('a', 64), new string('b', 64), new string('c', 64),
                new string('d', 64), "", "");
            var json = fake.PayloadJson();
            if (!json.Contains("lmr365-entra-oauth-cert/v1", StringComparison.Ordinal) ||
                json.Contains("proof", StringComparison.Ordinal)) return false;
            fake.PayloadJson("PIN=secret");
            return false;
        }
        catch (ArgumentException) { return true; }
    }
}
