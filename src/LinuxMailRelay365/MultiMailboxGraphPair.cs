using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft365Auth;

namespace LinuxMailRelay365;

internal sealed record MultiMailboxGraphPairRequest(string Scope, string SourceSha, string RuntimeSha,
    MultiMailboxIdentityRow Donor, string CandidateFile, string Nonce)
{
    internal const string Confirmation = "ADD_REVIEWED_MAILBOX_PUBLIC_CERT";
    internal bool Valid => Scope is "source" or "runtime" &&
        (SourceSha == "" || MultiMailboxSourceEditRequest.IsSha(SourceSha)) &&
        (RuntimeSha == "" || MultiMailboxSourceEditRequest.IsSha(RuntimeSha)) &&
        (Scope == "source" ? SourceSha != "" : RuntimeSha != "") &&
        Donor.Status == "public_certificate_read" && Donor.Signer == "software" &&
        Donor.Tenant is Guid tenant && tenant != Guid.Empty && Donor.Client is Guid client && client != Guid.Empty &&
        InstalledPostfixRoute.ValidAddress(Donor.Mailbox) && Donor.Sender == Donor.Mailbox &&
        MultiMailboxSourceEditRequest.IsSha(Donor.IdentitySha) &&
        MultiMailboxSourceEditRequest.IsSha(Donor.CertificateSha) &&
        MultiMailboxSourceEditRequest.IsSha(Nonce) &&
        Regex.IsMatch(CandidateFile, @"\Ambx-[a-f0-9]{32}\.json\z", RegexOptions.CultureInvariant);

    internal string Serialize(string pairSha = "", Guid? objectId = null)
    {
        bool proof = objectId is not null;
        if (!Valid || (proof ? objectId == Guid.Empty || !MultiMailboxSourceEditRequest.IsSha(pairSha) : pairSha != ""))
            throw new InvalidDataException("Invalid Graph pair selection.");
        return JsonSerializer.Serialize(new { action = proof ? "proof" : "inspect", scope = Scope,
            source_sha = SourceSha, runtime_sha = RuntimeSha, donor_mailbox = Donor.Mailbox,
            donor_sha = Donor.IdentitySha, donor_cert_sha = Donor.CertificateSha,
            candidate_file = CandidateFile, nonce = Nonce, pair_sha = pairSha,
            object_id = objectId?.ToString("D") ?? "", confirm = proof ? Confirmation : "" });
    }
}

internal sealed record MultiMailboxGraphPair(string PairSha, string CandidateMailbox, EntraCertificateEvidence Evidence)
{
    internal static MultiMailboxGraphPair Parse(string json, MultiMailboxGraphPairRequest req)
    {
        if (!req.Valid || json.Length > 72000 || json.Contains('\0'))
            throw new InvalidDataException("Invalid Graph pair receipt.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
        var root = doc.RootElement;
        string[] fields = ["version", "status", "nonce", "scope", "source_sha", "runtime_sha", "tenant",
            "client", "donor_mailbox", "candidate_mailbox", "candidate_file", "donor_sha",
            "candidate_sha", "donor_cert_sha", "candidate_cert_sha", "donor_der", "candidate_der",
            "changes", "mail_sent", "cloud_changed", "private_key_exported", "pair_sha"];
        if (root.ValueKind != JsonValueKind.Object ||
            !root.EnumerateObject().Select(p => p.Name).OrderBy(p => p, StringComparer.Ordinal)
                .SequenceEqual(fields.OrderBy(p => p, StringComparer.Ordinal)))
            throw new InvalidDataException("Unexpected Graph pair receipt.");
        string Read(string key) => root.GetProperty(key).GetString() ??
            throw new InvalidDataException("Missing Graph pair evidence.");
        if (root.GetProperty("version").GetInt32() != 1 || Read("status") != "public_pair" ||
            Read("nonce") != req.Nonce || Read("scope") != req.Scope ||
            Read("source_sha") != req.SourceSha || Read("runtime_sha") != req.RuntimeSha ||
            Read("tenant") != req.Donor.Tenant!.Value.ToString("D") ||
            Read("client") != req.Donor.Client!.Value.ToString("D") ||
            Read("donor_mailbox") != req.Donor.Mailbox || Read("donor_sha") != req.Donor.IdentitySha ||
            Read("donor_cert_sha") != req.Donor.CertificateSha || Read("candidate_file") != req.CandidateFile ||
            new[] {"changes", "mail_sent", "cloud_changed", "private_key_exported"}
                .Any(k => root.GetProperty(k).ValueKind != JsonValueKind.False))
            throw new InvalidDataException("Graph pair scope or context mismatch.");
        string candidate = Read("candidate_mailbox"), pair = Read("pair_sha"),
            candidateSha = Read("candidate_sha"), candidateCertSha = Read("candidate_cert_sha");
        if (!InstalledPostfixRoute.ValidAddress(candidate) || candidate != candidate.ToLowerInvariant() ||
            candidate == req.Donor.Mailbox ||
            !new[] { pair, candidateSha, candidateCertSha }.All(MultiMailboxSourceEditRequest.IsSha) ||
            candidateSha == req.Donor.IdentitySha || candidateCertSha == req.Donor.CertificateSha)
            throw new InvalidDataException("Invalid distinct candidate identity.");
        static void CheckDer(string value, string expected)
        {
            if (value.Length > 32768) throw new InvalidDataException("Public certificate too large.");
            byte[] raw = Convert.FromBase64String(value);
            if (raw.Length is < 250 or > 24576 ||
                Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant() != expected)
                throw new InvalidDataException("Public certificate digest mismatch.");
            using var cert = X509CertificateLoader.LoadCertificate(raw);
            using var rsa = cert.GetRSAPublicKey();
            if (cert.HasPrivateKey || !cert.RawData.AsSpan().SequenceEqual(raw) || rsa is null || rsa.KeySize < 2048)
                throw new InvalidDataException("Expected exact RSA public certificate.");
        }
        string oldDer = Read("donor_der"), newDer = Read("candidate_der");
        CheckDer(oldDer, req.Donor.CertificateSha);
        CheckDer(newDer, candidateCertSha);
        return new(pair, candidate, new(req.Donor.Tenant.Value, req.Donor.Client.Value,
            req.Donor.IdentitySha, candidateSha, req.Donor.CertificateSha, candidateCertSha, oldDer, newDer,
            EntraGraphCertificateAddKeyClient.MultiMailboxLabel));
    }

    internal static bool SelfTest()
    {
        using var a = RSA.Create(2048);
        using var b = RSA.Create(2048);
        using var old = new CertificateRequest("CN=donor", a, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        using var next = new CertificateRequest("CN=candidate", b, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var donor = new MultiMailboxIdentityRow("alice", "alice@example.org", "alice@example.org",
            Guid.NewGuid(), Guid.NewGuid(), new string('a',64), Hash(old.RawData), "software", "public_certificate_read");
        var req = new MultiMailboxGraphPairRequest("source", new string('b',64), "", donor,
            "mbx-" + new string('c',32) + ".json", new string('d',64));
        if (!req.Valid || (req with { CandidateFile = "../unsafe.json" }).Valid) return false;
        string json = JsonSerializer.Serialize(new { version=1, status="public_pair", nonce=req.Nonce,
            scope=req.Scope, source_sha=req.SourceSha, runtime_sha=req.RuntimeSha,
            tenant=donor.Tenant!.Value.ToString("D"), client=donor.Client!.Value.ToString("D"),
            donor_mailbox=donor.Mailbox, candidate_mailbox="bob@example.org", candidate_file=req.CandidateFile,
            donor_sha=donor.IdentitySha, candidate_sha=new string('e',64), donor_cert_sha=donor.CertificateSha,
            candidate_cert_sha=Hash(next.RawData), donor_der=Convert.ToBase64String(old.RawData),
            candidate_der=Convert.ToBase64String(next.RawData), changes=false, mail_sent=false,
            cloud_changed=false, private_key_exported=false, pair_sha=new string('f',64) });
        var pair = Parse(json, req);
        if (pair.CandidateMailbox != "bob@example.org" ||
            pair.Evidence.CertificateLabel != EntraGraphCertificateAddKeyClient.MultiMailboxLabel ||
            !req.Serialize(pair.PairSha, Guid.NewGuid()).Contains(MultiMailboxGraphPairRequest.Confirmation, StringComparison.Ordinal))
            return false;
        foreach (string bad in new[] { json.Replace("\"changes\":false", "\"changes\":true"),
            json.Replace(req.Nonce, req.SourceSha), json.Replace(Hash(next.RawData), donor.CertificateSha),
            json.Replace("bob@example.org", "alice@example.org") })
        {
            try { Parse(bad, req); return false; }
            catch (InvalidDataException) { }
        }
        return true;
    }
}
