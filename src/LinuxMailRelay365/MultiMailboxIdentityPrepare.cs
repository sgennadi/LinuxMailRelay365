using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace LinuxMailRelay365;

internal sealed record MultiMailboxIdentityPrepareRequest(string Tenant, string Client, string Mailbox,
    int Days, string SourceSha, string Nonce)
{
    internal const string Confirmation = "CREATE_UNBOUND_OAUTH_IDENTITY";
    internal string IdentityFile => "mbx-" + Nonce[..32] + ".json";
    private static bool CanonicalGuid(string s) => Guid.TryParseExact(s, "D", out var id) &&
        id != Guid.Empty && id.ToString("D") == s;
    internal bool Valid => CanonicalGuid(Tenant) && CanonicalGuid(Client) &&
        InstalledPostfixRoute.ValidAddress(Mailbox) && Mailbox == Mailbox.ToLowerInvariant() &&
        Days is >= 1 and <= 365 && MultiMailboxSourceEditRequest.IsSha(Nonce) &&
        (SourceSha == "" || MultiMailboxSourceEditRequest.IsSha(SourceSha));
    internal string Serialize(string approval = "")
    {
        if (!Valid || (approval != "" && !MultiMailboxSourceEditRequest.IsSha(approval)))
            throw new InvalidDataException("Invalid identity preparation request.");
        return JsonSerializer.Serialize(new { tenant = Tenant, client = Client, mailbox = Mailbox,
            days = Days, source_sha = SourceSha, nonce = Nonce, approval,
            confirm = approval == "" ? "" : Confirmation });
    }
}

internal sealed record MultiMailboxIdentityPrepareReceipt(string PlanSha, string RuntimeSha,
    string CertificateSha, byte[] PublicDer)
{
    internal static MultiMailboxIdentityPrepareReceipt Parse(string json,
        MultiMailboxIdentityPrepareRequest req, MultiMailboxIdentityPrepareReceipt? approved = null)
    {
        if (!req.Valid || json.Length > 16384 || json.Contains('\0'))
            throw new InvalidDataException("Invalid identity preparation receipt.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
        var root = doc.RootElement;
        string[] fields = ["version", "status", "plan_sha", "source_sha", "runtime_sha", "nonce",
            "tenant", "client", "mailbox", "days", "identity_file", "changes", "runtime_changed",
            "cloud_changed", "mail_sent", "certificate_sha256", "certificate_der"];
        if (root.ValueKind != JsonValueKind.Object ||
            !root.EnumerateObject().Select(x => x.Name).OrderBy(x => x, StringComparer.Ordinal)
                 .SequenceEqual(fields.OrderBy(x => x, StringComparer.Ordinal)))
            throw new InvalidDataException("Unexpected identity preparation receipt.");
        string Read(string k) => root.GetProperty(k).GetString() ??
            throw new InvalidDataException("Missing identity preparation evidence.");
        bool applying = approved is not null;
        if (root.GetProperty("version").GetInt32() != 1 ||
            Read("status") != (applying ? "prepared" : "preview") ||
            Read("source_sha") != req.SourceSha || Read("nonce") != req.Nonce ||
            Read("tenant") != req.Tenant || Read("client") != req.Client ||
            Read("mailbox") != req.Mailbox || Read("identity_file") != req.IdentityFile ||
            root.GetProperty("days").GetInt32() != req.Days ||
            root.GetProperty("changes").ValueKind != (applying ? JsonValueKind.True : JsonValueKind.False) ||
            new[] { "runtime_changed", "cloud_changed", "mail_sent" }
                .Any(k => root.GetProperty(k).ValueKind != JsonValueKind.False))
            throw new InvalidDataException("Identity preparation scope or context mismatch.");
        string plan = Read("plan_sha"), runtime = Read("runtime_sha"),
            certSha = Read("certificate_sha256"), certificate = Read("certificate_der");
        if (!MultiMailboxSourceEditRequest.IsSha(plan) ||
            (runtime != "" && !MultiMailboxSourceEditRequest.IsSha(runtime)) ||
            (approved is not null && (approved.PlanSha != plan || approved.RuntimeSha != runtime)))
            throw new InvalidDataException("Identity preparation approval mismatch.");
        if (!applying)
        {
            if (certSha != "" || certificate != "")
                throw new InvalidDataException("Preview must not contain generated certificate.");
            return new(plan, runtime, "", []);
        }
        if (!MultiMailboxSourceEditRequest.IsSha(certSha) || certificate.Length > 10924)
            throw new InvalidDataException("Invalid public certificate receipt.");
        byte[] der = Convert.FromBase64String(certificate);
        if (der.Length is < 1 or > 8192 ||
            Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant() != certSha)
            throw new InvalidDataException("Public certificate digest mismatch.");
        using var parsed = X509CertificateLoader.LoadCertificate(der);
        if (parsed.HasPrivateKey || !parsed.RawData.AsSpan().SequenceEqual(der))
            throw new InvalidDataException("Only exact public certificate DER is allowed.");
        return new(plan, runtime, certSha, der);
    }

    internal static bool SelfTest()
    {
        var req = new MultiMailboxIdentityPrepareRequest("11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222", "alice@example.org", 365, "", new string('a',64));
        string plan = new('b',64);
        if (!req.Valid || (req with { Days = 366 }).Valid ||
            !req.Serialize(plan).Contains(MultiMailboxIdentityPrepareRequest.Confirmation, StringComparison.Ordinal))
            return false;
        string Receipt(bool save, string hash = "", string cert = "") => JsonSerializer.Serialize(new {
            version = 1, status = save ? "prepared" : "preview", plan_sha = plan, source_sha = "",
            runtime_sha = "", nonce = req.Nonce, tenant = req.Tenant, client = req.Client,
            mailbox = req.Mailbox, days = req.Days, identity_file = req.IdentityFile, changes = save,
            runtime_changed = false, cloud_changed = false, mail_sent = false, certificate_sha256 = hash,
            certificate_der = cert });
        var preview = Parse(Receipt(false), req);
        using var rsa = RSA.Create(2048);
        var builder = new CertificateRequest("CN=LMR365 self test", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var generated = builder.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] der = generated.Export(X509ContentType.Cert);
        string sha = Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();
        string saved = Receipt(true, sha, Convert.ToBase64String(der));
        if (!Parse(saved, req, preview).PublicDer.AsSpan().SequenceEqual(der)) return false;
        foreach (string bad in new[] { saved.Replace("\"cloud_changed\":false", "\"cloud_changed\":true"),
            saved.Replace(sha, new string('c',64)), saved.Replace(plan, new string('d',64)),
            saved.Replace(req.IdentityFile, "../unsafe.json") })
        {
            try { Parse(bad, req, preview); return false; }
            catch (InvalidDataException) { }
        }
        return true;
    }
}
