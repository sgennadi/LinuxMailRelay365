using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Bounded public-only identity receipt. This correlates two configuration
// observations, not a live signer, active Postfix route or SMTP session.
internal sealed record ActiveOAuthCertificateAudit(string Target, string Mailbox,
    string Sha256, DateTimeOffset ValidFrom, DateTimeOffset ValidUntil,
    string Status, DateTimeOffset ObservedAt)
{
    internal static ActiveOAuthCertificateAudit Parse(string raw, string target,
        Guid tenant, Guid client, string mailbox, IReadOnlyList<CloudCredentialObject> credentials,
        DateTimeOffset now)
    {
        if (target is not ("primary" or "sidecar") || tenant == Guid.Empty || client == Guid.Empty ||
            !SshRemote.IsEmail(mailbox) || raw.Length > 50000 || raw.Contains('\0'))
            throw new InvalidDataException("Invalid active OAuth audit context.");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in raw.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string text = line.TrimEnd('\r');
            int eq = text.IndexOf('=');
            if (!text.StartsWith("ACTIVE_OAUTH_", StringComparison.Ordinal) || eq <= 13 ||
                !fields.TryAdd(text[13..eq], text[(eq + 1)..]))
                throw new InvalidDataException("Invalid active OAuth receipt.");
        }
        string Read(string key) => fields.TryGetValue(key, out string? value) ? value :
            throw new InvalidDataException("Missing active OAuth receipt field.");
        if (fields.Count != 12 || Read("VERSION") != "1" || Read("TARGET") != target ||
            Read("TENANT_ID") != tenant.ToString("D") || Read("CLIENT_ID") != client.ToString("D") ||
            !string.Equals(Read("MAILBOX"), mailbox, StringComparison.OrdinalIgnoreCase) ||
            Read("PRIVATE_KEY_EXPORTED") != "no" || Read("SIGNING_TESTED") != "no" ||
            Read("MAIL_SENT") != "no" || Read("CONFIG_CHANGED") != "no" ||
            !Regex.IsMatch(Read("IDENTITY_SHA256"), @"\A[a-f0-9]{64}\z"))
            throw new InvalidDataException("Active OAuth identity or flags mismatch.");
        byte[] der;
        try { der = Convert.FromBase64String(Read("CERT_DER_BASE64")); }
        catch (FormatException) { throw new InvalidDataException("Invalid public DER."); }
        string sha = Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();
        if (der.Length is < 250 or > 24576 || Read("CERT_SHA256") != sha)
            throw new InvalidDataException("Certificate SHA mismatch.");
        using var cert = X509CertificateLoader.LoadCertificate(der);
        using var rsa = cert.GetRSAPublicKey();
        if (rsa is null || rsa.KeySize < 2048 || !der.AsSpan().SequenceEqual(cert.RawData))
            throw new InvalidDataException("Invalid public RSA certificate.");
        DateTimeOffset from = cert.NotBefore.ToUniversalTime(), until = cert.NotAfter.ToUniversalTime();
        var eligible = credentials.Where(c => c.Type == "AsymmetricX509Cert" && c.Usage == "Verify").ToArray();
        var matching = eligible.Where(c => c.CertificateSha256 == sha).ToArray();
        bool localValid = from <= now && now < until;
        string status = matching.Any(c => localValid && c.ValidFrom <= now && now < c.ValidUntil) ? "match_current" :
            matching.Length > 0 ? "match_outside_validity" :
            eligible.Any(c => c.CertificateSha256 is null) ? "unverified_graph_public_key" : "not_found";
        return new(target, mailbox, sha, from, until, status, now);
    }

    internal string Describe() => "Source: " + Target + " app.json (configured identity)" +
        Environment.NewLine + "Mailbox: " + Mailbox +
        Environment.NewLine + "Public certificate SHA-256: " + Sha256 +
        Environment.NewLine + "Certificate validity (UTC): " + ValidFrom.ToString("u") + " - " + ValidUntil.ToString("u") +
        Environment.NewLine + "Comparison: " + Status +
        Environment.NewLine + "Linux sampled (UTC): " + ObservedAt.ToString("u") +
        Environment.NewLine + "Compared against the Graph inventory in this window, not a fresh cloud read." +
        Environment.NewLine + "Private key not exported. Signing, effective Postfix routing, SMTP AUTH and delivery NOT tested.";

    internal static bool SelfTest()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=fixture", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var cert = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        string sha = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
        Guid tenant = Guid.NewGuid(), client = Guid.NewGuid();
        const string mailbox = "fixture@example.org";
        string receipt = "ACTIVE_OAUTH_TARGET=primary\nACTIVE_OAUTH_TENANT_ID=" + tenant +
            "\nACTIVE_OAUTH_CLIENT_ID=" + client + "\nACTIVE_OAUTH_MAILBOX=" + mailbox +
            "\nACTIVE_OAUTH_IDENTITY_SHA256=" + new string('a', 64) +
            "\nACTIVE_OAUTH_CERT_SHA256=" + sha +
            "\nACTIVE_OAUTH_CERT_DER_BASE64=" + Convert.ToBase64String(cert.RawData) +
            "\nACTIVE_OAUTH_VERSION=1\nACTIVE_OAUTH_PRIVATE_KEY_EXPORTED=no\nACTIVE_OAUTH_SIGNING_TESTED=no\n" +
            "ACTIVE_OAUTH_MAIL_SENT=no\nACTIVE_OAUTH_CONFIG_CHANGED=no\n";
        var valid = new CloudCredentialObject(Guid.NewGuid(), "fixture", "AsymmetricX509Cert", "Verify",
            now.AddDays(-1), now.AddDays(1), sha);
        ActiveOAuthCertificateAudit Check(IReadOnlyList<CloudCredentialObject> keys, string? input = null) =>
            Parse(input ?? receipt, "primary", tenant, client, mailbox, keys, now);
        if (Check([valid]).Status != "match_current" ||
            Check([valid with { ValidUntil = now.AddSeconds(-1) }]).Status != "match_outside_validity" ||
            Check([valid with { CertificateSha256 = null }]).Status != "unverified_graph_public_key" ||
            Check([valid with { CertificateSha256 = new string('b', 64) }]).Status != "not_found") return false;
        foreach (string bad in new[] { receipt.Replace(mailbox, "other@example.org"),
            receipt.Replace(sha, new string('c', 64)), receipt.Replace("TARGET=primary", "TARGET=sidecar"),
            receipt + "ACTIVE_OAUTH_VERSION=1\n", receipt.Replace("MAIL_SENT=no", "MAIL_SENT=yes") })
        {
            try { Check([valid], bad); return false; }
            catch (InvalidDataException) { }
        }
        return true;
    }
}
