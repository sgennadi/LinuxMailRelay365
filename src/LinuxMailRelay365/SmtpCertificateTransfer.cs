using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace LinuxMailRelay365;

internal static class SmtpCertificateTransfer
{
    internal static async Task<string> StageAsync(SshEndpoint endpoint,
        X509Certificate2 leaf, X509Certificate2Collection chain, string domain,
        CancellationToken cancellationToken = default)
    {
        if (Uri.CheckHostName(domain) != UriHostNameType.Dns ||
            !System.Text.RegularExpressions.Regex.IsMatch(domain, @"\A[A-Za-z0-9.-]{1,253}\z"))
            throw new ArgumentException("Invalid certificate DNS name.");
        bool directRoot = string.Equals(endpoint.Username, "root", StringComparison.Ordinal);
        if (!directRoot && !string.IsNullOrEmpty(endpoint.SudoPassword))
            throw new InvalidOperationException("Certificate transfer requires root or passwordless sudo.");
        string command = (directRoot ? "" : "sudo -n ") + EmbeddedAssets.BuildSmtpCertificateImportCommand(domain);
        using var rsa = leaf.GetRSAPrivateKey();
        using var ec = leaf.GetECDsaPrivateKey();
        byte[] key = rsa is not null ? rsa.ExportPkcs8PrivateKey() :
            ec is not null ? ec.ExportPkcs8PrivateKey() :
            throw new CryptographicException("Unsupported private key.");
        try
        {
            var intermediates = string.Join("\n", chain.Cast<X509Certificate2>()
                .Where(c => !c.RawData.AsSpan().SequenceEqual(leaf.RawData))
                .Select(c => c.ExportCertificatePem()));
            if (string.IsNullOrWhiteSpace(intermediates))
                throw new CryptographicException("Certificate chain required.");
            string Encode(string value) => Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes(value));
            var payload = JsonSerializer.Serialize(new {
                certificate = Encode(leaf.ExportCertificatePem()),
                chain = Encode(intermediates),
                key = Encode(PemEncoding.WriteString("PRIVATE KEY", key))
            });
            var result = await SshRemote.ExecuteAsync(endpoint,
                command,
                payload, TimeSpan.FromSeconds(120), cancellationToken);
            if (result.ExitCode != 0)
                throw new InvalidOperationException("Remote certificate import refused.");
            using var report = JsonDocument.Parse(result.StdOut);
            if (report.RootElement.GetProperty("status").GetString() != "staged_locally_validated")
                throw new InvalidOperationException("Remote staging not confirmed.");
            var generation = report.RootElement.GetProperty("generation").GetString();
            if (generation is null || !System.Text.RegularExpressions.Regex.IsMatch(generation, @"\Acandidate-[a-f0-9]{64}\z"))
                throw new InvalidDataException("Invalid generation identifier.");
            return generation;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
