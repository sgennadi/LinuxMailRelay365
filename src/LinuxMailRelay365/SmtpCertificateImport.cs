using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LinuxMailRelay365;

internal static class SmtpCertificateImport
{
    internal static X509Certificate2 LoadPem(string certificatePath, string keyPath)
    {
        CheckSize(certificatePath);
        CheckSize(keyPath);
        var cert = X509Certificate2.CreateFromPemFile(certificatePath, keyPath);
        try { CheckIdentity(cert); return cert; }
        catch { cert.Dispose(); throw; }
    }

    internal static X509Certificate2 LoadPkcs12(string path, string password)
    {
        CheckSize(path);
        var cert = X509CertificateLoader.LoadPkcs12FromFile(path, password,
            X509KeyStorageFlags.EphemeralKeySet);
        try { CheckIdentity(cert); return cert; }
        catch { cert.Dispose(); throw; }
    }

    internal static X509Certificate2Collection LoadPkcs12Chain(string path, string password)
    {
        CheckSize(path);
        var certificates = X509CertificateLoader.LoadPkcs12CollectionFromFile(path, password,
            X509KeyStorageFlags.EphemeralKeySet);
        try
        {
            if (certificates.Count > 32 || certificates.Cast<X509Certificate2>().Count(c => c.HasPrivateKey) != 1)
                throw new CryptographicException("Exactly one private-key identity is required.");
            CheckIdentity(certificates.Cast<X509Certificate2>().Single(c => c.HasPrivateKey));
            return certificates;
        }
        catch
        {
            foreach (var cert in certificates) cert.Dispose();
            throw;
        }
    }

    internal static X509Certificate2Collection LoadPemChain(string path)
    {
        CheckSize(path);
        var certificates = new X509Certificate2Collection();
        try
        {
            certificates.ImportFromPemFile(path);
            if (certificates.Count == 0 || certificates.Count > 32)
                throw new CryptographicException("Invalid certificate chain size.");
            return certificates;
        }
        catch
        {
            foreach (var cert in certificates) cert.Dispose();
            throw;
        }
    }

    internal static bool VerifyLocalChain(X509Certificate2 leaf, X509Certificate2Collection intermediates)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.ExtraStore.AddRange(intermediates);
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.System;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        return chain.Build(leaf);
    }

    private static void CheckSize(string path)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length <= 0 || file.Length > 4 * 1024 * 1024)
            throw new InvalidDataException("Invalid certificate import file size.");
    }

    private static void CheckIdentity(X509Certificate2 cert)
    {
        if (!cert.HasPrivateKey || DateTime.UtcNow < cert.NotBefore.ToUniversalTime() ||
            DateTime.UtcNow >= cert.NotAfter.ToUniversalTime())
            throw new CryptographicException("Missing private key or certificate outside validity period.");
    }
}
