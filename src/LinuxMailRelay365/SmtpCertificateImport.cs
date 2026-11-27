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
