using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Stable updates require a trusted and pinned Authenticode publisher.
// An explicitly approved, non-elevated test Preview can update from a published
// unsigned GitHub prerelease using its SHA-256 digest; NEVER accept for Stable.
// Both paths enforce architecture, version, self-test, backup and rollback.
internal sealed record SignedUpdateOffer(string Version, string Tag, string PageUrl,
    Uri AssetUrl, string AssetName, string ArchiveSha, long ArchiveBytes);

internal static class SignedPortableUpdater
{
    private const string Repository = "sgennadi/LinuxMailRelay365";
    private const string Executable = "LinuxMailRelay365.exe";
    private const string PreviewPublisherMarker = "0000000000000000000000000000000000000000000000000000000000000000";
    private const long MaximumArchive = 450L * 1024 * 1024;
    private const long MaximumExecutable = 450L * 1024 * 1024;
    private const int MaximumMetadata = 2 * 1024 * 1024;
    private static readonly Regex VersionPattern = new(
        @"\A(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([A-Za-z0-9][A-Za-z0-9.-]*))?\z",
        RegexOptions.CultureInvariant);
    private static readonly Guid GenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private static string Architecture => RuntimeInformation.ProcessArchitecture switch
    {
        System.Runtime.InteropServices.Architecture.X64 => "x64",
        System.Runtime.InteropServices.Architecture.Arm64 => "arm64",
        _ => throw new PlatformNotSupportedException("Updater supports Windows x64/ARM64 only.")
    };

    private static string ExpectedAsset => "LinuxMailRelay365-win-" + Architecture + ".zip";

    private static bool Digest(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static string Str(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.Object &&
        value.TryGetProperty(name, out var entry) &&
        entry.ValueKind == JsonValueKind.String ? entry.GetString() ?? "" : "";

    private static bool Bool(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.Object &&
        value.TryGetProperty(name, out var entry) &&
        entry.ValueKind == JsonValueKind.True;

    private static bool TrustedGithubUrl(string input, string relativePath)
    {
        return Uri.TryCreate(input, UriKind.Absolute, out var url) &&
            url.Scheme == Uri.UriSchemeHttps &&
            string.Equals(url.Host, "github.com", StringComparison.OrdinalIgnoreCase) &&
            url.IsDefaultPort && url.UserInfo.Length == 0 &&
            url.Query.Length == 0 && url.Fragment.Length == 0 &&
            string.Equals(Uri.UnescapeDataString(url.AbsolutePath),
                relativePath, StringComparison.Ordinal);
    }

    private static bool TrustedRedirect(Uri url) =>
        url.Scheme == Uri.UriSchemeHttps && url.IsDefaultPort &&
        url.UserInfo.Length == 0 &&
        url.Host is "github.com" or "release-assets.githubusercontent.com" or
            "objects.githubusercontent.com";

    private static int CompareNumeric(string a, string b)
    {
        a = a.TrimStart('0');
        b = b.TrimStart('0');
        if (a.Length != b.Length) return a.Length.CompareTo(b.Length);
        return string.CompareOrdinal(a, b);
    }

    private static int CompareVersions(string left, string right)
    {
        var a = VersionPattern.Match(left);
        var b = VersionPattern.Match(right);
        if (!a.Success || !b.Success)
            throw new InvalidDataException("Invalid signed update semantic version.");
        for (int i = 1; i < 4; i++)
        {
            int c = CompareNumeric(a.Groups[i].Value, b.Groups[i].Value);
            if (c != 0) return c;
        }
        string preA = a.Groups[4].Value, preB = b.Groups[4].Value;
        if (preA.Length == 0) return preB.Length == 0 ? 0 : 1;
        if (preB.Length == 0) return -1;
        var aTags = preA.Split('.');
        var bTags = preB.Split('.');
        for (int i = 0; i < Math.Min(aTags.Length, bTags.Length); i++)
        {
            bool an = aTags[i].All(char.IsAsciiDigit);
            bool bn = bTags[i].All(char.IsAsciiDigit);
            int c = an && bn ? CompareNumeric(aTags[i], bTags[i]) :
                an ? -1 : bn ? 1 : string.CompareOrdinal(aTags[i], bTags[i]);
            if (c != 0) return c;
        }
        return aTags.Length.CompareTo(bTags.Length);
    }

    internal static bool IsPreviewRelease(SignedUpdateOffer offer) =>
        Regex.IsMatch(offer.Tag,
            @"\Av(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-preview\.(0|[1-9]\d*)\z",
            RegexOptions.CultureInvariant) &&
        string.Equals(offer.Tag[1..], offer.Version, StringComparison.Ordinal) &&
        CompareVersions(offer.Version, UpdateCheck.Version) > 0;

    internal static SignedUpdateOffer? SelectRelease(
        JsonElement catalog, bool includePreview, string currentVersion, string expectedAsset)
    {
        if (catalog.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Invalid release catalog.");
        if (!VersionPattern.IsMatch(currentVersion) ||
            expectedAsset is not ("LinuxMailRelay365-win-x64.zip" or
                "LinuxMailRelay365-win-arm64.zip"))
            throw new InvalidDataException("Untrusted updater inputs.");
        SignedUpdateOffer? best = null;
        foreach (var item in catalog.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object || Bool(item, "draft")) continue;
            string rawTag = Str(item, "tag_name");
            string version = rawTag.StartsWith('v') ? rawTag[1..] : rawTag;
            if (!VersionPattern.IsMatch(version) ||
                CompareVersions(version, currentVersion) <= 0) continue;
            bool prerelease = Bool(item, "prerelease") || version.Contains('-');
            if (prerelease && !includePreview) continue;
            if (!TrustedGithubUrl(Str(item, "html_url"),
                "/" + Repository + "/releases/tag/" + rawTag)) continue;
            if (!item.TryGetProperty("assets", out var assets) ||
                assets.ValueKind != JsonValueKind.Array) continue;
            SignedUpdateOffer? offered = null;
            int matches = 0;
            foreach (var asset in assets.EnumerateArray())
            {
                if (!string.Equals(Str(asset, "name"), expectedAsset, StringComparison.Ordinal))
                    continue;
                matches++;
                if (matches > 1) break;
                string rawSha = Str(asset, "digest");
                if (!rawSha.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ||
                    !Digest(rawSha[7..])) continue;
                if (!asset.TryGetProperty("size", out var size) ||
                    !size.TryGetInt64(out long archiveSize) ||
                    archiveSize <= 0 || archiveSize > MaximumArchive) continue;
                string exactDownload = "/" + Repository + "/releases/download/" +
                    rawTag + "/" + expectedAsset;
                string url = Str(asset, "browser_download_url");
                if (!TrustedGithubUrl(url, exactDownload)) continue;
                offered = new SignedUpdateOffer(version, rawTag,
                    Str(item, "html_url"), new Uri(url), expectedAsset,
                    rawSha[7..].ToLowerInvariant(), archiveSize);
            }
            if (matches != 1 || offered is null) continue;
            if (best is null || CompareVersions(offered.Version, best.Version) > 0)
                best = offered;
            else if (CompareVersions(offered.Version, best.Version) == 0 &&
                     !string.Equals(offered.ArchiveSha, best.ArchiveSha,
                         StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Conflicting published releases of the same version.");
        }
        return best;
    }

    internal static async Task<SignedUpdateOffer?> FindAsync(
        bool includePreview, CancellationToken ct)
    {
        using var http = CreateHttp();
        using var request = new HttpRequestMessage(HttpMethod.Get,
            "https://api.github.com/repos/" + Repository + "/releases?per_page=50");
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("LinuxMailRelay365", "0.1"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > MaximumMetadata)
            throw new InvalidDataException("Oversized release metadata.");
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var memory = new MemoryStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = await stream.ReadAsync(buffer.AsMemory(), ct)) > 0)
        {
            if (memory.Length + n > MaximumMetadata)
                throw new InvalidDataException("Oversized release metadata.");
            memory.Write(buffer, 0, n);
        }
        memory.Position = 0;
        using var doc = await JsonDocument.ParseAsync(memory,
            new JsonDocumentOptions { MaxDepth = 24 }, ct);
        return SelectRelease(doc.RootElement, includePreview, UpdateCheck.Version,
            ExpectedAsset);
    }

    private static HttpClient CreateHttp() =>
        new(new HttpClientHandler { AllowAutoRedirect = false })
        { Timeout = TimeSpan.FromMinutes(8) };

    private static string UpdateRoot()
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(local) || !Path.IsPathFullyQualified(local))
            throw new InvalidOperationException("Cannot identify a trusted per-user update directory.");
        string app = Path.Combine(local, "LinuxMailRelay365");
        string root = Path.Combine(app, "Updater");
        Directory.CreateDirectory(root);
        RejectLinks(local);
        RejectLinks(app);
        RejectLinks(root);
        return root;
    }

    private static void RejectLinks(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Updater path has an unsafe filesystem link.");
    }

    internal static bool CanInstall(out string publisherHash, out string whyNot)
    {
        publisherHash = "";
        whyNot = "";
        if (!OperatingSystem.IsWindows())
        {
            whyNot = "Signed updater is Windows-only.";
            return false;
        }
        string? current = Environment.ProcessPath;
        if (current is null ||
            !string.Equals(Path.GetFileName(current), Executable, StringComparison.OrdinalIgnoreCase))
        {
            whyNot = "Updater requires the installed LinuxMailRelay365.exe.";
            return false;
        }
        try
        {
            string? hash = VerifiedPublisher(current);
            if (hash is null)
            {
                whyNot = "This copy is not Authenticode-signed and Windows-trusted.";
                return false;
            }
            publisherHash = hash;
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or
            CryptographicException or ArgumentException)
        {
            whyNot = "Current executable publisher trust cannot be verified.";
            return false;
        }
    }

    private static bool IsNonElevatedWindowsProcess()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    // Only an unsigned portable Preview running without administrative
    // privilege can opt in. A signed app cannot downgrade its update policy.
    internal static bool CanInstallPreview(out string whyNot)
    {
        whyNot = "";
        if (!OperatingSystem.IsWindows() ||
            !UpdateCheck.Version.Contains("-preview.", StringComparison.Ordinal))
        {
            whyNot = "Unsigned Preview updates require a Windows Preview build.";
            return false;
        }
        string? path = Environment.ProcessPath;
        if (path is null ||
            !string.Equals(Path.GetFileName(path), Executable,
                StringComparison.OrdinalIgnoreCase))
        {
            whyNot = "A portable LinuxMailRelay365.exe is required.";
            return false;
        }
        try
        {
            if (!IsNonElevatedWindowsProcess())
            {
                whyNot = "Unsigned Preview updating is blocked when elevated. Restart the GUI without administrator rights.";
                return false;
            }
            RejectLinks(path);
            if (!CorrectPeMachine(path, Architecture) ||
                !CorrectVersion(path, UpdateCheck.Version) ||
                VerifiedPublisher(path) is not null)
            {
                whyNot = "The current Preview is signed, changed or has the wrong architecture.";
                return false;
            }
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or
            CryptographicException or ArgumentException or System.Security.SecurityException)
        {
            whyNot = "Current Preview executable could not be verified.";
            return false;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        internal uint cbStruct;
        internal IntPtr pcwszFilePath;
        internal IntPtr hFile;
        internal IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        internal uint cbStruct;
        internal IntPtr pPolicyCallbackData;
        internal IntPtr pSIPClientData;
        internal uint dwUIChoice;
        internal uint fdwRevocationChecks;
        internal uint dwUnionChoice;
        internal IntPtr pFile;
        internal uint dwStateAction;
        internal IntPtr hWVTStateData;
        internal IntPtr pwszURLReference;
        internal uint dwProvFlags;
        internal uint dwUIContext;
        internal IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", PreserveSig = true, ExactSpelling = true,
        CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(
        IntPtr hWnd, ref Guid actionId, IntPtr trustData);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptQueryObject(uint objectType,
        [MarshalAs(UnmanagedType.LPWStr)] string filePath,
        uint expectedContents, uint expectedFormats, uint flags,
        out uint encoding, out uint contentType, out uint formatType,
        out IntPtr certStore, out IntPtr cryptMsg, out IntPtr context);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptMsgGetParam(IntPtr cryptMsg,
        uint parameter, uint index, IntPtr result, ref uint resultSize);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertFindCertificateInStore(
        IntPtr certStore, uint encoding, uint findFlags, uint findType,
        IntPtr findParameter, IntPtr previousCert);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertFreeCertificateContext(IntPtr certificate);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertCloseStore(IntPtr store, uint flags);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptMsgClose(IntPtr cryptMsg);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCertificateContext
    {
        internal uint dwCertEncodingType;
        internal IntPtr pbCertEncoded;
        internal uint cbCertEncoded;
        internal IntPtr pCertInfo;
        internal IntPtr hCertStore;
    }

    // WinTrust validates the entire Authenticode signature and trust chain.
    // CryptoAPI then locates the actual signing leaf by issuer and serial,
    // not an arbitrary intermediate certificate in the signed PKCS#7 bag.
    // No obsolete X509Certificate.CreateFromSignedFile API is used.
    private static string? SignedPublisherCertificateHash(string filePath)
    {
        IntPtr store = IntPtr.Zero, message = IntPtr.Zero, context = IntPtr.Zero;
        if (!CryptQueryObject(1, filePath, 1u << 10, 0x0000000E, 0,
            out _, out _, out _, out store, out message, out context))
            return null;
        try
        {
            if (store == IntPtr.Zero || message == IntPtr.Zero)
                return null;
            uint signerInfoSize = 0;
            if (!CryptMsgGetParam(message, 7, 0, IntPtr.Zero, ref signerInfoSize) ||
                signerInfoSize is < 1 or > 65536)
                return null;
            IntPtr info = Marshal.AllocHGlobal((int)signerInfoSize);
            try
            {
                if (!CryptMsgGetParam(message, 7, 0, info, ref signerInfoSize))
                    return null;
                // CERT_FIND_SUBJECT_CERT + X509_ASN_ENCODING|PKCS_7_ASN_ENCODING.
                IntPtr leafContext = CertFindCertificateInStore(
                    store, 0x00010001, 0, 0x000B0000, info, IntPtr.Zero);
                if (leafContext == IntPtr.Zero) return null;
                try
                {
                    var native = Marshal.PtrToStructure<NativeCertificateContext>(leafContext);
                    if (native.cbCertEncoded is < 64 or > 65536 ||
                        native.pbCertEncoded == IntPtr.Zero)
                        return null;
                    byte[] der = new byte[native.cbCertEncoded];
                    Marshal.Copy(native.pbCertEncoded, der, 0, der.Length);
                    using var leaf = X509CertificateLoader.LoadCertificate(der);
                    if (leaf.NotBefore > DateTime.UtcNow || leaf.NotAfter < DateTime.UtcNow)
                        return null;
                    return Convert.ToHexStringLower(SHA256.HashData(der));
                }
                finally { CertFreeCertificateContext(leafContext); }
            }
            finally { Marshal.FreeHGlobal(info); }
        }
        finally
        {
            if (message != IntPtr.Zero) CryptMsgClose(message);
            if (store != IntPtr.Zero) CertCloseStore(store, 0);
        }
    }

    private static string? VerifiedPublisher(string path)
    {
        if (!OperatingSystem.IsWindows() || !File.Exists(path)) return null;
        RejectLinks(path);
        IntPtr name = IntPtr.Zero, filePtr = IntPtr.Zero, dataPtr = IntPtr.Zero;
        try
        {
            name = Marshal.StringToCoTaskMemUni(Path.GetFullPath(path));
            var file = new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = name
            };
            filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(file, filePtr, false);
            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = 2,              // WTD_UI_NONE
                fdwRevocationChecks = 1,      // WTD_REVOKE_WHOLECHAIN
                dwUnionChoice = 1,            // WTD_CHOICE_FILE
                pFile = filePtr,
                dwProvFlags = 0x00000080      // WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            };
            dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            Marshal.StructureToPtr(data, dataPtr, false);
            var id = GenericVerifyV2;
            if (WinVerifyTrust(IntPtr.Zero, ref id, dataPtr) != 0)
                return null;
            return SignedPublisherCertificateHash(path);
        }
        finally
        {
            if (dataPtr != IntPtr.Zero) Marshal.FreeHGlobal(dataPtr);
            if (filePtr != IntPtr.Zero) Marshal.FreeHGlobal(filePtr);
            if (name != IntPtr.Zero) Marshal.FreeCoTaskMem(name);
        }
    }

    private static ushort ExpectedMachine(string architecture) => architecture switch
    {
        "x64" => 0x8664,
        "arm64" => 0xaa64,
        _ => throw new InvalidDataException("Invalid release architecture.")
    };

    private static bool CorrectPeMachine(string path, string architecture)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length < 0x100) return false;
        using var reader = new BinaryReader(file);
        if (reader.ReadUInt16() != 0x5a4d) return false;
        file.Position = 0x3c;
        int pe = reader.ReadInt32();
        if (pe is < 64 || pe > file.Length - 6) return false;
        file.Position = pe;
        return reader.ReadUInt32() == 0x00004550 &&
            reader.ReadUInt16() == ExpectedMachine(architecture);
    }

    private static bool TrustedCandidate(string path, string expectedVersion,
        string publisher, bool unsignedPreview) =>
        CorrectPeMachine(path, Architecture) &&
        CorrectVersion(path, expectedVersion) &&
        (unsignedPreview
            ? VerifiedPublisher(path) is null
            : string.Equals(VerifiedPublisher(path), publisher,
                StringComparison.OrdinalIgnoreCase));

    private static string FileSha256(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read);
        return Convert.ToHexStringLower(SHA256.HashData(file));
    }

    private static bool CorrectVersion(string path, string expected)
    {
        string version = FileVersionInfo.GetVersionInfo(path).ProductVersion ?? "";
        return version == expected ||
            (version.StartsWith(expected, StringComparison.Ordinal) &&
             version.Length > expected.Length &&
             version[expected.Length] == '+');
    }

    private static async Task DownloadAsync(SignedUpdateOffer offer,
        string path, CancellationToken ct, IProgress<(long, long)>? progress)
    {
        using var http = CreateHttp();
        Uri url = offer.AssetUrl;
        for (int redirects = 0; redirects <= 5; redirects++)
        {
            if (!TrustedRedirect(url))
                throw new InvalidDataException("Unsigned or unapproved update download redirect.");
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("LinuxMailRelay365", "0.1"));
            using var response = await http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.RequestMessage?.RequestUri is not { } servedFrom ||
                !TrustedRedirect(servedFrom))
                throw new InvalidDataException("Updater HTTP redirect was not approved.");
            if (response.StatusCode is HttpStatusCode.MovedPermanently or
                HttpStatusCode.Redirect or HttpStatusCode.RedirectMethod or
                HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
            {
                var next = response.Headers.Location ??
                    throw new InvalidDataException("Update download redirected without Location.");
                url = next.IsAbsoluteUri ? next : new Uri(url, next);
                continue;
            }
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is { } length &&
                length != offer.ArchiveBytes)
                throw new InvalidDataException("Published update size differs.");
            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            long bytes = 0;
            // FileShare.None keeps the partial archive private while writing.
            // Dispose the writer BEFORE re-opening the file for SHA-256.
            await using (var output = new FileStream(path, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                byte[] buffer = new byte[81920];
                int count;
                while ((count = await stream.ReadAsync(buffer.AsMemory(), ct)) > 0)
                {
                    if (bytes + count > offer.ArchiveBytes || bytes + count > MaximumArchive)
                        throw new InvalidDataException("Update download exceeded exact published size.");
                    await output.WriteAsync(buffer.AsMemory(0, count), ct);
                    bytes += count;
                    progress?.Report((bytes, offer.ArchiveBytes));
                }
                await output.FlushAsync(ct);
            }
            if (bytes != offer.ArchiveBytes ||
                !string.Equals(FileSha256(path), offer.ArchiveSha,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Update download SHA-256 mismatch.");
            return;
        }
        throw new InvalidDataException("Too many update redirect hops.");
    }

    private static string ExtractSingleExe(string archivePath, string folder)
    {
        using var archive = ZipFile.OpenRead(archivePath);
        if (archive.Entries.Count != 1)
            throw new InvalidDataException("Update ZIP must contain exactly one EXE.");
        var entry = archive.Entries[0];
        if (entry.FullName != Executable ||
            entry.Length <= 0 || entry.Length > MaximumExecutable ||
            (entry.ExternalAttributes >> 16 & 0xF000) == 0xA000)
            throw new InvalidDataException("Unsafe update archive contents.");
        string extracted = Path.Combine(folder, Executable);
        using (var input = entry.Open())
        using (var output = new FileStream(extracted, FileMode.CreateNew, FileAccess.Write,
                   FileShare.None, 81920))
        {
            byte[] buffer = new byte[81920];
            long bytes = 0;
            int count;
            while ((count = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (bytes + count > entry.Length || bytes + count > MaximumExecutable)
                    throw new InvalidDataException("Update ZIP expansion exceeded limit.");
                output.Write(buffer, 0, count);
                bytes += count;
            }
            output.Flush(true);
            if (bytes != entry.Length)
                throw new InvalidDataException("Update EXE was truncated.");
        }
        return extracted;
    }

    private static async Task<bool> HealthAsync(string executable, CancellationToken ct)
    {
        using var process = Process.Start(new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList = { "--self-test" }
        }) ?? throw new IOException("Cannot start update self-test.");
        using var max = CancellationTokenSource.CreateLinkedTokenSource(ct);
        max.CancelAfter(TimeSpan.FromMinutes(2));
        try { await process.WaitForExitAsync(max.Token); }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            return false;
        }
        return process.ExitCode == 0;
    }

    internal static async Task StageAndLaunchAsync(SignedUpdateOffer offer,
        string publisher, CancellationToken ct,
        IProgress<(long, long)>? progress = null, bool unsignedPreview = false)
    {
        bool sourceApproved = unsignedPreview
            ? publisher.Length == 0 && IsPreviewRelease(offer) &&
              CanInstallPreview(out _)
            : Digest(publisher) &&
              CanInstall(out var currentPublisher, out _) &&
              string.Equals(currentPublisher, publisher, StringComparison.OrdinalIgnoreCase);
        if (!sourceApproved ||
            CompareVersions(offer.Version, UpdateCheck.Version) <= 0 ||
            offer.AssetName != ExpectedAsset ||
            !TrustedGithubUrl(offer.PageUrl,
                "/" + Repository + "/releases/tag/" + offer.Tag) ||
            !TrustedGithubUrl(offer.AssetUrl.ToString(),
                "/" + Repository + "/releases/download/" + offer.Tag + "/" + ExpectedAsset) ||
            !Digest(offer.ArchiveSha) ||
            offer.ArchiveBytes <= 0 || offer.ArchiveBytes > MaximumArchive)
            throw new InvalidOperationException("Update review no longer matches the installed app.");
        string original = Environment.ProcessPath!;
        string root = UpdateRoot();
        if (File.Exists(Path.Combine(root, "manual-review.hold")))
            throw new InvalidOperationException("Previous updater failure requires manual review.");
        string stage = Path.Combine(root, "stage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stage);
        try
        {
            RejectLinks(stage);
            string zip = Path.Combine(stage, offer.AssetName);
            await DownloadAsync(offer, zip, ct, progress);
            string candidate = ExtractSingleExe(zip, stage);
            if (!TrustedCandidate(candidate, offer.Version, publisher, unsignedPreview))
                throw new InvalidDataException("Update PE architecture, release version or publisher trust mismatch.");
            if (!await HealthAsync(candidate, ct))
                throw new InvalidDataException("Staged application self-test failed.");
            string sha = FileSha256(candidate);
            string helper = Path.Combine(stage, "LinuxMailRelay365-UpdateHelper.exe");
            File.Copy(original, helper, overwrite: false);
            if (!TrustedCandidate(helper, UpdateCheck.Version, publisher, unsignedPreview))
                throw new InvalidDataException("Update helper did not match installed publisher and version.");
            ct.ThrowIfCancellationRequested();
            var info = new ProcessStartInfo(helper)
            {
                UseShellExecute = false, CreateNoWindow = true,
                WorkingDirectory = stage
            };
            foreach (string argument in new[]
            {
                unsignedPreview ? "--apply-preview-update" : "--apply-signed-update",
                Environment.ProcessId.ToString(CultureInfo.InvariantCulture),
                original, candidate, sha,
                unsignedPreview ? PreviewPublisherMarker : publisher,
                stage, offer.Version
            }) info.ArgumentList.Add(argument);
            using var process = Process.Start(info) ??
                throw new IOException("Cannot start signed update helper.");
            // Caller must close current GUI immediately, allowing replacement.
        }
        catch
        {
            try { Directory.Delete(stage, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            throw;
        }
    }

    private static int RunInstalledHealth(string executable)
    {
        using var p = Process.Start(new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true,
            ArgumentList = { "--self-test" }
        });
        if (p is null) return 4;
        if (!p.WaitForExit(120000))
        {
            try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            return 4;
        }
        return p.ExitCode;
    }

    private static void WriteStatus(string root, string status)
    {
        try
        {
            File.WriteAllText(Path.Combine(root, "last-update-result.txt"), status + Environment.NewLine);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static string ParseUpdateStatus(string token) => token switch
    {
        "SIGNED_UPDATE_INSTALLED" or "UNSIGNED_PREVIEW_UPDATE_INSTALLED" => "INSTALLED",
        "SIGNED_UPDATE_ROLLED_BACK" or "UNSIGNED_PREVIEW_UPDATE_ROLLED_BACK" => "ROLLED_BACK",
        "SIGNED_UPDATE_FAILED_MANUAL_REVIEW" or
            "UNSIGNED_PREVIEW_UPDATE_FAILED_MANUAL_REVIEW" => "MANUAL_REVIEW_REQUIRED",
        _ => "UNKNOWN"
    };

    // Status is local and intentionally allowlisted, not rendered from raw file
    // contents, paths, usernames or error messages.
    internal static string LastUpdateStatus()
    {
        if (!OperatingSystem.IsWindows()) return "";
        try
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(local)) return "";
            string app = Path.Combine(local, "LinuxMailRelay365");
            string root = Path.Combine(app, "Updater");
            if (!Directory.Exists(root)) return "";
            RejectLinks(local);
            RejectLinks(app);
            RejectLinks(root);
            string hold = Path.Combine(root, "manual-review.hold");
            if (File.Exists(hold))
            {
                RejectLinks(hold);
                return "MANUAL_REVIEW_REQUIRED";
            }
            string result = Path.Combine(root, "last-update-result.txt");
            if (!File.Exists(result)) return "";
            RejectLinks(result);
            if (new FileInfo(result).Length > 128) return "UNKNOWN";
            return ParseUpdateStatus(File.ReadAllText(result).Trim());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or
            ArgumentException or System.Security.SecurityException)
        {
            return "UNAVAILABLE";
        }
    }

    internal static int ApplyFromHelper(string[] args, bool unsignedPreview = false)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 7 ||
            !int.TryParse(args[0], NumberStyles.None, CultureInfo.InvariantCulture, out int parentId) ||
            parentId <= 0 || !Digest(args[3]) ||
            !(unsignedPreview
                ? string.Equals(args[4], PreviewPublisherMarker, StringComparison.Ordinal)
                : Digest(args[4])) ||
            !VersionPattern.IsMatch(args[6]) ||
            (unsignedPreview &&
                (!UpdateCheck.Version.Contains("-preview.", StringComparison.Ordinal) ||
                 !Regex.IsMatch(args[6],
                     @"\A\d+\.\d+\.\d+-preview\.(0|[1-9]\d*)\z",
                     RegexOptions.CultureInvariant) ||
                 CompareVersions(args[6], UpdateCheck.Version) <= 0 ||
                 !IsNonElevatedWindowsProcess())))
            return 2;
        string target = Path.GetFullPath(args[1]);
        string candidate = Path.GetFullPath(args[2]);
        string stage = Path.GetFullPath(args[5]);
        string root = UpdateRoot();
        var compare = StringComparison.OrdinalIgnoreCase;
        if (Path.GetFileName(target) != Executable ||
            !string.Equals(Path.GetDirectoryName(candidate), stage, compare) ||
            !string.Equals(Path.GetDirectoryName(stage), root, compare) ||
            !Path.GetFileName(stage).StartsWith("stage-", StringComparison.Ordinal) ||
            !string.Equals(Path.GetFileName(candidate), Executable, StringComparison.Ordinal) ||
            !string.Equals(Path.GetDirectoryName(Environment.ProcessPath), stage, compare) ||
            !string.Equals(Path.GetFileName(Environment.ProcessPath),
                "LinuxMailRelay365-UpdateHelper.exe", StringComparison.Ordinal) ||
            !File.Exists(target) || !File.Exists(candidate))
            return 2;
        string backup = target + ".bak";
        string previousBackup = backup + ".prior-" + Guid.NewGuid().ToString("N");
        string next = target + ".update-new";
        string hold = Path.Combine(root, "manual-review.hold");
        bool movedPreviousBackup = false;
        bool replaced = false;
        bool rolledBack = false;
        try
        {
            RejectLinks(stage);
            RejectLinks(candidate);
            RejectLinks(target);
            RejectLinks(Path.GetDirectoryName(target)!);
            if (File.Exists(hold) || File.Exists(next) ||
                !TrustedCandidate(Environment.ProcessPath!, UpdateCheck.Version,
                    args[4], unsignedPreview) ||
                !TrustedCandidate(target, UpdateCheck.Version, args[4], unsignedPreview) ||
                !TrustedCandidate(candidate, args[6], args[4], unsignedPreview) ||
                !string.Equals(FileSha256(candidate), args[3], StringComparison.OrdinalIgnoreCase))
                return 2;
            try
            {
                using var parent = Process.GetProcessById(parentId);
                if (!parent.WaitForExit(90000))
                    return 3;
            }
            catch (ArgumentException) { /* Already exited. */ }
            // All executable signature/hash checks are repeated AFTER waiting.
            if (!TrustedCandidate(target, UpdateCheck.Version, args[4], unsignedPreview) ||
                !TrustedCandidate(candidate, args[6], args[4], unsignedPreview) ||
                !string.Equals(FileSha256(candidate), args[3], compare))
                throw new InvalidDataException("Publisher or EXE changed while waiting.");
            // An atomic same-volume File.Replace cannot be performed from the
            // source EXE process; this helper is a signed verified copy.
            using var mutex = new FileStream(target + ".update.lock", FileMode.OpenOrCreate,
                FileAccess.ReadWrite, FileShare.None);
            File.Copy(candidate, next, overwrite: false);
            if (!string.Equals(FileSha256(next), args[3], compare) ||
                !TrustedCandidate(next, args[6], args[4], unsignedPreview))
                throw new InvalidDataException("Prepared update copy changed.");
            if (File.Exists(backup))
            {
                RejectLinks(backup);
                File.Move(backup, previousBackup);
                movedPreviousBackup = true;
            }
            File.Replace(next, target, backup, ignoreMetadataErrors: false);
            replaced = true;
            if (RunInstalledHealth(target) != 0 ||
                !string.Equals(FileSha256(target), args[3], compare))
                throw new InvalidOperationException("Installed application health test failed.");
            var started = Process.Start(new ProcessStartInfo(target)
            {
                UseShellExecute = true, WorkingDirectory = Path.GetDirectoryName(target)!
            });
            if (started is null)
                throw new IOException("Updated application could not be started.");
            WriteStatus(root, unsignedPreview ?
                "UNSIGNED_PREVIEW_UPDATE_INSTALLED" : "SIGNED_UPDATE_INSTALLED");
            // The newly created .bak is the immediate rollback checkpoint.
            // The pre-existing .bak is no longer needed after a healthy start.
            if (movedPreviousBackup)
            {
                try { File.Delete(previousBackup); } catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            return 0;
        }
        catch (Exception)
        {
            if (replaced && File.Exists(backup))
            {
                try
                {
                    // Windows File.Replace requires a non-empty backup pathname.
                    // The previously consumed .update-new name is available and
                    // will be removed in finally after restoring the old EXE.
                    File.Replace(backup, target, next, ignoreMetadataErrors: false);
                    rolledBack = true;
                }
                catch (Exception) { rolledBack = false; }
            }
            if (movedPreviousBackup && File.Exists(previousBackup))
            {
                try
                {
                    if (!File.Exists(backup))
                        File.Move(previousBackup, backup);
                }
                catch (IOException) { rolledBack = false; }
                catch (UnauthorizedAccessException) { rolledBack = false; }
            }
            WriteStatus(root, replaced && rolledBack ?
                (unsignedPreview ? "UNSIGNED_PREVIEW_UPDATE_ROLLED_BACK" : "SIGNED_UPDATE_ROLLED_BACK") :
                (unsignedPreview ? "UNSIGNED_PREVIEW_UPDATE_FAILED_MANUAL_REVIEW" : "SIGNED_UPDATE_FAILED_MANUAL_REVIEW"));
            try { File.WriteAllText(hold, "Manual review required before another update."); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            return replaced && rolledBack ? 4 : 5;
        }
        finally
        {
            try { if (File.Exists(next)) File.Delete(next); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static bool ArchiveAndPeSafetySelfTest()
    {
        string folder = Path.Combine(Path.GetTempPath(),
            "lmr365-updater-safety-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            string traversalZip = Path.Combine(folder, "traversal.zip");
            using (var archive = ZipFile.Open(traversalZip, ZipArchiveMode.Create))
                archive.CreateEntry("../untrusted.exe");
            try { ExtractSingleExe(traversalZip, folder); return false; }
            catch (InvalidDataException) { }

            string duplicateZip = Path.Combine(folder, "duplicate.zip");
            using (var archive = ZipFile.Open(duplicateZip, ZipArchiveMode.Create))
            {
                archive.CreateEntry(Executable);
                archive.CreateEntry(Executable);
            }
            try { ExtractSingleExe(duplicateZip, folder); return false; }
            catch (InvalidDataException) { }

            string fakePe = Path.Combine(folder, Executable);
            byte[] pe = new byte[512];
            pe[0] = 0x4d; pe[1] = 0x5a; // MZ
            pe[0x3c] = 0x80;            // e_lfanew
            pe[0x80] = 0x50; pe[0x81] = 0x45; // PE header
            pe[0x84] = 0x64; pe[0x85] = 0x86; // x64 machine
            File.WriteAllBytes(fakePe, pe);
            return CorrectPeMachine(fakePe, "x64") &&
                   !CorrectPeMachine(fakePe, "arm64") &&
                   !CorrectVersion(fakePe, "0.1.1") &&
                   !File.Exists(Path.Combine(folder, "untrusted.exe"));
        }
        finally
        {
            try { Directory.Delete(folder, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    internal static bool SelfTest()
    {
        if (CompareVersions("0.1.0", "0.1.0-preview.22") <= 0 ||
            CompareVersions("0.1.0-preview.23", "0.1.0-preview.22") <= 0 ||
            CompareVersions("0.1.0-preview.9", "0.1.0-preview.22") >= 0 ||
            TrustedGithubUrl("https://bad.example/test",
                "/sgennadi/LinuxMailRelay365/releases/tag/v0.1.1"))
            return false;
        var asset = "LinuxMailRelay365-win-x64.zip";
        const string hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        static string Fixture(string asset, string digest, bool preview,
            bool duplicate = false)
        {
            string link = "https://github.com/sgennadi/LinuxMailRelay365/releases/download/" +
                "v0.1.0-preview.23/" + asset;
            string item = JsonSerializer.Serialize(new
            {
                name = asset, digest = "sha256:" + digest, size = 100L,
                browser_download_url = link
            });
            return "[{\"tag_name\":\"v0.1.0-preview.23\",\"draft\":false," +
                "\"prerelease\":" + (preview ? "true" : "false") +
                ",\"html_url\":\"https://github.com/sgennadi/LinuxMailRelay365/releases/tag/" +
                "v0.1.0-preview.23\",\"assets\":[" + item +
                (duplicate ? "," + item : "") + "]}]";
        }
        static SignedUpdateOffer? Parse(string json, bool allow)
        {
            using var document = JsonDocument.Parse(json);
            return SelectRelease(document.RootElement, allow, "0.1.0-preview.22",
                "LinuxMailRelay365-win-x64.zip");
        }
        using var previewFixture = JsonDocument.Parse(Fixture(asset, hash, true));
        var fixtureOffer = SelectRelease(previewFixture.RootElement, true,
            "0.1.0-preview.22", asset);
        return ApplyFromHelper(Array.Empty<string>()) == 2 &&
               ApplyFromHelper(Array.Empty<string>(), unsignedPreview: true) == 2 &&
               fixtureOffer is not null && IsPreviewRelease(fixtureOffer) &&
               !IsPreviewRelease(new SignedUpdateOffer("0.1.1", "v0.1.1",
                   "https://github.com/sgennadi/LinuxMailRelay365/releases/tag/v0.1.1",
                   new Uri("https://github.com/sgennadi/LinuxMailRelay365/releases/download/v0.1.1/" + asset),
                   asset, hash, 100L)) &&
               Parse(Fixture(asset, hash, true), true)?.Version == "0.1.0-preview.23" &&
               Parse(Fixture(asset, hash, true), false) is null &&
               Parse(Fixture(asset, hash, false), false) is null &&
               Parse(Fixture(asset, hash, true, duplicate: true), true) is null &&
               Parse(Fixture(asset, "bad", true), true) is null &&
               Parse(Fixture("other.zip", hash, true), true) is null &&
               !TrustedRedirect(new Uri("http://release-assets.githubusercontent.com/x")) &&
               !TrustedRedirect(new Uri("https://attacker@github.com/x")) &&
               !Digest("not-a-hash") &&
               ParseUpdateStatus("UNSIGNED_PREVIEW_UPDATE_INSTALLED") == "INSTALLED" &&
               ParseUpdateStatus("UNSIGNED_PREVIEW_UPDATE_ROLLED_BACK") == "ROLLED_BACK" &&
               ParseUpdateStatus("UNSIGNED_PREVIEW_UPDATE_FAILED_MANUAL_REVIEW") ==
                   "MANUAL_REVIEW_REQUIRED" &&
               ParseUpdateStatus("untrusted message\r\nDOWNLOADED") == "UNKNOWN" &&
               ArchiveAndPeSafetySelfTest();
    }
}
