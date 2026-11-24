#if !USE_UNIVERSAL_UPDATER
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Standalone, READ-ONLY updater fallback. This only discovers eligible releases;
// it never downloads, executes or installs software. When the user's shared
// UniversalUpdater module is present, the full shared verifier is compiled instead.
internal static class UpdateCheck
{
    internal const string Version = "0.1.1-rc.17";
    private const int MaximumMetadataBytes = 2 * 1024 * 1024;
    private const string Repository = "sgennadi/LinuxMailRelay365";

    internal static async Task<(string? url, string message)> QueryAsync(
        bool includePreview, CancellationToken ct)
    {
        const string repository = Repository;
        // Download for the running PE architecture, not the OS: a win-x64
        // executable can run under ARM64 Windows emulation.
        string platform = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => throw new PlatformNotSupportedException("Unsupported Windows update architecture.")
        };
        string expectedAsset = $"LinuxMailRelay365-win-{platform}.zip";
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        { Timeout = TimeSpan.FromSeconds(20), MaxResponseContentBufferSize = MaximumMetadataBytes };
        using var request = new HttpRequestMessage(HttpMethod.Get,
            "https://api.github.com/repos/" + repository + "/releases?per_page=50");
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("LinuxMailRelay365", "0.1"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return (null, "The GitHub repository has no published releases yet.");
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > MaximumMetadataBytes)
            throw new InvalidDataException("GitHub release metadata is too large.");
        byte[] bytes = await response.Content.ReadAsByteArrayAsync(ct);
        if (bytes.Length > MaximumMetadataBytes)
            throw new InvalidDataException("GitHub release metadata is too large.");
        using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 24 });
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Unexpected GitHub API response.");
        var (bestUrl, bestVersion) = SelectRelease(doc.RootElement, expectedAsset, includePreview);
        return bestUrl is null
            ? (null, "No eligible newer published GitHub Release was found. " +
                "Matching releases must be strictly newer than the installed SemVer version.")
            : (bestUrl, "Version " + bestVersion +
                " is available. Installation requires operator consent and an Authenticode-signed app/update with matching Windows-trusted publisher.");
    }

    // Strictly read-only catalog selection. A GitHub-provided SHA is metadata,
    // not proof of Authenticode or the publisher's trustworthiness.
    internal static (string? Url, string? Version) SelectRelease(
        JsonElement releases, string expectedAsset, bool includePreview)
    {
        if (releases.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Expected a GitHub release catalog array.");
        string? bestUrl = null;
        string? bestVersion = null;
        foreach (var item in releases.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object || Bool(item, "draft")) continue;
            string rawTag = Str(item, "tag_name");
            if (rawTag.StartsWith('v')) rawTag = rawTag[1..];
            string tag = rawTag;
            if (!ReleaseVersion.IsValid(tag) || ReleaseVersion.Compare(tag, Version) <= 0) continue;
            bool prerelease = Bool(item, "prerelease") || tag.Contains('-');
            if (prerelease && !includePreview) continue;
            if (!item.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
                continue;
            bool hasSafeAsset = false;
            bool duplicateAsset = false;
            int matchingAssets = 0;
            foreach (var asset in assets.EnumerateArray())
            {
                if (!string.Equals(Str(asset, "name"), expectedAsset, StringComparison.Ordinal)) continue;
                matchingAssets++;
                if (matchingAssets > 1) { duplicateAsset = true; break; }
                if (!Regex.IsMatch(Str(asset, "digest"), "^sha256:[A-Fa-f0-9]{64}$")) continue;
                if (!asset.TryGetProperty("size", out var size) || !size.TryGetInt64(out long count) ||
                    count is < 1 or > 500_000_000) continue;
                if (!SafeGithubUrl(Str(asset, "browser_download_url"),
                    $"/{Repository}/releases/download/{Str(item, "tag_name")}/{expectedAsset}")) continue;
                hasSafeAsset = true;
                // Continue scanning: duplicate architecture assets make the
                // release ambiguous even if the first one was valid.
            }
            if (!hasSafeAsset || duplicateAsset) continue;
            string page = Str(item, "html_url");
            if (!SafeGithubUrl(page, $"/{Repository}/releases/tag/{Str(item, "tag_name")}")) continue;
            if (bestVersion is null || ReleaseVersion.Compare(tag, bestVersion) > 0)
            { bestVersion = tag; bestUrl = page; }
        }
        return (bestUrl, bestVersion);
    }

    internal static bool SelfTest()
    {
        static string Catalog(string tag, bool prerelease, string digest, string asset,
            string? pageOverride = null, bool duplicate = false)
        {
            string fullTag = "v" + tag;
            string assetUrl = "https://github.com/sgennadi/LinuxMailRelay365/releases/download/" +
                fullTag + "/" + asset;
            string page = pageOverride ??
                "https://github.com/sgennadi/LinuxMailRelay365/releases/tag/" + fullTag;
            string entry = System.Text.Json.JsonSerializer.Serialize(new
            {
                name = asset, digest, size = 10_000L,
                browser_download_url = assetUrl
            });
            return "[{\"draft\":false,\"prerelease\":" +
                (prerelease ? "true" : "false") +
                ",\"tag_name\":\"" + fullTag +
                "\",\"html_url\":\"" + page +
                "\",\"assets\":[" + entry +
                (duplicate ? "," + entry : "") + "]}]";
        }
        static (string?, string?) Select(string json, bool preview)
        {
            using var doc = JsonDocument.Parse(json);
            return SelectRelease(doc.RootElement, "LinuxMailRelay365-win-x64.zip", preview);
        }
        const string name = "LinuxMailRelay365-win-x64.zip";
        const string sha = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // A numeric Stable 0.1.0 must NOT downgrade to any 0.1.0 Preview.
        // A future 0.1.1 Preview is newer, but is visible only when Preview is opted in.
        const string newerPreview = "0.1.2-preview.1";
        if (Select(Catalog("0.1.0-preview.26", true, sha, name), true).Item1 is not null ||
            Select(Catalog(newerPreview, true, sha, name), false).Item1 is not null ||
            Select(Catalog(newerPreview, true, sha, name), true).Item2 != newerPreview ||
            Select(Catalog(newerPreview, false, sha, name), false).Item1 is not null ||
            Select(Catalog("0.1.0-preview.16", true, sha, name), true).Item1 is not null ||
            Select(Catalog("0.1.1", false, sha, name), false).Item2 != "0.1.1" ||
            Select(Catalog("0.1.1", false, "sha256:invalid", name), true).Item1 is not null ||
            Select(Catalog("0.1.1", false, sha, "wrong.zip"), true).Item1 is not null ||
            Select(Catalog("0.1.1", false, sha, name, duplicate:true), true).Item1 is not null ||
            Select(Catalog("0.1.1", false, sha, name,
                "https://attacker@github.com/sgennadi/LinuxMailRelay365/releases/tag/v0.1.1"),
                true).Item1 is not null)
            return false;
        return true;
    }

    private static string Str(JsonElement element, string name) =>
        element.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString() ?? "" : "";
    private static bool Bool(JsonElement element, string name) =>
        element.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.True;

    private static bool SafeGithubUrl(string candidate, string exactPath) =>
        Uri.TryCreate(candidate, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps &&
        string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase) &&
        uri.IsDefaultPort && uri.UserInfo.Length == 0 &&
        uri.Query.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(Uri.UnescapeDataString(uri.AbsolutePath), exactPath, StringComparison.Ordinal);
}

internal static class ReleaseVersion
{
    private static readonly Regex Pattern = new(
        @"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([A-Za-z0-9][A-Za-z0-9.-]*))?$",
        RegexOptions.CultureInvariant);
    internal static bool IsValid(string value) => Pattern.IsMatch(value);
    internal static int Compare(string a, string b)
    {
        var x = Pattern.Match(a); var y = Pattern.Match(b);
        if (!x.Success || !y.Success) throw new FormatException("Invalid release version.");
        for (int i = 1; i <= 3; i++)
        {
            // unsigned to cover valid SemVer without integer overflows
            var n = CompareDigits(x.Groups[i].Value, y.Groups[i].Value);
            if (n != 0) return n;
        }
        string preX = x.Groups[4].Value, preY = y.Groups[4].Value;
        if (preX.Length == 0) return preY.Length == 0 ? 0 : 1;
        if (preY.Length == 0) return -1;
        var xa = preX.Split('.'); var ya = preY.Split('.');
        for (int i = 0; i < Math.Min(xa.Length, ya.Length); i++)
        {
            bool xn = xa[i].All(char.IsAsciiDigit), yn = ya[i].All(char.IsAsciiDigit);
            int c = xn && yn ? CompareDigits(xa[i], ya[i]) :
                    xn ? -1 : yn ? 1 : string.CompareOrdinal(xa[i], ya[i]);
            if (c != 0) return c;
        }
        return xa.Length.CompareTo(ya.Length);
    }
    private static int CompareDigits(string x, string y)
    {
        x = x.TrimStart('0'); y = y.TrimStart('0');
        if (x.Length != y.Length) return x.Length.CompareTo(y.Length);
        return string.CompareOrdinal(x, y);
    }

    internal static bool SelfTest() =>
        Compare("0.1.1", "0.1.1-preview.9") > 0 &&
        Compare("0.1.1-preview.10", "0.1.1-preview.9") > 0 &&
        Compare("0.1.1-rc.5", "0.1.1-rc.4") > 0 &&
        Compare("0.1.1-rc.6", "0.1.1-rc.5") > 0 &&
        Compare("0.1.1-rc.7", "0.1.1-rc.6") > 0 &&
        Compare("0.1.1", "0.1.1-rc.7") > 0 &&
        Compare("0.1.1", "0.1.1-rc.6") > 0 &&
        Compare("0.1.1", "0.1.1-rc.5") > 0 &&
        Compare("0.1.0-preview.16", "0.1.0-preview.3") > 0 &&
        Compare("0.1.0", "0.1.0-preview.16") > 0 &&
        Compare("0.1.0", "0.1.1") < 0;
}
#endif
