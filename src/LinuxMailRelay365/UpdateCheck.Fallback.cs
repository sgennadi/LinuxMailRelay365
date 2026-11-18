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
    internal const string Version = "0.1.0-preview.12";
    private const int MaximumMetadataBytes = 2 * 1024 * 1024;

    internal static async Task<(string? url, string message)> QueryAsync(
        bool includePreview, CancellationToken ct)
    {
        const string repository = "sgennadi/LinuxMailRelay365";
        string platform = RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "arm64" : "x64";
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
        string? bestUrl = null;
        string? bestVersion = null;
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object || Bool(item, "draft")) continue;
            bool prerelease = Bool(item, "prerelease");
            if (prerelease && !includePreview) continue;
            string tag = Str(item, "tag_name").TrimStart('v');
            if (!ReleaseVersion.IsValid(tag) || ReleaseVersion.Compare(tag, Version) <= 0) continue;
            if (!item.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
                continue;
            bool hasSafeAsset = false;
            foreach (var asset in assets.EnumerateArray())
            {
                if (!string.Equals(Str(asset, "name"), expectedAsset, StringComparison.Ordinal)) continue;
                if (!Regex.IsMatch(Str(asset, "digest"), "^sha256:[A-Fa-f0-9]{64}$")) continue;
                if (!asset.TryGetProperty("size", out var size) || !size.TryGetInt64(out long count) ||
                    count is < 1 or > 500_000_000) continue;
                if (!SafeGithubUrl(Str(asset, "browser_download_url"),
                    $"/{repository}/releases/download/{Str(item, "tag_name")}/{expectedAsset}")) continue;
                hasSafeAsset = true;
                break;
            }
            if (!hasSafeAsset) continue;
            string page = Str(item, "html_url");
            if (!SafeGithubUrl(page, $"/{repository}/releases/tag/{Str(item, "tag_name")}")) continue;
            if (bestVersion is null || ReleaseVersion.Compare(tag, bestVersion) > 0)
            { bestVersion = tag; bestUrl = page; }
        }
        return bestUrl is null
            ? (null, "No newer verified GitHub release is available. Installation is not automatic.")
            : (bestUrl, "Version " + bestVersion + " is available. Review the release before installing.");
    }

    private static string Str(JsonElement element, string name) =>
        element.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString() ?? "" : "";
    private static bool Bool(JsonElement element, string name) =>
        element.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.True;

    private static bool SafeGithubUrl(string candidate, string exactPath) =>
        Uri.TryCreate(candidate, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host == "github.com" &&
        uri.Port == 443 && uri.Query.Length == 0 && uri.Fragment.Length == 0 &&
        uri.AbsolutePath == exactPath;
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
        Compare("0.1.0-preview.12", "0.1.0-preview.3") > 0 &&
        Compare("0.1.0", "0.1.0-preview.12") > 0 &&
        Compare("0.1.0", "0.1.1") < 0;
}
#endif
