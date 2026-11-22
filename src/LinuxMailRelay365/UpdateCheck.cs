#if USE_UNIVERSAL_UPDATER
using UniversalUpdater;

namespace LinuxMailRelay365;

internal static class UpdateCheck
{
    internal const string Version = "0.1.1-rc.2";
    internal static async Task<(string? url, string message)> QueryAsync(bool includePreview, CancellationToken ct)
    {
        string architecture = UpdateOptions.CurrentWindowsArchitecture();
        var rule = architecture == "win-arm64"
            ? new UpdateAssetRule("win-arm64", "LinuxMailRelay365-win-arm64.zip", PackageKind.SingleExeZip, "LinuxMailRelay365.exe")
            : new UpdateAssetRule("win-x64", "LinuxMailRelay365-win-x64.zip", PackageKind.SingleExeZip, "LinuxMailRelay365.exe");
        using var client = new GitHubReleaseClient();
        UpdateRelease? best = null;
        foreach (var channel in includePreview
            ? new[] { UpdateChannel.Stable, UpdateChannel.Prerelease }
            : new[] { UpdateChannel.Stable })
        {
            var options = new UpdateOptions
            {
                ProductId = "LinuxMailRelay365",
                Repository = "sgennadi/LinuxMailRelay365",
                InstalledVersion = Version,
                Architecture = architecture,
                Channel = channel,
                Assets = [rule]
            };
            var release = await client.CheckAsync(options, ct);
            if (release is not null && (best is null || release.Version > best.Version))
                best = release;
        }
        return best is null
            ? (null, "No matching new signed/digested GitHub release available. This may be expected before the repository is published.")
            : (best.ReleaseUrl, "Update available: " + best.Version);
    }
}
#endif
