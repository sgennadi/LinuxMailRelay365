using System.Text.Json;
using System.Text.Json.Serialization;

namespace LinuxMailRelay365;

// Deliberately no password, sudo password, key path, host-key trust,
// tenant, tokens or arbitrary settings. Never serialize SshEndpoint.
internal sealed record SshProfile(string Host, int Port, string Username, bool PasswordMode)
{
    internal void Validate()
    {
        if (Host is null || Username is null || Host != Host.Trim() || Username != Username.Trim())
            throw new InvalidDataException("Invalid saved SSH endpoint.");
        new SshEndpoint(Host, Port, Username, "").Validate();
    }

    internal bool SameEndpoint(SshProfile other) =>
        Port == other.Port && string.Equals(Host, other.Host, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(Username, other.Username, StringComparison.Ordinal);

    public override string ToString() => $"{Username}@{Host}:{Port}";
}

internal static class SshProfileStore
{
    private const int MaxProfiles = 100;
    private const int MaxBytes = 128 * 1024;
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private static string FilePath(string directory) => Path.Combine(directory, "ssh-profiles.json");

    private static void Validate(IReadOnlyList<SshProfile> profiles)
    {
        if (profiles.Count > MaxProfiles) throw new InvalidDataException("Too many SSH profiles.");
        for (int i = 0; i < profiles.Count; i++)
        {
            var profile = profiles[i] ?? throw new InvalidDataException("Invalid SSH profile.");
            profile.Validate();
            if (profiles.Take(i).Any(p => p.SameEndpoint(profile)))
                throw new InvalidDataException("Duplicate SSH profile.");
        }
    }

    internal static IReadOnlyList<SshProfile> Load(string directory)
    {
        string path = FilePath(directory);
        if (!File.Exists(path)) return Array.Empty<SshProfile>();
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length > MaxBytes) throw new InvalidDataException("SSH profile file is too large.");
        using var document = JsonDocument.Parse(file);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Invalid SSH profile collection.");
        foreach (var item in document.RootElement.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid SSH profile.");
            var keys = item.EnumerateObject().Select(p => p.Name).ToArray();
            if (keys.Length != 4 || !new HashSet<string>(StringComparer.Ordinal)
                { "Host", "Port", "Username", "PasswordMode" }.SetEquals(keys))
                throw new InvalidDataException("Unexpected SSH profile fields.");
        }
        var profiles = document.RootElement.Deserialize<SshProfile[]>(Options)
            ?? throw new InvalidDataException("Invalid SSH profile collection.");
        Validate(profiles);
        return profiles;
    }

    private static void Save(string directory, IReadOnlyList<SshProfile> profiles)
    {
        Validate(profiles);
        Directory.CreateDirectory(directory);
        string path = FilePath(directory);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var data = JsonSerializer.SerializeToUtf8Bytes(profiles, Options);
            if (data.Length > MaxBytes) throw new InvalidDataException("SSH profile file is too large.");
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(data);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    internal static IReadOnlyList<SshProfile> Remember(string directory, SshProfile profile)
    {
        profile.Validate();
        var old = Load(directory);
        var profiles = new[] { profile }.Concat(old.Where(p => !p.SameEndpoint(profile)))
            .Take(MaxProfiles).ToArray();
        Save(directory, profiles);
        return profiles;
    }

    internal static IReadOnlyList<SshProfile> Remove(string directory, SshProfile profile)
    {
        var profiles = Load(directory).Where(p => !p.SameEndpoint(profile)).ToArray();
        Save(directory, profiles);
        return profiles;
    }

    internal static bool SelfTest()
    {
        string directory = Path.Combine(Path.GetTempPath(), "LMR365-ssh-" + Guid.NewGuid().ToString("N"));
        try
        {
            if (Load(directory).Count != 0) return false;
            var a = new SshProfile("one.example.org", 22, "root", true);
            var b = new SshProfile("two.example.org", 2222, "operator", false);
            Remember(directory, a);
            Remember(directory, b);
            var updated = a with { PasswordMode = false };
            var list = Remember(directory, updated);
            if (!list.SequenceEqual(new[] { updated, b }) || !Load(directory).SequenceEqual(list))
                return false;
            using (var json = JsonDocument.Parse(File.ReadAllBytes(FilePath(directory))))
                if (json.RootElement.EnumerateArray().Any(item =>
                    !new HashSet<string> { "Host", "Port", "Username", "PasswordMode" }
                        .SetEquals(item.EnumerateObject().Select(p => p.Name)))) return false;
            if (!Remove(directory, a).SequenceEqual(new[] { b })) return false;
            string invalid = "[{\"Host\":\"one.example.org\",\"Port\":22,\"Username\":\"root\",\"PasswordMode\":true,\"Password\":\"fixture\"}]";
            File.WriteAllText(FilePath(directory), invalid);
            try { Remember(directory, a); return false; } catch (InvalidDataException) {}
            return File.ReadAllText(FilePath(directory)) == invalid;
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }
}
