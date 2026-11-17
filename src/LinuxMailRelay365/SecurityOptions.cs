using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LinuxMailRelay365;

// Preferences are never proof that Microsoft 365 or the Linux hardware was changed.
// All optional security mechanisms start OFF. Stored data contains no secrets.
internal sealed class SecurityOptions
{
    public bool RequestHardwareBackedKey { get; set; } = false;
    public bool RequestIpConditionalAccess { get; set; } = false;
    public bool RequestEntraSignInMonitoring { get; set; } = false;
}

internal static class SecurityOptionsStore
{
    internal static string Identity(SshEndpoint endpoint)
    {
        endpoint.Validate();
        string canonical = $"{endpoint.Host.ToLowerInvariant()}|{endpoint.Port}|{endpoint.Username.ToLowerInvariant()}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))[..24].ToLowerInvariant();
    }

    internal static string FilePath(string directory, SshEndpoint endpoint) =>
        Path.Combine(directory, "security-plan-" + Identity(endpoint) + ".json");

    internal static SecurityOptions Load(string directory, SshEndpoint endpoint)
    {
        string path = FilePath(directory, endpoint);
        if (!File.Exists(path)) return new SecurityOptions();
        try
        {
            return JsonSerializer.Deserialize<SecurityOptions>(File.ReadAllText(path))
                ?? new SecurityOptions();
        }
        catch (JsonException)
        {
            // Refuse to silently reset a damaged plan; the operator must inspect it.
            throw new InvalidDataException("The saved security plan is invalid. Review " + path);
        }
    }

    internal static void Save(string directory, SshEndpoint endpoint, SecurityOptions value)
    {
        Directory.CreateDirectory(directory);
        string path = FilePath(directory, endpoint);
        string temporary = path + ".tmp";
        var payload = JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(temporary, payload + Environment.NewLine, new UTF8Encoding(false));
        File.Move(temporary, path, overwrite: true);
    }
}

// The scanner does not trust a TPM device node, PKCS#11 library or driver alone
// as evidence that hardware signing is ready for use with our OAuth transport.
internal sealed class LinuxSecurityInventory
{
    private readonly Dictionary<string, string> data;
    private LinuxSecurityInventory(Dictionary<string, string> values) => data = values;

    internal static LinuxSecurityInventory Parse(string stdout)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in stdout.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var split = line.IndexOf('=');
            if (split < 2 || split > 60) continue;
            var key = line[..split];
            if (!key.All(c => char.IsAsciiLetterUpper(c) || char.IsAsciiDigit(c) || c == '_')) continue;
            var value = line[(split + 1)..];
            if (value.Length > 250 || value.Any(char.IsControl)) continue;
            values[key] = value;
        }
        if (values.GetValueOrDefault("PROBE_VERSION") != "2")
            throw new InvalidDataException("Unexpected Linux security probe version.");
        return new LinuxSecurityInventory(values);
    }

    internal string Get(string key) => data.GetValueOrDefault(key, "unknown");
    internal bool HasTpm2 => Get("TPM_VERSION") == "2" && Get("TPM_DEVICE") != "unavailable";
    internal bool TpmResponded => HasTpm2 && Get("TPM2_COMMAND_PROBE") == "responding";
    internal bool HasPkcs11TokenHint => Get("PKCS11_TOKENS") == "detected_unverified";
    internal bool HardwareSigningReady => Get("HARDWARE_SIGNING_CONFIGURED") == "yes";

    internal string SummaryRu() =>
        $"ОС: {Get("OS_ID")} {Get("OS_VERSION")}; MTA: {Get("MTA")}\n" +
        $"TPM: версия {Get("TPM_VERSION")}, устройство {Get("TPM_DEVICE")}; доступ: {Get("TPM_DEVICE_ACCESS")}\n" +
        $"TPM2 tools: {Get("TPM2_TOOLS")}; проверка ответа: {Get("TPM2_COMMAND_PROBE")}\n" +
        $"PKCS#11 tools: {Get("PKCS11_TOOL")}; токены: {Get("PKCS11_TOKENS")}\n" +
        $"TPM2 PKCS#11: {Get("TPM2_PKCS11_TOOL")}; p11-kit: {Get("PKCS11_MIDDLEWARE")}\n" +
        "Аппаратная подпись: не подтверждена; автоматически не включалась. Совместимость транспорта ещё не проверена.";
}

internal static class SecurityOptionsSelfTest
{
    internal static bool Run()
    {
        string directory = Path.Combine(Path.GetTempPath(), "LMR365-tests-" + Guid.NewGuid().ToString("N"));
        try
        {
            var a = new SshEndpoint("server-a.example", 22, "admin", "");
            var b = new SshEndpoint("server-b.example", 22, "admin", "");
            var first = SecurityOptionsStore.Load(directory, a);
            if (first.RequestHardwareBackedKey || first.RequestIpConditionalAccess ||
                first.RequestEntraSignInMonitoring) return false;
            first.RequestIpConditionalAccess = true;
            SecurityOptionsStore.Save(directory, a, first);
            var reloaded = SecurityOptionsStore.Load(directory, a);
            var independent = SecurityOptionsStore.Load(directory, b);
            if (!reloaded.RequestIpConditionalAccess ||
                independent.RequestIpConditionalAccess || independent.RequestHardwareBackedKey)
                return false;
            var report = LinuxSecurityInventory.Parse(
                "PROBE_VERSION=2\nTPM_VERSION=2\nTPM_DEVICE=/dev/tpmrm0\n" +
                "TPM2_COMMAND_PROBE=responding\nHARDWARE_SIGNING_CONFIGURED=not_verified\n");
            return report.HasTpm2 && report.TpmResponded && !report.HardwareSigningReady;
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}
