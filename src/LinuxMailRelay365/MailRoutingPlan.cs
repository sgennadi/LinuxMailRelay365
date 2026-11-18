using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Configuration INTENT only. No routing option in this file changes Postfix,
// Entra, MX, SPF, connector permissions, sender identity or DNS.
internal sealed class MailRoutingPlan
{
    public string Transport { get; set; } = "oauth2";
    public string SenderPolicy { get; set; } = "fixed-mailbox";
    public bool PreserveExistingMail { get; set; } = true;
    public string VerifiedDomain { get; set; } = "";
    public string ListenIpv4 { get; set; } = "";
    public string TrustedCidrs { get; set; } = "";
    public int SidecarPort { get; set; } = 2525;
}

internal sealed record MailRoutingInventory(string Mta, string CurrentRelay, string CurrentTransport, string ConfigSha256)
{
    internal static MailRoutingInventory Parse(string text)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            int n = line.IndexOf('=');
            if (n < 1 || n > 50 || line.Length > 1024) continue;
            values[line[..n]] = line[(n + 1)..].Trim();
        }
        if (values.GetValueOrDefault("PROBE_VERSION") != "2")
            throw new InvalidDataException("Unsupported Linux routing probe.");
        var mta = values.GetValueOrDefault("MTA") ?? "unknown";
        if (mta is not ("none" or "postfix" or "sendmail" or "exim"))
            throw new InvalidDataException("Unknown MTA; refusing to modify a mail server.");
        return new MailRoutingInventory(mta,
            values.GetValueOrDefault("POSTFIX_RELAY") ?? "",
            values.GetValueOrDefault("POSTFIX_TRANSPORT") ?? "",
            values.GetValueOrDefault("POSTFIX_CONFIG_SHA256") ?? "unavailable");
    }
}

internal static class MailRoutingPlanStore
{
    internal static string Identity(string host, string port, string user)
    {
        var name = host.Trim().ToLowerInvariant();
        var login = user.Trim().ToLowerInvariant();
        if (!Regex.IsMatch(name, @"^[a-z0-9][a-z0-9.-]{0,252}$",
                RegexOptions.CultureInvariant) ||
            !int.TryParse(port, out int number) || number is < 1 or > 65535 ||
            !Regex.IsMatch(login, @"^[a-z_][a-z0-9_-]{0,31}$",
                RegexOptions.CultureInvariant))
            throw new ArgumentException("Check the Linux hostname, SSH port and username.");
        var id = name + "|" + number + "|" + login;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(id)))[..24].ToLowerInvariant();
    }

    internal static string PathFor(string directory, string identity) =>
        Path.Combine(directory, "routing-plan-" + identity + ".json");

    internal static MailRoutingPlan Load(string directory, string identity)
    {
        var path = PathFor(directory, identity);
        if (!File.Exists(path)) return new();
        var state = JsonSerializer.Deserialize<MailRoutingPlan>(File.ReadAllText(path))
                    ?? throw new InvalidDataException("Routing plan is empty.");
        Validate(state);
        return state;
    }

    internal static void Validate(MailRoutingPlan state)
    {
        if (state.SidecarPort is < 1024 or > 65535)
            throw new InvalidDataException("Isolated SMTP port must be between 1024 and 65535.");
        if (state.Transport is not ("oauth2" or "connector") ||
            state.SenderPolicy is not ("fixed-mailbox" or "preserve-domain" or "masquerade"))
            throw new InvalidDataException("Unsupported routing policy.");
        if (state.VerifiedDomain.Length > 253 ||
            (state.VerifiedDomain.Length > 0 &&
             !Regex.IsMatch(state.VerifiedDomain, @"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$",
                 RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)))
            throw new InvalidDataException("The accepted mail domain must be a valid DNS name.");
        if (state.ListenIpv4.Length > 0)
        {
            if (!System.Net.IPAddress.TryParse(state.ListenIpv4, out var address) ||
                address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new InvalidDataException("SMTP listen IP must be a valid IPv4.");
            byte[] b = address.GetAddressBytes();
            if (!((b[0] == 10) || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                  (b[0] == 192 && b[1] == 168)) || string.IsNullOrWhiteSpace(state.TrustedCidrs))
                throw new InvalidDataException("Remote SMTP requires a private listener IP and trusted client CIDRs.");
        }
        else if (!string.IsNullOrWhiteSpace(state.TrustedCidrs))
            throw new InvalidDataException("Trusted client networks require a listener IPv4.");
        var cidrs = state.TrustedCidrs.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (cidrs.Length > 8)
            throw new InvalidDataException("At most 8 trusted client networks are allowed.");
        foreach (string cidr in cidrs)
        {
            var pieces = cidr.Split('/');
            if (pieces.Length != 2 || !System.Net.IPAddress.TryParse(pieces[0], out var ip) ||
                ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                !int.TryParse(pieces[1], out int bits) || bits is < 8 or > 32)
                throw new InvalidDataException("Invalid trusted network CIDR: " + cidr);
        }
    }

    internal static void Save(string directory, string identity, MailRoutingPlan state)
    {
        Validate(state);
        Directory.CreateDirectory(directory);
        var dest = PathFor(directory, identity);
        var temp = dest + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state, new JsonSerializerOptions
            { WriteIndented = true }) + Environment.NewLine, new UTF8Encoding(false));
        File.Move(temp, dest, overwrite: true);
    }

    internal static bool SelfTest()
    {
        var folder = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "lmr365-route-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var a = Identity("LINUX-A.Example", "22", "Admin");
            var b = Identity("linux-b.example", "22", "admin");
            if (a == b || a != Identity("linux-a.example", "0022", "admin")) return false;
            var defaults = Load(folder, a);
            if (defaults.Transport != "oauth2" || defaults.SenderPolicy != "fixed-mailbox" ||
                !defaults.PreserveExistingMail || defaults.SidecarPort != 2525) return false;
            Validate(new MailRoutingPlan { SidecarPort = 2526 });
            try { Validate(new MailRoutingPlan { SidecarPort = 25 }); return false; }
            catch (InvalidDataException) { }
            Save(folder, a, new MailRoutingPlan
                { Transport = "connector", SenderPolicy = "preserve-domain",
                  PreserveExistingMail = true, VerifiedDomain = "example.org" });
            if (Load(folder, a).Transport != "connector" ||
                Load(folder, b).Transport != "oauth2") return false;
            const string digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            var old = MailRoutingInventory.Parse(
                "PROBE_VERSION=2\nMTA=postfix\nPOSTFIX_RELAY=[mail.example]\nPOSTFIX_CONFIG_SHA256=" + digest + "\n");
            var changed = MailRoutingInventory.Parse(
                "PROBE_VERSION=2\nMTA=postfix\nPOSTFIX_RELAY=[mail.example]\nPOSTFIX_CONFIG_SHA256=" +
                new string('b', 64) + "\n");
            if (old == changed || old.ConfigSha256 != digest) return false;
            var privateMail = new MailRoutingPlan {
                ListenIpv4 = "192.168.2.5", TrustedCidrs = "192.168.2.0/24" };
            Validate(privateMail);
            try {
                Validate(new MailRoutingPlan { TrustedCidrs = "0.0.0.0/0" });
                return false;
            } catch (InvalidDataException) { }
            if (old.Mta != "postfix" || old.CurrentRelay != "[mail.example]") return false;
            var contents = File.ReadAllText(PathFor(folder, a));
            return !contents.Contains("password", StringComparison.OrdinalIgnoreCase) &&
                   !contents.Contains("privateKey", StringComparison.OrdinalIgnoreCase);
        }
        finally { if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true); }
    }
}
