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
    // These host-scoped values are plan input only, NOT permission to edit
    // primary Postfix or proof of public/tenant SMTP readiness.
    public string PostfixBasicsHostname { get; set; } = "";
    public string PostfixBasicsDomain { get; set; } = "";
    public string PostfixBasicsInterfaces { get; set; } = "loopback-only";
    // Recipient preference only. Never evidence of tenant authorization.
    public string RecipientScope { get; set; } = "unknown";
    public string SenderPolicy { get; set; } = "fixed-mailbox";
    // Operator intent only. Multi-mailbox XOAUTH2 is NOT applied until
    // authenticated sender ownership and Exchange rights are validated.
    public string OAuthSenderMode { get; set; } = "fixed-mailbox";
    public string OAuthSenderMapPath { get; set; } = "";
    public bool PreserveExistingMail { get; set; } = true;
    public string VerifiedDomain { get; set; } = "";
    // Per-Linux-host preflight choices. Paths only, never TLS key contents.
    public string EopMxHost { get; set; } = "";
    public string EopFixedSender { get; set; } = "";
    // Linux-only root:root 0600 mapping path, never the owner file content.
    public string EopSenderOwnerFile { get; set; } = "";
    public string EopPublicIp { get; set; } = "";
    // Nonsecret, host-scoped Exchange Online Connector display name.
    public string EopConnectorName { get; set; } = "LinuxMailRelay365 SMTP Relay";
    public string EopCertificatePath { get; set; } = "";
    public string EopKeyPath { get; set; } = "";
    public string ListenIpv4 { get; set; } = "";
    // Host-scoped SMTP TLS certificate identity, never secret material.
    public string PrivateSmtpServerName { get; set; } = "";
    public string TrustedCidrs { get; set; } = "";
    public int SidecarPort { get; set; } = 2525;
    // Saved REQUEST only; a separate reviewed action enables public SMTP.
    public bool PublicInternetRequested { get; set; } = false;
    // UI disclosure preference only; never grants SMTP privileges.
    public bool ShowAdvancedSmtpTools { get; set; } = false;
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
        const string fqdn = @"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z";
        if (state.PostfixBasicsInterfaces is not ("loopback-only" or "all") ||
            state.PostfixBasicsHostname.Length > 253 ||
            state.PostfixBasicsDomain.Length > 253 ||
            (state.PostfixBasicsHostname.Length > 0 &&
                !Regex.IsMatch(state.PostfixBasicsHostname, fqdn, RegexOptions.CultureInvariant)) ||
            (state.PostfixBasicsDomain.Length > 0 &&
                !Regex.IsMatch(state.PostfixBasicsDomain, fqdn, RegexOptions.CultureInvariant)))
            throw new InvalidDataException("Invalid planned primary Postfix hostname/domain/interface.");
        if (state.SidecarPort is < 1024 or > 65535)
            throw new InvalidDataException("Isolated SMTP port must be between 1024 and 65535.");
        if (state.RecipientScope is not ("unknown" or "internal-only" or "external-needed"))
            throw new InvalidDataException("Invalid recipient scope.");
        if (state.Transport is not ("oauth2" or "connector" or "direct-send") ||
            state.SenderPolicy is not ("fixed-mailbox" or "preserve-domain" or "masquerade") ||
            state.OAuthSenderMode is not ("fixed-mailbox" or "authorized-multiple-mailboxes"))
            throw new InvalidDataException("Unsupported routing policy.");
        // This plan does NOT authorize any mailbox or SMTP account and never
        // supplies the sender map directly to the active Postfix transport.
        string senderMap = state.OAuthSenderMapPath;
        if (senderMap.Length > 0 &&
            (senderMap.Length > 256 || !Regex.IsMatch(senderMap,
                 @"\A/[A-Za-z0-9_./-]{1,255}\z", RegexOptions.CultureInvariant) ||
             senderMap.Split('/').Any(part => part is "." or "..") ||
             !senderMap.StartsWith("/etc/linuxmailrelay365/", StringComparison.Ordinal)))
            throw new InvalidDataException("OAuth sender map must be an absolute trusted Linux /etc/linuxmailrelay365/ path.");
        if (state.OAuthSenderMode == "authorized-multiple-mailboxes" &&
            state.Transport == "oauth2" && senderMap.Length == 0)
            throw new InvalidDataException("Choose an OAuth sender authorization map path before saving multi-mailbox intent.");
        // Only operator configuration hints are stored; no passwords,
        // private key bytes, hash values, signed tokens or tenant attestations.
        if (state.EopConnectorName.Length is < 3 or > 70 ||
            !Regex.IsMatch(state.EopConnectorName, @"\A[A-Za-z0-9][A-Za-z0-9._ -]{2,69}\z"))
            throw new InvalidDataException("Connector name may contain English letters, digits, space, dot, hyphen and underscore.");
        if (new[] { state.EopMxHost, state.EopFixedSender, state.EopPublicIp,
                     state.EopCertificatePath, state.EopKeyPath, state.EopSenderOwnerFile }
            .Any(value => value.Length > 256 || value.Contains('\n') || value.Contains('\r')))
            throw new InvalidDataException("EOP routing option exceeds safe length.");
        if (state.PrivateSmtpServerName.Length > 253 ||
            (state.PrivateSmtpServerName.Length > 0 &&
             !Regex.IsMatch(state.PrivateSmtpServerName,
                @"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)))
            throw new InvalidDataException("SMTP TLS server name must be a valid DNS name.");
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
            if (defaults.Transport != "oauth2" || defaults.RecipientScope != "unknown" ||
                defaults.PostfixBasicsHostname != "" || defaults.PostfixBasicsInterfaces != "loopback-only" ||
                defaults.SenderPolicy != "fixed-mailbox" ||
                defaults.OAuthSenderMode != "fixed-mailbox" || defaults.OAuthSenderMapPath != "" ||
                !defaults.PreserveExistingMail || defaults.SidecarPort != 2525 ||
                defaults.PublicInternetRequested || defaults.ShowAdvancedSmtpTools) return false;
            Save(folder, b, new MailRoutingPlan { PublicInternetRequested = true,
                PrivateSmtpServerName = "smtp-b.example.org", ShowAdvancedSmtpTools = true });
            if (!Load(folder, b).PublicInternetRequested ||
                Load(folder, b).PrivateSmtpServerName != "smtp-b.example.org" ||
                Load(folder, a).PrivateSmtpServerName != "" ||
                !Load(folder, b).ShowAdvancedSmtpTools ||
                Load(folder, a).PublicInternetRequested || Load(folder, a).ShowAdvancedSmtpTools)
                return false;
            Save(folder, a, new MailRoutingPlan {
                Transport = "direct-send", EopMxHost = "example-org.mail.protection.outlook.com",
                EopFixedSender = "alerts@example.org", VerifiedDomain = "example.org",
                ShowAdvancedSmtpTools = true });
            if (Load(folder, a).EopFixedSender != "alerts@example.org" ||
                Load(folder, b).EopMxHost != "") return false;
            Save(folder, a, new MailRoutingPlan {
                Transport = "oauth2", OAuthSenderMode = "authorized-multiple-mailboxes",
                OAuthSenderMapPath = "/etc/linuxmailrelay365/oauth-senders.tsv" });
            if (Load(folder, a).OAuthSenderMode != "authorized-multiple-mailboxes" ||
                Load(folder, a).OAuthSenderMapPath != "/etc/linuxmailrelay365/oauth-senders.tsv") return false;
            try { Validate(new MailRoutingPlan {
                OAuthSenderMode = "authorized-multiple-mailboxes",
                OAuthSenderMapPath = "../../bad/path" }); return false;
            } catch (InvalidDataException) { }
            try { Validate(new MailRoutingPlan {
                OAuthSenderMode = "authorized-multiple-mailboxes",
                OAuthSenderMapPath = "/etc/linuxmailrelay365/../etc/passwd" }); return false;
            } catch (InvalidDataException) { }
            try { Validate(new MailRoutingPlan {
                OAuthSenderMode = "authorized-multiple-mailboxes" }); return false;
            } catch (InvalidDataException) { }
            try { Validate(new MailRoutingPlan { RecipientScope = "invalid" }); return false; }
            catch (InvalidDataException) { }
            Save(folder, b, new MailRoutingPlan { RecipientScope = "external-needed" });
            if (Load(folder, b).RecipientScope != "external-needed") return false;
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
