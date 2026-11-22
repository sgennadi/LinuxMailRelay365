using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Read-only connection inventory. This is not a Microsoft 365 verified-domain
// claim and never authorizes changing an MTA's existing configuration.
internal sealed record LinuxConnectionProfile(
    string Hostname, string Fqdn, string Domain, string Distribution, string Mta,
    string ServiceStatus, string PostfixHostname, string PostfixDomain,
    string PostfixInterfaces, string PostfixProtocols,
    IReadOnlyList<int> ConfiguredSmtpPorts, IReadOnlyList<int> ListeningSmtpPorts)
{
    internal static LinuxConnectionProfile Parse(string text)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            int split = line.IndexOf('=');
            if (split <= 0 || split > 80 || line.Length > 1024) continue;
            var key = line[..split];
            if (!Regex.IsMatch(key, @"^[A-Z][A-Z0-9_]+$", RegexOptions.CultureInvariant))
                continue;
            var value = line[(split + 1)..];
            if (value.Any(char.IsControl)) continue;
            values[key] = value.Trim();
        }
        if (values.GetValueOrDefault("PROBE_VERSION") != "2")
            throw new InvalidDataException("Unsupported Linux profile probe.");
        string Get(string key) => values.GetValueOrDefault(key) ?? "";
        static IReadOnlyList<int> Ports(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return Array.Empty<int>();
            var ports = new SortedSet<int>();
            foreach (var item in value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                if (!int.TryParse(item, out int port) || port is < 1 or > 65535)
                    throw new InvalidDataException("Invalid detected SMTP port.");
                ports.Add(port);
            }
            return [.. ports];
        }
        return new LinuxConnectionProfile(Get("SYSTEM_HOSTNAME"), Get("SYSTEM_FQDN"),
            Get("SYSTEM_DOMAIN"), (Get("OS_ID") + " " + Get("OS_VERSION")).Trim(),
            Get("MTA"), Get("MTA_SERVICE_STATUS"), Get("POSTFIX_MYHOSTNAME"),
            Get("POSTFIX_MYDOMAIN"), Get("POSTFIX_INET_INTERFACES"),
            Get("POSTFIX_INET_PROTOCOLS"), Ports(Get("SMTP_CONFIGURED_PORTS")),
            Ports(Get("SMTP_LISTENING_PORTS")));
    }

    internal string? CandidateDomain =>
        !string.IsNullOrWhiteSpace(PostfixDomain) ? PostfixDomain :
        !string.IsNullOrWhiteSpace(Domain) ? Domain : null;

    internal string Summary(int language)
    {
        string Show(string value) => string.IsNullOrWhiteSpace(value) ? "—" : value;
        string Ports(IReadOnlyList<int> value) => value.Count == 0 ? "—" : string.Join(", ", value);
        return language switch
        {
            0 => "Сервер: " + Show(Hostname) + "  |  FQDN: " + Show(Fqdn) +
                 "\nDNS-домен: " + Show(Domain) + "  |  ОС: " + Show(Distribution) +
                 "\nMTA: " + Show(Mta) + "  |  Служба: " + Show(ServiceStatus) +
                 "\nPostfix myhostname/mydomain: " + Show(PostfixHostname) + " / " + Show(PostfixDomain) +
                 "\nPostfix inet_interfaces: " + Show(PostfixInterfaces) + "  |  inet_protocols: " + Show(PostfixProtocols) +
                 "\nНастроенные SMTP-порты: " + Ports(ConfiguredSmtpPorts) +
                 "  |  Обнаружены слушающие TCP-порты: " + Ports(ListeningSmtpPorts),
            2 => "שרת: " + Show(Hostname) + "  |  FQDN: " + Show(Fqdn) +
                 "\nדומיין DNS: " + Show(Domain) + "  |  מערכת: " + Show(Distribution) +
                 "\nשרת דואר: " + Show(Mta) + "  |  שירות: " + Show(ServiceStatus) +
                 "\nPostfix myhostname/mydomain: " + Show(PostfixHostname) + " / " + Show(PostfixDomain) +
                 "\nPostfix inet_interfaces: " + Show(PostfixInterfaces) + "  |  inet_protocols: " + Show(PostfixProtocols) +
                 "\nיציאות SMTP מוגדרות: " + Ports(ConfiguredSmtpPorts) +
                 "  |  יציאות TCP מאזינות שזוהו: " + Ports(ListeningSmtpPorts),
            _ => "Server: " + Show(Hostname) + "  |  FQDN: " + Show(Fqdn) +
                 "\nDNS domain: " + Show(Domain) + "  |  OS: " + Show(Distribution) +
                 "\nMTA: " + Show(Mta) + "  |  Service: " + Show(ServiceStatus) +
                 "\nPostfix myhostname/mydomain: " + Show(PostfixHostname) + " / " + Show(PostfixDomain) +
                 "\nPostfix inet_interfaces: " + Show(PostfixInterfaces) + "  |  inet_protocols: " + Show(PostfixProtocols) +
                 "\nConfigured SMTP ports: " + Ports(ConfiguredSmtpPorts) +
                 "  |  Observed listening TCP ports: " + Ports(ListeningSmtpPorts)
        };
    }

    internal static bool SelfTest()
    {
        const string probe = "PROBE_VERSION=2\nOS_ID=rocky\nOS_VERSION=9.3\n" +
            "SYSTEM_HOSTNAME=mail01\nSYSTEM_FQDN=mail01.example.org\nSYSTEM_DOMAIN=example.org\n" +
            "MTA=postfix\nMTA_SERVICE_STATUS=active\n" +
            "POSTFIX_MYHOSTNAME=mail01.example.org\nPOSTFIX_MYDOMAIN=example.org\n" +
            "POSTFIX_INET_INTERFACES=all\nPOSTFIX_INET_PROTOCOLS=ipv4\n" +
            "SMTP_CONFIGURED_PORTS=587,25,2526,25\nSMTP_LISTENING_PORTS=25,2526\n";
        var p = Parse(probe);
        if (p.Mta != "postfix" || p.CandidateDomain != "example.org" ||
            !p.ConfiguredSmtpPorts.SequenceEqual(new[] { 25, 587, 2526 }) ||
            !p.ListeningSmtpPorts.SequenceEqual(new[] { 25, 2526 }) ||
            !p.Summary(1).Contains("Configured SMTP ports: 25, 587, 2526", StringComparison.Ordinal) ||
            !p.Summary(0).Contains("Настроенные", StringComparison.Ordinal))
            return false;
        var noMta = Parse("PROBE_VERSION=2\nMTA=none\n");
        if (noMta.ConfiguredSmtpPorts.Count != 0 || noMta.CandidateDomain is not null) return false;
        try { Parse("PROBE_VERSION=2\nSMTP_CONFIGURED_PORTS=2525,70000\n"); return false; }
        catch (InvalidDataException) { }
        try { Parse("PROBE_VERSION=3\n"); return false; }
        catch (InvalidDataException) { }
        return true;
    }
}
