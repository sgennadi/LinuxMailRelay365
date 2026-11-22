namespace LinuxMailRelay365;

// Read-only information from the Linux capability probe. Never interpret a
// TCP listener as proof that SMTP relay is reachable or safe on the Internet.
internal sealed record LinuxServerOverview(
    string Hostname, string Fqdn, string Domain, string Mta, string ServiceStatus,
    string ConfiguredSmtpPorts, string ListeningSmtpPorts, string PostfixHostname,
    string PostfixDomain, string Interfaces, string Protocols)
{
    private static readonly string[] Keys =
    [
        "SYSTEM_HOSTNAME", "SYSTEM_FQDN", "SYSTEM_DOMAIN", "MTA",
        "MTA_SERVICE_STATUS", "SMTP_CONFIGURED_PORTS", "SMTP_LISTENING_PORTS",
        "POSTFIX_MYHOSTNAME", "POSTFIX_MYDOMAIN", "POSTFIX_INET_INTERFACES",
        "POSTFIX_INET_PROTOCOLS", "PROBE_VERSION"
    ];

    internal static LinuxServerOverview Parse(string output)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            int equals = line.IndexOf('=');
            if (equals < 1 || equals > 64) continue;
            string key = line[..equals];
            if (!Keys.Contains(key, StringComparer.Ordinal)) continue;
            string value = line[(equals + 1)..].Trim();
            if (value.Length > 255 || value.Any(char.IsControl)) continue;
            values[key] = value;
        }
        if (values.GetValueOrDefault("PROBE_VERSION") != "2" ||
            !values.ContainsKey("MTA"))
            throw new InvalidDataException("Linux server profile is incomplete or has an unsupported probe version.");
        string Get(string key) => values.GetValueOrDefault(key, "");
        return new LinuxServerOverview(
            Get("SYSTEM_HOSTNAME"), Get("SYSTEM_FQDN"), Get("SYSTEM_DOMAIN"),
            Get("MTA"), Get("MTA_SERVICE_STATUS"), NormalizePorts(Get("SMTP_CONFIGURED_PORTS")),
            NormalizePorts(Get("SMTP_LISTENING_PORTS")), Get("POSTFIX_MYHOSTNAME"),
            Get("POSTFIX_MYDOMAIN"), Get("POSTFIX_INET_INTERFACES"),
            Get("POSTFIX_INET_PROTOCOLS"));
    }

    // Only display actual numeric ports returned by Linux. Never assume 2525
    // or port 25 is configured or available.
    private static string NormalizePorts(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        var ports = new SortedSet<int>();
        foreach (var part in value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (!int.TryParse(part, out int port) || port is < 1 or > 65535)
                throw new InvalidDataException("Linux reported an invalid TCP port.");
            ports.Add(port);
        }
        return string.Join(",", ports);
    }

    internal string Display(int language) => language switch
    {
        0 => "Узел: " + Label(Hostname) + "  |  FQDN: " + Label(Fqdn) +
             "\nДомен: " + Label(Domain) + "  |  MTA: " + Label(Mta) +
             " (" + Label(ServiceStatus) + ")" +
             "\nНастроенные SMTP-порты: " + Label(ConfiguredSmtpPorts) +
             "  |  TCP-порты с listener: " + Label(ListeningSmtpPorts) +
             "\nPostfix hostname/domain: " + Label(PostfixHostname) + " / " + Label(PostfixDomain) +
             "\ninet_interfaces: " + Label(Interfaces) + "  |  inet_protocols: " + Label(Protocols),
        2 => "שרת: " + Label(Hostname) + "  |  FQDN: " + Label(Fqdn) +
             "\nדומיין: " + Label(Domain) + "  |  MTA: " + Label(Mta) +
             " (" + Label(ServiceStatus) + ")" +
             "\nיציאות SMTP מוגדרות: " + Label(ConfiguredSmtpPorts) +
             "  |  יציאות TCP מאזינות: " + Label(ListeningSmtpPorts) +
             "\nPostfix hostname/domain: " + Label(PostfixHostname) + " / " + Label(PostfixDomain) +
             "\ninet_interfaces: " + Label(Interfaces) + "  |  inet_protocols: " + Label(Protocols),
        _ => "Host: " + Label(Hostname) + "  |  FQDN: " + Label(Fqdn) +
             "\nDomain: " + Label(Domain) + "  |  MTA: " + Label(Mta) +
             " (" + Label(ServiceStatus) + ")" +
             "\nConfigured SMTP ports: " + Label(ConfiguredSmtpPorts) +
             "  |  TCP listening ports: " + Label(ListeningSmtpPorts) +
             "\nPostfix hostname/domain: " + Label(PostfixHostname) + " / " + Label(PostfixDomain) +
             "\ninet_interfaces: " + Label(Interfaces) + "  |  inet_protocols: " + Label(Protocols)
    };

    private static string Label(string value) => string.IsNullOrWhiteSpace(value) ? "—" : value;

    internal static bool SelfTest()
    {
        var value = Parse(
            "PROBE_VERSION=2\nSYSTEM_HOSTNAME=mail\nSYSTEM_FQDN=mail.example.org\n" +
            "SYSTEM_DOMAIN=example.org\nMTA=postfix\nMTA_SERVICE_STATUS=active\n" +
            "SMTP_CONFIGURED_PORTS=587,25,25,2526\nSMTP_LISTENING_PORTS=25,2526\n" +
            "POSTFIX_MYHOSTNAME=mail.example.org\nPOSTFIX_MYDOMAIN=example.org\n" +
            "POSTFIX_INET_INTERFACES=all\nPOSTFIX_INET_PROTOCOLS=ipv4\n");
        if (value.Fqdn != "mail.example.org" ||
            value.ConfiguredSmtpPorts != "25,587,2526" ||
            value.ListeningSmtpPorts != "25,2526" ||
            !value.Display(1).Contains("inet_interfaces: all", StringComparison.Ordinal) ||
            !value.Display(0).Contains("Узел:", StringComparison.Ordinal))
            return false;
        try { Parse("PROBE_VERSION=3\nMTA=postfix\n"); return false; }
        catch (InvalidDataException) { }
        try { Parse("PROBE_VERSION=2\nMTA=postfix\nSMTP_CONFIGURED_PORTS=70000\n"); return false; }
        catch (InvalidDataException) { }
        return true;
    }
}
