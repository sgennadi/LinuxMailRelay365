using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Never treat OS hostname/domain as proof of Exchange tenant ownership.
internal sealed class MailHostInspection
{
    private readonly IReadOnlyDictionary<string, string> values;
    private MailHostInspection(IReadOnlyDictionary<string, string> items) => values = items;
    internal string Fqdn => Get("MAIL_HOST_FQDN");
    internal string Domain => Get("MAIL_HOST_DOMAIN");
    internal string ShortHostname => Get("MAIL_HOST_SHORT");
    internal string Mta => Get("MAIL_HOST_MTA");
    internal string MtaState => Get("MAIL_HOST_MTA_STATE");
    internal bool HasFqdn => Fqdn != "unavailable";
    internal bool HasDomain => Domain != "unavailable";
    internal string Get(string name) => values.TryGetValue(name, out var result) ? result : "unavailable";

    internal static MailHostInspection Parse(string output)
    {
        if (output.Length > 8192) throw new InvalidDataException("Oversized hostname report.");
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            int n = line.IndexOf('=');
            if (n is < 1 or > 80 || line.Length > 340) continue;
            string key = line[..n];
            string value = line[(n + 1)..];
            if (!Regex.IsMatch(key, @"\AMAIL_HOST_[A-Z0-9_]+\z", RegexOptions.CultureInvariant) ||
                !Regex.IsMatch(value, @"\A[A-Za-z0-9_.$/,: @{}\[\]+-]*\z", RegexOptions.CultureInvariant) ||
                !values.TryAdd(key, value))
                throw new InvalidDataException("Malformed or duplicate mail-host setting.");
        }
        foreach (var key in new[] {
            "MAIL_HOST_VERSION", "MAIL_HOST_SHORT", "MAIL_HOST_FQDN", "MAIL_HOST_DOMAIN",
            "MAIL_HOST_MTA", "MAIL_HOST_MTA_STATE", "MAIL_HOST_TRUST", "MAIL_HOST_CHANGES"
        })
            if (!values.ContainsKey(key))
                throw new InvalidDataException("Hostname report incomplete.");
        if (values["MAIL_HOST_VERSION"] != "1" || values["MAIL_HOST_CHANGES"] != "no" ||
            values["MAIL_HOST_TRUST"] != "os_report_unverified" ||
            values["MAIL_HOST_MTA"] is not ("postfix" or "exim" or "sendmail" or "none" or "unknown"))
            throw new InvalidDataException("Untrusted hostname report.");
        const string dns = @"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+";
        foreach (string key in new[] { "MAIL_HOST_FQDN", "MAIL_HOST_DOMAIN" })
        {
            string value = values[key];
            if (value != "unavailable" && (value.Length > 253 ||
                !Regex.IsMatch(value, "\\A" + dns + "\\z", RegexOptions.CultureInvariant)))
                throw new InvalidDataException("Remote hostname/domain invalid.");
        }
        return new MailHostInspection(values);
    }

    private IEnumerable<string> ReadRows(string prefix, int count) =>
        values.Where(pair => pair.Key.StartsWith(prefix, StringComparison.Ordinal))
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Take(count).Select(pair => pair.Value);

    // A suggested listener must be attached to an administratively UP and
    // operationally UP interface and be RFC1918 IPv4. This is UI intent only,
    // not authorization to open a network port or trust an SMTP client.
    internal IReadOnlyList<(string Name, string Address)> ActivePrivateIPv4s()
    {
        if (Get("MAIL_HOST_NET_STATE") != "ok" ||
            Get("MAIL_HOST_NET_AUDIT_VERSION") != "1")
            return Array.Empty<(string Name, string Address)>();
        var up = new HashSet<string>(StringComparer.Ordinal);
        foreach (string row in ReadRows("MAIL_HOST_IFACE_", 16))
        {
            string[] parts = row.Split(',');
            if (parts.Length == 3 && parts[1] == "up" && parts[2] == "up" &&
                Regex.IsMatch(parts[0], @"\A[A-Za-z0-9_.-]{1,32}\z",
                    RegexOptions.CultureInvariant))
                up.Add(parts[0]);
        }
        var candidates = new List<(string Name, string Address)>();
        foreach (string row in ReadRows("MAIL_HOST_ADDR_", 24))
        {
            string[] parts = row.Split(',');
            if (parts.Length != 4 || parts[1] != "ipv4" || !up.Contains(parts[0]))
                continue;
            string[] ipAndPrefix = parts[2].Split('/');
            if (ipAndPrefix.Length != 2 ||
                !int.TryParse(ipAndPrefix[1], out int prefix) || prefix is < 0 or > 32 ||
                !System.Net.IPAddress.TryParse(ipAndPrefix[0], out var ip) ||
                ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                continue;
            byte[] b = ip.GetAddressBytes();
            bool privateV4 = b[0] == 10 ||
                (b[0] == 172 && b[1] is >= 16 and <= 31) ||
                (b[0] == 192 && b[1] == 168);
            if (privateV4 && candidates.All(x => x.Address != ip.ToString()))
                candidates.Add((parts[0], ip.ToString()));
        }
        return candidates;
    }

    private string NetworkSummary(int language)
    {
        if (Get("MAIL_HOST_NET_AUDIT_VERSION") != "1")
            return language == 0 ? "Сетевые интерфейсы не проверены." :
                language == 2 ? "ממשקי הרשת לא נבדקו." : "Network interfaces not inspected.";
        string interfaces = string.Join("; ", ReadRows("MAIL_HOST_IFACE_", 12));
        string addresses = string.Join("; ", ReadRows("MAIL_HOST_ADDR_", 14));
        string sockets = string.Join("; ", ReadRows("MAIL_HOST_SOCKET_0", 12));
        string status = Get("MAIL_HOST_NET_BIND_RESULT");
        return "Linux interfaces (admin/oper): " + (interfaces.Length == 0 ? "unverified" : interfaces) +
            Environment.NewLine + "Assigned IPs: " + (addresses.Length == 0 ? "unverified" : addresses) +
            Environment.NewLine + "SMTP sockets (unattributed): " +
            (sockets.Length == 0 ? "none observed or unavailable" : sockets) +
            "; selected port=" + Get("MAIL_HOST_NET_PORT") +
            Environment.NewLine + "Bind comparison: " + status +
            "; network=" + Get("MAIL_HOST_NET_STATE") +
            "; ss=" + Get("MAIL_HOST_SOCKET_STATE") +
            "; truncated=" + Get("MAIL_HOST_NET_TRUNCATED") + "/" + Get("MAIL_HOST_SOCKET_TRUNCATED") +
            ". Sockets do NOT prove owning MTA, firewall/NAT access or Internet reachability.";
    }

    internal string Summary(int language)
    {
        string prefix = language == 0 ? "Linux сообщает" : language == 2
            ? "שרת Linux מדווח" : "Linux reports";
        string reminder = language == 0
            ? "Это не подтверждает DNS, владение доменом M365 или сертификат."
            : language == 2 ? "זו אינה הוכחה לבעלות על דומיין Microsoft 365."
            : "This is not proof of DNS, M365 accepted-domain rights or certificate identity.";
        string config = Mta switch
        {
            "postfix" =>
                "Postfix: myhostname=" + Get("MAIL_HOST_POSTFIX_MYHOSTNAME") +
                "; mydomain=" + Get("MAIL_HOST_POSTFIX_MYDOMAIN") +
                "; myorigin=" + Get("MAIL_HOST_POSTFIX_MYORIGIN") +
                "; mydestination=" + Get("MAIL_HOST_POSTFIX_MYDESTINATION") +
                "; inet_interfaces=" + Get("MAIL_HOST_POSTFIX_INET_INTERFACES") +
                "; inet_protocols=" + Get("MAIL_HOST_POSTFIX_INET_PROTOCOLS"),
            "exim" =>
                "Exim: primary_hostname=" + Get("MAIL_HOST_EXIM_PRIMARY_HOSTNAME") +
                "; qualify_domain=" + Get("MAIL_HOST_EXIM_QUALIFY_DOMAIN") +
                "; local_interfaces=" + Get("MAIL_HOST_EXIM_LOCAL_INTERFACES") +
                "; local_domains/routers/ACL require manual review.",
            "sendmail" =>
                "Sendmail: sendmail.mc=" + Get("MAIL_HOST_SENDMAIL_MC") +
                "; listener=" + Get("MAIL_HOST_SENDMAIL_LISTENER") +
                "; masquerade=" + Get("MAIL_HOST_SENDMAIL_MASQUERADE") +
                "; sendmail.cf=" + Get("MAIL_HOST_SENDMAIL_CF"),
            _ => "MTA settings not verified."
        };
        return prefix + ": FQDN=" + Fqdn + "; domain=" + Domain +
            "; MTA=" + Mta + " (" + MtaState + ")." +
            Environment.NewLine + config + Environment.NewLine + NetworkSummary(language) +
            Environment.NewLine + reminder;
    }

    internal static bool SelfTest()
    {
        const string valid = "MAIL_HOST_VERSION=1\nMAIL_HOST_SHORT=mail\n" +
            "MAIL_HOST_FQDN=mail.example.com\nMAIL_HOST_DOMAIN=example.com\n" +
            "MAIL_HOST_MTA=postfix\nMAIL_HOST_MTA_STATE=active\n" +
            "MAIL_HOST_TRUST=os_report_unverified\nMAIL_HOST_CHANGES=no\n";
        var snapshot = Parse(valid);
        if (!snapshot.HasFqdn || snapshot.Domain != "example.com" ||
            !snapshot.Summary(0).Contains("Postfix", StringComparison.Ordinal)) return false;
        try { Parse(valid.Replace("mail.example.com", "mail.example.com;rm")); return false; }
        catch (InvalidDataException) { }
        try { Parse(valid + "MAIL_HOST_DOMAIN=evil.example.com\n"); return false; }
        catch (InvalidDataException) { }
        try { Parse(valid.Replace("MAIL_HOST_CHANGES=no", "MAIL_HOST_CHANGES=yes")); return false; }
        catch (InvalidDataException) { }
        const string network = "MAIL_HOST_NET_AUDIT_VERSION=1\n" +
            "MAIL_HOST_NET_STATE=ok\n" +
            "MAIL_HOST_IFACE_01=eth0,up,up\n" +
            "MAIL_HOST_IFACE_02=eth1,up,down\n" +
            "MAIL_HOST_IFACE_03=eth2,up,up\n" +
            "MAIL_HOST_ADDR_01=eth0,ipv4,10.0.0.5/24,global\n" +
            "MAIL_HOST_ADDR_02=eth1,ipv4,192.168.1.9/24,global\n" +
            "MAIL_HOST_ADDR_03=eth2,ipv4,8.8.8.8/32,global\n" +
            "MAIL_HOST_SOCKET_01=127.0.0.1:25\n";
        var withNetwork = Parse(valid + network);
        if (!withNetwork.Summary(1).Contains("eth0,up,up", StringComparison.Ordinal) ||
            !withNetwork.Summary(1).Contains("127.0.0.1:25", StringComparison.Ordinal) ||
            withNetwork.ActivePrivateIPv4s().Count != 1 ||
            withNetwork.ActivePrivateIPv4s()[0].Address != "10.0.0.5" ||
            withNetwork.ActivePrivateIPv4s()[0].Name != "eth0")
            return false;
        return true;
    }
}
