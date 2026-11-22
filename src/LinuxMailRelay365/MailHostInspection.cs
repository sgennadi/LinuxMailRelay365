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
    internal string ConfiguredSmtpPortState => Get("MAIL_HOST_SMTP_CONFIG_PORTS");
    internal string ConfiguredSmtpPortSource => Get("MAIL_HOST_SMTP_CONFIG_SOURCE");

    internal IReadOnlyList<int> ConfiguredSmtpPorts()
    {
        if (ConfiguredSmtpPortSource is not
            ("postfix_master_cf" or "exim_daemon_smtp_ports" or "sendmail_cf") ||
            !System.Text.RegularExpressions.Regex.IsMatch(ConfiguredSmtpPortState,
                @"\A[1-9][0-9]{0,4}(?:,[1-9][0-9]{0,4}){0,15}\z"))
            return Array.Empty<int>();
        return ConfiguredSmtpPortState.Split(',').Select(int.Parse).ToArray();
    }
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
        // Configuration ports are NOT an assertion of live socket ownership.
        // Optional for older read-only fixture schemas; never trusted if absent.
        string source = values.TryGetValue("MAIL_HOST_SMTP_CONFIG_SOURCE", out var declaredSource)
            ? declaredSource : "unverified";
        string ports = values.TryGetValue("MAIL_HOST_SMTP_CONFIG_PORTS", out var declaredPorts)
            ? declaredPorts : "unverified";
        bool possibleSource = source is ("postfix_master_cf" or "exim_daemon_smtp_ports" or
            "sendmail_cf" or "unverified");
        bool possibleState = ports is ("unverified" or "dynamic_or_unverified" or
            "none_configured") || Regex.IsMatch(ports,
            @"\A[1-9][0-9]{0,4}(?:,[1-9][0-9]{0,4}){0,15}\z", RegexOptions.CultureInvariant);
        bool sourceMatchesMta = source == "unverified" ||
            (source == "postfix_master_cf" && values["MAIL_HOST_MTA"] == "postfix") ||
            (source == "exim_daemon_smtp_ports" && values["MAIL_HOST_MTA"] == "exim") ||
            (source == "sendmail_cf" && values["MAIL_HOST_MTA"] == "sendmail");
        if (!possibleSource || !possibleState || !sourceMatchesMta ||
            (source == "unverified" && ports != "unverified") ||
            (ports is not ("unverified" or "dynamic_or_unverified" or "none_configured") &&
             ports.Split(',').Any(x => !int.TryParse(x, out int n) || n > 65535)))
            throw new InvalidDataException("Untrusted configured SMTP port inventory.");
        const string dns = @"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+";
        foreach (string key in new[] { "MAIL_HOST_FQDN", "MAIL_HOST_DOMAIN" })
        {
            string value = values[key];
            if (value != "unavailable" && (value.Length > 253 ||
                !Regex.IsMatch(value, "\\A" + dns + "\\z", RegexOptions.CultureInvariant)))
                throw new InvalidDataException("Remote hostname/domain invalid.");
        }
        static bool OneOf(IReadOnlyDictionary<string, string> fields,
            string key, params string[] choices) =>
            !fields.TryGetValue(key, out var value) || choices.Contains(value, StringComparer.Ordinal);
        if (!OneOf(values, "MAIL_HOST_EXIM_BIND_POLICY", "unverified",
                "loopback_declared", "non_loopback_declared_requires_review",
                "dynamic_or_unverified") ||
            !OneOf(values, "MAIL_HOST_EXIM_SMARTHOST_HINT", "unverified",
                "template_declares_smarthost_requires_router_review",
                "template_only_no_verified_router") ||
            !OneOf(values, "MAIL_HOST_EXIM_RELAY_POLICY",
                "routers_transports_and_acl_unverified") ||
            !OneOf(values, "MAIL_HOST_EXIM_TLS_DECLARATION",
                "unverified", "dynamic_or_unverified", "starttls_not_declared",
                "starttls_cert_key_declared_unverified", "partial_tls_declaration") ||
            !OneOf(values, "MAIL_HOST_EXIM_AUTH_DECLARATION",
                "unverified", "dynamic_or_unverified", "auth_not_advertised",
                "auth_hosts_declared_backend_unverified") ||
            !OneOf(values, "MAIL_HOST_SENDMAIL_TLS_DECLARATION",
                "unverified", "server_tls_not_observed",
                "server_cert_key_declared_unverified", "partial_tls_declaration") ||
            !OneOf(values, "MAIL_HOST_SENDMAIL_AUTH_DECLARATION",
                "unverified", "mechanisms_not_observed",
                "mechanisms_declared_backend_unverified") ||
            !OneOf(values, "MAIL_HOST_SENDMAIL_CF_LISTENER", "unverified",
                "loopback_declared", "non_loopback_or_default_requires_review") ||
            !OneOf(values, "MAIL_HOST_SENDMAIL_CF_SMARTHOST", "unverified",
                "declared", "not_declared") ||
            !OneOf(values, "MAIL_HOST_SENDMAIL_CF_MASQUERADE", "unverified",
                "declared", "not_declared") ||
            !OneOf(values, "MAIL_HOST_SENDMAIL_RELAY_POLICY",
                "access_maps_and_relay_checks_unverified") ||
            (values.TryGetValue("MAIL_HOST_EXIM_SMTP_PORTS", out var ports) &&
             ports != "unverified" &&
             (!Regex.IsMatch(ports, @"\A[1-9][0-9]{0,4}(?:,[1-9][0-9]{0,4}){0,15}\z",
                 RegexOptions.CultureInvariant) ||
              ports.Split(',').Any(p => !int.TryParse(p, out int n) || n > 65535))))
            throw new InvalidDataException("Untrusted MTA setting status.");
        return new MailHostInspection(values);
    }

    private IEnumerable<string> ReadRows(string prefix, int count) =>
        values.Where(pair => pair.Key.StartsWith(prefix, StringComparison.Ordinal))
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Take(count).Select(pair => pair.Value);

    // Prefix MAIL_HOST_SOCKET_ also matches status/owner metadata. Include
    // all 01..24 numbered sockets without accidentally displaying those flags.
    private IEnumerable<string> ReadSocketRows() =>
        values.Where(pair => System.Text.RegularExpressions.Regex.IsMatch(pair.Key,
            @"\AMAIL_HOST_SOCKET_[0-9]{2}\z", RegexOptions.CultureInvariant))
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Take(24).Select(pair => pair.Value);

    // A suggested listener must be attached to an administratively UP and
    // operationally UP interface and be RFC1918 IPv4. This is UI intent only,
    // not authorization to open a network port or trust an SMTP client.
    internal IReadOnlyList<(string Name, string Address)> ActivePrivateIPv4s()
    {
        if (Get("MAIL_HOST_NET_STATE") != "ok" ||
            Get("MAIL_HOST_NET_AUDIT_VERSION") != "1" ||
            Get("MAIL_HOST_NET_TRUNCATED") != "no")
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

    // Advisory only. A clear socket scan does not establish that the primary
    // MTA is disabled at boot; the root installer checks that independently.
    internal string StandardPort25Observation()
    {
        if (Get("MAIL_HOST_SOCKET_STATE") != "ok" ||
            Get("MAIL_HOST_SOCKET_TRUNCATED") != "no")
            return "unverified";
        for (int n = 1; n <= 24; n++)
        {
            string observed = Get("MAIL_HOST_SOCKET_" + n.ToString("00"));
            if (observed.EndsWith(":25", StringComparison.Ordinal))
                return "occupied";
        }
        return "no_listener_observed";
    }

    private string NetworkSummary(int language)
    {
        static string Tr(int lang, string ru, string en, string he) =>
            lang == 0 ? ru : lang == 2 ? he : en;
        if (Get("MAIL_HOST_NET_AUDIT_VERSION") != "1")
            return Tr(language, "Сетевые интерфейсы не проверены.",
                "Network interfaces not inspected.", "ממשקי הרשת לא נבדקו.");
        string interfaces = string.Join("; ", ReadRows("MAIL_HOST_IFACE_", 12));
        string addresses = string.Join("; ", ReadRows("MAIL_HOST_ADDR_", 14));
        string sockets = string.Join("; ", ReadSocketRows());
        string status = Get("MAIL_HOST_NET_BIND_RESULT");
        string unknown = Tr(language, "не подтверждено", "unverified", "לא אומת");
        string noSocket = Get("MAIL_HOST_SOCKET_STATE") == "ok"
            ? Tr(language, "не обнаружены", "none observed", "לא נמצאו")
            : unknown;
        string hint = status switch
        {
            "configured_ip_admin_down" => Tr(language,
                "IP назначен административно отключённому интерфейсу.",
                "Configured IP belongs to an administratively DOWN interface.",
                "כתובת ה-IP משויכת לממשק מושבת."),
            "configured_ip_oper_down" => Tr(language,
                "IP назначен неработающему интерфейсу (нет carrier).",
                "Configured IP belongs to an operationally DOWN interface.",
                "כתובת ה-IP משויכת לממשק שאינו פעיל."),
            "configured_ip_oper_unverified" => Tr(language,
                "Рабочее состояние интерфейса не подтверждено.",
                "Interface operational state is unverified.",
                "המצב התפעולי של הממשק אינו מאומת."),
            "incomplete_network_or_socket_inventory" => Tr(language,
                "Список интерфейсов или портов обрезан: результаты неполные.",
                "Network or socket inventory truncated: results are incomplete.",
                "רשימת הממשקים או השקעים חלקית."),
            "mta_bind_configuration_unverified" => Tr(language,
                "Настройку привязки MTA нельзя достоверно разобрать.",
                "MTA bind configuration cannot be verified.",
                "לא ניתן לאמת את תצורת ההאזנה של שרת הדואר."),
            _ => ""
        };
        return Tr(language, "Интерфейсы Linux (админ./раб.): ",
                "Linux interfaces (admin/oper): ", "ממשקי Linux (ניהולי/תפעולי): ") +
            (interfaces.Length == 0 ? unknown : interfaces) +
            Environment.NewLine +
            Tr(language, "Назначенные IP: ", "Assigned IPs: ", "כתובות IP שהוקצו: ") +
            (addresses.Length == 0 ? unknown : addresses) +
            Environment.NewLine +
            Tr(language, "Слушающие SMTP-сокеты (владелец неизвестен): ",
                "SMTP sockets (owner not verified): ", "שקעי SMTP (בעלות לא מאומתת): ") +
            (sockets.Length == 0 ? noSocket : sockets) +
            Environment.NewLine +
            Tr(language, "Порт мастера: ", "Wizard port: ", "פורט האשף: ") +
            Get("MAIL_HOST_NET_PORT") +
            "; inet_interfaces/local_interfaces: " + Get("MAIL_HOST_NET_CONFIG_KIND") +
            Environment.NewLine +
            Tr(language, "Сравнение привязок: ", "Bind comparison: ", "השוואת כתובות האזנה: ") +
            status + (hint.Length == 0 ? "" : " — " + hint) +
            Environment.NewLine +
            "ip=" + Get("MAIL_HOST_NET_STATE") +
            "; ss=" + Get("MAIL_HOST_SOCKET_STATE") +
            "; truncated=" + Get("MAIL_HOST_NET_TRUNCATED") + "/" +
            Get("MAIL_HOST_SOCKET_TRUNCATED") +
            Environment.NewLine +
            Tr(language,
                "Сокет не доказывает принадлежность MTA или доступность через firewall/NAT/Интернет.",
                "A socket does not prove MTA ownership or firewall/NAT/Internet reachability.",
                "שקע אינו מוכיח בעלות של שרת דואר או גישה דרך חומת אש/אינטרנט.");
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
                "; interface_policy=" + Get("MAIL_HOST_EXIM_BIND_POLICY") +
                "; daemon_smtp_ports=" + Get("MAIL_HOST_EXIM_SMTP_PORTS") +
                "; Debian smarthost hint=" + Get("MAIL_HOST_EXIM_SMARTHOST_HINT") +
                "; TLS declaration=" + Get("MAIL_HOST_EXIM_TLS_DECLARATION") +
                "; AUTH declaration=" + Get("MAIL_HOST_EXIM_AUTH_DECLARATION") +
                "; effective routers/transports/ACL, SMTP TLS handshake and AUTH require review.",
            "sendmail" =>
                "Sendmail: sendmail.mc=" + Get("MAIL_HOST_SENDMAIL_MC") +
                "; .mc listener=" + Get("MAIL_HOST_SENDMAIL_LISTENER") +
                "; .mc masquerade=" + Get("MAIL_HOST_SENDMAIL_MASQUERADE") +
                "; sendmail.cf=" + Get("MAIL_HOST_SENDMAIL_CF") +
                "; .cf listener=" + Get("MAIL_HOST_SENDMAIL_CF_LISTENER") +
                "; .cf SmartHost=" + Get("MAIL_HOST_SENDMAIL_CF_SMARTHOST") +
                "; .cf masquerade=" + Get("MAIL_HOST_SENDMAIL_CF_MASQUERADE") +
                "; TLS declaration=" + Get("MAIL_HOST_SENDMAIL_TLS_DECLARATION") +
                "; AUTH declaration=" + Get("MAIL_HOST_SENDMAIL_AUTH_DECLARATION") +
                "; access maps, relay restrictions, SMTP TLS handshake and AUTH require review.",
            _ => "MTA settings not verified."
        };
        string configPorts = ConfiguredSmtpPortState;
        string configLabel = language == 0 ? "Настроенные входящие TCP/SMTP порты" :
            language == 2 ? "יציאות TCP/SMTP נכנסות מוגדרות" : "Configured inbound TCP/SMTP ports";
        string state = configPorts is "unavailable" or "unverified" or "dynamic_or_unverified"
            ? (language == 0 ? "не подтверждены" : language == 2 ? "לא אומתו" : "unverified")
            : configPorts == "none_configured"
                ? (language == 0 ? "нет активных объявлений" : language == 2 ? "לא הוגדרו" : "none declared")
                : configPorts;
        return prefix + ": FQDN=" + Fqdn + "; domain=" + Domain +
            "; MTA=" + Mta + " (" + MtaState + ")." +
            Environment.NewLine + config +
            Environment.NewLine + configLabel + ": " + state +
            " [source=" + ConfiguredSmtpPortSource + "; configured, not necessarily listening]" +
            Environment.NewLine + NetworkSummary(language) +
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
            "MAIL_HOST_NET_TRUNCATED=no\n" +
            "MAIL_HOST_IFACE_01=eth0,up,up\n" +
            "MAIL_HOST_IFACE_02=eth1,up,down\n" +
            "MAIL_HOST_IFACE_03=eth2,up,up\n" +
            "MAIL_HOST_ADDR_01=eth0,ipv4,10.0.0.5/24,global\n" +
            "MAIL_HOST_ADDR_02=eth1,ipv4,192.168.1.9/24,global\n" +
            "MAIL_HOST_ADDR_03=eth2,ipv4,8.8.8.8/32,global\n" +
            "MAIL_HOST_SOCKET_01=127.0.0.1:25\n";
        var withNetwork = Parse(valid + network);
        if (Parse(valid + network + "MAIL_HOST_SOCKET_STATE=ok\n" +
            "MAIL_HOST_SOCKET_TRUNCATED=no\n").StandardPort25Observation() != "occupied" ||
            Parse(valid + network.Replace("MAIL_HOST_SOCKET_01=127.0.0.1:25\n", "") +
            "MAIL_HOST_SOCKET_STATE=ok\nMAIL_HOST_SOCKET_TRUNCATED=no\n")
                .StandardPort25Observation() != "no_listener_observed" ||
            withNetwork.StandardPort25Observation() != "unverified") return false;
        var tenSockets = Parse(valid + network +
            "MAIL_HOST_SOCKET_10=127.0.0.1:2526\n" +
            "MAIL_HOST_SOCKET_OWNER=unverified\n");
        if (!tenSockets.Summary(1).Contains("127.0.0.1:2526", StringComparison.Ordinal) ||
            tenSockets.Summary(1).Contains("unverified; unverified", StringComparison.Ordinal))
            return false;
        if (!withNetwork.Summary(1).Contains("eth0,up,up", StringComparison.Ordinal) ||
            !withNetwork.Summary(1).Contains("127.0.0.1:25", StringComparison.Ordinal) ||
            withNetwork.ActivePrivateIPv4s().Count != 1 ||
            withNetwork.ActivePrivateIPv4s()[0].Address != "10.0.0.5" ||
            withNetwork.ActivePrivateIPv4s()[0].Name != "eth0" ||
            Parse(valid + network.Replace("MAIL_HOST_NET_TRUNCATED=no",
                "MAIL_HOST_NET_TRUNCATED=yes")).ActivePrivateIPv4s().Count != 0)
            return false;
        string exim = valid.Replace("MAIL_HOST_MTA=postfix", "MAIL_HOST_MTA=exim") +
            "MAIL_HOST_EXIM_SMTP_PORTS=25,587,2525\n" +
            "MAIL_HOST_EXIM_BIND_POLICY=loopback_declared\n" +
            "MAIL_HOST_EXIM_SMARTHOST_HINT=template_declares_smarthost_requires_router_review\n" +
            "MAIL_HOST_EXIM_TLS_DECLARATION=starttls_cert_key_declared_unverified\n" +
            "MAIL_HOST_EXIM_AUTH_DECLARATION=auth_hosts_declared_backend_unverified\n";
        if (!Parse(exim).Summary(1).Contains("daemon_smtp_ports=25,587,2525",
                StringComparison.Ordinal)) return false;
        string configPorts = valid + "MAIL_HOST_SMTP_CONFIG_SOURCE=postfix_master_cf\n" +
            "MAIL_HOST_SMTP_CONFIG_PORTS=25,2525\n";
        var configured = Parse(configPorts);
        if (!configured.Summary(0).Contains("25,2525", StringComparison.Ordinal) ||
            configured.ConfiguredSmtpPorts().Count != 2 ||
            configured.ConfiguredSmtpPorts()[1] != 2525) return false;
        try { Parse(configPorts.Replace("25,2525", "25,0")); return false; }
        catch (InvalidDataException) { }
        try { Parse(configPorts.Replace("postfix_master_cf", "sendmail_cf")); return false; }
        catch (InvalidDataException) { }
        try { Parse(exim.Replace("MAIL_HOST_EXIM_BIND_POLICY=loopback_declared",
            "MAIL_HOST_EXIM_BIND_POLICY=unsafe_verified")); return false; }
        catch (InvalidDataException) { }
        try { Parse(exim.Replace("starttls_cert_key_declared_unverified",
            "tls_live_validated")); return false; }
        catch (InvalidDataException) { }
        string sendmail = valid.Replace("MAIL_HOST_MTA=postfix", "MAIL_HOST_MTA=sendmail") +
            "MAIL_HOST_SENDMAIL_CF_LISTENER=loopback_declared\n" +
            "MAIL_HOST_SENDMAIL_CF_SMARTHOST=declared\n" +
            "MAIL_HOST_SENDMAIL_TLS_DECLARATION=server_cert_key_declared_unverified\n" +
            "MAIL_HOST_SENDMAIL_AUTH_DECLARATION=mechanisms_declared_backend_unverified\n";
        if (!Parse(sendmail).Summary(1).Contains(".cf SmartHost=declared",
                StringComparison.Ordinal)) return false;
        return true;
    }
}
