using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Read-only, TLS-verified SMTP port tests originating from Linux. The
// optional one-shot AUTH tests an operator-provided App Password without
// logging it, saving it, or submitting even an SMTP MAIL FROM command.
internal sealed record GoogleSmtpPortStatus(int Port, string Tcp, string Tls, string Auth)
{
    internal bool ReadyForAuth => Tcp == "reachable" && Tls == "verified" &&
        Auth is "plain" or "login";
}

internal sealed record GoogleSmtpAudit(
    string Profile, string Host, string Dns,
    IReadOnlyList<GoogleSmtpPortStatus> Ports, string AuthResult)
{
    private static readonly string[] TcpStates = [
        "reachable", "timeout", "refused", "failed", "dns_failed", "smtp_error"
    ];
    private static readonly string[] TlsStates = [
        "verified", "unverified", "not_offered", "certificate_invalid",
        "tls_failed", "smtp_error"
    ];
    private static readonly string[] AuthStates = [
        "plain", "login", "oauth_only", "none", "unverified"
    ];
    private static readonly string[] TestResults = [
        "not_requested", "accepted", "rejected", "rejected_or_policy",
        "temporary_error", "unverified", "tls_or_connect_unverified",
        "method_not_advertised"
    ];

    internal static string HostFor(string profile) => profile switch
    {
        "gmail" => "smtp.gmail.com",
        "workspace" => "smtp-relay.gmail.com",
        _ => throw new ArgumentException("Unsupported Google SMTP profile.", nameof(profile))
    };

    internal static int[] PortsFor(string profile) => profile switch
    {
        "gmail" => [587, 465],
        "workspace" => [587, 465, 25],
        _ => throw new ArgumentException("Unsupported Google SMTP profile.", nameof(profile))
    };

    internal static string BuildScript(string pythonSource, string profile,
        string? mailbox = null, string? ephemeralAppPassword = null, int authPort = 587)
    {
        HostFor(profile);
        if (authPort is not (465 or 587))
            throw new ArgumentOutOfRangeException(nameof(authPort));
        bool auth = mailbox is not null || ephemeralAppPassword is not null;
        if (auth)
        {
            if (mailbox is null || ephemeralAppPassword is null ||
                !Regex.IsMatch(mailbox,
                    @"\A[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{2,190}\z",
                    RegexOptions.CultureInvariant) ||
                ephemeralAppPassword.Length is < 1 or > 256 ||
                ephemeralAppPassword.Any(char.IsControl))
                throw new InvalidDataException("Invalid one-shot SMTP credential input.");
        }
        if (!pythonSource.Contains("# LMR365_CONFIG_MARKER", StringComparison.Ordinal) ||
            pythonSource.Contains("CONFIG_B64 =", StringComparison.Ordinal))
            throw new InvalidDataException("Unrecognized embedded Google SMTP probe.");
        var request = new {
            profile,
            authenticate = auth,
            auth_port = authPort,
            user = auth ? mailbox : null,
            secret = auth ? ephemeralAppPassword : null
        };
        string encoded = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request)));
        // Nothing sensitive is passed as a command-line argument, environment
        // variable or file. SSH standard input is encrypted end-to-end.
        return "set -eu\npython3 - <<'LMR365_GOOGLE_PROBE'\n" +
            pythonSource.Replace("# LMR365_CONFIG_MARKER",
                "CONFIG_B64 = \"" + encoded + "\"", StringComparison.Ordinal) +
            "\nLMR365_GOOGLE_PROBE\n";
    }

    internal static GoogleSmtpAudit Parse(string output, string expectedProfile)
    {
        string expectedHost = HostFor(expectedProfile);
        if (output.Length is < 150 or > 5000 || output.Contains('\0'))
            throw new InvalidDataException("Incomplete or unsafe Google SMTP report.");
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string line = raw.TrimEnd('\r');
            int cut = line.IndexOf('=');
            if (cut <= 0 || cut > 64) throw new InvalidDataException("Unexpected SMTP report line.");
            string key = line[..cut], value = line[(cut + 1)..];
            if (!Regex.IsMatch(key, @"\AGOOGLE_SMTP_AUDIT_[A-Z0-9_]+\z",
                    RegexOptions.CultureInvariant) ||
                !Regex.IsMatch(value, @"\A[a-z0-9_.-]+\z",
                    RegexOptions.CultureInvariant) ||
                !values.TryAdd(key, value))
                throw new InvalidDataException("Invalid or duplicate Google SMTP report entry.");
        }
        string Value(string name) => values.TryGetValue("GOOGLE_SMTP_AUDIT_" + name, out var v)
            ? v : throw new InvalidDataException("Missing Google SMTP report field: " + name);
        if (Value("VERSION") != "1" || Value("PROFILE") != expectedProfile ||
            Value("HOST") != expectedHost ||
            Value("MAIL_SENT") != "no" || Value("CONFIG_CHANGED") != "no" ||
            Value("SECRETS_ECHOED") != "no")
            throw new InvalidDataException("Unexpected Google SMTP probe identity or state.");
        string dns = Value("DNS");
        if (dns is not ("resolved" or "failed"))
            throw new InvalidDataException("Invalid Google SMTP DNS status.");
        string result = Value("AUTH_RESULT");
        if (!TestResults.Contains(result, StringComparer.Ordinal))
            throw new InvalidDataException("Invalid SMTP AUTH result.");
        var ports = new List<GoogleSmtpPortStatus>();
        foreach (int port in PortsFor(expectedProfile))
        {
            string tcp = Value("PORT_" + port + "_TCP");
            string tls = Value("PORT_" + port + "_TLS");
            string auth = Value("PORT_" + port + "_AUTH");
            if (!TcpStates.Contains(tcp, StringComparer.Ordinal) ||
                !TlsStates.Contains(tls, StringComparer.Ordinal) ||
                !AuthStates.Contains(auth, StringComparer.Ordinal))
                throw new InvalidDataException("Invalid Google SMTP port state.");
            ports.Add(new(port, tcp, tls, auth));
        }
        if (values.Count != 8 + ports.Count * 3)
            throw new InvalidDataException("Unexpected extra SMTP result field.");
        return new(expectedProfile, expectedHost, dns, ports, result);
    }

    internal string Display(int language)
    {
        static string T(int lang, string ru, string en, string he) =>
            lang == 0 ? ru : lang == 2 ? he : en;
        var lines = new List<string> {
            Host + " · DNS: " + Dns
        };
        foreach (var p in Ports)
            lines.Add("TCP " + p.Port + ": " + p.Tcp +
                "  |  TLS: " + p.Tls + "  |  AUTH: " + p.Auth);
        string result = AuthResult switch
        {
            "accepted" => T(language, "SMTP AUTH принят. Отправка письма НЕ проверялась.",
                "SMTP AUTH accepted. Mail delivery NOT tested.",
                "אימות SMTP הצליח. מסירת דואר לא נבדקה."),
            "rejected_or_policy" or "rejected" => T(language,
                "SMTP AUTH отклонён (пароль, учётная запись или политика).",
                "SMTP AUTH rejected (credential, account or policy).",
                "אימות SMTP נדחה."),
            "not_requested" => T(language,
                "Пароль не проверялся.",
                "Credentials were not tested.",
                "הסיסמה לא נבדקה."),
            _ => T(language,
                "SMTP AUTH не подтверждён: ", "SMTP AUTH not verified: ",
                "אימות SMTP לא אומת: ") + AuthResult
        };
        lines.Add(result);
        lines.Add(T(language,
            "Доступные TCP/TLS-порты не подтверждают право Relay, доставку или разрешённый IP Workspace.",
            "TCP/TLS connectivity does NOT prove relay authorization, delivery or Workspace IP allowlisting.",
            "גישה ל-TCP/TLS אינה הוכחה לאישור ממסר או מסירת דואר."));
        return string.Join(Environment.NewLine, lines);
    }

    internal static bool SelfTest()
    {
        string fixture = "GOOGLE_SMTP_AUDIT_VERSION=1\n" +
            "GOOGLE_SMTP_AUDIT_PROFILE=gmail\nGOOGLE_SMTP_AUDIT_HOST=smtp.gmail.com\n" +
            "GOOGLE_SMTP_AUDIT_DNS=resolved\n" +
            "GOOGLE_SMTP_AUDIT_PORT_587_TCP=reachable\n" +
            "GOOGLE_SMTP_AUDIT_PORT_587_TLS=verified\n" +
            "GOOGLE_SMTP_AUDIT_PORT_587_AUTH=plain\n" +
            "GOOGLE_SMTP_AUDIT_PORT_465_TCP=timeout\n" +
            "GOOGLE_SMTP_AUDIT_PORT_465_TLS=unverified\n" +
            "GOOGLE_SMTP_AUDIT_PORT_465_AUTH=unverified\n" +
            "GOOGLE_SMTP_AUDIT_AUTH_RESULT=accepted\n" +
            "GOOGLE_SMTP_AUDIT_MAIL_SENT=no\n" +
            "GOOGLE_SMTP_AUDIT_CONFIG_CHANGED=no\n" +
            "GOOGLE_SMTP_AUDIT_SECRETS_ECHOED=no\n";
        var parsed = Parse(fixture, "gmail");
        if (parsed.Ports.Count != 2 || !parsed.Ports[0].ReadyForAuth ||
            parsed.Ports[1].ReadyForAuth ||
            !parsed.Display(1).Contains("NOT tested", StringComparison.Ordinal))
            return false;
        try { Parse(fixture, "workspace"); return false; }
        catch (InvalidDataException) { }
        try { Parse(fixture + "GOOGLE_SMTP_AUDIT_AUTH_RESULT=accepted\n", "gmail"); return false; }
        catch (InvalidDataException) { }
        try { Parse(fixture.Replace("MAIL_SENT=no", "MAIL_SENT=yes"), "gmail"); return false; }
        catch (InvalidDataException) { }
        string py = "# LMR365_CONFIG_MARKER\nprint('safe')";
        var script = BuildScript(py, "gmail", "mail@example.org", "one-use-app-password");
        if (script.Contains("one-use-app-password", StringComparison.Ordinal) ||
            !script.Contains("python3 -", StringComparison.Ordinal) ||
            !script.Contains("LMR365_GOOGLE_PROBE", StringComparison.Ordinal))
            return false;
        try { BuildScript(py, "gmail", "mail@example.org", "bad\nsecret"); return false; }
        catch (InvalidDataException) { }
        try { BuildScript(py, "smtp.evil.org"); return false; }
        catch (ArgumentException) { }
        return true;
    }
}
