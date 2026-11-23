using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// The GUI can test a selected arbitrary SMTP endpoint without claiming that
// Postfix routing, sender authorization or message delivery has been verified.
internal sealed record CustomSmtpAudit(
    string Host, int Port, string Mode, string Dns, string Tcp,
    string Tls, string Auth, string AuthResult)
{
    private static readonly Regex HostPattern = new(
        @"\A(?=.{1,253}\z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?" +
        @"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    internal static string CheckedHost(string host)
    {
        if (host != host.Trim() || !HostPattern.IsMatch(host))
            throw new ArgumentException("Invalid SMTP destination host.");
        if (Regex.IsMatch(host, @"\A[0-9.]+\z", RegexOptions.CultureInvariant) &&
            (!IPAddress.TryParse(host, out var ip) ||
             ip.AddressFamily != AddressFamily.InterNetwork ||
             !string.Equals(ip.ToString(), host, StringComparison.Ordinal)))
            throw new ArgumentException("Invalid SMTP IPv4 destination.");
        return host.ToLowerInvariant();
    }

    internal static string BuildScript(string source, string host, int port,
        string mode, string? username = null, string? password = null)
    {
        string validatedHost = CheckedHost(host);
        if (port is < 1 or > 65535 ||
            mode is not ("starttls" or "implicit" or "plain"))
            throw new ArgumentException("Invalid custom SMTP port or TLS mode.");
        bool testAuth = username is not null || password is not null;
        if (testAuth)
        {
            if (mode == "plain" || string.IsNullOrWhiteSpace(username) ||
                string.IsNullOrEmpty(password) || username.Length > 254 ||
                password.Length > 256 ||
                username.Any(c => c < 33 || c > 126) ||
                password.Any(char.IsControl))
                throw new InvalidDataException(
                    "Custom SMTP AUTH requires a valid one-use account and verified TLS.");
        }
        if (!source.Contains("# LMR365_CONFIG_MARKER", StringComparison.Ordinal) ||
            source.Contains("CONFIG_B64 =", StringComparison.Ordinal))
            throw new InvalidDataException("Invalid embedded custom SMTP probe.");
        var request = new {
            host = validatedHost, port, tls = mode,
            authenticate = testAuth,
            username = username ?? "",
            secret = password ?? ""
        };
        string encoded = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request)));
        // The source, including the ephemeral credential, is placed ONLY in
        // encrypted SSH stdin, never in logs/args/env or on Linux disk.
        return "set +x\nset -eu\npython3 -I - <<'LMR365_CUSTOM_SMTP_PROBE'\n" +
            source.Replace("# LMR365_CONFIG_MARKER",
                "CONFIG_B64 = \"" + encoded + "\"", StringComparison.Ordinal) +
            "\nLMR365_CUSTOM_SMTP_PROBE\n";
    }

    internal static CustomSmtpAudit Parse(
        string output, string host, int port, string mode, bool requestedAuth)
    {
        string expected = CheckedHost(host);
        if (port is < 1 or > 65535 ||
            mode is not ("starttls" or "implicit" or "plain") ||
            output.Length is < 180 or > 4096 || output.Contains('\0'))
            throw new InvalidDataException("Incomplete custom SMTP diagnostic result.");
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string line = raw.TrimEnd('\r');
            int separator = line.IndexOf('=');
            if (separator < 1 || separator > 64)
                throw new InvalidDataException("Malformed custom SMTP report.");
            string key = line[..separator], value = line[(separator + 1)..];
            if (!Regex.IsMatch(key, @"\ACUSTOM_SMTP_AUDIT_[A-Z0-9_]+\z",
                    RegexOptions.CultureInvariant) ||
                !Regex.IsMatch(value, @"\A[A-Za-z0-9_.-]+\z",
                    RegexOptions.CultureInvariant) ||
                !values.TryAdd(key, value))
                throw new InvalidDataException("Unexpected custom SMTP report entry.");
        }
        string Value(string suffix) =>
            values.TryGetValue("CUSTOM_SMTP_AUDIT_" + suffix, out var found)
                ? found : throw new InvalidDataException("Missing SMTP report field.");
        if (values.Count != 11 || Value("VERSION") != "1" ||
            Value("HOST") != expected || Value("PORT") != port.ToString() ||
            Value("MODE") != mode || Value("MAIL_SENT") != "no" ||
            Value("CONFIG_CHANGED") != "no" || Value("SECRETS_ECHOED") != "no")
            throw new InvalidDataException("Custom SMTP report identity invalid.");

        string dns = Value("DNS"), tcp = Value("TCP"), tls = Value("TLS");
        string auth = Value("AUTH"), authResult = Value("AUTH_RESULT");
        if (dns is not ("resolved" or "failed") ||
            tcp is not ("reachable" or "timeout" or "refused" or "failed"
                or "dns_failed" or "smtp_error") ||
            tls is not ("verified" or "unverified" or "not_offered" or
                "not_used" or "certificate_invalid" or "tls_failed" or "smtp_error") ||
            auth is not ("plain" or "login" or "oauth_only" or
                "none" or "unverified") ||
            authResult is not ("not_requested" or "accepted" or "rejected" or
                "rejected_or_policy" or "temporary_error" or "unverified" or
                "method_not_advertised"))
            throw new InvalidDataException("Unexpected custom SMTP diagnostic status.");
        if ((!requestedAuth && authResult != "not_requested") ||
            (authResult == "accepted" && (!requestedAuth || tls != "verified")) ||
            (mode == "plain" && (requestedAuth || tls == "verified")) ||
            (authResult != "not_requested" && tls != "verified") ||
            (tls == "verified" && tcp != "reachable") ||
            (dns == "failed" && tcp != "dns_failed"))
            throw new InvalidDataException("Inconsistent SMTP/TLS/AUTH status.");
        return new(expected, port, mode, dns, tcp, tls, auth, authResult);
    }

    internal static bool SelfTest()
    {
        const string fixture =
            "CUSTOM_SMTP_AUDIT_VERSION=1\n" +
            "CUSTOM_SMTP_AUDIT_HOST=relay.example.org\n" +
            "CUSTOM_SMTP_AUDIT_PORT=2525\n" +
            "CUSTOM_SMTP_AUDIT_MODE=starttls\n" +
            "CUSTOM_SMTP_AUDIT_DNS=resolved\n" +
            "CUSTOM_SMTP_AUDIT_TCP=reachable\n" +
            "CUSTOM_SMTP_AUDIT_TLS=verified\n" +
            "CUSTOM_SMTP_AUDIT_AUTH=plain\n" +
            "CUSTOM_SMTP_AUDIT_AUTH_RESULT=not_requested\n" +
            "CUSTOM_SMTP_AUDIT_MAIL_SENT=no\n" +
            "CUSTOM_SMTP_AUDIT_CONFIG_CHANGED=no\n" +
            "CUSTOM_SMTP_AUDIT_SECRETS_ECHOED=no\n";
        var parsed = Parse(fixture, "relay.example.org", 2525, "starttls", false);
        if (parsed.Port != 2525 || parsed.Tls != "verified")
            return false;
        string python = "# LMR365_CONFIG_MARKER\nprint('safe')";
        string script = BuildScript(python, parsed.Host, parsed.Port,
            parsed.Mode, "user@example.org", "one-use-test-only");
        if (script.Contains("one-use-test-only", StringComparison.Ordinal) ||
            !script.Contains("python3 -I -", StringComparison.Ordinal))
            return false;
        try { BuildScript(python, parsed.Host, 25, "plain", "a", "pw"); return false; }
        catch (InvalidDataException) { }
        try { BuildScript(python, "host;id", 587, "starttls"); return false; }
        catch (ArgumentException) { }
        try { Parse(fixture.Replace("MAIL_SENT=no", "MAIL_SENT=yes"),
                parsed.Host, parsed.Port, parsed.Mode, false); return false; }
        catch (InvalidDataException) { }
        try { Parse(fixture, parsed.Host, 587, parsed.Mode, false); return false; }
        catch (InvalidDataException) { }
        try { Parse(fixture.Replace("AUTH_RESULT=not_requested", "AUTH_RESULT=accepted"),
                parsed.Host, parsed.Port, parsed.Mode, false); return false; }
        catch (InvalidDataException) { }
        return true;
    }
}
