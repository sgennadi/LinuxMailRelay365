using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Unlike Google-specific routes, these results bind the exact operator-selected
// host, outgoing TCP port, TLS policy and outbound SMTP AUTH mode.
internal sealed record CustomRoutePreview(
    string Host, int Port, string Tls, string AuthMode, string Fingerprint,
    bool HasConflictingMaps, string Queue, bool ApplyAllowed,
    string OutboundSasl, string PasswordMap, string TlsLevel,
    string PostfixScope, string ClientSasl, bool HasSelfLoopRisk);

internal sealed record CustomRouteApplyResult(
    string Host, int Port, string Tls, string AuthMode,
    string BackupId, bool CredentialStoredOnLinux);

internal static class CustomPostfixRoute
{
    private static readonly Regex ShaPattern =
        new(@"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex BackupPattern = new(
        @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z",
        RegexOptions.CultureInvariant);

    internal static string CheckedMode(string tls, string authMode)
    {
        if (tls is not ("starttls" or "implicit" or "plain") ||
            authMode is not ("none" or "password") ||
            (tls == "plain" && authMode == "password"))
            throw new ArgumentException("Unsupported outbound SMTP TLS/AUTH combination.");
        return tls;
    }

    private static Dictionary<string, string> ParseDictionary(string output)
    {
        if (output.Length is < 180 or > 4096 || output.Contains('\0'))
            throw new InvalidDataException("Invalid custom route result length.");
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string line = raw.TrimEnd('\r');
            int cut = line.IndexOf('=');
            if (cut < 1 || cut > 70)
                throw new InvalidDataException("Malformed custom route status.");
            string key = line[..cut], value = line[(cut + 1)..];
            if (!Regex.IsMatch(key, @"\ACUSTOM_ROUTE_[A-Z0-9_]+\z") ||
                !Regex.IsMatch(value, @"\A[A-Za-z0-9_.-]+\z") ||
                !values.TryAdd(key, value))
                throw new InvalidDataException("Unexpected or repeated custom route status field.");
        }
        return values;
    }

    private static string Value(IReadOnlyDictionary<string, string> fields, string suffix) =>
        fields.TryGetValue("CUSTOM_ROUTE_" + suffix, out var value)
            ? value : throw new InvalidDataException("Missing custom route status field.");

    internal static CustomRoutePreview ParsePreview(
        string output, string host, int port, string tls, string authMode)
    {
        host = CustomSmtpAudit.CheckedHost(host);
        CheckedMode(tls, authMode);
        var data = ParseDictionary(output);
        if (data.Count != 18 || Value(data, "VERSION") != "1" ||
            Value(data, "HOST") != host ||
            Value(data, "PORT") != port.ToString() ||
            Value(data, "TLS") != tls || Value(data, "AUTH_MODE") != authMode ||
            Value(data, "INBOUND_CHANGED") != "no" ||
            Value(data, "MAIL_SENT") != "no" ||
            Value(data, "CONFIG_CHANGED") != "no")
            throw new InvalidDataException("Custom route preview is inconsistent.");
        string sha = Value(data, "PREVIEW_SHA256");
        string conflicts = Value(data, "CONFLICTING_MAPS");
        string queue = Value(data, "QUEUE");
        string outboundSasl = Value(data, "OUTBOUND_SASL");
        string map = Value(data, "PASSWORD_MAP");
        string tlsLevel = Value(data, "TLS_LEVEL");
        string scope = Value(data, "POSTFIX_SCOPE");
        string client = Value(data, "CLIENT_SASL");
        string risk = Value(data, "SELF_LOOP_RISK");
        string allowed = Value(data, "APPLY_ALLOWED");
        if (!ShaPattern.IsMatch(sha) ||
            conflicts is not ("yes" or "no") ||
            queue is not ("empty" or "nonempty" or "unverified") ||
            outboundSasl is not ("enabled" or "disabled" or "unverified") ||
            map is not ("configured" or "not_configured") ||
            tlsLevel is not ("none" or "may" or "encrypt" or "verify" or "secure"
                or "dane" or "dane-only" or "fingerprint" or "unverified") ||
            scope is not ("verified" or "unverified") ||
            client is not ("ready" or "missing" or "unverified" or "not_required") ||
            risk is not ("yes" or "no") ||
            allowed is not ("yes" or "no") ||
            (authMode == "password" && client == "not_required") ||
            (authMode == "none" && client != "not_required") ||
            (allowed == "yes" &&
                (conflicts == "yes" || queue != "empty" ||
                 scope != "verified" || risk == "yes" ||
                 (authMode == "password" && client != "ready"))))
            throw new InvalidDataException("Custom SMTP migration not safely authorized.");
        return new(host, port, tls, authMode, sha, conflicts == "yes",
            queue, allowed == "yes", outboundSasl, map, tlsLevel, scope,
            client, risk == "yes");
    }

    internal static CustomRouteApplyResult ParseApply(
        string output, string host, int port, string tls, string authMode)
    {
        host = CustomSmtpAudit.CheckedHost(host);
        CheckedMode(tls, authMode);
        var data = ParseDictionary(output);
        if (data.Count != 11 || Value(data, "VERSION") != "1" ||
            Value(data, "HOST") != host || Value(data, "PORT") != port.ToString() ||
            Value(data, "TLS") != tls || Value(data, "AUTH_MODE") != authMode ||
            Value(data, "APPLIED") != "yes" ||
            Value(data, "ROLLBACK") != "not_required" ||
            Value(data, "INBOUND_CHANGED") != "no" ||
            Value(data, "MAIL_SENT") != "no" ||
            Value(data, "SECRET_STORED_ON_LINUX") !=
                (authMode == "password" ? "yes" : "no"))
            throw new InvalidDataException("Custom SMTP route Apply was not verified.");
        string backup = Value(data, "BACKUP_ID");
        if (!BackupPattern.IsMatch(backup))
            throw new InvalidDataException("Missing verified Postfix backup ID.");
        return new(host, port, tls, authMode, backup, authMode == "password");
    }

    internal static string BuildScript(
        string managerSource, string recoverySource,
        string host, int port, string tls, string authMode,
        string operation, string? expectedSha = null,
        string? username = null, string? oneUseSecret = null,
        string? plaintextApproval = null)
    {
        host = CustomSmtpAudit.CheckedHost(host);
        CheckedMode(tls, authMode);
        if (port is < 1 or > 65535 ||
            operation is not ("preview" or "apply"))
            throw new ArgumentException("Invalid custom SMTP route request.");
        bool apply = operation == "apply";
        if (apply && (expectedSha is null || !ShaPattern.IsMatch(expectedSha)))
            throw new ArgumentException("Exact approved Postfix SHA256 required.");
        if (!apply && (expectedSha is not null || username is not null ||
            oneUseSecret is not null || plaintextApproval is not null))
            throw new ArgumentException("Read-only Preview must not carry authorization or secrets.");
        if (apply && authMode == "password" &&
            (string.IsNullOrWhiteSpace(username) || oneUseSecret is null ||
             username.Length > 254 || oneUseSecret.Length is < 1 or > 256 ||
             username.Any(c => c < 33 || c > 126 || c == ':') ||
             oneUseSecret.Any(char.IsControl)))
            throw new InvalidDataException("Invalid one-time SMTP AUTH credential.");
        if (apply && authMode == "none" &&
            (username is not null || oneUseSecret is not null))
            throw new InvalidDataException("No SMTP credential allowed for IP/no-auth relay.");
        if (apply && tls == "plain" &&
            plaintextApproval != "I_ACCEPT_UNENCRYPTED_OUTBOUND_SMTP")
            throw new InvalidOperationException("Unencrypted relay requires typed consent.");
        if ((tls != "plain" || !apply) && plaintextApproval is not null)
            throw new InvalidOperationException("Unexpected unencrypted SMTP approval.");
        if (!managerSource.Contains("# LMR365_CONFIG_MARKER", StringComparison.Ordinal) ||
            !managerSource.Contains("# LMR365_RECOVERY_MARKER", StringComparison.Ordinal) ||
            managerSource.Contains("CONFIG_B64 =", StringComparison.Ordinal) ||
            !recoverySource.Contains("BACKUP_STATUS=verified", StringComparison.Ordinal))
            throw new InvalidDataException("Invalid embedded custom routing/recovery scripts.");
        var request = new {
            host, port, tls,
            auth_mode = authMode,
            operation,
            expected_sha = expectedSha ?? "",
            username = username ?? "",
            secret = oneUseSecret ?? "",
            plaintext_approval = plaintextApproval ?? ""
        };
        string encoded = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request)));
        string backupSource = Convert.ToBase64String(Encoding.UTF8.GetBytes(recoverySource));
        string script = managerSource
            .Replace("# LMR365_CONFIG_MARKER",
                "CONFIG_B64 = \"" + encoded + "\"", StringComparison.Ordinal)
            .Replace("# LMR365_RECOVERY_MARKER",
                "RECOVERY_B64 = \"" + backupSource + "\"", StringComparison.Ordinal);
        // The actual payload stays in encrypted SSH stdin, NOT command arguments,
        // environment, a file, the diagnostic journal or a PowerShell script.
        return "set +x\nset -eu\npython3 -I - <<'LMR365_CUSTOM_POSTFIX_ROUTE'\n" +
            script + "\nLMR365_CUSTOM_POSTFIX_ROUTE\n";
    }

    internal static bool SelfTest()
    {
        const string preview =
            "CUSTOM_ROUTE_VERSION=1\n" +
            "CUSTOM_ROUTE_HOST=relay.example.org\n" +
            "CUSTOM_ROUTE_PORT=2525\n" +
            "CUSTOM_ROUTE_TLS=starttls\n" +
            "CUSTOM_ROUTE_AUTH_MODE=password\n" +
            "CUSTOM_ROUTE_PREVIEW_SHA256=" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
            "CUSTOM_ROUTE_CONFLICTING_MAPS=no\n" +
            "CUSTOM_ROUTE_QUEUE=empty\n" +
            "CUSTOM_ROUTE_OUTBOUND_SASL=enabled\n" +
            "CUSTOM_ROUTE_PASSWORD_MAP=configured\n" +
            "CUSTOM_ROUTE_TLS_LEVEL=encrypt\n" +
            "CUSTOM_ROUTE_POSTFIX_SCOPE=verified\n" +
            "CUSTOM_ROUTE_CLIENT_SASL=ready\n" +
            "CUSTOM_ROUTE_SELF_LOOP_RISK=no\n" +
            "CUSTOM_ROUTE_APPLY_ALLOWED=yes\n" +
            "CUSTOM_ROUTE_INBOUND_CHANGED=no\n" +
            "CUSTOM_ROUTE_MAIL_SENT=no\n" +
            "CUSTOM_ROUTE_CONFIG_CHANGED=no\n";
        var parsed = ParsePreview(preview, "relay.example.org", 2525, "starttls", "password");
        if (!parsed.ApplyAllowed || parsed.HasSelfLoopRisk || parsed.Fingerprint.Length != 64)
            return false;
        const string apply =
            "CUSTOM_ROUTE_VERSION=1\n" +
            "CUSTOM_ROUTE_HOST=relay.example.org\n" +
            "CUSTOM_ROUTE_PORT=2525\n" +
            "CUSTOM_ROUTE_TLS=starttls\n" +
            "CUSTOM_ROUTE_AUTH_MODE=password\n" +
            "CUSTOM_ROUTE_BACKUP_ID=20261123T070001Z-abcdef012345\n" +
            "CUSTOM_ROUTE_APPLIED=yes\n" +
            "CUSTOM_ROUTE_ROLLBACK=not_required\n" +
            "CUSTOM_ROUTE_INBOUND_CHANGED=no\n" +
            "CUSTOM_ROUTE_MAIL_SENT=no\n" +
            "CUSTOM_ROUTE_SECRET_STORED_ON_LINUX=yes\n";
        if (!ParseApply(apply, "relay.example.org", 2525, "starttls", "password")
             .CredentialStoredOnLinux)
            return false;
        try { ParsePreview(preview + "CUSTOM_ROUTE_EXTRA=yes\n",
                "relay.example.org", 2525, "starttls", "password"); return false; }
        catch (InvalidDataException) { }
        try { ParsePreview(preview.Replace("QUEUE=empty", "QUEUE=nonempty"),
                "relay.example.org", 2525, "starttls", "password"); return false; }
        catch (InvalidDataException) { }
        try { ParseApply(apply.Replace("MAIL_SENT=no", "MAIL_SENT=yes"),
                "relay.example.org", 2525, "starttls", "password"); return false; }
        catch (InvalidDataException) { }
        const string py = "# LMR365_CONFIG_MARKER\n# LMR365_RECOVERY_MARKER";
        const string recovery = "BACKUP_STATUS=verified";
        string builder = BuildScript(py, recovery, "relay.example.org", 2525,
            "starttls", "password", "apply", new string('a', 64),
            "user@example.org", "ONE-USE-PASSWORD");
        if (builder.Contains("ONE-USE-PASSWORD", StringComparison.Ordinal))
            return false;
        try { BuildScript(py, recovery, "relay.example.org", 587,
                "plain", "password", "preview"); return false; }
        catch (ArgumentException) { }
        try { BuildScript(py, recovery, "relay.example.org", 25,
                "plain", "none", "apply", new string('a', 64)); return false; }
        catch (InvalidOperationException) { }
        try { BuildScript(py, recovery, "relay.example.org", 25,
                "starttls", "none", "apply", new string('a', 64),
                "user", "secret"); return false; }
        catch (InvalidDataException) { }
        return true;
    }
}
