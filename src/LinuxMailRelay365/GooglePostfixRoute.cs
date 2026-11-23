using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Linux root-only manager: preview is read-only; Apply requires the exact
// approved fingerprint, an empty queue and verified recovery snapshot.
// This NEVER chooses or changes a Linux listening port.
internal sealed record GoogleRoutePreview(
    string Profile, int Port, string Fingerprint, bool HasConflictingMaps,
    string Queue, bool ApplyAllowed, string OutboundSasl,
    string PasswordMap, string TlsLevel, string PostfixScope, string ClientSasl);

internal sealed record GoogleRouteApplyResult(string Profile, int Port,
    string BackupId, bool StoredRootOnlyCredential)
{
    internal static GoogleRouteApplyResult Parse(string output, string profile, int port)
    {
        var data = GooglePostfixRoute.ParseDictionary(output);
        if (GooglePostfixRoute.Value(data, "VERSION") != "1" ||
            GooglePostfixRoute.Value(data, "PROFILE") != profile ||
            GooglePostfixRoute.Value(data, "PORT") != port.ToString() ||
            GooglePostfixRoute.Value(data, "APPLIED") != "yes" ||
            GooglePostfixRoute.Value(data, "ROLLBACK") != "not_required" ||
            GooglePostfixRoute.Value(data, "INBOUND_CHANGED") != "no" ||
            GooglePostfixRoute.Value(data, "MAIL_SENT") != "no" ||
            GooglePostfixRoute.Value(data, "SECRET_STORED_ON_LINUX") !=
                (profile == "gmail" ? "yes" : "no") ||
            data.Count != 9)
            throw new InvalidDataException("Google upstream route apply result not verified.");
        string id = GooglePostfixRoute.Value(data, "BACKUP_ID");
        if (!Regex.IsMatch(id, @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z"))
            throw new InvalidDataException("Verified Postfix backup ID missing.");
        return new(profile, port, id, profile == "gmail");
    }
}

internal static class GooglePostfixRoute
{
    internal static string Value(IReadOnlyDictionary<string, string> data, string name) =>
        data.TryGetValue("GOOGLE_ROUTE_" + name, out var value) ? value :
            throw new InvalidDataException("Missing Google route result field.");

    internal static Dictionary<string, string> ParseDictionary(string output)
    {
        if (output.Length is < 80 or > 4096 || output.Contains('\0'))
            throw new InvalidDataException("Google route report is incomplete.");
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string line = raw.TrimEnd('\r');
            int pos = line.IndexOf('=');
            if (pos < 1 || pos > 72) throw new InvalidDataException("Malformed Google relay report.");
            var key = line[..pos];
            var value = line[(pos + 1)..];
            if (!Regex.IsMatch(key, @"\AGOOGLE_ROUTE_[A-Z0-9_]+\z") ||
                !Regex.IsMatch(value, @"\A[A-Za-z0-9_.-]+\z") ||
                !values.TryAdd(key, value))
                throw new InvalidDataException("Unexpected or duplicate Google route report entry.");
        }
        return values;
    }

    internal static GoogleRoutePreview ParsePreview(string output, string profile, int port)
    {
        _ = GoogleSmtpAudit.HostFor(profile);
        var values = ParseDictionary(output);
        if (Value(values, "VERSION") != "1" ||
            Value(values, "PROFILE") != profile ||
            Value(values, "PORT") != port.ToString() ||
            Value(values, "INBOUND_CHANGED") != "no" ||
            Value(values, "MAIL_SENT") != "no" ||
            Value(values, "CONFIG_CHANGED") != "no" ||
            values.Count != 15)
            throw new InvalidDataException("Invalid read-only Google upstream preview.");
        string sha = Value(values, "PREVIEW_SHA256");
        string queue = Value(values, "QUEUE");
        string conflict = Value(values, "CONFLICTING_MAPS");
        string allowed = Value(values, "APPLY_ALLOWED");
        string outboundSasl = Value(values, "OUTBOUND_SASL");
        string passwordMap = Value(values, "PASSWORD_MAP");
        string tlsLevel = Value(values, "TLS_LEVEL");
        string postfixScope = Value(values, "POSTFIX_SCOPE");
        string clientSasl = Value(values, "CLIENT_SASL");
        if (outboundSasl is not ("enabled" or "disabled" or "unverified") ||
            passwordMap is not ("configured" or "not_configured") ||
            tlsLevel is not ("none" or "may" or "encrypt" or "dane" or "dane-only"
                or "fingerprint" or "verify" or "secure" or "unverified"))
            throw new InvalidDataException("Unsafe Postfix outbound SASL/TLS status.");
        if (postfixScope is not ("verified" or "unverified") ||
            clientSasl is not ("ready" or "missing" or "unverified" or "not_required") ||
            (profile == "gmail" && clientSasl == "not_required") ||
            (profile == "workspace" && clientSasl != "not_required"))
            throw new InvalidDataException("Invalid Postfix instance or client SASL status.");
        if (!Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z") ||
            queue is not ("empty" or "nonempty" or "unverified") ||
            conflict is not ("yes" or "no") ||
            allowed is not ("yes" or "no") ||
            (allowed == "yes" && (queue != "empty" || conflict != "no" ||
                postfixScope != "verified" ||
                (profile == "gmail" && clientSasl != "ready"))))
            throw new InvalidDataException("Unsafe or inconsistent Google relay preview.");
        return new(profile, port, sha, conflict == "yes", queue,
            allowed == "yes", outboundSasl, passwordMap, tlsLevel,
            postfixScope, clientSasl);
    }

    internal static string BuildScript(string managerSource, string recoverySource,
        string profile, int port, string operation, string? expectedSha = null,
        string? mailbox = null, string? oneTimeAppPassword = null)
    {
        if (GoogleSmtpAudit.HostFor(profile).Length == 0 ||
            !GoogleSmtpAudit.PortsFor(profile).Contains(port) ||
            operation is not ("preview" or "apply"))
            throw new ArgumentException("Unsupported Google SMTP route request.");
        bool applying = operation == "apply";
        if (applying && (expectedSha is null ||
            !Regex.IsMatch(expectedSha, @"\A[a-f0-9]{64}\z")))
            throw new ArgumentException("An exact reviewed SHA256 is required for Apply.");
        if (!applying && (expectedSha is not null || mailbox is not null ||
            oneTimeAppPassword is not null))
            throw new ArgumentException("Preview cannot carry credentials or Apply approval.");
        if (applying && profile == "gmail" &&
            (mailbox is null || oneTimeAppPassword is null ||
             !Regex.IsMatch(mailbox, @"\A[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{2,190}\z") ||
             oneTimeAppPassword.Length is < 1 or > 256 ||
             oneTimeAppPassword.Any(char.IsControl)))
            throw new InvalidDataException("Gmail SMTP requires an approved one-time App Password.");
        if (applying && profile == "workspace" &&
            (mailbox is not null || oneTimeAppPassword is not null))
            throw new InvalidDataException("Workspace IP relay cannot receive a Gmail password.");
        if (!managerSource.Contains("# LMR365_CONFIG_MARKER", StringComparison.Ordinal) ||
            !managerSource.Contains("# LMR365_RECOVERY_MARKER", StringComparison.Ordinal) ||
            !recoverySource.Contains("BACKUP_STATUS=verified", StringComparison.Ordinal))
            throw new InvalidDataException("Unrecognized embedded Postfix recovery resources.");
        var req = new
        {
            profile, port, operation,
            expected_sha = expectedSha ?? "",
            user = mailbox ?? "",
            secret = oneTimeAppPassword ?? ""
        };
        string config = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(req)));
        string recovery = Convert.ToBase64String(Encoding.UTF8.GetBytes(recoverySource));
        string script = managerSource
            .Replace("# LMR365_CONFIG_MARKER",
                "CONFIG_B64 = \"" + config + "\"", StringComparison.Ordinal)
            .Replace("# LMR365_RECOVERY_MARKER",
                "RECOVERY_B64 = \"" + recovery + "\"", StringComparison.Ordinal);
        return "set +x\nset -eu\npython3 -I - <<'LMR365_POSTFIX_GOOGLE_ROUTE'\n" +
            script + "\nLMR365_POSTFIX_GOOGLE_ROUTE\n";
    }

    internal static bool SelfTest()
    {
        const string preview = "GOOGLE_ROUTE_VERSION=1\n" +
            "GOOGLE_ROUTE_PROFILE=gmail\nGOOGLE_ROUTE_PORT=587\n" +
            "GOOGLE_ROUTE_PREVIEW_SHA256=" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
            "GOOGLE_ROUTE_CONFLICTING_MAPS=no\n" +
            "GOOGLE_ROUTE_QUEUE=empty\n" +
            "GOOGLE_ROUTE_OUTBOUND_SASL=enabled\n" +
            "GOOGLE_ROUTE_PASSWORD_MAP=configured\n" +
            "GOOGLE_ROUTE_TLS_LEVEL=encrypt\n" +
            "GOOGLE_ROUTE_POSTFIX_SCOPE=verified\n" +
            "GOOGLE_ROUTE_CLIENT_SASL=ready\n" +
            "GOOGLE_ROUTE_APPLY_ALLOWED=yes\n" +
            "GOOGLE_ROUTE_INBOUND_CHANGED=no\nGOOGLE_ROUTE_MAIL_SENT=no\n" +
            "GOOGLE_ROUTE_CONFIG_CHANGED=no\n";
        var result = ParsePreview(preview, "gmail", 587);
        if (!result.ApplyAllowed || result.HasConflictingMaps ||
            result.PostfixScope != "verified" || result.ClientSasl != "ready" ||
            result.Fingerprint.Length != 64) return false;
        try { ParsePreview(preview.Replace("QUEUE=empty", "QUEUE=nonempty"), "gmail", 587); return false; }
        catch (InvalidDataException) { }
        try { ParsePreview(preview.Replace("INBOUND_CHANGED=no", "INBOUND_CHANGED=yes"), "gmail", 587); return false; }
        catch (InvalidDataException) { }
        try { ParsePreview(preview.Replace("CLIENT_SASL=ready", "CLIENT_SASL=missing"), "gmail", 587); return false; }
        catch (InvalidDataException) { }
        try { ParsePreview(preview.Replace("POSTFIX_SCOPE=verified", "POSTFIX_SCOPE=unverified"), "gmail", 587); return false; }
        catch (InvalidDataException) { }
        try { BuildScript("", "", "gmail", 587, "apply"); return false; }
        catch (ArgumentException) { }
        try { BuildScript("", "", "workspace", 587, "apply", new string('a', 64),
            "admin@example.org", "secret"); return false; }
        catch (InvalidDataException) { }
        return true;
    }
}
