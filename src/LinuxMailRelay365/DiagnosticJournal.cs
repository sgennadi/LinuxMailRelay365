using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record DiagnosticEvent(DateTimeOffset Utc, string Kind, string Result);

// Reports are privacy-safe by construction: no hostnames, identities, paths,
// raw SMTP banners, tokens, private keys, or unfiltered command output.
internal sealed class DiagnosticJournal
{
    private readonly List<DiagnosticEvent> history = [];
    private readonly object gate = new();
    internal void Record(string kind, string result)
    {
        var evt = new DiagnosticEvent(DateTimeOffset.UtcNow, Kind(kind), Result(result));
        lock (gate)
        {
            history.Add(evt);
            if (history.Count > 200) history.RemoveRange(0, history.Count - 200);
        }
    }

    private static string Kind(string kind) => kind switch
    {
        "ssh" or "linux-security" or "entra" or "tenant-discovery" or
        "postfix" or "preflight" or "token" or "smtp-test" or "update" or
        "certificate" or "diagnostics" => kind,
        _ => "other"
    };
    private static string Result(string result) => result switch
    {
        "started" or "ok" or "failed" or "cancelled" or "skipped" => result,
        _ => "unknown"
    };

    internal string ExportJson()
    {
        DiagnosticEvent[] events;
        lock (gate) events = history.ToArray();
        var report = new
        {
            schema = "linuxmailrelay365/diagnostics-v1",
            product = "LinuxMailRelay365",
            version = UpdateCheck.Version,
            capturedUtc = DateTimeOffset.UtcNow,
            secretMaterialIncluded = false,
            personalDataIncluded = false,
            containsRawHostnames = false,
            operations = events
        };
        return JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
    }

    internal static string SanitizeLocalActivity(string text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        string value = text.Replace('\r', ' ').Replace('\n', ' ');
        // Avoid accidentally printing HTTP bearer tokens or exposed PEM blocks.
        value = Regex.Replace(value, @"(?i)(bearer\s+)[A-Za-z0-9._~+/-]{15,}", "$1[REDACTED]");
        value = Regex.Replace(value, @"(?i)(access_token|refresh_token|client_assertion|client_secret|password|passphrase)(\s*[:=]\s*)[^\s,;]+", "$1$2[REDACTED]");
        value = Regex.Replace(value, @"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{10,}\b", "[JWT REDACTED]");
        value = Regex.Replace(value, @"-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----.*", "[PEM REDACTED]", RegexOptions.IgnoreCase);
        return value;
    }

    internal static bool SelfTest()
    {
        var j = new DiagnosticJournal();
        j.Record("ssh", "ok");
        j.Record("smtp-test", "failed");
        var s = j.ExportJson();
        return s.Contains("linuxmailrelay365/diagnostics-v1", StringComparison.Ordinal) &&
            s.Contains("smtp-test", StringComparison.Ordinal) &&
            !s.Contains("private_key", StringComparison.Ordinal) &&
            SanitizeLocalActivity("Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890")
                .Contains("[REDACTED]", StringComparison.Ordinal) &&
            SanitizeLocalActivity("client_secret=myvalue").Contains("[REDACTED]", StringComparison.Ordinal);
    }
}
