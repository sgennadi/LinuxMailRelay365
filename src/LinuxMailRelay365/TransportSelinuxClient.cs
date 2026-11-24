using System.Globalization;
using System.Text;
using System.Text.Json;

namespace LinuxMailRelay365;

internal sealed record TransportSelinuxReadiness(string Mode, string Backend, string Sasl,
    string Labels, IReadOnlyDictionary<int, string> Ports);

internal static class TransportSelinuxClient
{
    internal static string Build(IEnumerable<AdvancedRouteRule> draft)
    {
        var rules = MultiTransportClient.Eligible(draft);
        var payload = JsonSerializer.Serialize(rules.Select(r => new {
            selector = r.Selector, pattern = r.Pattern, host = r.Host,
            port = r.Port, tls = r.TlsMode, auth = r.AuthMode }).ToArray());
        string script = "set +x\nset -Eeuo pipefail\numask 077\n" +
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n" +
            "work=$(mktemp -d /tmp/lmr365-route-policy.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n";
        foreach (var (name, source) in new[] {
            ("stage-conditional-postfix-maps.py", EmbeddedAssets.ConditionalStageManager),
            ("conditional-postfix-transaction.py", EmbeddedAssets.ConditionalTransactionManager),
            ("inspect-conditional-postfix-activation.py", EmbeddedAssets.ConditionalActivationPreflight),
            ("compile-conditional-transports.py", EmbeddedAssets.ConditionalTransportCompiler),
            ("inspect-conditional-transport-selinux.py", EmbeddedAssets.ConditionalTransportSelinuxLabels),
            ("inspect-conditional-transport-selinux-readiness.py", EmbeddedAssets.ConditionalTransportSelinuxReadiness)
        })
        {
            if (string.IsNullOrWhiteSpace(source) || source.Contains('\0'))
                throw new InvalidDataException("Invalid embedded policy module.");
            script += "base64 -d > \"$work/" + name + "\" <<'LMR365_POLICY_SOURCE'\n" +
                Convert.ToBase64String(Encoding.UTF8.GetBytes(source)) + "\nLMR365_POLICY_SOURCE\n";
        }
        return script + "builtin printf '%s' '" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)) +
            "' | base64 -d | python3 -I -B \"$work/inspect-conditional-transport-selinux-readiness.py\" --backend auto\n";
    }

    internal static TransportSelinuxReadiness Parse(string output, int exitCode,
        IEnumerable<AdvancedRouteRule> draft)
    {
        var rules = MultiTransportClient.Eligible(draft);
        if (exitCode != 0 || output.Length > 4096)
            throw new InvalidDataException("Unverified policy inspection.");
        const string prefix = "SELINUX_ROUTE_";
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            int i = line.IndexOf('=');
            if (i <= prefix.Length || !line.StartsWith(prefix, StringComparison.Ordinal) ||
                !fields.TryAdd(line[prefix.Length..i], line[(i+1)..]))
                throw new InvalidDataException("Malformed policy inspection.");
        }
        if (!new HashSet<string>(StringComparer.Ordinal) { "STATUS", "MODE", "PLAN", "BACKEND",
            "SASL", "LABELS", "PORTS", "WRITE_ALLOWED", "RUNTIME_VERIFIED",
            "CHANGES_APPLIED", "MAIL_SENT" }.SetEquals(fields.Keys) ||
            fields["STATUS"] != "read_only" || fields["PLAN"] != AdvancedRoutePlanner.PlanSha256(rules) ||
            new[] { "WRITE_ALLOWED", "RUNTIME_VERIFIED", "CHANGES_APPLIED", "MAIL_SENT" }
                .Any(key => fields[key] != "no"))
            throw new InvalidDataException("Unverified policy receipt.");
        string mode = fields["MODE"], backend = fields["BACKEND"],
            sasl = fields["SASL"], labels = fields["LABELS"];
        if (mode is not ("enforcing" or "permissive" or "inactive_or_unavailable" or "unverified") ||
            backend is not ("hash" or "lmdb" or "unavailable" or "unverified") ||
            sasl is not ("not_required" or "cyrus_available" or "unavailable" or "unverified") ||
            (sasl == "not_required") != rules.All(r => r.AuthMode == "none") ||
            labels is not ("not_checked" or "policy_match_read_only" or "unverified"))
            throw new InvalidDataException("Invalid policy receipt value.");
        bool active = mode is "enforcing" or "permissive";
        bool indexed = backend is "hash" or "lmdb";
        if ((labels != "not_checked") != (active && indexed))
            throw new InvalidDataException("Inconsistent label inspection.");
        var ports = new SortedDictionary<int, string>();
        foreach (string item in fields["PORTS"].Split(','))
        {
            string[] parts = item.Split(':');
            if (parts.Length != 2 ||
                !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out int port) ||
                port < 1 || port > 65535 || parts[0] != port.ToString(CultureInfo.InvariantCulture) ||
                parts[1] is not ("smtp_port_t" or "other_type" or "no_specific_type" or "not_checked" or "unverified") ||
                (parts[1] != "not_checked") != active || !ports.TryAdd(port, parts[1]))
                throw new InvalidDataException("Invalid outbound port inspection.");
        }
        if (!ports.Keys.SequenceEqual(rules.Select(r => r.Port).Distinct().OrderBy(n => n)))
            throw new InvalidDataException("Outbound port set does not match the draft.");
        return new(mode, backend, sasl, labels,
            new System.Collections.ObjectModel.ReadOnlyDictionary<int, string>(ports));
    }

    internal static bool SelfTest()
    {
        var rule = new AdvancedRouteRule(AdvancedRouteMatchKind.ExactEnvelopeSender,
            "one@example.org", "smtp.example.net", 2526, "starttls", "password");
        var rules = new[] { rule, rule with { Pattern = "two@example.org", Port = 465, TlsMode = "implicit" } };
        string receipt = "SELINUX_ROUTE_STATUS=read_only\nSELINUX_ROUTE_MODE=enforcing\n" +
            "SELINUX_ROUTE_PLAN=" + AdvancedRoutePlanner.PlanSha256(rules) + "\n" +
            "SELINUX_ROUTE_BACKEND=hash\nSELINUX_ROUTE_SASL=cyrus_available\n" +
            "SELINUX_ROUTE_LABELS=policy_match_read_only\n" +
            "SELINUX_ROUTE_PORTS=465:smtp_port_t,2526:no_specific_type\n" +
            "SELINUX_ROUTE_WRITE_ALLOWED=no\nSELINUX_ROUTE_RUNTIME_VERIFIED=no\n" +
            "SELINUX_ROUTE_CHANGES_APPLIED=no\nSELINUX_ROUTE_MAIL_SENT=no\n";
        var report = Parse(receipt, 0, rules);
        if (report.Ports.Count != 2 || report.Ports[2526] != "no_specific_type" ||
            !Build(rules).Contains("--backend auto", StringComparison.Ordinal))
            return false;
        foreach (string bad in new[] { receipt.Replace("WRITE_ALLOWED=no", "WRITE_ALLOWED=yes"),
            receipt.Replace("2526:no_specific_type", "2525:no_specific_type"),
            receipt.Replace("MODE=enforcing", "MODE=inactive_or_unavailable"),
            receipt.Replace("BACKEND=hash", "BACKEND=unavailable"),
            receipt.Replace("SASL=cyrus_available", "SASL=not_required"),
            receipt + "SELINUX_ROUTE_SECRET=fixture\n", receipt + "SELINUX_ROUTE_MODE=enforcing\n" })
        {
            try { Parse(bad, 0, rules); return false; }
            catch (InvalidDataException) {}
        }
        try { Parse(receipt, 2, rules); return false; } catch (InvalidDataException) {}
        return true;
    }
}
