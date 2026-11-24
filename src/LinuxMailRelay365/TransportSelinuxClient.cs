using System.Globalization;
using System.Text;
using System.Text.Json;

namespace LinuxMailRelay365;

internal sealed record TransportSelinuxReadiness(string Mode, string Backend, string Sasl,
    string Labels, IReadOnlyDictionary<int, string> Ports);

internal sealed record TransportAvcCounts(int Enforced, int Permissive, int Unknown);
internal sealed record TransportAvcReport(string Mode, string Status,
    IReadOnlyDictionary<int, TransportAvcCounts> Ports);

internal static class TransportSelinuxClient
{
    internal static string Build(IEnumerable<AdvancedRouteRule> draft, bool audit = false)
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
            ("inspect-conditional-transport-selinux-readiness.py", EmbeddedAssets.ConditionalTransportSelinuxReadiness),
            ("inspect-conditional-transport-selinux-avc.py", EmbeddedAssets.ConditionalTransportSelinuxAvc)
        })
        {
            if (string.IsNullOrWhiteSpace(source) || source.Contains('\0'))
                throw new InvalidDataException("Invalid embedded policy module.");
            script += "base64 -d > \"$work/" + name + "\" <<'LMR365_POLICY_SOURCE'\n" +
                Convert.ToBase64String(Encoding.UTF8.GetBytes(source)) + "\nLMR365_POLICY_SOURCE\n";
        }
        string command = audit
            ? "\"$work/inspect-conditional-transport-selinux-avc.py\""
            : "\"$work/inspect-conditional-transport-selinux-readiness.py\" --backend auto";
        return script + "builtin printf '%s' '" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)) +
            "' | base64 -d | python3 -I -B " + command + "\n";
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

    internal static TransportAvcReport ParseAvc(string output, int exitCode,
        IEnumerable<AdvancedRouteRule> draft)
    {
        var rules = MultiTransportClient.Eligible(draft);
        if (exitCode != 0 || output.Length > 4096)
            throw new InvalidDataException("Unverified AVC inspection.");
        const string prefix = "SELINUX_AVC_";
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            int i = line.IndexOf('=');
            if (i <= prefix.Length || !line.StartsWith(prefix, StringComparison.Ordinal) ||
                !fields.TryAdd(line[prefix.Length..i], line[(i+1)..]))
                throw new InvalidDataException("Malformed AVC inspection.");
        }
        if (!new HashSet<string>(StringComparer.Ordinal) { "STATUS", "MODE", "PLAN", "WINDOW",
            "PORTS", "WRITE_ALLOWED", "RUNTIME_VERIFIED", "CHANGES_APPLIED", "MAIL_SENT" }
            .SetEquals(fields.Keys) || fields["PLAN"] != AdvancedRoutePlanner.PlanSha256(rules) ||
            fields["WINDOW"] != "recent" ||
            new[] { "WRITE_ALLOWED", "RUNTIME_VERIFIED", "CHANGES_APPLIED", "MAIL_SENT" }
                .Any(key => fields[key] != "no"))
            throw new InvalidDataException("Unverified AVC receipt.");
        string mode = fields["MODE"], status = fields["STATUS"];
        if (mode is not ("enforcing" or "permissive" or "inactive_or_unavailable" or "unverified") ||
            status is not ("records_read" or "no_matches_or_unavailable" or "unverified" or "not_checked") ||
            (status != "not_checked") != (mode is "enforcing" or "permissive"))
            throw new InvalidDataException("Invalid AVC report state.");
        static int Number(string value, int min, int max)
        {
            if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int n) ||
                n < min || n > max || n.ToString(CultureInfo.InvariantCulture) != value)
                throw new InvalidDataException("Invalid AVC count.");
            return n;
        }
        var ports = new SortedDictionary<int, TransportAvcCounts>();
        foreach (string item in fields["PORTS"].Split(','))
        {
            var parts = item.Split(':');
            if (parts.Length != 4) throw new InvalidDataException("Invalid AVC port entry.");
            int port = Number(parts[0], 1, 65535);
            var counts = new TransportAvcCounts(Number(parts[1], 0, 2097152),
                Number(parts[2], 0, 2097152), Number(parts[3], 0, 2097152));
            if ((status != "records_read" && counts != new TransportAvcCounts(0, 0, 0)) ||
                !ports.TryAdd(port, counts))
                throw new InvalidDataException("Inconsistent AVC evidence.");
        }
        if (!ports.Keys.SequenceEqual(rules.Select(r => r.Port).Distinct().OrderBy(n => n)))
            throw new InvalidDataException("AVC port set does not match the draft.");
        return new(mode, status,
            new System.Collections.ObjectModel.ReadOnlyDictionary<int, TransportAvcCounts>(ports));
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
        string avc = "SELINUX_AVC_STATUS=records_read\nSELINUX_AVC_MODE=enforcing\n" +
            "SELINUX_AVC_PLAN=" + AdvancedRoutePlanner.PlanSha256(rules) + "\n" +
            "SELINUX_AVC_WINDOW=recent\nSELINUX_AVC_PORTS=465:0:1:0,2526:2:0:1\n" +
            "SELINUX_AVC_WRITE_ALLOWED=no\nSELINUX_AVC_RUNTIME_VERIFIED=no\n" +
            "SELINUX_AVC_CHANGES_APPLIED=no\nSELINUX_AVC_MAIL_SENT=no\n";
        if (ParseAvc(avc, 0, rules).Ports[2526] != new TransportAvcCounts(2, 0, 1) ||
            !Build(rules, audit: true).EndsWith("inspect-conditional-transport-selinux-avc.py\"\n",
                StringComparison.Ordinal))
            return false;
        foreach (string bad in new[] { avc.Replace("records_read", "no_matches_or_unavailable"),
            avc.Replace("2526:2:0:1", "2525:2:0:1"), avc.Replace("2526:2:0:1", "2526:-2:0:1"),
            avc.Replace("RUNTIME_VERIFIED=no", "RUNTIME_VERIFIED=yes"),
            avc + "SELINUX_AVC_RAW=fixture\n" })
        {
            try { ParseAvc(bad, 0, rules); return false; } catch (InvalidDataException) {}
        }
        return true;
    }
}
