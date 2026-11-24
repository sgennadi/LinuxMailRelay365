using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Only disconnected candidate maps; no production activation operation exists.
internal sealed record ConditionalStageReceipt(string Status, string PlanSha,
    string? ManifestSha, string? CompiledSha, string? Backend, int LookupCount);

internal static class ConditionalStageClient
{
    private static bool IsSha(string? value) => value is not null &&
        Regex.IsMatch(value, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant);

    internal static IReadOnlyList<AdvancedRouteRule> Eligible(
        IEnumerable<AdvancedRouteRule> rules)
    {
        var items = AdvancedRoutePlanner.ValidatePlan(rules);
        if (items.Count == 0 || items.Any(x =>
                x.TlsMode != "starttls" || x.AuthMode != "none"))
            throw new InvalidOperationException(
                "Offline staging currently supports non-overlapping STARTTLS/no-AUTH rules only.");
        if (AdvancedRoutePlanner.PossibleOverlaps(items).Count != 0)
            throw new InvalidOperationException("Resolve overlapping route conditions first.");
        var domains = items.Where(x => x.Kind == AdvancedRouteMatchKind.RecipientDomain)
            .Select(x => x.Pattern).ToArray();
        if (domains.Any(a => domains.Any(b => a != b &&
                a.EndsWith("." + b, StringComparison.Ordinal))))
            throw new InvalidOperationException(
                "Recipient parent/subdomain combinations need separate routing review.");
        return items;
    }

    internal static string Build(string source, IEnumerable<AdvancedRouteRule> rules,
        string operation, string? manifestSha = null)
    {
        var items = Eligible(rules);
        string planSha = AdvancedRoutePlanner.PlanSha256(items);
        string args = operation switch
        {
            "plan" => "--plan",
            "stage" => "--stage --approve-sha256 " + planSha +
                " --confirm STAGE_CONDITIONAL_MAPS_ONLY",
            "verify" => "--verify " + planSha,
            "compile" when IsSha(manifestSha) => "--compile " + planSha +
                " --approve-manifest-sha256 " + manifestSha +
                " --confirm COMPILE_CONDITIONAL_MAPS_ONLY",
            "verify-compiled" => "--verify-compiled " + planSha,
            _ => throw new ArgumentException("Unsupported staging operation or approval.")
        };
        if (operation != "compile" && manifestSha is not null)
            throw new ArgumentException("Unexpected compile approval.");
        if (source.Length == 0 || source.Contains('\0'))
            throw new ArgumentException("Invalid embedded staging source.");
        var json = JsonSerializer.Serialize(items.Select(x => new {
            selector = x.Selector, pattern = x.Pattern, host = x.Host,
            port = x.Port, tls = x.TlsMode, auth = x.AuthMode
        }));
        string script = "set +x\nset -Eeuo pipefail\numask 077\n" +
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n" +
            "work=$(mktemp -d /tmp/lmr365-conditional.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/stage.py\" <<'LMR365_CONDITIONAL_SOURCE'\n" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(source)) +
            "\nLMR365_CONDITIONAL_SOURCE\n";
        if (operation is "plan" or "stage")
            script += "printf '%s' '" +
                Convert.ToBase64String(Encoding.UTF8.GetBytes(json)) +
                "' | base64 -d | python3 -I \"$work/stage.py\" " + args + "\n";
        else
            script += "python3 -I \"$work/stage.py\" " + args + "\n";
        return script;
    }

    internal static ConditionalStageReceipt Parse(string output, string operation,
        string planSha, int expectedRules)
    {
        if (!IsSha(planSha) || expectedRules is < 1 or > 24 || output.Length > 4096)
            throw new InvalidDataException("Invalid conditional stage context or response.");
        string status = operation switch
        {
            "plan" => "plan_only",
            "stage" => "staged_verified",
            "verify" => "verified_read_only",
            "compile" => "compiled_verified",
            "verify-compiled" => "compiled_verified_read_only",
            _ => throw new ArgumentException("Invalid conditional staging operation.")
        };
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            int at = line.IndexOf('=');
            if (at <= 0 || !line.StartsWith("CONDITIONAL_STAGE_", StringComparison.Ordinal)
                || !fields.TryAdd(line[..at], line[(at + 1)..]))
                throw new InvalidDataException("Malformed conditional stage response.");
        }
        string? Get(string suffix) => fields.GetValueOrDefault("CONDITIONAL_STAGE_" + suffix);
        bool compiled = operation is "compile" or "verify-compiled";
        if (Get("STATUS") != status || Get("PLAN_SHA256") != planSha ||
            Get("ACTIVE") != "no" || Get("POSTFIX_CHANGED") != "no" ||
            fields.Count != (compiled ? 8 : operation == "plan" ? 4 : 5))
            throw new InvalidDataException("Unexpected or unsafe conditional stage response.");
        string? manifest = Get("MANIFEST_SHA256"), compiledSha = Get("COMPILED_SHA256"),
            backend = Get("MAP_BACKEND");
        if ((operation != "plan" && !IsSha(manifest)) ||
            (operation == "plan" && manifest is not null))
            throw new InvalidDataException("Missing or unexpected staging manifest.");
        int count = 0;
        if (compiled && (!IsSha(compiledSha) || backend is not ("hash" or "lmdb") ||
            !int.TryParse(Get("LOOKUP_COUNT"), NumberStyles.None,
                CultureInfo.InvariantCulture, out count) || count != expectedRules))
            throw new InvalidDataException("Native lookup receipt is invalid.");
        if (!compiled && (compiledSha is not null || backend is not null ||
                Get("LOOKUP_COUNT") is not null))
            throw new InvalidDataException("Unexpected compiled result.");
        return new(status, planSha, manifest, compiledSha, backend, count);
    }

    internal static bool SelfTest()
    {
        var rules = new[] { new AdvancedRouteRule(AdvancedRouteMatchKind.ExactEnvelopeSender,
            "user@example.org", "relay.example.net", 46500, "starttls", "none") };
        string sha = AdvancedRoutePlanner.PlanSha256(rules), manifest = new('a', 64),
            compiled = new('b', 64);
        string common = "CONDITIONAL_STAGE_PLAN_SHA256=" + sha +
            "\nCONDITIONAL_STAGE_ACTIVE=no\nCONDITIONAL_STAGE_POSTFIX_CHANGED=no\n";
        string response = "CONDITIONAL_STAGE_STATUS=compiled_verified\n" + common +
            "CONDITIONAL_STAGE_MANIFEST_SHA256=" + manifest +
            "\nCONDITIONAL_STAGE_COMPILED_SHA256=" + compiled +
            "\nCONDITIONAL_STAGE_MAP_BACKEND=lmdb\nCONDITIONAL_STAGE_LOOKUP_COUNT=1\n";
        if (Parse(response, "compile", sha, 1).CompiledSha != compiled ||
            Parse("CONDITIONAL_STAGE_STATUS=plan_only\n" + common,
                "plan", sha, 1).ManifestSha is not null ||
            !Build("print('fixture')", rules, "stage").Contains(
                "--confirm STAGE_CONDITIONAL_MAPS_ONLY", StringComparison.Ordinal) ||
            !Build("print('fixture')", rules, "compile", manifest).Contains(
                "--approve-manifest-sha256 " + manifest, StringComparison.Ordinal))
            return false;
        foreach (string invalid in new[] {
            response.Replace("ACTIVE=no", "ACTIVE=yes"),
            response.Replace("LOOKUP_COUNT=1", "LOOKUP_COUNT=2"),
            response.Replace("MAP_BACKEND=lmdb", "MAP_BACKEND=ldap"),
            response + "CONDITIONAL_STAGE_ACTIVE=no\n",
            response.Replace("POSTFIX_CHANGED=no", "POSTFIX_CHANGED=yes")
        })
        {
            try { Parse(invalid, "compile", sha, 1); return false; }
            catch (InvalidDataException) { }
        }
        try { Eligible([rules[0] with { AuthMode = "password" }]); return false; }
        catch (InvalidOperationException) { }
        try { Build("fixture", rules, "apply", manifest); return false; }
        catch (ArgumentException) { }
        return true;
    }
}
