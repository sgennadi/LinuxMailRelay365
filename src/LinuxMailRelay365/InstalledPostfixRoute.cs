using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// The native lookup is evidence from a sampled configuration, not live routing
// or authorization to send. No raw map results or credentials are accepted.
internal sealed record InstalledPostfixRoute(string Target, string AddressClass,
    string TransportLookup, string SenderTransportLookup, string SenderRelayLookup,
    string Source, string Route, string Endpoint, string Overrides, string Status)
{
    private const string Label = @"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
    internal static bool ValidAddress(string value) =>
        value.Length <= 254 && !value.Contains("..", StringComparison.Ordinal) &&
        Regex.IsMatch(value, @"\A[a-z0-9][a-z0-9._+%-]{0,62}@" + Label + @"(?:\." + Label + @")+\z");
    internal static string Request(string target, string sender, string recipient, string nonce)
    {
        if (target is not ("primary" or "sidecar") || !ValidAddress(sender) || !ValidAddress(recipient) ||
            !Regex.IsMatch(nonce, @"\A[0-9a-f]{64}\z"))
            throw new ArgumentException("Invalid route lookup selection.");
        return JsonSerializer.Serialize(new { target, sender, recipient, nonce });
    }
    internal static string Sha(string request) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(request))).ToLowerInvariant();
    internal static InstalledPostfixRoute Parse(string json, string target, string nonce, string requestSha)
    {
        if (json.Length > 8192 || json.Contains('\0')) throw new InvalidDataException("Invalid route report.");
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        string Read(string key) => root.GetProperty(key).GetString() ?? throw new InvalidDataException("Missing value.");
        string Code(string key, params string[] allowed)
        {
            string value = Read(key);
            if (!allowed.Contains(value, StringComparer.Ordinal))
                throw new InvalidDataException("Unrecognized route evidence.");
            return value;
        }
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 15 ||
            root.EnumerateObject().Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != 15 ||
            root.GetProperty("version").GetInt32() != 1 || Read("target") != target ||
            Read("nonce") != nonce || Read("request_sha256") != requestSha ||
            root.GetProperty("changes").ValueKind != JsonValueKind.False ||
            root.GetProperty("mail_sent").ValueKind != JsonValueKind.False)
            throw new InvalidDataException("Route receipt context mismatch.");
        string Lookup(string key) => Code(key, "not_declared", "no_match", "matched_exact",
            "matched_extension", "matched_domain", "matched_parent", "matched_wildcard", "unsupported", "unverified");
        string cls = Code("address_class", "local", "virtual_alias", "virtual_mailbox", "relay", "default", "unknown");
        string transport = Lookup("transport_lookup"), senderTransport = Lookup("sender_transport_lookup"),
            senderRelay = Lookup("sender_relay_lookup");
        string source = Code("source", "unknown", "transport_maps", "local_transport", "virtual_transport",
            "relay_transport", "sender_transport_map", "default_transport", "sender_relay_map", "relayhost");
        string route = Code("route", "unknown", "oauth_pipe", "local", "virtual", "error", "discard",
            "custom_transport", "smtp_dns", "smtp_m365_eop", "smtp_m365_submission", "smtp_other");
        string endpoint = Read("endpoint");
        string overrides = Code("rewriting_or_overrides", "absent", "declared", "unverified");
        string status = Code("status", "candidate", "review", "unverified");
        bool smtpEndpoint = route is "smtp_m365_eop" or "smtp_m365_submission" or "smtp_other";
        if (smtpEndpoint)
        {
            var match = Regex.Match(endpoint, @"\A(?:\[(" + Label + @"(?:\." + Label + @")*)\]|(" +
                Label + @"(?:\." + Label + @")*))\:([0-9]{1,5})\z");
            if (!match.Success || endpoint.Length > 261 || !int.TryParse(match.Groups[3].Value, out int port) ||
                port is < 1 or > 65535)
                throw new InvalidDataException("Invalid route endpoint.");
            string host = match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;
            string expected = host.EndsWith(".mail.protection.outlook.com", StringComparison.Ordinal) && port == 25
                ? "smtp_m365_eop" : host == "smtp.office365.com" && port == 587 ? "smtp_m365_submission" : "smtp_other";
            if (route != expected) throw new InvalidDataException("Inconsistent provider evidence.");
        }
        else if (endpoint.Length != 0) throw new InvalidDataException("Unexpected route endpoint.");
        if ((status == "candidate") != (route != "unknown" && source != "unknown") ||
            status == "candidate" && (cls == "unknown" || overrides != "absent" ||
                new[] { transport, senderTransport, senderRelay }.Any(v => v is "unverified" or "unsupported")))
            throw new InvalidDataException("Inconsistent route status.");
        return new(target, cls, transport, senderTransport, senderRelay, source, route, endpoint, overrides, status);
    }

    internal string Describe() => "READ-ONLY CONFIGURATION CANDIDATE" + Environment.NewLine +
        "Postfix instance: " + Target + Environment.NewLine +
        "Recipient address class: " + AddressClass + Environment.NewLine +
        "transport_maps: " + TransportLookup + Environment.NewLine +
        "sender_dependent_default_transport_maps: " + SenderTransportLookup + Environment.NewLine +
        "sender_dependent_relayhost_maps: " + SenderRelayLookup + Environment.NewLine +
        "Rewriting / service overrides: " + Overrides + Environment.NewLine +
        "Selected source: " + Source + Environment.NewLine + "Candidate: " + Route +
        (Endpoint.Length == 0 ? "" : Environment.NewLine + "Configured next hop: " + Endpoint) +
        Environment.NewLine + "Result: " + Status + Environment.NewLine + Environment.NewLine +
        "Only allowlisted single local hash/LMDB routing maps are queried. Dynamic maps, rewriting, " +
        "live process state, sender rights, master service implementation, TLS and actual delivery are not verified. " +
        "No mail sent and no live configuration changed.";

    internal static bool SelfTest()
    {
        string nonce = new('a', 64);
        string request = Request("primary", "user@example.org", "dest@example.net", nonce);
        string sha = Sha(request);
        string json = JsonSerializer.Serialize(new { version = 1, target = "primary", nonce, request_sha256 = sha,
            changes = false, mail_sent = false, address_class = "default", transport_lookup = "no_match",
            sender_transport_lookup = "not_declared", sender_relay_lookup = "matched_exact", source = "sender_relay_map",
            route = "smtp_m365_submission", endpoint = "[smtp.office365.com]:587", rewriting_or_overrides = "absent",
            status = "candidate" });
        if (Parse(json, "primary", nonce, sha).Route != "smtp_m365_submission") return false;
        foreach (string bad in new[] { json.Replace("matched_exact", "unsupported"),
            json.Replace("smtp.office365.com", "other.example.org"), json.Replace("primary", "sidecar"),
            json.Replace("\"changes\":false", "\"changes\":true"), json.Replace("candidate", "review") })
        {
            try { Parse(bad, "primary", nonce, sha); return false; }
            catch (InvalidDataException) { }
        }
        return !ValidAddress("user@example.org;whoami") && !ValidAddress("user@foo..example");
    }
}
