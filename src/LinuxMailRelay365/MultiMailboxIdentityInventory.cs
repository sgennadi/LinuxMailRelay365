using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record MultiMailboxIdentityRow(string Login, string Sender, string Mailbox,
    Guid? Tenant, Guid? Client, string IdentitySha, string CertificateSha, string Signer, string Status)
{
    // Compare only an exact, previously inspected application. A positive
    // digest match is not proof of a signer, SMTP AUTH or delivery.
    internal string CompareCloud(CloudObjectsInventory? cloud, DateTimeOffset now)
    {
        if (cloud is null || Status != "public_certificate_read" ||
            Tenant != cloud.Tenant || Client != cloud.Client ||
            cloud.ApplicationStatus != "found" || CertificateSha.Length == 0)
            return "not_compared";
        var keys = cloud.Certificates.Where(c => c.Type == "AsymmetricX509Cert" && c.Usage == "Verify").ToArray();
        var matching = keys.Where(c => c.CertificateSha256 == CertificateSha).ToArray();
        if (matching.Any(c => c.ValidFrom <= now && now < c.ValidUntil))
            return "matches_graph_credential_dates";
        if (matching.Length > 0) return "matches_outside_graph_dates";
        return keys.Any(c => c.CertificateSha256 is null) ? "graph_key_unverified" : "not_found_in_graph_sample";
    }

    internal string CompareMailboxRbac(CloudObjectsInventory? cloud)
    {
        if (cloud is null || Tenant != cloud.Tenant || Client != cloud.Client ||
            cloud.MailboxAudit is not { } audit || audit.Mailbox != Mailbox)
            return "not_compared";
        return audit.ScopedConfigurationObserved ? "scoped_configuration_observed" : "review";
    }
}

internal sealed record MultiMailboxIdentityMap(string Status, string Sha256, MultiMailboxIdentityRow[] Rows);
internal sealed record MultiMailboxIdentityInventory(MultiMailboxIdentityMap Source,
    MultiMailboxIdentityMap Runtime, string Relation, string InstalledBinding)
{
    private static bool Sha(string value) => Regex.IsMatch(value, @"\A[a-f0-9]{64}\z");
    private static string Read(JsonElement item, string key) =>
        item.GetProperty(key).GetString() ?? throw new InvalidDataException("Missing identity inventory value.");
    private static void Object(JsonElement item, int count)
    {
        if (item.ValueKind != JsonValueKind.Object ||
            item.EnumerateObject().Count() != count ||
            item.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != count)
            throw new InvalidDataException("Invalid identity inventory shape.");
    }
    private static string Code(JsonElement item, string key, params string[] allowed)
    {
        string value = Read(item, key);
        if (!allowed.Contains(value, StringComparer.Ordinal))
            throw new InvalidDataException("Unrecognized identity inventory state.");
        return value;
    }
    private static Guid? ExactGuid(string value)
    {
        if (value.Length == 0) return null;
        if (!Guid.TryParseExact(value, "D", out var parsed) || parsed == Guid.Empty ||
            parsed.ToString("D") != value)
            throw new InvalidDataException("Invalid OAuth identity ID.");
        return parsed;
    }
    internal static MultiMailboxIdentityMap Map(JsonElement item)
    {
        Object(item, 3);
        string status = Code(item, "status", "ok", "absent", "unverified"), sha = Read(item, "sha256");
        var list = item.GetProperty("rows");
        if (list.ValueKind != JsonValueKind.Array || list.GetArrayLength() > 64 ||
            (status == "ok" ? !Sha(sha) || list.GetArrayLength() == 0 :
                sha.Length != 0 || list.GetArrayLength() != 0))
            throw new InvalidDataException("Invalid multi-mailbox map receipt.");
        var rows = new List<MultiMailboxIdentityRow>();
        var senders = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in list.EnumerateArray())
        {
            Object(row, 9);
            string login = Read(row, "login"), sender = Read(row, "sender"), mailbox = Read(row, "mailbox");
            if (!Regex.IsMatch(login, @"\A[a-z0-9][a-z0-9_.@-]{2,63}\z") ||
                !InstalledPostfixRoute.ValidAddress(mailbox) || sender != mailbox || !senders.Add(sender))
                throw new InvalidDataException("Invalid sender map row.");
            var tenant = ExactGuid(Read(row, "tenant"));
            var client = ExactGuid(Read(row, "client"));
            string identity = Read(row, "identity_sha256"), cert = Read(row, "certificate_sha256"),
                signer = Code(row, "signer", "software", "hardware", "unknown"),
                state = Code(row, "status", "unverified", "certificate_unverified", "public_certificate_read");
            if (state == "unverified" ? tenant is not null || client is not null || identity.Length != 0 ||
                cert.Length != 0 || signer != "unknown" :
                tenant is null || client is null || !Sha(identity) || signer == "unknown" ||
                (state == "public_certificate_read" ? !Sha(cert) : cert.Length != 0))
                throw new InvalidDataException("Inconsistent OAuth identity evidence.");
            rows.Add(new(login, sender, mailbox, tenant, client, identity, cert, signer, state));
        }
        return new(status, sha, rows.ToArray());
    }
    internal static MultiMailboxIdentityInventory Parse(string json, string nonce)
    {
        if (!Sha(nonce) || json.Length > 180000 || json.Contains('\0'))
            throw new InvalidDataException("Invalid identity inventory.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
        var root = doc.RootElement;
        Object(root, 10);
        if (root.GetProperty("version").GetInt32() != 1 || Read(root, "nonce") != nonce ||
            new[] { "changes", "mail_sent", "private_key_read", "signing_tested" }
                .Any(key => root.GetProperty(key).ValueKind != JsonValueKind.False))
            throw new InvalidDataException("Unexpected identity inventory context.");
        var source = Map(root.GetProperty("source"));
        var runtime = Map(root.GetProperty("runtime"));
        string relation = Code(root, "relation", "same", "different", "source_only", "runtime_only", "neither", "unverified");
        string expected = source.Status == "unverified" || runtime.Status == "unverified" ? "unverified" :
            source.Status == "ok" && runtime.Status == "ok" ? (source.Sha256 == runtime.Sha256 ? "same" : "different") :
            source.Status == "ok" ? "source_only" : runtime.Status == "ok" ? "runtime_only" : "neither";
        string binding = Code(root, "installed_binding", "matches_marker", "not_installed",
            "missing_marker", "mismatch", "unverified");
        if (relation != expected ||
            (binding == "matches_marker" && runtime.Status != "ok") ||
            (binding == "not_installed" && runtime.Status != "absent") ||
            (binding == "missing_marker" && runtime.Status == "absent"))
            throw new InvalidDataException("Inconsistent map or installed marker evidence.");
        return new(source, runtime, relation, binding);
    }

    internal static bool SelfTest()
    {
        string nonce = new('a', 64), sha = new('b', 64), cert = new('c', 64), identity = new('d', 64);
        Guid tenant = Guid.NewGuid(), client = Guid.NewGuid(), other = Guid.NewGuid();
        var row = new { login = "alice", sender = "alice@example.org", mailbox = "alice@example.org",
            tenant = tenant.ToString("D"), client = client.ToString("D"), identity_sha256 = identity,
            certificate_sha256 = cert, signer = "software", status = "public_certificate_read" };
        var map = new { status = "ok", sha256 = sha, rows = new[] { row } };
        string json = JsonSerializer.Serialize(new { version = 1, nonce, changes = false, mail_sent = false,
            private_key_read = false, signing_tested = false, source = map, runtime = map, relation = "same",
            installed_binding = "matches_marker" });
        var parsed = Parse(json, nonce);
        if (parsed.Runtime.Rows.Single().Client != client || parsed.Relation != "same") return false;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var cloud = new CloudObjectsInventory(tenant, client, "found", other, "fixture",
            "found", other, [new(Guid.NewGuid(), "fixture", "AsymmetricX509Cert", "Verify",
                now.AddDays(-1), now.AddDays(1), cert)], [], [], [],
            new("alice@example.org", other, "verified", "enabled", "inherit", "enabled", "verified", "in_scope"));
        var item = parsed.Runtime.Rows[0];
        if (item.CompareCloud(cloud, now) != "matches_graph_credential_dates" ||
            item.CompareCloud(cloud with { Client = other }, now) != "not_compared" ||
            item.CompareMailboxRbac(cloud) != "scoped_configuration_observed" ||
            item.CompareMailboxRbac(cloud with { MailboxAudit = cloud.MailboxAudit! with { Mailbox = "bob@example.org" } }) != "not_compared")
            return false;
        foreach (string bad in new[] { json.Replace("\"relation\":\"same\"", "\"relation\":\"different\""),
            json.Replace("\"changes\":false", "\"changes\":true"), json.Replace("\"private_key_read\":false", "\"private_key_read\":true"),
            json.Replace("\"certificate_sha256\":\"" + cert + "\"", "\"certificate_sha256\":\"\""),
            json.Replace("\"sender\":\"alice@example.org\"", "\"sender\":\"other@example.org\"") })
        {
            try { Parse(bad, nonce); return false; }
            catch (InvalidDataException) { }
        }
        return true;
    }
}
