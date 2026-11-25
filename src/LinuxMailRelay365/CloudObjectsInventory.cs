using System.Text.Json;

namespace LinuxMailRelay365;

internal sealed record CloudConnectorObject(
    string Identity, string Name, string Type, bool Enabled,
    IReadOnlyList<string> SenderIps, IReadOnlyList<string> SenderDomains,
    string TlsCertificateName, string Ownership);

internal sealed record CloudCredentialObject(
    Guid KeyId, string Name, string Type, string Usage,
    DateTimeOffset ValidFrom, DateTimeOffset ValidUntil, string? CertificateSha256 = null);

internal sealed record CloudScopeObject(string Name, string Filter);
internal sealed record CloudAssignmentObject(string Name, string Role, string Scope);

internal sealed record CloudSmtpMailboxAudit(
    string Mailbox, Guid EnterpriseObjectId, string MailboxIdentity,
    string OrganizationPolicy, string MailboxPolicy, string EffectivePolicy,
    string ExchangePrincipal, string SmtpRbac)
{
    internal bool ScopedConfigurationObserved =>
        MailboxIdentity == "verified" && EffectivePolicy == "enabled" &&
        ExchangePrincipal == "verified" && SmtpRbac == "in_scope";
    internal static string Effective(string organization, string mailbox) =>
        mailbox is "enabled" or "disabled" ? mailbox :
        mailbox == "inherit" && (organization is "enabled" or "disabled") ?
            organization : "unverified";
}

internal sealed record CloudObjectsInventory(
    Guid Tenant, Guid? Client, string ApplicationStatus, Guid? ApplicationObjectId,
    string ApplicationName, string ServicePrincipalStatus, Guid? ServicePrincipalObjectId,
    IReadOnlyList<CloudCredentialObject> Certificates,
    IReadOnlyList<CloudConnectorObject> Connectors,
    IReadOnlyList<CloudScopeObject> Scopes,
    IReadOnlyList<CloudAssignmentObject> RoleAssignments,
    CloudSmtpMailboxAudit? MailboxAudit = null)
{
    internal static CloudObjectsInventory Parse(string json, Guid expectedTenant, Guid? expectedClient,
        string? expectedMailbox = null, Guid? expectedEnterprise = null)
    {
        if ((expectedMailbox is null) != (expectedEnterprise is null) ||
            (expectedMailbox is not null && (expectedClient is null ||
                expectedEnterprise == Guid.Empty || !SshRemote.IsEmail(expectedMailbox))))
            throw new InvalidDataException("SMTP mailbox audit selection invalid.");
        if (json.Length > 300_000 || json.Contains('\0'))
            throw new InvalidDataException("Cloud inventory is too large or contains null bytes.");
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 14 });
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            Read(root, "schema", 64) != "linuxmailrelay365-cloud-objects/v1" ||
            !root.TryGetProperty("changesApplied", out var changed) ||
            changed.ValueKind != JsonValueKind.False ||
            !Guid.TryParse(Read(root, "tenantId", 36), out Guid actual) ||
            actual != expectedTenant || actual == Guid.Empty)
            throw new InvalidDataException("Cloud inventory tenant or schema mismatch.");

        string client = Read(root, "clientId", 36);
        Guid? parsedClient = string.IsNullOrEmpty(client) ? null :
            Guid.TryParse(client, out Guid g) && g != Guid.Empty ? g :
            throw new InvalidDataException("Cloud inventory client ID invalid.");
        if (parsedClient != expectedClient)
            throw new InvalidDataException("Cloud inventory refers to a different application.");

        JsonElement application = Object(root, "application");
        JsonElement sp = Object(root, "enterpriseApplication");
        string applicationStatus = OneOf(Read(application, "status", 32),
            "not_selected", "found", "unverified");
        string serviceStatus = OneOf(Read(sp, "status", 32),
            "not_selected", "found", "unverified");
        var applicationId = Identifier(application, "objectId", applicationStatus == "found");
        var serviceId = Identifier(sp, "objectId", serviceStatus == "found");
        if (parsedClient is null &&
            (applicationStatus != "not_selected" || serviceStatus != "not_selected"))
            throw new InvalidDataException("Unselected app should have no inventory.");

        var certificates = ReadArray(root, "certificates", 64, value => new CloudCredentialObject(
            Guid.Parse(Read(value, "keyId", 36)),
            Read(value, "label", 128), Read(value, "type", 32),
            Read(value, "usage", 32),
            DateTimeOffset.Parse(Read(value, "validFrom", 50)).ToUniversalTime(),
            DateTimeOffset.Parse(Read(value, "validUntil", 50)).ToUniversalTime()));
        var connectors = ReadArray(root, "connectors", 100, value => new CloudConnectorObject(
            Read(value, "identity", 256), Read(value, "name", 90),
            Read(value, "type", 40), Boolean(value, "enabled"),
            ReadArray(value, "senderIps", 24, item => TextValue(item, 64)),
            ReadArray(value, "senderDomains", 40, item => TextValue(item, 253)),
            Read(value, "tlsCertificateName", 253),
            OneOf(Read(value, "ownership", 32), "unverified", "verified")));
        var scopes = ReadArray(root, "scopes", 100, value => new CloudScopeObject(
            Read(value, "name", 128), Read(value, "filter", 300)));
        var assignments = ReadArray(root, "roleAssignments", 100, value => new CloudAssignmentObject(
            Read(value, "name", 128), Read(value, "role", 128), Read(value, "scope", 128)));
        if (certificates.GroupBy(x => x.KeyId).Any(g => g.Count() != 1) ||
            connectors.GroupBy(x => x.Identity, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() != 1))
            throw new InvalidDataException("Duplicate cloud object identifiers.");
        CloudSmtpMailboxAudit? mailboxAudit = null;
        bool hasAudit = root.TryGetProperty("mailboxAudit", out var audit) &&
            audit.ValueKind != JsonValueKind.Null;
        if (hasAudit != (expectedMailbox is not null))
            throw new InvalidDataException("Missing or unexpected SMTP mailbox audit.");
        if (hasAudit)
        {
            if (audit.ValueKind != JsonValueKind.Object ||
                audit.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != 8 ||
                audit.EnumerateObject().Count() != 8 ||
                !string.Equals(Read(audit, "mailbox", 254), expectedMailbox, StringComparison.Ordinal) ||
                !Guid.TryParse(Read(audit, "enterpriseObjectId", 36), out Guid enterprise) ||
                enterprise != expectedEnterprise)
                throw new InvalidDataException("SMTP mailbox audit identity mismatch.");
            string mailboxIdentity = OneOf(Read(audit, "mailboxIdentity", 32), "verified", "unverified");
            string organization = OneOf(Read(audit, "organizationPolicy", 32), "enabled", "disabled", "unverified");
            string policy = OneOf(Read(audit, "mailboxPolicy", 32), "enabled", "disabled", "inherit", "unverified");
            string effective = OneOf(Read(audit, "effectivePolicy", 32), "enabled", "disabled", "unverified");
            string principal = OneOf(Read(audit, "exchangePrincipal", 32), "verified", "unverified");
            string rbac = OneOf(Read(audit, "smtpRbac", 32), "in_scope", "out_of_scope", "no_smtp_role", "unverified");
            if (effective != CloudSmtpMailboxAudit.Effective(organization, policy) ||
                (mailboxIdentity != "verified" && policy != "unverified") ||
                ((mailboxIdentity != "verified" || principal != "verified") && rbac != "unverified"))
                throw new InvalidDataException("Inconsistent SMTP mailbox audit evidence.");
            mailboxAudit = new(expectedMailbox!, enterprise, mailboxIdentity, organization,
                policy, effective, principal, rbac);
        }
        return new(actual, parsedClient, applicationStatus, applicationId,
            Read(application, "name", 128), serviceStatus, serviceId,
            certificates, connectors, scopes, assignments, mailboxAudit);
    }

    private static string OneOf(string input, params string[] values) =>
        values.Contains(input, StringComparer.Ordinal) ? input :
        throw new InvalidDataException("Unexpected cloud object status.");

    private static string TextValue(JsonElement value, int max)
    {
        if (value.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("Unexpected cloud object text value.");
        string s = value.GetString() ?? "";
        if (s.Length > max || s.Any(char.IsControl))
            throw new InvalidDataException("Unexpected cloud object text length.");
        return s;
    }

    private static string Read(JsonElement json, string name, int limit)
    {
        if (!json.TryGetProperty(name, out var value))
            throw new InvalidDataException("Cloud inventory field missing: " + name);
        return TextValue(value, limit);
    }

    private static JsonElement Object(JsonElement json, string name)
    {
        if (!json.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Missing cloud inventory object: " + name);
        return value;
    }

    private static Guid? Identifier(JsonElement json, string name, bool required)
    {
        string s = Read(json, name, 36);
        if (string.IsNullOrEmpty(s) && !required) return null;
        if (!Guid.TryParse(s, out var result) || result == Guid.Empty)
            throw new InvalidDataException("Invalid cloud object GUID.");
        return result;
    }

    private static bool Boolean(JsonElement json, string name)
    {
        if (!json.TryGetProperty(name, out var value) ||
            value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new InvalidDataException("Cloud inventory bool field missing.");
        return value.GetBoolean();
    }

    private static T[] ReadArray<T>(
        JsonElement json, string name, int maximum, Func<JsonElement, T> parse)
    {
        if (!json.TryGetProperty(name, out var element) ||
            element.ValueKind != JsonValueKind.Array || element.GetArrayLength() > maximum)
            throw new InvalidDataException("Cloud inventory array invalid: " + name);
        return element.EnumerateArray().Select(parse).ToArray();
    }

    internal string Summary()
    {
        return "Tenant: " + Tenant + Environment.NewLine +
            "Application: " + ApplicationStatus + " | " + ApplicationName +
            " | Object ID: " + (ApplicationObjectId?.ToString() ?? "not verified") +
            " | Client ID: " + (Client?.ToString() ?? "not selected") + Environment.NewLine +
            "Enterprise Application: " + ServicePrincipalStatus + " | Object ID: " +
            (ServicePrincipalObjectId?.ToString() ?? "not verified") + Environment.NewLine +
            "OAuth certificate credentials: " + Certificates.Count +
            " | Inbound Connectors: " + Connectors.Count +
            " | Management Scopes: " + Scopes.Count +
            " | Exchange role assignments: " + RoleAssignments.Count;
    }

    internal static bool SelfTest()
    {
        const string app = "11111111-1111-4111-8111-111111111111";
        const string tenant = "22222222-2222-4222-8222-222222222222";
        const string cert = "33333333-3333-4333-8333-333333333333";
        string test = """
            {"schema":"linuxmailrelay365-cloud-objects/v1","tenantId":"TENANT",
            "clientId":"APP","application":{"status":"found","objectId":"APP","name":"Example"},
            "enterpriseApplication":{"status":"unverified","objectId":""},
            "certificates":[{"keyId":"CERT","label":"Server","type":"AsymmetricX509Cert",
            "usage":"Verify","validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z"}],
            "connectors":[{"identity":"example-connector","name":"LinuxMailRelay365 Test",
            "type":"OnPremises","enabled":true,"senderIps":["8.8.8.8"],
            "senderDomains":["example.org"],"tlsCertificateName":"","ownership":"unverified"}],
            "scopes":[],"roleAssignments":[],"changesApplied":false}
            """.Replace("TENANT", tenant).Replace("CERT", cert).Replace("APP", app);
        var record = Parse(test, Guid.Parse(tenant), Guid.Parse(app));
        if (record.Certificates.Count != 1 || record.Connectors.Count != 1 ||
            record.ApplicationStatus != "found" ||
            record.ServicePrincipalStatus != "unverified" ||
            record.Connectors[0].Ownership != "unverified" ||
            record.Connectors[0].SenderIps[0] != "8.8.8.8")
            return false;
        try { Parse(test.Replace("\"changesApplied\":false", "\"changesApplied\":true"),
            Guid.Parse(tenant), Guid.Parse(app)); return false; }
        catch (InvalidDataException) { }
        try { Parse(test, Guid.NewGuid(), Guid.Parse(app)); return false; }
        catch (InvalidDataException) { }
        try { Parse(test.Replace("\"ownership\":\"unverified\"", "\"ownership\":\"mine\""),
            Guid.Parse(tenant), Guid.Parse(app)); return false; }
        catch (InvalidDataException) { }
        const string mailbox = "fixture@example.org";
        string audited = test.Replace("\"changesApplied\":false", """
            "mailboxAudit":{"mailbox":"fixture@example.org","enterpriseObjectId":"33333333-3333-4333-8333-333333333333",
            "mailboxIdentity":"verified","organizationPolicy":"disabled","mailboxPolicy":"enabled",
            "effectivePolicy":"enabled","exchangePrincipal":"verified","smtpRbac":"in_scope"},"changesApplied":false
            """);
        CloudObjectsInventory ReadAudit(string json) =>
            Parse(json, Guid.Parse(tenant), Guid.Parse(app), mailbox, Guid.Parse(cert));
        if (ReadAudit(audited).MailboxAudit?.ScopedConfigurationObserved != true) return false;
        bool RejectAudit(string json)
        {
            try { ReadAudit(json); return false; }
            catch (InvalidDataException) { return true; }
        }
        if (!RejectAudit(test) ||
            !RejectAudit(audited.Replace(mailbox, "other@example.org")) ||
            !RejectAudit(audited.Replace("\"effectivePolicy\":\"enabled\"", "\"effectivePolicy\":\"disabled\"")) ||
            !RejectAudit(audited.Replace("\"exchangePrincipal\":\"verified\"", "\"exchangePrincipal\":\"unverified\"")) ||
            !RejectAudit(audited.Replace("\"smtpRbac\":\"in_scope\"", "\"smtpRbac\":\"in_scope\",\"smtpRbac\":\"in_scope\"")))
            return false;
        return ReadAudit(audited.Replace("\"smtpRbac\":\"in_scope\"", "\"smtpRbac\":\"out_of_scope\""))
            .MailboxAudit?.ScopedConfigurationObserved == false;
    }
}
