namespace LinuxMailRelay365;

// An observation is tied to one map, one selected row, and its full
// identity/public-certificate evidence, not merely the mailbox address.
internal sealed record MultiMailboxCloudSelection(string Scope, string MapSha,
    string InstalledBinding, MultiMailboxIdentityRow Row)
{
    internal static MultiMailboxCloudSelection? Capture(MultiMailboxIdentityInventory inventory,
        string scope, MultiMailboxIdentityRow? row)
    {
        if (row is null || scope is not ("source" or "runtime") ||
            row.Status == "unverified" || row.Tenant is not Guid tenant || tenant == Guid.Empty ||
            row.Client is not Guid client || client == Guid.Empty)
            return null;
        var map = scope == "source" ? inventory.Source : inventory.Runtime;
        if (map.Status != "ok" || map.Rows.Count(r => r == row) != 1) return null;
        return new(scope, map.Sha256, scope == "runtime" ? inventory.InstalledBinding : "", row);
    }

    internal bool Matches(MultiMailboxIdentityInventory inventory, string scope,
        MultiMailboxIdentityRow? row) => this == Capture(inventory, scope, row);

    internal void RequireUnchanged(MultiMailboxIdentityInventory inventory)
    {
        if (!Matches(inventory, Scope, Row))
            throw new InvalidDataException("Selected multi-mailbox configuration changed during cloud audit.");
    }
}

internal sealed record MultiMailboxCloudObservation(MultiMailboxCloudSelection Selection,
    CloudObjectsInventory Cloud, DateTimeOffset SampledAt)
{
    internal static MultiMailboxCloudObservation Create(MultiMailboxCloudSelection selection,
        CloudObjectsInventory cloud, DateTimeOffset sampledAt)
    {
        if (selection.Row.Tenant != cloud.Tenant || selection.Row.Client != cloud.Client ||
            cloud.ApplicationStatus != "found" || cloud.ApplicationObjectId is not Guid app || app == Guid.Empty)
            throw new InvalidDataException("Cloud application identity mismatch.");
        if (cloud.ServicePrincipalStatus == "found")
        {
            if (cloud.ServicePrincipalObjectId is not Guid sp || sp == Guid.Empty ||
                cloud.MailboxAudit is not { } audit || audit.EnterpriseObjectId != sp ||
                audit.Mailbox != selection.Row.Mailbox)
                throw new InvalidDataException("Cloud mailbox or service principal identity mismatch.");
        }
        else if (cloud.ServicePrincipalStatus != "unverified" ||
                 cloud.ServicePrincipalObjectId is not null || cloud.MailboxAudit is not null)
            throw new InvalidDataException("Unexpected Exchange audit without an exact service principal.");
        if (cloud.Connectors.Count != 0 || cloud.Scopes.Count != 0 || cloud.RoleAssignments.Count != 0)
            throw new InvalidDataException("Unexpected broad cloud inventory in mailbox-only result.");
        return new(selection, cloud, sampledAt);
    }

    internal string GraphStatus(DateTimeOffset now) => Selection.Row.CompareCloud(Cloud, now);

    internal string Describe(DateTimeOffset now) =>
        "Selected mailbox cloud sample (UTC): " + SampledAt.ToString("u") + Environment.NewLine +
        "App Registration: " + Cloud.ApplicationStatus + " | Object ID: " + Cloud.ApplicationObjectId +
        Environment.NewLine + "Enterprise Application: " + Cloud.ServicePrincipalStatus +
        " | Object ID: " + (Cloud.ServicePrincipalObjectId?.ToString("D") ?? "unverified") +
        Environment.NewLine + "Public certificate / Graph credential: " + GraphStatus(now) +
        Environment.NewLine + (Cloud.MailboxAudit is { } audit ?
            "Primary mailbox identity: " + audit.MailboxIdentity +
            Environment.NewLine + "Organization SMTP AUTH: " + audit.OrganizationPolicy +
            Environment.NewLine + "Mailbox SMTP AUTH: " + audit.MailboxPolicy +
            Environment.NewLine + "Effective configuration: " + audit.EffectivePolicy +
            Environment.NewLine + "Exchange service principal: " + audit.ExchangePrincipal +
            Environment.NewLine + "Application SMTP.SendAsApp RBAC: " + audit.SmtpRbac :
            "Exchange mailbox policy / RBAC: not verified (exact service principal unavailable)") +
        Environment.NewLine + "Read-only sample. Local certificate validity, private-key possession, separate Entra grants, " +
        "Conditional Access, actual SMTP authentication and delivery are NOT verified.";

    internal static bool SelfTest()
    {
        Guid tenant = Guid.NewGuid(), client = Guid.NewGuid(), app = Guid.NewGuid(), sp = Guid.NewGuid();
        var row = new MultiMailboxIdentityRow("alice", "alice@example.org", "alice@example.org",
            tenant, client, new string('a',64), new string('b',64), "software", "public_certificate_read");
        var map = new MultiMailboxIdentityMap("ok", new string('c',64), [row]);
        var inventory = new MultiMailboxIdentityInventory(map, map, "same", "matches_marker");
        var selected = MultiMailboxCloudSelection.Capture(inventory, "runtime", row);
        if (selected is null || !selected.Matches(inventory, "runtime", row) ||
            selected.Matches(inventory, "source", row) ||
            selected.Matches(inventory with { Runtime = map with { Sha256 = new string('d',64) } }, "runtime", row) ||
            selected.Matches(inventory with { InstalledBinding = "mismatch" }, "runtime", row) ||
            selected.Matches(inventory with { Runtime = map with { Rows = [row with { CertificateSha = new string('d',64) }] } }, "runtime", row))
            return false;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var audit = new CloudSmtpMailboxAudit(row.Mailbox, sp, "verified", "enabled", "inherit",
            "enabled", "verified", "in_scope");
        var cloud = new CloudObjectsInventory(tenant, client, "found", app, "fixture", "found", sp,
            [new(Guid.NewGuid(), "fixture", "AsymmetricX509Cert", "Verify",
                now.AddDays(-1), now.AddDays(1), row.CertificateSha)], [], [], [], audit);
        if (Create(selected, cloud, now).GraphStatus(now) != "matches_graph_credential_dates" ||
            Create(selected, cloud with { ServicePrincipalStatus = "unverified",
                ServicePrincipalObjectId = null, MailboxAudit = null }, now).Cloud.MailboxAudit is not null)
            return false;
        foreach (var wrong in new[] { cloud with { Tenant = Guid.NewGuid() }, cloud with { Client = Guid.NewGuid() },
            cloud with { MailboxAudit = audit with { Mailbox = "bob@example.org" } },
            cloud with { MailboxAudit = audit with { EnterpriseObjectId = Guid.NewGuid() } },
            cloud with { MailboxAudit = null }, cloud with { ServicePrincipalObjectId = Guid.Empty } })
        {
            try { Create(selected, wrong, now); return false; }
            catch (InvalidDataException) { }
        }
        try
        {
            selected.RequireUnchanged(inventory with { Runtime = map with { Rows = [row with { IdentitySha = new string('f',64) }] } });
            return false;
        }
        catch (InvalidDataException) { return true; }
    }
}
