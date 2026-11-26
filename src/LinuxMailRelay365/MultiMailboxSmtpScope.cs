using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LinuxMailRelay365;

internal sealed record MultiMailboxSmtpScopeRequest(Guid Tenant, Guid Client, Guid Enterprise,
    string Mailbox, string Nonce, bool EnableMailboxSmtp)
{
    internal const string Confirmation = "CREATE_REVIEWED_MAILBOX_SMTP_SCOPE";
    internal bool Valid => Tenant != Guid.Empty && Client != Guid.Empty && Enterprise != Guid.Empty &&
        Client != Enterprise && InstalledPostfixRoute.ValidAddress(Mailbox) &&
        Mailbox == Mailbox.ToLowerInvariant() && MultiMailboxSourceEditRequest.IsSha(Nonce);
    internal string ScopeName(Guid id) => "LMR365-MBX-" +
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            Tenant.ToString("D") + "|" + Client.ToString("D") + "|" + id.ToString("D")))).ToLowerInvariant()[..32];
}

internal sealed record MultiMailboxSmtpScopePlan(string PlanSha, Guid MailboxGuid, string ScopeName,
    string Principal, int ExistingRoles, int ExistingInScope, string OrganizationPolicy,
    string MailboxPolicy, string EffectivePolicy, bool CreateRole, bool EnableMailboxSmtp, string CanonicalPlan)
{
    internal bool ChangesNeeded => CreateRole || EnableMailboxSmtp;
    internal string Describe(MultiMailboxSmtpScopeRequest req) =>
        "Tenant: " + req.Tenant + Environment.NewLine + "Application: " + req.Client +
        Environment.NewLine + "Enterprise object: " + req.Enterprise + Environment.NewLine + "Primary mailbox: " + req.Mailbox +
        Environment.NewLine + "Recipient GUID: " + MailboxGuid + Environment.NewLine + "Scope: " + ScopeName +
        Environment.NewLine + "Filter: Guid -eq '" + MailboxGuid.ToString("D") + "'" +
        Environment.NewLine + "Exchange service principal: " + Principal +
        Environment.NewLine + "Existing SMTP roles: " + ExistingRoles + "; in scope: " + ExistingInScope +
        Environment.NewLine + "Create new single-mailbox SMTP role: " + (CreateRole ? "YES" : "no") +
        Environment.NewLine + "Organization SMTP AUTH: " + OrganizationPolicy +
        Environment.NewLine + "Mailbox SMTP AUTH: " + MailboxPolicy + " (effective: " + EffectivePolicy + ")" +
        Environment.NewLine + "Enable SMTP AUTH for this mailbox: " + (EnableMailboxSmtp ? "YES" : "no") +
        Environment.NewLine + "Plan SHA-256: " + PlanSha + Environment.NewLine + Environment.NewLine +
        "Existing grants are cumulative at application level. This does not prove exclusive access to this mailbox. " +
        "No Entra API grants, existing role edits, organization policy changes or mail sending. Partial failures require manual review.";

    internal static MultiMailboxSmtpScopePlan Parse(string json, MultiMailboxSmtpScopeRequest req,
        MultiMailboxSmtpScopePlan? approved = null)
    {
        if (!req.Valid || json.Length > 16384 || json.Contains('\0')) throw new InvalidDataException("Invalid RBAC result.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 6 });
        var root = doc.RootElement;
        static void Exact(JsonElement obj, params string[] keys)
        {
            if (obj.ValueKind != JsonValueKind.Object ||
                !obj.EnumerateObject().Select(p => p.Name).OrderBy(p => p, StringComparer.Ordinal)
                    .SequenceEqual(keys.OrderBy(p => p, StringComparer.Ordinal)))
                throw new InvalidDataException("Unexpected RBAC result fields.");
        }
        static string Text(JsonElement obj, string key) => obj.GetProperty(key).GetString() ??
            throw new InvalidDataException("Missing RBAC evidence.");
        Exact(root, "plan", "planSha256", "applied", "changes", "effectivePolicy", "authorization",
            "graphChanged", "organizationChanged", "mailSent", "postFixChanged");
        bool applied = approved is not null;
        if (root.GetProperty("applied").GetBoolean() != applied ||
            new[] {"graphChanged","organizationChanged","mailSent","postFixChanged"}
                .Any(k => root.GetProperty(k).ValueKind != JsonValueKind.False) ||
            Text(root, "authorization") != (applied ? "in_scope" : "not_run"))
            throw new InvalidDataException("RBAC result scope mismatch.");
        var p = root.GetProperty("plan");
        Exact(p, "schema","tenantId","clientId","enterpriseObjectId","mailbox","mailboxGuid","nonce",
            "scopeName","assignmentName","filter","principal","existingSmtpRoles","existingInScope",
            "organizationPolicy","mailboxPolicy","effectivePolicy","createRole","enableMailboxSmtp","requestedEnableMailboxSmtp");
        string Read(string key) => Text(p, key);
        if (Read("schema") != "linuxmailrelay365-mailbox-smtp-plan/v1" ||
            Read("tenantId") != req.Tenant.ToString("D") || Read("clientId") != req.Client.ToString("D") ||
            Read("enterpriseObjectId") != req.Enterprise.ToString("D") || Read("mailbox") != req.Mailbox ||
            Read("nonce") != req.Nonce || p.GetProperty("requestedEnableMailboxSmtp").GetBoolean() != req.EnableMailboxSmtp ||
            !Guid.TryParseExact(Read("mailboxGuid"), "D", out var id) || id == Guid.Empty || Read("mailboxGuid") != id.ToString("D"))
            throw new InvalidDataException("RBAC selection mismatch.");
        string scope = req.ScopeName(id), sha = Text(root, "planSha256"), canonical = p.GetRawText();
        if (Read("scopeName") != scope || Read("assignmentName") != scope + "-SMTP" ||
            Read("filter") != "Guid -eq '" + id.ToString("D") + "'" || !MultiMailboxSourceEditRequest.IsSha(sha) ||
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant() != sha)
            throw new InvalidDataException("RBAC plan digest or scope mismatch.");
        string principal = Read("principal"), org = Read("organizationPolicy"), mailbox = Read("mailboxPolicy"), effective = Read("effectivePolicy");
        int roles = p.GetProperty("existingSmtpRoles").GetInt32(), inScope = p.GetProperty("existingInScope").GetInt32();
        bool create = p.GetProperty("createRole").GetBoolean(), enable = p.GetProperty("enableMailboxSmtp").GetBoolean();
        if (principal is not ("create" or "reuse") || roles is < 0 or > 256 || inScope < 0 || inScope > roles ||
            (principal == "create" && roles != 0) || org is not ("enabled" or "disabled") ||
            mailbox is not ("enabled" or "disabled" or "inherit") || effective != (mailbox == "inherit" ? org : mailbox) ||
            create != (inScope == 0) || enable != (req.EnableMailboxSmtp && effective == "disabled") ||
            root.GetProperty("changes").GetBoolean() != (applied && (create || enable)) ||
            Text(root, "effectivePolicy") != (applied && enable ? "enabled" : effective))
            throw new InvalidDataException("Inconsistent RBAC plan.");
        var plan = new MultiMailboxSmtpScopePlan(sha,id,scope,principal,roles,inScope,org,mailbox,effective,create,enable,canonical);
        if (applied && (!plan.ChangesNeeded || plan != approved)) throw new InvalidDataException("RBAC Apply differs from review.");
        return plan;
    }

    internal static bool SelfTest()
    {
        var req = new MultiMailboxSmtpScopeRequest(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "alice@example.org", new string('a',64), true);
        var id = Guid.NewGuid();
        string scope = req.ScopeName(id);
        var p = new { schema = "linuxmailrelay365-mailbox-smtp-plan/v1", tenantId = req.Tenant.ToString("D"),
            clientId = req.Client.ToString("D"), enterpriseObjectId = req.Enterprise.ToString("D"), mailbox = req.Mailbox,
            mailboxGuid = id.ToString("D"), nonce = req.Nonce, scopeName = scope, assignmentName = scope + "-SMTP",
            filter = "Guid -eq '" + id.ToString("D") + "'", principal = "create", existingSmtpRoles = 0,
            existingInScope = 0, organizationPolicy = "disabled", mailboxPolicy = "inherit", effectivePolicy = "disabled",
            createRole = true, enableMailboxSmtp = true, requestedEnableMailboxSmtp = true };
        string sha = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(p))).ToLowerInvariant();
        string Receipt(bool apply) => JsonSerializer.Serialize(new { plan = p, planSha256 = sha, applied = apply,
            changes = apply, effectivePolicy = apply ? "enabled" : "disabled", authorization = apply ? "in_scope" : "not_run",
            graphChanged = false, organizationChanged = false, mailSent = false, postFixChanged = false });
        var preview = Parse(Receipt(false), req);
        if (!preview.ChangesNeeded || !preview.EnableMailboxSmtp || Parse(Receipt(true),req,preview) != preview) return false;
        foreach (string bad in new[] { Receipt(true).Replace("\"graphChanged\":false","\"graphChanged\":true"),
            Receipt(true).Replace(sha,new string('b',64)), Receipt(true).Replace(req.Mailbox,"bob@example.org"),
            Receipt(true).Replace("\"createRole\":true","\"createRole\":false") })
        {
            try { Parse(bad, req, preview); return false; }
            catch (InvalidDataException) { }
        }
        return true;
    }
}
