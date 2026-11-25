using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record MultiMailboxSourceEditRequest(string Action, string BaseSha, int BaseCount,
    string OldMailbox, string Login, string Mailbox, string IdentityFile, string Nonce)
{
    internal const string Confirmation = "SAVE_PLANNED_MAILBOX_MAP";
    internal static bool IsSha(string value) => Regex.IsMatch(value, @"\A[a-f0-9]{64}\z");
    internal static bool IsFile(string value) =>
        Regex.IsMatch(value, @"\A[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.json\z");
    internal static bool IsLogin(string value) => Regex.IsMatch(value, @"\A[a-z0-9][a-z0-9_.@-]{2,63}\z");
    internal bool Valid =>
        IsSha(Nonce) && BaseCount is >= 0 and <= 64 &&
        (BaseCount == 0 ? BaseSha == "" : IsSha(BaseSha)) &&
        (Action == "add" ? OldMailbox == "" && BaseCount < 64 :
            Action is "edit" or "remove" && BaseCount > 0 && InstalledPostfixRoute.ValidAddress(OldMailbox)) &&
        (Action == "remove" ? BaseCount > 1 && Login == "" && Mailbox == "" && IdentityFile == "" :
            IsLogin(Login) && InstalledPostfixRoute.ValidAddress(Mailbox) &&
            (IdentityFile == "" || IsFile(IdentityFile)));

    internal string Serialize(string approval = "")
    {
        if (!Valid || (approval != "" && !IsSha(approval)))
            throw new InvalidDataException("Invalid source-map edit request.");
        return JsonSerializer.Serialize(new { action = Action, base_sha = BaseSha,
            old_mailbox = OldMailbox, login = Login, mailbox = Mailbox, identity_file = IdentityFile,
            nonce = Nonce, approval, confirm = approval == "" ? "" : Confirmation });
    }
}

internal sealed record MultiMailboxSourceEditPlan(string PlanSha, string NewSha, int NewCount,
    MultiMailboxIdentityRow? Selected, string IdentityFile)
{
    internal string Describe(MultiMailboxSourceEditRequest req) =>
        "Operation: " + req.Action.ToUpperInvariant() + Environment.NewLine +
        "Map: /etc/linuxmailrelay365/oauth-senders.tsv (Source / Planned only)" + Environment.NewLine +
        "Rows: " + req.BaseCount + " -> " + NewCount + Environment.NewLine +
        (req.OldMailbox.Length > 0 ? "Previous mailbox: " + req.OldMailbox + Environment.NewLine : "") +
        (Selected is { } row ?
            "SMTP login: " + row.Login + Environment.NewLine +
            "Mailbox / envelope sender: " + row.Mailbox + Environment.NewLine +
            "Existing identity file: " + IdentityFile + Environment.NewLine +
            "Tenant ID: " + row.Tenant + Environment.NewLine +
            "Client ID: " + row.Client + Environment.NewLine +
            "Signer: " + row.Signer + Environment.NewLine +
            "Public certificate SHA-256: " + row.CertificateSha + Environment.NewLine : "") +
        "Original map SHA-256: " + (req.BaseSha == "" ? "absent" : req.BaseSha) + Environment.NewLine +
        "New map SHA-256: " + NewSha + Environment.NewLine +
        "Reviewed plan SHA-256: " + PlanSha + Environment.NewLine + Environment.NewLine +
        "A root-private backup is required before saving. No runtime map, credentials, Microsoft 365 object, " +
        "queue, service or live Postfix configuration is changed. Removing a row does not delete its identity.";

    internal static (MultiMailboxSourceEditPlan Plan, string BackupId) Parse(string json,
        MultiMailboxSourceEditRequest req, MultiMailboxSourceEditPlan? approved = null)
    {
        if (!req.Valid || json.Length > 16000 || json.Contains('\0'))
            throw new InvalidDataException("Invalid source-map edit receipt.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 17 ||
            root.EnumerateObject().Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != 17)
            throw new InvalidDataException("Unexpected source-map edit receipt shape.");
        string Read(string name) => root.GetProperty(name).GetString() ??
            throw new InvalidDataException("Missing source-map evidence.");
        bool saving = approved is not null;
        if (root.GetProperty("version").GetInt32() != 1 ||
            Read("action") != req.Action || Read("base_sha") != req.BaseSha ||
            Read("old_mailbox") != req.OldMailbox || Read("nonce") != req.Nonce ||
            Read("status") != (saving ? "saved" : "preview") ||
            root.GetProperty("changes").ValueKind != (saving ? JsonValueKind.True : JsonValueKind.False) ||
            new[] { "runtime_changed", "mail_sent", "cloud_changed" }
                .Any(k => root.GetProperty(k).ValueKind != JsonValueKind.False))
            throw new InvalidDataException("Source-map edit context or scope mismatch.");
        string planSha = Read("plan_sha"), newSha = Read("new_sha"),
            file = Read("identity_file"), backup = Read("backup_id");
        int count = root.GetProperty("new_count").GetInt32();
        int expectedCount = req.BaseCount + (req.Action == "add" ? 1 : req.Action == "remove" ? -1 : 0);
        if (!MultiMailboxSourceEditRequest.IsSha(planSha) || !MultiMailboxSourceEditRequest.IsSha(newSha) ||
            newSha == req.BaseSha || root.GetProperty("old_count").GetInt32() != req.BaseCount ||
            count != expectedCount || count is < 1 or > 64 ||
            (saving ? !Regex.IsMatch(backup, @"\Asource-[a-z0-9_]{8}\z") : backup != ""))
            throw new InvalidDataException("Invalid map plan or backup evidence.");
        var selected = root.GetProperty("selected");
        MultiMailboxIdentityRow? row = null;
        if (req.Action == "remove")
        {
            if (selected.ValueKind != JsonValueKind.Null || file != "")
                throw new InvalidDataException("Unexpected identity on removal.");
        }
        else
        {
            if (!MultiMailboxSourceEditRequest.IsFile(file) ||
                (req.IdentityFile != "" && req.IdentityFile != file))
                throw new InvalidDataException("Wrong existing identity file.");
            var one = JsonSerializer.SerializeToElement(new { status = "ok", sha256 = newSha, rows = new[] { selected } });
            row = MultiMailboxIdentityInventory.Map(one).Rows.Single();
            if (row.Status != "public_certificate_read" || row.Login != req.Login ||
                row.Mailbox != req.Mailbox || row.Sender != req.Mailbox)
                throw new InvalidDataException("Selected identity differs from the request.");
        }
        var plan = new MultiMailboxSourceEditPlan(planSha, newSha, count, row, file);
        if (saving && plan != approved)
            throw new InvalidDataException("Saved receipt differs from the explicitly approved preview.");
        return (plan, backup);
    }

    internal static bool SelfTest()
    {
        var req = new MultiMailboxSourceEditRequest("add", "", 0, "", "alice", "alice@example.org",
            "alice.json", new string('a', 64));
        string sha = new('b', 64), planSha = new('c', 64);
        var row = new { login = req.Login, sender = req.Mailbox, mailbox = req.Mailbox,
            tenant = Guid.NewGuid().ToString("D"), client = Guid.NewGuid().ToString("D"),
            identity_sha256 = new string('d',64), certificate_sha256 = new string('e',64),
            signer = "software", status = "public_certificate_read" };
        string Receipt(bool save) => JsonSerializer.Serialize(new { version = 1, action = "add",
            base_sha = "", old_mailbox = "", nonce = req.Nonce, status = save ? "saved" : "preview",
            changes = save, runtime_changed = false, mail_sent = false, cloud_changed = false,
            plan_sha = planSha, new_sha = sha, identity_file = req.IdentityFile,
            backup_id = save ? "source-abcdefgh" : "", old_count = 0, new_count = 1, selected = row });
        if (!req.Valid || (req with { IdentityFile = "../alice.json" }).Valid ||
            (req with { Action = "remove", BaseCount = 1, BaseSha = sha, OldMailbox = req.Mailbox,
                Login = "", Mailbox = "", IdentityFile = "" }).Valid) return false;
        var preview = Parse(Receipt(false), req).Plan;
        if (Parse(Receipt(true), req, preview).BackupId != "source-abcdefgh") return false;
        foreach (string bad in new[] { Receipt(true).Replace("\"runtime_changed\":false", "\"runtime_changed\":true"),
            Receipt(true).Replace(sha, new string('f',64)),
            Receipt(true).Replace("source-abcdefgh", "../unsafe"),
            Receipt(true).Replace("alice.json", "other.json"),
            Receipt(true).Replace("alice@example.org", "bob@example.org") })
        {
            try { Parse(bad, req, preview); return false; }
            catch (InvalidDataException) { }
        }
        return true;
    }
}
