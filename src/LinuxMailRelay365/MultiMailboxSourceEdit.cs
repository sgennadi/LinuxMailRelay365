using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record MultiMailboxSourceEditRequest(string Action, string BaseSha, int BaseCount,
    string OldMailbox, string Login, string Mailbox, string IdentityFile, string Nonce, string BackupId = "")
{
    internal const string Confirmation = "SAVE_PLANNED_MAILBOX_MAP";
    internal const string RestoreConfirmation = "RESTORE_PLANNED_MAILBOX_MAP";
    internal static bool IsBackup(string value) => Regex.IsMatch(value, @"\Asource-[a-z0-9_]{8}\z");
    internal string ConfirmationPhrase => Action == "restore" ? RestoreConfirmation : Confirmation;
    internal static bool IsSha(string value) => Regex.IsMatch(value, @"\A[a-f0-9]{64}\z");
    internal static bool IsFile(string value) =>
        Regex.IsMatch(value, @"\A[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.json\z");
    internal static bool IsLogin(string value) => Regex.IsMatch(value, @"\A[a-z0-9][a-z0-9_.@-]{2,63}\z");
    internal bool Valid =>
        IsSha(Nonce) && BaseCount is >= 0 and <= 64 &&
        (BaseCount == 0 ? BaseSha == "" : IsSha(BaseSha)) &&
        (Action == "restore" ? BaseCount > 0 && IsBackup(BackupId) &&
            OldMailbox == "" && Login == "" && Mailbox == "" && IdentityFile == "" :
        BackupId == "" &&
        (Action == "add" ? OldMailbox == "" && BaseCount < 64 :
            Action is "edit" or "remove" && BaseCount > 0 && InstalledPostfixRoute.ValidAddress(OldMailbox)) &&
        (Action == "remove" ? BaseCount > 1 && Login == "" && Mailbox == "" && IdentityFile == "" :
            IsLogin(Login) && InstalledPostfixRoute.ValidAddress(Mailbox) &&
            (IdentityFile == "" || IsFile(IdentityFile))));

    internal string Serialize(string approval = "")
    {
        if (!Valid || (approval != "" && !IsSha(approval)))
            throw new InvalidDataException("Invalid source-map edit request.");
        if (Action == "restore")
            return JsonSerializer.Serialize(new { action = Action, base_sha = BaseSha,
                old_mailbox = "", login = "", mailbox = "", identity_file = "", nonce = Nonce,
                backup_id = BackupId, approval, confirm = approval == "" ? "" : RestoreConfirmation });
        return JsonSerializer.Serialize(new { action = Action, base_sha = BaseSha,
            old_mailbox = OldMailbox, login = Login, mailbox = Mailbox, identity_file = IdentityFile,
            nonce = Nonce, approval, confirm = approval == "" ? "" : Confirmation });
    }
}

internal sealed record MultiMailboxSourceEditPlan(string PlanSha, string NewSha, int NewCount,
    MultiMailboxIdentityRow? Selected, string IdentityFile, string RestoredFrom = "",
    string SelinuxMode = "", string SelinuxPolicySha = "")
{
    internal string Describe(MultiMailboxSourceEditRequest req) =>
        "Operation: " + req.Action.ToUpperInvariant() + Environment.NewLine +
        "Map: /etc/linuxmailrelay365/oauth-senders.tsv (Source / Planned only)" + Environment.NewLine +
        "Rows: " + req.BaseCount + " -> " + NewCount + Environment.NewLine +
        (RestoredFrom.Length > 0 ? "Restore from: " + RestoredFrom + Environment.NewLine +
            "Restore only the previous source-map bytes, preserving current source file metadata. Current map is backed up again." + Environment.NewLine : "") +
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
        "Reviewed plan SHA-256: " + PlanSha + Environment.NewLine +
        (SelinuxMode == "" ? "" : "SELinux: " + SelinuxMode + "; policy SHA-256: " + SelinuxPolicySha +
            Environment.NewLine + "Only new map/backup inodes receive installed-policy labels; existing policy is unchanged." + Environment.NewLine) +
        Environment.NewLine +
        "A root-private backup is required before saving. No runtime map, credentials, Microsoft 365 object, " +
        "queue, service or live Postfix configuration is changed. Removing a row does not delete its identity.";

    internal static (MultiMailboxSourceEditPlan Plan, string BackupId) Parse(string json,
        MultiMailboxSourceEditRequest req, MultiMailboxSourceEditPlan? approved = null)
    {
        if (!req.Valid || json.Length > 16000 || json.Contains('\0'))
            throw new InvalidDataException("Invalid source-map edit receipt.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
        var root = doc.RootElement;
        bool restoring = req.Action == "restore";
        bool labeled = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("selinux_mode", out _);
        int fields = (restoring ? 18 : 17) + (labeled ? 2 : 0);
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != fields ||
            root.EnumerateObject().Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != fields)
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
        string restoredFrom = restoring ? Read("restored_from") : "";
        if (restoring && restoredFrom != req.BackupId)
            throw new InvalidDataException("Wrong selected backup.");
        int count = root.GetProperty("new_count").GetInt32();
        int expectedCount = req.BaseCount + (req.Action == "add" ? 1 : req.Action == "remove" ? -1 : 0);
        if (!MultiMailboxSourceEditRequest.IsSha(planSha) || !MultiMailboxSourceEditRequest.IsSha(newSha) ||
            newSha == req.BaseSha || root.GetProperty("old_count").GetInt32() != req.BaseCount ||
            (!restoring && count != expectedCount) || count is < 1 or > 64 ||
            (saving ? !Regex.IsMatch(backup, @"\Asource-[a-z0-9_]{8}\z") : backup != ""))
            throw new InvalidDataException("Invalid map plan or backup evidence.");
        var selected = root.GetProperty("selected");
        MultiMailboxIdentityRow? row = null;
        if (req.Action is "remove" or "restore")
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
        string mode = labeled ? Read("selinux_mode") : "", policy = labeled ? Read("selinux_policy_sha") : "";
        if (labeled && (mode is not ("enforcing" or "permissive") || !MultiMailboxSourceEditRequest.IsSha(policy)))
            throw new InvalidDataException("Invalid SELinux source-map evidence.");
        var plan = new MultiMailboxSourceEditPlan(planSha, newSha, count, row, file, restoredFrom, mode, policy);
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
        string policy = new('9',64);
        string Labeled(string body) => body[..^1] + ",\"selinux_mode\":\"enforcing\",\"selinux_policy_sha\":\""+policy+"\"}";
        var labeledPreview = Parse(Labeled(Receipt(false)),req).Plan;
        if (labeledPreview.SelinuxMode!="enforcing" || Parse(Labeled(Receipt(true)),req,labeledPreview).Plan.SelinuxPolicySha!=policy)
            return false;
        foreach (string bad in new[]{Receipt(true),Labeled(Receipt(true)).Replace("enforcing","permissive"),
            Labeled(Receipt(true)).Replace(policy,new string('8',64))})
        {
            try { Parse(bad,req,labeledPreview); return false; } catch(InvalidDataException) { }
        }
        var restore = new MultiMailboxSourceEditRequest("restore", sha, 1, "", "", "", "",
            req.Nonce, "source-abcdefgh");
        if (!restore.Valid || (restore with { BackupId = "../unsafe" }).Valid ||
            !restore.Serialize(planSha).Contains("RESTORE_PLANNED_MAILBOX_MAP", StringComparison.Ordinal))
            return false;
        string RestoreReceipt(bool save) => JsonSerializer.Serialize(new { version = 1, action = "restore",
            base_sha = sha, old_mailbox = "", nonce = req.Nonce, status = save ? "saved" : "preview",
            changes = save, runtime_changed = false, mail_sent = false, cloud_changed = false,
            plan_sha = planSha, new_sha = new string('f',64), identity_file = "",
            backup_id = save ? "source-ijklmnop" : "", old_count = 1, new_count = 2,
            selected = (object?)null, restored_from = restore.BackupId });
        var restoration = Parse(RestoreReceipt(false), restore).Plan;
        if (Parse(RestoreReceipt(true), restore, restoration).BackupId != "source-ijklmnop") return false;
        try { Parse(RestoreReceipt(true).Replace("source-abcdefgh", "source-zzzzzzzz"), restore, restoration); return false; }
        catch (InvalidDataException) { return MultiMailboxSourceBackupCatalog.SelfTest(); }
    }
}

internal sealed record MultiMailboxSourceBackup(string BackupId, string MapSha, int RowCount);

internal sealed record MultiMailboxSourceBackupCatalog(int Scanned, MultiMailboxSourceBackup[] Backups)
{
    internal static string Request(string sha, string nonce)
    {
        if (!MultiMailboxSourceEditRequest.IsSha(sha) || !MultiMailboxSourceEditRequest.IsSha(nonce))
            throw new InvalidDataException("Invalid backup catalog context.");
        return JsonSerializer.Serialize(new { action = "list_backups", base_sha = sha, nonce });
    }

    internal static MultiMailboxSourceBackupCatalog Parse(string json, string sha, int count, string nonce)
    {
        _ = Request(sha, nonce);
        if (count is < 1 or > 64 || json.Length > 16384 || json.Contains('\0'))
            throw new InvalidDataException("Invalid backup catalog receipt.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 5 });
        var root = doc.RootElement;
        static bool Exact(JsonElement obj, params string[] fields) =>
            obj.ValueKind == JsonValueKind.Object &&
            obj.EnumerateObject().Select(p => p.Name).OrderBy(p => p, StringComparer.Ordinal)
                .SequenceEqual(fields.OrderBy(p => p, StringComparer.Ordinal));
        if (!Exact(root, "version", "action", "status", "nonce", "base_sha", "old_count",
            "scanned", "backups", "changes", "runtime_changed", "mail_sent", "cloud_changed") ||
            root.GetProperty("version").GetInt32() != 1 ||
            root.GetProperty("action").GetString() != "list_backups" ||
            root.GetProperty("status").GetString() != "catalog" ||
            root.GetProperty("nonce").GetString() != nonce ||
            root.GetProperty("base_sha").GetString() != sha ||
            root.GetProperty("old_count").GetInt32() != count ||
            new[] { "changes", "runtime_changed", "mail_sent", "cloud_changed" }
                .Any(k => root.GetProperty(k).ValueKind != JsonValueKind.False))
            throw new InvalidDataException("Backup catalog context or scope mismatch.");
        int scanned = root.GetProperty("scanned").GetInt32();
        var entries = root.GetProperty("backups");
        if (scanned is < 0 or > 256 || entries.ValueKind != JsonValueKind.Array ||
            entries.GetArrayLength() > Math.Min(scanned, 64))
            throw new InvalidDataException("Invalid backup catalog bounds.");
        var result = new List<MultiMailboxSourceBackup>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries.EnumerateArray())
        {
            if (!Exact(entry, "backup_id", "map_sha", "row_count"))
                throw new InvalidDataException("Unexpected backup catalog entry.");
            string id = entry.GetProperty("backup_id").GetString() ?? "";
            string map = entry.GetProperty("map_sha").GetString() ?? "";
            int rows = entry.GetProperty("row_count").GetInt32();
            if (!MultiMailboxSourceEditRequest.IsBackup(id) || !ids.Add(id) ||
                !MultiMailboxSourceEditRequest.IsSha(map) || map == sha || rows is < 1 or > 64)
                throw new InvalidDataException("Invalid backup catalog entry.");
            result.Add(new(id, map, rows));
        }
        return new(scanned, result.OrderBy(x => x.BackupId, StringComparer.Ordinal).ToArray());
    }

    internal static bool SelfTest()
    {
        string sha = new('a', 64), nonce = new('b', 64);
        string json = JsonSerializer.Serialize(new { version = 1, action = "list_backups", status = "catalog",
            nonce, base_sha = sha, old_count = 1, scanned = 2,
            backups = new[] { new { backup_id = "source-abcdefgh", map_sha = new string('c', 64), row_count = 2 } },
            changes = false, runtime_changed = false, mail_sent = false, cloud_changed = false });
        if (Parse(json, sha, 1, nonce).Backups.Single().RowCount != 2) return false;
        foreach (string bad in new[] { json.Replace("source-abcdefgh", "../unsafe"),
            json.Replace("\"changes\":false", "\"changes\":true"), json.Replace(nonce, sha),
            json.Replace("\"scanned\":2", "\"scanned\":0") })
        {
            try { Parse(bad, sha, 1, nonce); return false; }
            catch (InvalidDataException) { }
        }
        return true;
    }
}
