using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record MultiMailboxSmtpAuthRequest(MultiMailboxCloudSelection Selection, string Nonce)
{
    internal const string Confirmation = "CHECK_SELECTED_MAILBOX_SMTP_AUTH_ONLY";
    internal bool Valid => Selection.Scope is "source" or "runtime" &&
        MultiMailboxSourceEditRequest.IsSha(Selection.MapSha) &&
        Selection.Row.Status == "public_certificate_read" && Selection.Row.Signer is "software" or "hardware" &&
        Selection.Row.Tenant is Guid t && t != Guid.Empty && Selection.Row.Client is Guid c && c != Guid.Empty &&
        Selection.Row.Mailbox == Selection.Row.Sender && InstalledPostfixRoute.ValidAddress(Selection.Row.Mailbox) &&
        Regex.IsMatch(Selection.Row.Login, @"\A[a-z0-9][a-z0-9_.@-]{2,63}\z") &&
        new[] { Selection.Row.IdentitySha, Selection.Row.CertificateSha, Nonce }.All(MultiMailboxSourceEditRequest.IsSha);
    internal string Serialize()
    {
        if (!Valid) throw new InvalidDataException("Invalid selected mailbox authentication request.");
        var row = Selection.Row;
        return JsonSerializer.Serialize(new { scope=Selection.Scope,map_sha=Selection.MapSha,login=row.Login,
            mailbox=row.Mailbox,tenant=row.Tenant!.Value.ToString("D"),client=row.Client!.Value.ToString("D"),
            identity_sha=row.IdentitySha,certificate_sha=row.CertificateSha,signer=row.Signer,nonce=Nonce,confirm=Confirmation });
    }
}

internal sealed record MultiMailboxSmtpAuthReceipt(string Status)
{
    internal bool Authenticated => Status == "authenticated";
    internal string Describe() => Status switch {
        "authenticated" => "Local PS256 signature, Entra token, STARTTLS and Exchange SMTP AUTH XOAUTH2 accepted (235).",
        "config_failed" => "Service-account configuration or certificate access failed.",
        "signing_failed" => "Local PS256 signing or certificate verification failed.",
        "token_failed" => "Entra token acquisition unverified; check HTTPS, certificate and tenant/application settings.",
        "starttls_unavailable" => "SMTP server did not advertise STARTTLS.",
        "xoauth2_unavailable" => "SMTP server did not advertise XOAUTH2 after STARTTLS.",
        "smtp_failed" => "SMTP connection, TLS or authentication failed; check outbound port 587 and policy.",
        "identity_changed" => "Identity changed during the probe; discard this result.",
        "worker_failed" => "Service-account probe failed or timed out; check permissions, SELinux and network.",
        _ when Status.StartsWith("token_http_",StringComparison.Ordinal) =>
            "Entra token endpoint HTTP " + Status[11..] + "; check registered certificate and app/tenant policy.",
        _ when Status.StartsWith("smtp_rejected_",StringComparison.Ordinal) =>
            "Exchange SMTP rejected or did not complete authentication (SMTP " + Status[14..] +
            "); check scoped RBAC, mailbox SMTP AUTH and security policy.",
        _ => "Authentication unverified."
    };

    internal static MultiMailboxSmtpAuthReceipt Parse(string json, MultiMailboxSmtpAuthRequest req)
    {
        if (!req.Valid || json.Length > 8192 || json.Contains('\0')) throw new InvalidDataException("Invalid SMTP probe receipt.");
        using var doc=JsonDocument.Parse(json,new JsonDocumentOptions {MaxDepth=3});
        var r=doc.RootElement;
        string[] keys=["version","nonce","scope","map_sha","login","mailbox","tenant","client","identity_sha",
            "certificate_sha","signer","status","authenticated","service_account","endpoint","mail_sent","changes",
            "runtime_changed","cloud_changed","token_exported","delivery_verified"];
        if (r.ValueKind!=JsonValueKind.Object || !r.EnumerateObject().Select(x=>x.Name).OrderBy(x=>x,StringComparer.Ordinal)
            .SequenceEqual(keys.OrderBy(x=>x,StringComparer.Ordinal))) throw new InvalidDataException("Unexpected SMTP probe receipt.");
        string Read(string k)=>r.GetProperty(k).GetString() ?? throw new InvalidDataException("Missing SMTP evidence.");
        var row=req.Selection.Row;
        string status=Read("status");
        if (r.GetProperty("version").GetInt32()!=1 || Read("nonce")!=req.Nonce ||
            Read("scope")!=req.Selection.Scope || Read("map_sha")!=req.Selection.MapSha ||
            Read("login")!=row.Login || Read("mailbox")!=row.Mailbox ||
            Read("tenant")!=row.Tenant!.Value.ToString("D") || Read("client")!=row.Client!.Value.ToString("D") ||
            Read("identity_sha")!=row.IdentitySha || Read("certificate_sha")!=row.CertificateSha ||
            Read("signer")!=row.Signer || Read("service_account")!="m365mailer" || Read("endpoint")!="smtp.office365.com:587" ||
            !Regex.IsMatch(status,@"\A(?:authenticated|config_failed|signing_failed|token_failed|token_http_[1-5][0-9]{2}|starttls_unavailable|xoauth2_unavailable|smtp_failed|smtp_rejected_[1-5][0-9]{2}|identity_changed|worker_failed)\z") ||
            r.GetProperty("authenticated").GetBoolean()!=(status=="authenticated") ||
            new[]{"mail_sent","changes","runtime_changed","cloud_changed","token_exported","delivery_verified"}
                .Any(k=>r.GetProperty(k).ValueKind!=JsonValueKind.False))
            throw new InvalidDataException("SMTP probe scope or result mismatch.");
        return new(status);
    }

    internal static bool SelfTest()
    {
        var row=new MultiMailboxIdentityRow("alice","alice@example.org","alice@example.org",Guid.NewGuid(),Guid.NewGuid(),
            new string('a',64),new string('b',64),"software","public_certificate_read");
        var req=new MultiMailboxSmtpAuthRequest(new("source",new string('c',64),"",row),new string('d',64));
        string Receipt(string status)=>JsonSerializer.Serialize(new {version=1,nonce=req.Nonce,scope="source",
            map_sha=req.Selection.MapSha,login=row.Login,mailbox=row.Mailbox,tenant=row.Tenant!.Value.ToString("D"),
            client=row.Client!.Value.ToString("D"),identity_sha=row.IdentitySha,certificate_sha=row.CertificateSha,signer=row.Signer,
            status,authenticated=status=="authenticated",service_account="m365mailer",endpoint="smtp.office365.com:587",
            mail_sent=false,changes=false,runtime_changed=false,cloud_changed=false,token_exported=false,delivery_verified=false});
        if (!Parse(Receipt("authenticated"),req).Authenticated ||
            Parse(Receipt("smtp_rejected_535"),req).Authenticated ||
            !Parse(Receipt("smtp_rejected_535"),req).Describe().Contains("535",StringComparison.Ordinal) ||
            !Parse(Receipt("token_http_401"),req).Describe().Contains("401",StringComparison.Ordinal)) return false;
        foreach (string bad in new[]{Receipt("authenticated").Replace("\"mail_sent\":false","\"mail_sent\":true"),
            Receipt("authenticated").Replace(req.Nonce,new string('e',64)),Receipt("smtp_rejected_535").Replace("\"authenticated\":false","\"authenticated\":true"),
            Receipt("secret-should-not-appear")})
        {
            try { Parse(bad,req); return false; } catch (InvalidDataException) { }
        }
        return true;
    }
}
