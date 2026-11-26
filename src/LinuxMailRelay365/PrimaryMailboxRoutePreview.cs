using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record PrimaryMailboxRoutePreview(string Mailbox,string ConfigSha,string Scope,
    string Route,string OverrideStatus,string LocalClasses,string Identity,string Service,string Queue)
{
    internal static bool ValidMailbox(string value) => value.Length<=254 && !value.Contains("..",StringComparison.Ordinal) &&
        Regex.IsMatch(value,@"\A[a-z0-9][a-z0-9._+%-]{0,62}@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z0-9]{2,63}\z");

    internal static PrimaryMailboxRoutePreview Parse(string raw,string mailbox,string nonce)
    {
        if(raw.Length>4096 || raw.Contains('\0') || !ValidMailbox(mailbox) ||
            !MultiMailboxSourceEditRequest.IsSha(nonce)) throw new InvalidDataException("Invalid primary route context.");
        using var doc=JsonDocument.Parse(raw);
        var root=doc.RootElement;
        string[] fields=["version","nonce","mailbox","config_sha256","identity","service","queue",
            "scope","route","override_status","local_classes","changes","mail_sent","apply_supported",
            "local_delivery_changed","listener_changed"];
        if(root.ValueKind!=JsonValueKind.Object || !root.EnumerateObject().Select(p=>p.Name).OrderBy(x=>x,StringComparer.Ordinal)
            .SequenceEqual(fields.OrderBy(x=>x,StringComparer.Ordinal))) throw new InvalidDataException("Unexpected primary route receipt.");
        string Read(string key)=>root.GetProperty(key).GetString() ?? throw new InvalidDataException("Missing route evidence.");
        string State(string key,params string[] allowed)
        {
            string value=Read(key);
            if(!allowed.Contains(value,StringComparer.Ordinal)) throw new InvalidDataException("Unknown route evidence.");
            return value;
        }
        if(root.GetProperty("version").GetInt32()!=1 || Read("nonce")!=nonce || Read("mailbox")!=mailbox ||
            !MultiMailboxSourceEditRequest.IsSha(Read("config_sha256")) ||
            new[]{"changes","mail_sent","apply_supported","local_delivery_changed","listener_changed"}
                .Any(key=>root.GetProperty(key).ValueKind!=JsonValueKind.False))
            throw new InvalidDataException("Primary route scope or safety flags mismatch.");
        return new(mailbox,Read("config_sha256"),State("scope","primary_only","review_required"),
            State("route","configured","migration_candidate","review_required"),
            State("override_status","present","absent"),State("local_classes","configured","not_declared"),
            State("identity","absent","mailbox_matches","different_mailbox","unverified"),
            State("service","active","unverified"),State("queue","empty","nonempty","unverified"));
    }

    internal string Describe() => "Primary Postfix · one Microsoft 365 sender" + Environment.NewLine +
        "Mailbox: "+Mailbox+Environment.NewLine+"Outbound: smtp.office365.com:587 (STARTTLS / XOAUTH2)"+
        Environment.NewLine+"Configuration SHA-256: "+ConfigSha+Environment.NewLine+
        "Instance scope: "+Scope+" | Service: "+Service+" | Queue: "+Queue+Environment.NewLine+
        "Current default/relay transport: "+Route+" | Alternate routes/overrides: "+OverrideStatus+
        Environment.NewLine+"Local/virtual address classes: "+LocalClasses+" | Local OAuth identity: "+Identity+
        Environment.NewLine+Environment.NewLine+
        "Proposed: change default_transport and relay_transport to the reviewed m365xoauth2 pipe; add or verify the dedicated pipe in master.cf. "+
        "Envelope sender and From are rewritten to this mailbox. Existing SMTP listener, local/virtual delivery and inbound policy must be preserved. "+
        "A configured local identity is not proof of certificate signing, Graph grants or SMTP AUTH."+
        Environment.NewLine+"READ-ONLY. In-place Apply/Restore is not implemented by this preview. Do not use Force Replace as a substitute.";

    internal static bool SelfTest()
    {
        string mailbox="alerts@example.org",nonce=new('a',64);
        string body=JsonSerializer.Serialize(new {version=1,nonce,mailbox,config_sha256=new string('b',64),
            identity="absent",service="active",queue="empty",scope="primary_only",route="migration_candidate",
            override_status="absent",local_classes="configured",changes=false,mail_sent=false,apply_supported=false,
            local_delivery_changed=false,listener_changed=false});
        if(Parse(body,mailbox,nonce).Route!="migration_candidate" || ValidMailbox("a..b@example.org"))return false;
        foreach(string bad in new[]{body.Replace(mailbox,"other@example.org"),body.Replace(nonce,new string('c',64)),
            body.Replace("\"apply_supported\":false","\"apply_supported\":true"),
            body.Replace("\"listener_changed\":false","\"listener_changed\":true")})
        {
            try {Parse(bad,mailbox,nonce);return false;} catch(InvalidDataException){}
        }
        return true;
    }
}
