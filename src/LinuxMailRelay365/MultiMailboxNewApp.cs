using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace LinuxMailRelay365;

internal sealed record MultiMailboxNewAppRequest(Guid Tenant, string Mailbox, int Days,
    string SourceSha, string RuntimeSha, string Nonce, Guid? ResumeClient, string? TpmHandle = null)
{
    internal string Name => "LMR365-MBX-" + Nonce[..32];
    internal string IdentityFile => "mbx-" + Nonce[..32] + ".json";
    internal string KeyDescription => TpmHandle is null ? "Software RSA-3072" : "TPM 2.0 RSA-2048 ("+TpmHandle+")";
    internal bool Valid => Tenant != Guid.Empty && ResumeClient != Guid.Empty &&
        (TpmHandle is null || MultiMailboxTpmDiscovery.ValidHandle(TpmHandle)) &&
        InstalledPostfixRoute.ValidAddress(Mailbox) && Mailbox == Mailbox.ToLowerInvariant() &&
        Days is >= 4 and <= 365 && MultiMailboxSourceEditRequest.IsSha(Nonce) &&
        new[] {SourceSha, RuntimeSha}.All(s => s == "" || MultiMailboxSourceEditRequest.IsSha(s));
    internal static string Phrase(string action) => action switch {
        "stage" => "STAGE_NEW_APP_CERTIFICATE", "claim" => "CREATE_NEW_ENTRA_APP",
        "finalize" => "BIND_VERIFIED_NEW_ENTRA_APP", _ => "" };
    internal string Serialize(string action, string approval = "", Guid? client = null)
    {
        if (!Valid || action is not ("preview" or "stage" or "inspect" or "claim" or "finalize") ||
            (Phrase(action) == "" ? approval != "" : !MultiMailboxSourceEditRequest.IsSha(approval)) ||
            (action == "finalize" ? client is null || client == Guid.Empty : client is not null))
            throw new InvalidDataException("Invalid new application request.");
        var payload = new Dictionary<string,object> { ["action"]=action,["tenant"]=Tenant.ToString("D"),
            ["mailbox"]=Mailbox,["days"]=Days,["source_sha"]=SourceSha,["runtime_sha"]=RuntimeSha,
            ["nonce"]=Nonce,["approval"]=approval,["client"]=client?.ToString("D") ?? "",["confirm"]=Phrase(action) };
        if (TpmHandle is not null) payload.Add("handle",TpmHandle);
        return JsonSerializer.Serialize(payload);
    }
}

internal sealed record MultiMailboxNewAppReceipt(string Status, string ApprovalSha, string CertificateSha,
    string PublicDerBase64, bool Claimed, string SelinuxMode = "", string SelinuxPolicySha = "")
{
    internal string PublicPem => PemEncoding.WriteString("CERTIFICATE", Convert.FromBase64String(PublicDerBase64));
    internal static MultiMailboxNewAppReceipt Parse(string json, MultiMailboxNewAppRequest req, string action,
        MultiMailboxNewAppReceipt? previous = null, Guid? client = null)
    {
        if (!req.Valid || json.Length > 20000 || json.Contains('\0'))
            throw new InvalidDataException("Invalid new application receipt.");
        using var doc=JsonDocument.Parse(json,new JsonDocumentOptions { MaxDepth=4 });
        var root=doc.RootElement;
        string[] fields=["version","status","approval_sha","source_sha","runtime_sha","nonce","tenant","mailbox","days",
            "identity_file","app_name","certificate_sha256","certificate_der","claimed","changes","runtime_changed","cloud_changed","mail_sent","client"];
        if (req.TpmHandle is not null) fields=[..fields,"handle"];
        bool labeled=root.ValueKind==JsonValueKind.Object && root.TryGetProperty("selinux_mode",out _);
        if (labeled) fields=[..fields,"selinux_mode","selinux_policy_sha"];
        if (root.ValueKind != JsonValueKind.Object ||
            !root.EnumerateObject().Select(x=>x.Name).OrderBy(x=>x,StringComparer.Ordinal)
                .SequenceEqual(fields.OrderBy(x=>x,StringComparer.Ordinal))) throw new InvalidDataException("Unexpected app receipt.");
        string Read(string k)=>root.GetProperty(k).GetString() ?? throw new InvalidDataException("Missing app evidence.");
        string status=action switch { "preview"=>"preview", "stage" or "inspect"=>"staged", "claim"=>"claimed",
            "finalize"=>"finalized", _=>throw new InvalidDataException("Unknown app action.") };
        bool writes=action is "stage" or "claim" or "finalize";
        if (root.GetProperty("version").GetInt32()!=1 || Read("status")!=status ||
            (req.TpmHandle is not null && Read("handle")!=req.TpmHandle) ||
            Read("tenant")!=req.Tenant.ToString("D") || Read("mailbox")!=req.Mailbox ||
            Read("source_sha")!=req.SourceSha || Read("runtime_sha")!=req.RuntimeSha || Read("nonce")!=req.Nonce ||
            Read("app_name")!=req.Name || Read("identity_file")!=req.IdentityFile ||
            root.GetProperty("days").GetInt32()!=req.Days || Read("client")!=(client?.ToString("D") ?? "") ||
            root.GetProperty("changes").GetBoolean()!=writes ||
            new[]{"runtime_changed","cloud_changed","mail_sent"}.Any(k=>root.GetProperty(k).ValueKind!=JsonValueKind.False))
            throw new InvalidDataException("New application receipt context mismatch.");
        bool claimed=root.GetProperty("claimed").GetBoolean();
        if ((action is "preview" or "stage") && claimed || (action is "claim" or "finalize") && !claimed)
            throw new InvalidDataException("Unexpected application creation claim.");
        string sha=Read("approval_sha"), cert=Read("certificate_sha256"), der=Read("certificate_der");
        if (!MultiMailboxSourceEditRequest.IsSha(sha)) throw new InvalidDataException("Missing app stage digest.");
        if (action=="preview")
        {
            if (cert!="" || der!="") throw new InvalidDataException("Preview contains certificate material.");
        }
        else
        {
            if (!MultiMailboxSourceEditRequest.IsSha(cert) || der.Length>10924)
                throw new InvalidDataException("Invalid public certificate.");
            byte[] bytes=Convert.FromBase64String(der);
            if (bytes.Length is <250 or >8192 ||
                Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()!=cert)
                throw new InvalidDataException("Certificate digest mismatch.");
            using var parsed=X509CertificateLoader.LoadCertificate(bytes);
            using var rsa=parsed.GetRSAPublicKey();
            if (parsed.HasPrivateKey || !parsed.RawData.AsSpan().SequenceEqual(bytes) || rsa is null ||
                (req.TpmHandle is null ? rsa.KeySize<3072 : rsa.KeySize!=2048))
                throw new InvalidDataException("Expected exact public RSA certificate.");
        }
        string mode=labeled?Read("selinux_mode"):"", policy=labeled?Read("selinux_policy_sha"):"";
        if (labeled && (req.TpmHandle is not null || mode is not ("enforcing" or "permissive") ||
            !MultiMailboxSourceEditRequest.IsSha(policy)))
            throw new InvalidDataException("Invalid new-app SELinux policy evidence.");
        if (previous is not null && (previous.SelinuxMode!=mode || previous.SelinuxPolicySha!=policy))
            throw new InvalidDataException("New-app SELinux policy changed.");
        if (previous is not null && previous.Status!="preview" &&
            (previous.ApprovalSha!=sha || previous.CertificateSha!=cert || previous.PublicDerBase64!=der))
            throw new InvalidDataException("Pending app certificate changed.");
        return new(status,sha,cert,der,claimed,mode,policy);
    }

    internal static bool SelfTest()
    {
        var req=new MultiMailboxNewAppRequest(Guid.NewGuid(),"alice@example.org",365,"","",new string('a',64),null);
        if (!req.Valid || (req with {Days=3}).Valid || req.IdentityFile!="mbx-"+new string('a',32)+".json") return false;
        using var key=RSA.Create(3072);
        using var cert=new CertificateRequest("CN=New app",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddDays(365));
        string hash=Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant(), sha=new('b',64);
        string json=JsonSerializer.Serialize(new {version=1,status="staged",approval_sha=sha,source_sha="",runtime_sha="",
            nonce=req.Nonce,tenant=req.Tenant.ToString("D"),mailbox=req.Mailbox,days=req.Days,identity_file=req.IdentityFile,
            app_name=req.Name,certificate_sha256=hash,certificate_der=Convert.ToBase64String(cert.RawData),
            claimed=false,changes=true,runtime_changed=false,cloud_changed=false,mail_sent=false,client=""});
        var staged=Parse(json,req,"stage");
        if (!staged.PublicPem.Contains("BEGIN CERTIFICATE",StringComparison.Ordinal) ||
            !req.Serialize("claim",sha).Contains("CREATE_NEW_ENTRA_APP",StringComparison.Ordinal)) return false;
        foreach (string bad in new[]{json.Replace(hash,new string('c',64)),json.Replace(req.Name,"Other app"),
            json.Replace("\"claimed\":false","\"claimed\":true"),json.Replace("\"cloud_changed\":false","\"cloud_changed\":true")})
        {
            try { Parse(bad,req,"stage"); return false; } catch (InvalidDataException) { }
        }
        var hardware=req with { TpmHandle="0x81010001" };
        using var tpmPublicKey=RSA.Create(2048);
        using var tpmPublicCert=new CertificateRequest("CN=TPM receipt test",tpmPublicKey,HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddDays(30));
        var tpmHash=Convert.ToHexString(SHA256.HashData(tpmPublicCert.RawData)).ToLowerInvariant();
        string tpmJson=json.Replace(hash,tpmHash).Replace(Convert.ToBase64String(cert.RawData),Convert.ToBase64String(tpmPublicCert.RawData));
        tpmJson=tpmJson[..^1]+",\"handle\":\"0x81010001\"}";
        if (Parse(tpmJson,hardware,"stage").CertificateSha!=tpmHash ||
            !hardware.Serialize("stage",sha).Contains("0x81010001",StringComparison.Ordinal) ||
            (hardware with { TpmHandle="0x81020000" }).Valid) return false;
        foreach (var (body,request) in new[]{(tpmJson,req),(json,hardware),
            (tpmJson.Replace("0x81010001","0x81010002"),hardware)})
        {
            try { Parse(body,request,"stage");return false; } catch(InvalidDataException) { }
        }
        string policy=new('e',64);
        string labeled=json[..^1]+",\"selinux_mode\":\"enforcing\",\"selinux_policy_sha\":\""+policy+"\"}";
        var labeledStage=Parse(labeled,req,"stage");
        string preview=labeled.Replace("\"status\":\"staged\"","\"status\":\"preview\"")
            .Replace("\"changes\":true","\"changes\":false").Replace(hash,"")
            .Replace(Convert.ToBase64String(cert.RawData),"");
        var labeledPreview=Parse(preview,req,"preview");
        if (Parse(labeled,req,"stage",labeledPreview).SelinuxPolicySha!=policy ||
            labeledStage.SelinuxMode!="enforcing") return false;
        foreach (string bad in new[]{json,labeled.Replace("enforcing","permissive"),
            labeled.Replace(policy,new string('f',64))})
        {
            try { Parse(bad,req,"stage",labeledPreview); return false; } catch(InvalidDataException) { }
        }
        return true;
    }
}
