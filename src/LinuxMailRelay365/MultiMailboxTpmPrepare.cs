using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record MultiMailboxTpmDiscovery(string? Handle, string Reason)
{
    internal static MultiMailboxTpmDiscovery Unavailable => new(null,"probe_unverified");
    internal bool Available => Handle is not null;
    internal static bool ValidHandle(string value) => Regex.IsMatch(value,@"\A0x8101[a-f0-9]{4}\z",RegexOptions.CultureInvariant);
    internal string Describe() => Available ? "TPM 2.0 ready for reviewed creation: " + Handle : Reason switch {
        "selinux_policy_review" => "SELinux policy-aware identity creation requires separate review.",
        "identity_directory_or_account" => "Trusted identity directory or m365mailer account is unavailable.",
        "tpm2_device_unavailable" => "TPM 2.0 resource-manager device was not verified.",
        "tpm2_tools_unavailable" => "Required trusted TPM utilities are unavailable.",
        "openssl_provider_unavailable" => "OpenSSL 3 native TPM2 provider was not verified.",
        "service_tpm_access_unavailable" => "TPM access or provider loading failed as m365mailer.",
        "persistent_inventory_unavailable" => "TPM persistent handle inventory unavailable.",
        "no_free_handle" => "No free handle in the managed TPM range.",
        _ => "TPM prerequisites could not be verified."
    };

    internal static MultiMailboxTpmDiscovery Parse(string json)
    {
        if (json.Length>2048 || json.Contains('\0')) throw new InvalidDataException("Invalid TPM discovery.");
        using var doc=JsonDocument.Parse(json);
        var r=doc.RootElement;
        Exact(r,"version","available","reason","handle","changes","key_created");
        bool ready=r.GetProperty("available").GetBoolean();
        string reason=Read(r,"reason"),handle=Read(r,"handle");
        if (r.GetProperty("version").GetInt32()!=1 || r.GetProperty("changes").GetBoolean() ||
            r.GetProperty("key_created").GetBoolean() ||
            (ready ? reason!="ready" || !ValidHandle(handle) :
             handle!="" || reason is not ("selinux_policy_review" or "identity_directory_or_account" or
                 "tpm2_device_unavailable" or "tpm2_tools_unavailable" or "openssl_provider_unavailable" or
                 "service_tpm_access_unavailable" or "persistent_inventory_unavailable" or "no_free_handle")))
            throw new InvalidDataException("TPM prerequisite result unverified.");
        return new(ready?handle:null,reason);
    }

    internal static string Read(JsonElement r,string k)=>r.GetProperty(k).GetString() ??
        throw new InvalidDataException("Missing TPM evidence.");
    internal static void Exact(JsonElement r,params string[] keys)
    {
        if (r.ValueKind!=JsonValueKind.Object || !r.EnumerateObject().Select(x=>x.Name).OrderBy(x=>x,StringComparer.Ordinal)
            .SequenceEqual(keys.OrderBy(x=>x,StringComparer.Ordinal)))
            throw new InvalidDataException("Unexpected TPM receipt fields.");
    }
}

internal static class MultiMailboxTpmPrepare
{
    internal const string Confirmation="CREATE_UNBOUND_TPM2_OAUTH_IDENTITY";
    internal static string Serialize(MultiMailboxIdentityPrepareRequest req,string handle,string approval="")
    {
        if (!MultiMailboxTpmDiscovery.ValidHandle(handle)) throw new InvalidDataException("Invalid TPM handle.");
        using var doc=JsonDocument.Parse(req.Serialize(approval));
        return JsonSerializer.Serialize(new {action=approval==""?"preview":"apply",identity=doc.RootElement,
            handle,confirm=approval==""?"":Confirmation});
    }

    internal static MultiMailboxIdentityPrepareReceipt Parse(string json,MultiMailboxIdentityPrepareRequest req,
        string handle,MultiMailboxIdentityPrepareReceipt? approved=null)
    {
        if (json.Length>20000 || json.Contains('\0') || !MultiMailboxTpmDiscovery.ValidHandle(handle))
            throw new InvalidDataException("Invalid TPM preparation receipt.");
        using var doc=JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=5});
        var r=doc.RootElement;
        MultiMailboxTpmDiscovery.Exact(r,"version","backend","handle","identity","persistent_created",
            "local_ps256_verified","hardware_attestation_verified","tpm_objects_removed","pem_key_created");
        bool applied=approved is not null;
        if (r.GetProperty("version").GetInt32()!=1 || MultiMailboxTpmDiscovery.Read(r,"backend")!="tpm2" ||
            MultiMailboxTpmDiscovery.Read(r,"handle")!=handle ||
            r.GetProperty("persistent_created").GetBoolean()!=applied || r.GetProperty("local_ps256_verified").GetBoolean()!=applied ||
            new[]{"hardware_attestation_verified","tpm_objects_removed","pem_key_created"}
                .Any(k=>r.GetProperty(k).ValueKind!=JsonValueKind.False))
            throw new InvalidDataException("TPM preparation scope or proof mismatch.");
        return MultiMailboxIdentityPrepareReceipt.Parse(r.GetProperty("identity").GetRawText(),req,approved);
    }

    internal static bool SelfTest()
    {
        string ready=JsonSerializer.Serialize(new {version=1,available=true,reason="ready",handle="0x81010000",changes=false,key_created=false});
        if (MultiMailboxTpmDiscovery.Parse(ready).Handle!="0x81010000" ||
            MultiMailboxTpmDiscovery.ValidHandle("0x81020000")) return false;
        foreach(string bad in new[]{ready.Replace("0x81010000","0x81020000"),ready.Replace("\"key_created\":false","\"key_created\":true"),
            ready.Replace("\"available\":true","\"available\":false")})
        {
            try { MultiMailboxTpmDiscovery.Parse(bad);return false; } catch(InvalidDataException) { }
        }
        var req=new MultiMailboxIdentityPrepareRequest(Guid.NewGuid().ToString("D"),Guid.NewGuid().ToString("D"),
            "alice@example.org",365,"",new string('a',64));
        return Serialize(req,"0x81010000",new string('b',64)).Contains(Confirmation,StringComparison.Ordinal);
    }
}
