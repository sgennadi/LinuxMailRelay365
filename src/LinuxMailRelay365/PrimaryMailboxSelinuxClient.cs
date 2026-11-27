using System.Text.Json;

namespace LinuxMailRelay365;

internal static class PrimaryMailboxSelinuxClient
{
    private static readonly string[] Labels=["config_directory","main_cf","master_cf","queue_directory","data_directory",
        "identity_directory","identity_config","transport","signer","recovery_parent","active_certificate","active_key_or_provider"];
    private static void Need(bool condition)
    {
        if(!condition) throw new InvalidDataException("Unverified primary SELinux observation.");
    }
    internal static string Describe(string raw,string nonce)
    {
        using var doc=PrimaryMailboxDeliveryClient.Document(raw);
        var root=doc.RootElement;
        PrimaryMailboxDeliveryClient.Exact(root,"version","nonce","status","mode","identity","labels","ports",
            "config_metadata_sha256","write_allowed","runtime_verified","changes_applied","mail_sent","network_attempted");
        string Read(string key)=>PrimaryMailboxDeliveryClient.Read(root,key);
        Need(PrimaryMailboxOfflineClient.IsSha(nonce) && Read("nonce")==nonce && root.GetProperty("version").GetInt32()==2);
        foreach(string flag in new[]{"write_allowed","runtime_verified","changes_applied","mail_sent","network_attempted"})
            Need(root.GetProperty(flag).ValueKind==JsonValueKind.False);
        string mode=Read("mode"),identity=Read("identity"),status=Read("status");
        bool active=mode is "enforcing" or "permissive";
        Need(active || mode is "inactive_or_unavailable" or "unverified");
        Need(active? identity is "pem" or "managed_tpm2_reference" or "custom_hardware" or "unverified":
            identity=="not_checked");
        var labels=root.GetProperty("labels");
        var ports=root.GetProperty("ports");
        PrimaryMailboxDeliveryClient.Exact(labels,Labels);
        PrimaryMailboxDeliveryClient.Exact(ports,"443","587");
        var states=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(string name in Labels)
        {
            string state=PrimaryMailboxDeliveryClient.Read(labels,name);
            Need(state is "not_checked" or "missing" or "unverified" or "label_missing" or
                "policy_match" or "policy_match_generic" or "policy_mismatch" or
                "data_directory_permissions_review" or "unsupported_path");
            Need(name=="data_directory" || state is not ("data_directory_permissions_review" or "unsupported_path"));
            Need(active || state=="not_checked");
            states.Add(name,state);
        }
        var portStates=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(string port in new[]{"443","587"})
        {
            string state=PrimaryMailboxDeliveryClient.Read(ports,port);
            Need(active?state is "expected_type" or "different_or_ambiguous_type" or "no_specific_type" or "unverified":
                state=="not_checked");
            portStates.Add(port,state);
        }
        string? sha=root.GetProperty("config_metadata_sha256").GetString();
        bool configMatch=active && new[]{"config_directory","main_cf","master_cf"}.All(x=>states[x]=="policy_match");
        Need(configMatch?PrimaryMailboxOfflineClient.IsSha(sha):sha is null);
        bool manual=mode=="enforcing" && configMatch && (identity is "pem" or "managed_tpm2_reference") &&
            states.Values.All(v=>v is "policy_match" or "policy_match_generic") &&
            portStates.Values.All(v=>v=="expected_type");
        Need(status==(!active?"inactive_or_unverified":manual?"manual_runtime_review_required":"policy_or_mode_review_required"));
        var lines=new List<string>{"SELinux: "+mode,"Active identity: "+identity,"Result: "+status,"",
            "FILE CONTEXT POLICY (read-only)"};
        lines.AddRange(states.Select(x=>x.Key.Replace('_',' ')+": "+x.Value.Replace('_',' ')));
        if(states["data_directory"]=="data_directory_permissions_review")
            lines.Add("Postfix data_directory must be writable/searchable by its dedicated mail_owner. Review native package ownership and permissions; no automatic chmod/chown.");
        if(states["data_directory"] is "policy_mismatch" or "label_missing")
            lines.Add("Postfix data directory context differs from native policy. Ask the Linux administrator to review: matchpathcon -V /var/lib/postfix; preview with restorecon -n -v /var/lib/postfix. No automatic relabel.");
        if(states["data_directory"]=="unsupported_path")
            lines.Add("A non-default Postfix data_directory requires manual review; this probe does not traverse custom paths.");
        lines.Add("");lines.Add("OUTBOUND POLICY PORT LABELS");
        lines.Add("TCP 443 / Entra HTTPS: "+portStates["443"]);
        lines.Add("TCP 587 / Microsoft 365 SMTP: "+portStates["587"]);
        if(sha is not null) lines.Add("Configuration metadata SHA-256: "+sha);
        lines.Add("");lines.Add("Matching labels do not establish SELinux allow rules or Postfix pipe-domain access.");
        lines.Add("No network, mail, relabel, policy, service or configuration change. Enforcing Apply remains blocked.");
        return string.Join(Environment.NewLine,lines);
    }
    internal static bool SelfTest()
    {
        string nonce=new('a',64);
        string good=JsonSerializer.Serialize(new {version=2,nonce,status="manual_runtime_review_required",
            mode="enforcing",identity="pem",labels=Labels.ToDictionary(k=>k,k=>"policy_match"),
            ports=new Dictionary<string,string>{{"443","expected_type"},{"587","expected_type"}},
            config_metadata_sha256=new string('b',64),write_allowed=false,runtime_verified=false,
            changes_applied=false,mail_sent=false,network_attempted=false});
        if(!Describe(good,nonce).Contains("Enforcing Apply remains blocked",StringComparison.Ordinal)) return false;
        foreach(string bad in new[]{good.Replace("\"write_allowed\":false","\"write_allowed\":true"),
            good.Replace("\"runtime_verified\":false","\"runtime_verified\":true"),
            good.Replace("\"network_attempted\":false","\"network_attempted\":true"),
            good.Replace("\"manual_runtime_review_required\"","\"ready\""),
            good.Replace("\"443\":\"expected_type\"","\"443\":\"different_or_ambiguous_type\"")})
        {
            try { Describe(bad,nonce);return false; } catch(InvalidDataException) {}
        }
        string denied=good.Replace("\"data_directory\":\"policy_match\"","\"data_directory\":\"data_directory_permissions_review\"")
            .Replace("\"manual_runtime_review_required\"","\"policy_or_mode_review_required\"");
        if(!Describe(denied,nonce).Contains("mail_owner",StringComparison.Ordinal)) return false;
        string mismatch=good.Replace("\"data_directory\":\"policy_match\"","\"data_directory\":\"policy_mismatch\"")
            .Replace("\"manual_runtime_review_required\"","\"policy_or_mode_review_required\"");
        if(!Describe(mismatch,nonce).Contains("restorecon -n -v /var/lib/postfix",StringComparison.Ordinal)) return false;
        foreach(string bad in new[]{denied.Replace("\"policy_or_mode_review_required\"","\"manual_runtime_review_required\""),
            good.Replace("\"main_cf\":\"policy_match\"","\"main_cf\":\"unsupported_path\""),
            good.Replace("\"version\":2","\"version\":1")})
        {
            try { Describe(bad,nonce);return false; } catch(InvalidDataException) {}
        }
        try { Describe(good,new string('c',64));return false; } catch(InvalidDataException) {}
        return EmbeddedAssets.BuildPrimaryMailboxSelinuxReadiness(nonce).Contains(
            "inspect-primary-mailbox-selinux.py",StringComparison.Ordinal);
    }
}
