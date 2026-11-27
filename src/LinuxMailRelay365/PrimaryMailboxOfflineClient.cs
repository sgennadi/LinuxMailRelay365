using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record PrimaryMailboxOfflineReceipt(string Sha,string? RuntimeSha,string? Phase);

internal static class PrimaryMailboxOfflineClient
{
    internal const string Maintenance = "I_HAVE_PREVENTED_CONCURRENT_MAIL_AND_CONFIG_CHANGES";
    internal const string Auth = "VERIFY_PRIMARY_MAILBOX_SMTP_AUTH";
    internal const string Apply = "APPLY_STOPPED_PRIMARY_MAILBOX_ROUTE";
    internal const string Restore = "RESTORE_STOPPED_PRIMARY_MAILBOX_ROUTE";
    internal const string Start = "START_REVIEWED_PRIMARY_MAILBOX_ROUTE";
    private const string Prefix = "PRIMARY_MAILBOX_OFFLINE_";

    internal static bool IsSha(string? value) => value is not null &&
        Regex.IsMatch(value,@"\A[a-f0-9]{64}\z",RegexOptions.CultureInvariant);

    internal static string Arguments(string action,string maintenance,string? mailbox,
        Guid? tenant,Guid? client,string? sha,string? confirmation,string? authConfirmation)
    {
        if (maintenance != Maintenance) throw new ArgumentException("Exclusive maintenance approval required.");
        string args;
        if (action is "review" or "apply" or "verify-applied" or "start")
        {
            if (mailbox is null || !PrimaryMailboxRoutePreview.ValidMailbox(mailbox) ||
                tenant is null || tenant == Guid.Empty || client is null || client == Guid.Empty)
                throw new ArgumentException("Exact primary mailbox, tenant and application required.");
            // The strict mailbox allowlist contains no shell quote, expansion,
            // whitespace, or command delimiter. GUIDs are canonical.
            string target = " --mailbox='" + mailbox + "' --tenant-id=" + tenant.Value.ToString("D") +
                " --client-id=" + client.Value.ToString("D");
            if (action == "review" && sha is null && confirmation == Auth && authConfirmation is null)
                args = "--review" + target + " --confirm=" + Auth;
            else if (action == "apply" && IsSha(sha) && confirmation == Apply && authConfirmation == Auth)
                args = "--apply" + target + " --expected-sha256=" + sha +
                    " --confirm=" + Apply + " --auth-confirmation=" + Auth;
            else if (action == "verify-applied" && IsSha(sha) && confirmation == Auth && authConfirmation is null)
                args = "--verify-applied=" + sha + target + " --confirm=" + Auth;
            else if (action == "start" && IsSha(sha) && confirmation == Start && authConfirmation == Auth)
                args = "--start=" + sha + target + " --confirm=" + Start + " --auth-confirmation=" + Auth;
            else throw new ArgumentException("Invalid reviewed route approval.");
        }
        else
        {
            if (!IsSha(sha) || mailbox is not null || tenant is not null || client is not null ||
                authConfirmation is not null)
                throw new ArgumentException("Exact backup identity required without OAuth arguments.");
            args = action switch {
                "inspect-backup" when confirmation is null => "--inspect-backup=" + sha,
                "restore" when confirmation == Restore => "--restore=" + sha + " --confirm=" + Restore,
                _ => throw new ArgumentException("Invalid backup operation approval.")
            };
        }
        return args + " --maintenance-confirmation=" + Maintenance;
    }

    internal static PrimaryMailboxOfflineReceipt Parse(string output,string action,string? expectedSha)
    {
        if (output.Length > 4096 || output.Contains('\0'))
            throw new InvalidDataException("Invalid offline receipt size.");
        var fields = new Dictionary<string,string>(StringComparer.Ordinal);
        foreach (string line in output.Replace("\r\n","\n",StringComparison.Ordinal).Split('\n'))
        {
            if (line.Length == 0) continue;
            int at=line.IndexOf('=');
            if (at <= Prefix.Length || !line.StartsWith(Prefix,StringComparison.Ordinal) ||
                !fields.TryAdd(line[Prefix.Length..at],line[(at+1)..]))
                throw new InvalidDataException("Invalid or duplicate offline receipt field.");
        }
        string? Read(string key) => fields.GetValueOrDefault(key);
        bool review=action=="review", inspect=action=="inspect-backup", verify=action=="verify-applied", start=action=="start";
        if (action is not ("review" or "apply" or "restore" or "inspect-backup" or "verify-applied" or "start") ||
            fields.Count != (verify || start ? 9 : review || inspect ? 8 : 7) ||
            Read("SERVICE_STARTED")!=(start?"observed_running":"no") ||
            Read("MAIL_SUBMITTED")!=(start?"not_verified":"no") ||
            Read("QUEUE_MODIFIED")!=(start?"not_verified":"no"))
            throw new InvalidDataException("Unexpected offline operation flags.");
        string status=action switch {
            "review"=>"reviewed_experimental","apply"=>"applied_offline_not_started",
            "restore"=>"restored_offline_not_started","verify-applied"=>"applied_runtime_reverified_not_started",
            "start"=>"started_running_observed",_=>"backup_phase_observed" };
        string change=action switch { "apply"=>"yes","restore"=>"restored",_=>"no" };
        string? sha=Read(review?"SHA256":"BACKUP_SHA256");
        if (Read("STATUS")!=status || Read("POSTFIX_CHANGED")!=change ||
            Read("SMTP_AUTH")!=(action is "review" or "apply" or "verify-applied" or "start" ? "observed":"not_attempted") ||
            !IsSha(sha) || (review ? expectedSha is not null : !IsSha(expectedSha) || sha!=expectedSha))
            throw new InvalidDataException("Unverified offline operation receipt.");
        string? runtime=(review||verify||start)?Read("RUNTIME_SHA256"):null;
        string? phase=(inspect||verify||start)?Read("PHASE"):null;
        if (((review||verify||start) && !IsSha(runtime)) ||
            (inspect && phase is not ("before" or "after" or "pipe_only")) || ((verify||start) && phase!="after"))
            throw new InvalidDataException("Unverified runtime or recovery evidence.");
        return new(sha!,runtime,phase);
    }

    internal static bool SelfTest()
    {
        string a=new('a',64), b=new('b',64);
        Guid tenant=Guid.Parse("11111111-1111-1111-1111-111111111111");
        Guid app=Guid.Parse("22222222-2222-2222-2222-222222222222");
        const string mail="alerts@example.org";
        string Row(string key,string value)=>Prefix+key+"="+value+"\n";
        string common=Row("SERVICE_STARTED","no")+Row("MAIL_SUBMITTED","no")+Row("QUEUE_MODIFIED","no");
        string review=Row("STATUS","reviewed_experimental")+Row("SHA256",a)+Row("RUNTIME_SHA256",b)+
            Row("SMTP_AUTH","observed")+Row("POSTFIX_CHANGED","no")+common;
        string apply=Row("STATUS","applied_offline_not_started")+Row("BACKUP_SHA256",a)+
            Row("SMTP_AUTH","observed")+Row("POSTFIX_CHANGED","yes")+common;
        string restore=Row("STATUS","restored_offline_not_started")+Row("BACKUP_SHA256",a)+
            Row("SMTP_AUTH","not_attempted")+Row("POSTFIX_CHANGED","restored")+common;
        string inspect=Row("STATUS","backup_phase_observed")+Row("BACKUP_SHA256",a)+Row("PHASE","pipe_only")+
            Row("SMTP_AUTH","not_attempted")+Row("POSTFIX_CHANGED","no")+common;
        string verify=Row("STATUS","applied_runtime_reverified_not_started")+Row("BACKUP_SHA256",a)+
            Row("RUNTIME_SHA256",b)+Row("PHASE","after")+Row("SMTP_AUTH","observed")+Row("POSTFIX_CHANGED","no")+common;
        string start=Row("STATUS","started_running_observed")+Row("BACKUP_SHA256",a)+
            Row("RUNTIME_SHA256",b)+Row("PHASE","after")+Row("SMTP_AUTH","observed")+Row("POSTFIX_CHANGED","no")+
            Row("SERVICE_STARTED","observed_running")+Row("MAIL_SUBMITTED","not_verified")+Row("QUEUE_MODIFIED","not_verified");
        if (Parse(start,"start",a)!=new PrimaryMailboxOfflineReceipt(a,b,"after") ||
            !Arguments("start",Maintenance,mail,tenant,app,a,Start,Auth).Contains("--auth-confirmation="+Auth,StringComparison.Ordinal) ||
            Parse(verify,"verify-applied",a)!=new PrimaryMailboxOfflineReceipt(a,b,"after") ||
            !Arguments("verify-applied",Maintenance,mail,tenant,app,a,Auth,null).Contains("--verify-applied="+a,StringComparison.Ordinal) ||
            Parse(review,"review",null)!=new PrimaryMailboxOfflineReceipt(a,b,null) ||
            Parse(apply,"apply",a).Sha!=a || Parse(restore,"restore",a).Sha!=a ||
            Parse(inspect,"inspect-backup",a).Phase!="pipe_only") return false;
        string args=Arguments("apply",Maintenance,mail,tenant,app,a,Apply,Auth);
        if (!args.Contains("--expected-sha256="+a,StringComparison.Ordinal) ||
            !args.Contains("--auth-confirmation="+Auth,StringComparison.Ordinal) ||
            Arguments("restore",Maintenance,null,null,null,a,Restore,null).Contains("--mailbox",StringComparison.Ordinal))
            return false;
        string bundle=EmbeddedAssets.BuildPrimaryMailboxOffline("review",Maintenance,mail,tenant,app,confirmation:Auth);
        if (!bundle.Contains("/run/lmr365-primary-mailbox.",StringComparison.Ordinal) ||
            !bundle.Contains("\"$work/m365_hardware_signer.py\"",StringComparison.Ordinal) ||
            !bundle.Contains("\"$work/manage-primary-mailbox-offline.py\" --review",StringComparison.Ordinal)) return false;
        foreach (string bad in new[] {review+Row("STATUS","reviewed_experimental"),
            review.Replace("MAIL_SUBMITTED=no","MAIL_SUBMITTED=yes"),
            review.Replace("RUNTIME_SHA256="+b,"RUNTIME_SHA256=wrong"),
            review.Replace("SMTP_AUTH=observed","SMTP_AUTH=not_attempted")})
        {
            try { Parse(bad,"review",null);return false; } catch (InvalidDataException) {}
        }
        foreach (string bad in new[] {
            start.Replace("SERVICE_STARTED=observed_running","SERVICE_STARTED=unverified"),
            start.Replace("QUEUE_MODIFIED=not_verified","QUEUE_MODIFIED=no"),
            start.Replace("MAIL_SUBMITTED=not_verified","MAIL_SUBMITTED=no"),
            start.Replace("PHASE=after","PHASE=pipe_only"),
            start.Replace("SMTP_AUTH=observed","SMTP_AUTH=unverified"),
            start.Replace("RUNTIME_SHA256="+b,"RUNTIME_SHA256=bad"),
            start+Row("STATUS","started_running_observed") })
        {
            try { Parse(bad,"start",a);return false; } catch (InvalidDataException) {}
        }
        try { Parse(start,"start",b);return false; } catch (InvalidDataException) {}
        try { Parse(start,"verify-applied",a);return false; } catch (InvalidDataException) {}
        try { Arguments("start",Maintenance,mail,tenant,app,a,Start,null);return false; } catch (ArgumentException) {}
        try { Arguments("start",Maintenance,mail,tenant,app,a,Auth,Auth);return false; } catch (ArgumentException) {}
        try { Parse(apply,"apply",b);return false; } catch (InvalidDataException) {}
        try { Parse(verify.Replace("PHASE=after","PHASE=pipe_only"),"verify-applied",a);return false; } catch (InvalidDataException) {}
        try { Parse(verify.Replace("SMTP_AUTH=observed","SMTP_AUTH=not_attempted"),"verify-applied",a);return false; } catch (InvalidDataException) {}
        try { Parse(verify,"verify-applied",b);return false; } catch (InvalidDataException) {}
        try { Arguments("verify-applied",Maintenance,mail,tenant,app,a,null,null);return false; } catch (ArgumentException) {}
        try { Parse(inspect.Replace("pipe_only","ready"),"inspect-backup",a);return false; } catch (InvalidDataException) {}
        try { Arguments("apply",Maintenance,mail,tenant,app,a,Apply,null);return false; } catch (ArgumentException) {}
        try { Arguments("review",Maintenance,"x'@example.org",tenant,app,null,Auth,null);return false; } catch (ArgumentException) {}
        try { Arguments("restore",Maintenance,mail,tenant,app,a,Restore,null);return false; } catch (ArgumentException) {}
        try { Arguments("inspect-backup","",null,null,null,a,null,null);return false; } catch (ArgumentException) {}
        return true;
    }
}
