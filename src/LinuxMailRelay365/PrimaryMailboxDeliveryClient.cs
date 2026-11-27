using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record PrimaryMailboxDeliveryRequest(string RunId,string Sender,string Internal,string External,
    string Domain,string BackupSha,Guid Tenant,Guid Client)
{
    private static bool DomainValid(string value)=>value.Length<=253 &&
        Regex.IsMatch(value,@"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z");
    private static string DomainOf(string value)=>value[(value.LastIndexOf('@')+1)..];
    private static bool MailValid(string value)=>value.Length<=254 &&
        !value.Contains("..",StringComparison.Ordinal) &&
        Regex.IsMatch(value,@"\A[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9_+-])?@[a-z0-9.-]+\z") &&
        DomainValid(DomainOf(value));
    internal bool Valid()=>Regex.IsMatch(RunId,@"\A[a-f0-9]{32}\z") &&
        MailValid(Sender) && PrimaryMailboxRoutePreview.ValidMailbox(Sender) && MailValid(Internal) &&
        MailValid(External) && DomainValid(Domain) && DomainOf(Sender)==Domain &&
        DomainOf(Internal)==Domain && DomainOf(External)!=Domain && Internal!=External &&
        PrimaryMailboxOfflineClient.IsSha(BackupSha) && Tenant!=Guid.Empty && Client!=Guid.Empty;
    private SortedDictionary<string,string> Fields()
    {
        if(!Valid()) throw new InvalidDataException("Invalid primary mailbox delivery request.");
        return new(StringComparer.Ordinal) {
            ["run_id"]=RunId,["sender"]=Sender,["internal"]=Internal,["external"]=External,
            ["accepted_domain"]=Domain,["backup_sha256"]=BackupSha,
            ["tenant_id"]=Tenant.ToString("D"),["client_id"]=Client.ToString("D")};
    }
    internal string Json()=>JsonSerializer.Serialize(Fields());
    internal string RequestSha()
    {
        // All fields are strictly validated ASCII. Match the compact sorted
        // Python ledger representation, including unescaped '+' and '%'.
        byte[] raw=JsonSerializer.SerializeToUtf8Bytes(Fields(),
            new JsonSerializerOptions {Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping});
        return Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant();
    }
    internal static PrimaryMailboxDeliveryRequest Parse(string raw)
    {
        using var doc=PrimaryMailboxDeliveryClient.Document(raw);
        var root=doc.RootElement;
        PrimaryMailboxDeliveryClient.Exact(root,"run_id","sender","internal","external","accepted_domain",
            "backup_sha256","tenant_id","client_id");
        string Read(string key)=>PrimaryMailboxDeliveryClient.Read(root,key);
        var tenant=Guid.ParseExact(Read("tenant_id"),"D");
        var client=Guid.ParseExact(Read("client_id"),"D");
        var request=new PrimaryMailboxDeliveryRequest(Read("run_id"),Read("sender"),Read("internal"),
            Read("external"),Read("accepted_domain"),Read("backup_sha256"),tenant,client);
        if(!request.Valid() || tenant.ToString("D")!=Read("tenant_id") ||
            client.ToString("D")!=Read("client_id"))
            throw new InvalidDataException("Invalid saved trace request.");
        return request;
    }
}

internal sealed record PrimaryMailboxDeliveryRow(string Role,string Submission,string Transport,string QueueId,string Queue,string Dsn);
internal sealed record PrimaryMailboxDeliveryReceipt(string PlanSha,string? RuntimeSha,string Source,PrimaryMailboxDeliveryRow[] Rows,
    long? StartedUnix=null,string? RequestSha=null);

internal static class PrimaryMailboxDeliveryClient
{
    internal const string Confirm="SEND_REVIEWED_PRIMARY_MAILBOX_TESTS";
    internal static JsonDocument Document(string raw)
    {
        if(raw.Length>16384 || raw.Contains('\0')) throw new InvalidDataException("Invalid delivery receipt size.");
        return JsonDocument.Parse(raw,new JsonDocumentOptions { MaxDepth=8 });
    }
    internal static void Exact(JsonElement root,params string[] fields)
    {
        if(root.ValueKind!=JsonValueKind.Object ||
            !root.EnumerateObject().Select(p=>p.Name).OrderBy(x=>x,StringComparer.Ordinal)
                .SequenceEqual(fields.OrderBy(x=>x,StringComparer.Ordinal)))
            throw new InvalidDataException("Unexpected or duplicate delivery receipt fields.");
    }
    internal static string Read(JsonElement root,string key)=>root.GetProperty(key).GetString() ??
        throw new InvalidDataException("Missing delivery receipt field.");
    private static void Need(bool value)
    {
        if(!value) throw new InvalidDataException("Unverified primary mailbox delivery receipt.");
    }
    internal static PrimaryMailboxDeliveryReceipt Parse(string raw,string action,
        PrimaryMailboxDeliveryRequest request,string? expectedSha)
    {
        Need(request.Valid() && action is "preview" or "submit" or "trace");
        using var doc=Document(raw);
        var root=doc.RootElement;
        string ReadRoot(string key)=>Read(root,key);
        string status=action switch { "preview"=>"review_ready","submit"=>"submission_recorded",_=>"trace_observed" };
        if(action=="preview")
            Exact(root,"status","run_id","plan_sha256","backup_sha256","runtime_sha256","mail_sent",
                "inbox_verified","recipient_role_proof","automatic_retry");
        else if(action=="submit")
            Exact(root,"status","run_id","plan_sha256","outcomes","inbox_verified","automatic_retry");
        else
            Exact(root,"status","run_id","plan_sha256","source","started_unix","request_sha256",
                "outcomes","inbox_verified","automatic_retry");
        string sha=ReadRoot("plan_sha256");
        Need(ReadRoot("status")==status && ReadRoot("run_id")==request.RunId &&
             PrimaryMailboxOfflineClient.IsSha(sha) && (expectedSha is null || sha==expectedSha) &&
             root.GetProperty("inbox_verified").ValueKind==JsonValueKind.False &&
             root.GetProperty("automatic_retry").ValueKind==JsonValueKind.False);
        if(action=="preview")
        {
            string runtime=ReadRoot("runtime_sha256");
            Need(expectedSha is null && ReadRoot("backup_sha256")==request.BackupSha &&
                PrimaryMailboxOfflineClient.IsSha(runtime) && root.GetProperty("mail_sent").ValueKind==JsonValueKind.False &&
                ReadRoot("recipient_role_proof")=="domain_comparison_only");
            return new(sha,runtime,"",[]);
        }
        if(action=="submit") Need(PrimaryMailboxOfflineClient.IsSha(expectedSha));
        string source=action=="trace"?ReadRoot("source"):"";
        Need(action!="trace" || source is "journal_recent_only" or "journal_unavailable");
        long? started=null;
        string? requestSha=null;
        if(action=="trace")
        {
            started=root.GetProperty("started_unix").GetInt64();
            requestSha=ReadRoot("request_sha256");
            Need(started.Value>0 && started.Value<=DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() &&
                requestSha==request.RequestSha());
        }
        var outcomes=root.GetProperty("outcomes");
        Need(outcomes.ValueKind==JsonValueKind.Object);
        string[] keys=outcomes.EnumerateObject().Select(p=>p.Name).ToArray();
        Need(keys.Distinct(StringComparer.Ordinal).Count()==keys.Length &&
            keys.All(k=>k is "internal" or "external") &&
            (action=="trace"?keys.Length==2:keys.Contains("internal")));
        var rows=new List<PrimaryMailboxDeliveryRow>();
        foreach(string role in new[]{"internal","external"})
        {
            if(!outcomes.TryGetProperty(role,out var row))
            {
                Need(action=="submit");
                rows.Add(new(role,"not_attempted","not_observed","","",""));
                continue;
            }
            if(action=="submit")
            {
                string state=row.GetString()??"";
                Need(state is "local_submission_accepted" or "submission_uncertain");
                rows.Add(new(role,state,"not_observed","","",""));
                continue;
            }
            Need(row.ValueKind==JsonValueKind.Object);
            string[] fields=row.EnumerateObject().Select(p=>p.Name).ToArray();
            Need(fields.Distinct(StringComparer.Ordinal).Count()==fields.Length &&
                fields.All(k=>k is "submission" or "transport" or "queue_id" or "queue" or "dsn"));
            string sub=Read(row,"submission"),transport=Read(row,"transport");
            string Optional(string key)=>row.TryGetProperty(key,out _)?Read(row,key):"";
            string qid=Optional("queue_id"),queue=Optional("queue"),dsn=Optional("dsn");
            Need(sub is "not_attempted" or "attempted" or "local_submission_accepted" or "submission_uncertain");
            Need(transport is "not_attempted" or "correlation_unavailable" or "unknown" or
                "exchange_smtp_accepted" or "pipe_sent_exchange_unverified" or "deferred" or "bounced");
            Need((qid.Length==0 || Regex.IsMatch(qid,@"\A[A-Za-z0-9]{5,80}\z")) &&
                queue is "" or "not_observed" or "active" or "deferred" or "incoming" or "hold" or "maildrop" or "other" or "unavailable");
            Need(dsn.Length==0 || Regex.IsMatch(dsn,@"\A[245]\.[0-9]{1,3}\.[0-9]{1,3}\z"));
            Need((sub=="not_attempted")== (transport=="not_attempted"));
            if(transport is "exchange_smtp_accepted" or "pipe_sent_exchange_unverified" or "deferred" or "bounced")
                Need(qid.Length>0 && dsn.StartsWith(transport=="deferred"?"4.":transport=="bounced"?"5.":"2.",StringComparison.Ordinal));
            if(qid.Length==0) Need(queue.Length==0 && dsn.Length==0 && transport is "not_attempted" or "correlation_unavailable");
            rows.Add(new(role,sub,transport,qid,queue,dsn));
        }
        if(action=="submit" && rows[1].Submission!="not_attempted")
            Need(rows[0].Submission=="local_submission_accepted");
        return new(sha,null,source,rows.ToArray(),started,requestSha);
    }
    internal static (string Payload,List<string> Attempted) ExchangeTracePayload(
        PrimaryMailboxDeliveryRequest request,PrimaryMailboxDeliveryReceipt local,DateTimeOffset now)
    {
        Need(request.Valid() && PrimaryMailboxOfflineClient.IsSha(local.PlanSha) &&
             local.RequestSha==request.RequestSha() && local.StartedUnix.HasValue &&
             local.Source is "journal_recent_only" or "journal_unavailable");
        long started=local.StartedUnix!.Value;
        Need(started>=now.AddDays(-7).ToUnixTimeSeconds() &&
             started<=now.AddMinutes(5).ToUnixTimeSeconds());
        Need(local.Rows.Length==2 && local.Rows.Select(r=>r.Role).OrderBy(x=>x,StringComparer.Ordinal)
             .SequenceEqual(new[]{"external","internal"}));
        var attempted=new List<string>();
        foreach(string role in new[]{"internal","external"})
        {
            var row=local.Rows.Single(r=>r.Role==role);
            if(row.Submission is "attempted" or "local_submission_accepted" or "submission_uncertain")
                attempted.Add(role);
            else Need(row.Submission=="not_attempted");
        }
        Need(attempted.Count>0);
        return (JsonSerializer.Serialize(new Dictionary<string,object> {
            ["run_id"]=request.RunId,["accepted_domain"]=request.Domain,["sender"]=request.Sender,
            ["internal"]=request.Internal,["external"]=request.External,
            ["started_unix"]=started,["attempted"]=attempted
        }),attempted);
    }

    internal static bool SelfTest()
    {
        string a=new('a',64),b=new('b',64),run=new('1',32);
        var request=new PrimaryMailboxDeliveryRequest(run,"alerts@example.org","test@example.org",
            "test@example.net","example.org",a,Guid.Parse("11111111-1111-1111-1111-111111111111"),
            Guid.Parse("22222222-2222-2222-2222-222222222222"));
        if(PrimaryMailboxDeliveryRequest.Parse(request.Json())!=request ||
            (request with { External="test@example.org" }).Valid()) return false;
        string preview=JsonSerializer.Serialize(new {status="review_ready",run_id=run,plan_sha256=a,
            backup_sha256=a,runtime_sha256=b,mail_sent=false,inbox_verified=false,
            recipient_role_proof="domain_comparison_only",automatic_retry=false});
        string submit=JsonSerializer.Serialize(new {status="submission_recorded",run_id=run,plan_sha256=a,
            outcomes=new Dictionary<string,string>{{"internal","local_submission_accepted"},{"external","submission_uncertain"}},
            inbox_verified=false,automatic_retry=false});
        long started=DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds();
        string trace=JsonSerializer.Serialize(new {status="trace_observed",run_id=run,plan_sha256=a,
            source="journal_recent_only",started_unix=started,request_sha256=request.RequestSha(),
            outcomes=new Dictionary<string,object>{
                ["internal"]=new {submission="local_submission_accepted",transport="exchange_smtp_accepted",
                    queue_id="ABC12345",queue="not_observed",dsn="2.0.0"},
                ["external"]=new {submission="submission_uncertain",transport="correlation_unavailable"}},
            inbox_verified=false,automatic_retry=false});
        if(Parse(preview,"preview",request,null).RuntimeSha!=b ||
            Parse(submit,"submit",request,a).Rows[1].Submission!="submission_uncertain" ||
            Parse(trace,"trace",request,a).Rows[0].QueueId!="ABC12345") return false;
        foreach(string bad in new[]{trace.Replace("2.0.0","4.0.0"),trace.Replace("ABC12345","bad!"),
            trace.Replace("\"inbox_verified\":false","\"inbox_verified\":true"),
            trace.Replace("\"automatic_retry\":false","\"automatic_retry\":true"),
            trace.Replace("\"source\":","\"extra\":true,\"source\":")})
        {
            try { Parse(bad,"trace",request,a);return false; } catch(InvalidDataException) {}
        }
        try { Parse(trace,"trace",request,b);return false; } catch(InvalidDataException) {}
        try { Parse(trace,"trace",request with { External="other@example.net" },a);return false; }
        catch(InvalidDataException) {}
        var local=Parse(trace,"trace",request,a);
        var cloud=ExchangeTracePayload(request,local,DateTimeOffset.UtcNow);
        if(!cloud.Attempted.SequenceEqual(new[]{"internal","external"})) return false;
        using(var payload=Document(cloud.Payload))
        {
            Exact(payload.RootElement,"run_id","accepted_domain","sender","internal","external","started_unix","attempted");
            if(payload.RootElement.GetProperty("started_unix").GetInt64()!=started) return false;
        }
        var partial=local with { Rows=[local.Rows[0],local.Rows[1] with {Submission="not_attempted"}] };
        if(!ExchangeTracePayload(request,partial,DateTimeOffset.UtcNow).Attempted.SequenceEqual(new[]{"internal"})) return false;
        foreach(var bad in new[]{local with { RequestSha=b },local with { StartedUnix=started-8*86400 },
            local with { StartedUnix=started+86400 },
            local with { Rows=[local.Rows[0] with {Submission="not_attempted"},local.Rows[1] with {Submission="not_attempted"}] }})
        {
            try { ExchangeTracePayload(request,bad,DateTimeOffset.UtcNow);return false; } catch(InvalidDataException) {}
        }
        string bundle=EmbeddedAssets.BuildPrimaryMailboxDeliveryProbe("submit",request,a,Confirm);
        return bundle.Contains("probe-primary-mailbox-delivery.py",StringComparison.Ordinal) &&
            bundle.Contains("review-postfix-m365-delivery.py",StringComparison.Ordinal) &&
            bundle.Contains("--confirm="+Confirm,StringComparison.Ordinal);
    }
}
