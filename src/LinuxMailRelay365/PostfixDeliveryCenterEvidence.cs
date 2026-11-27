using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Values from each read-only source are checked before display. No positive
// result from one source is promoted to a different delivery evidence level.
internal static class PostfixDeliveryCenterEvidence
{
    internal sealed record Observation(string State, string Detail, bool Positive = false);

    internal static JsonDocument Parse(string json)
    {
        if (json.Length > 65536 || json.Contains('\0')) throw new InvalidDataException("Invalid evidence size.");
        return JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 12 });
    }

    internal static string Field(JsonElement root, string name) =>
        root.GetProperty(name).GetString() ?? throw new InvalidDataException("Missing evidence field.");

    internal static void Exact(JsonElement obj, params string[] expected)
    {
        if (obj.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected object.");
        var names = obj.EnumerateObject().Select(p => p.Name).ToArray();
        if (names.Length != expected.Length || names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
            names.Except(expected, StringComparer.Ordinal).Any())
            throw new InvalidDataException("Unexpected or duplicate evidence field.");
    }

    internal static void FalseFlags(JsonElement root, params string[] names)
    {
        foreach (string name in names)
            if (root.GetProperty(name).ValueKind != JsonValueKind.False)
                throw new InvalidDataException("Unexpected evidence claim.");
    }

    private static string RequestSha(string request, string[] keys)
    {
        using var input = Parse(request);
        Exact(input.RootElement, keys);
        var fields = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (string key in keys)
        {
            string value = Field(input.RootElement, key);
            if (value.Length is < 1 or > 254 || value.Any(c => c < 32 || c > 126))
                throw new InvalidDataException("Invalid request token.");
            fields.Add(key, value);
        }
        if (!Regex.IsMatch(fields["run_id"], @"\A[a-f0-9]{32}\z"))
            throw new InvalidDataException("Invalid Run ID.");
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(fields,
            new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))).ToLowerInvariant();
    }

    private static string Run(string request)
    {
        using var input = Parse(request);
        return Field(input.RootElement, "run_id");
    }

    private static void TraceContext(JsonElement root, string request, bool local)
    {
        string[] keys = local ? ["recipient", "run_id"] :
            ["accepted_domain", "external", "internal", "mx", "run_id", "sender"];
        if (Field(root,"status") != (local ? "local_trace_observed" : "trace_observed") ||
            Field(root,"run_id") != Run(request) || Field(root,"request_sha256") != RequestSha(request,keys) ||
            Field(root,"source") is not ("journal_recent_only" or "journal_unavailable") ||
            root.GetProperty("started_unix").GetInt64() <= 0)
            throw new InvalidDataException("Trace context mismatch.");
        FalseFlags(root,"automatic_retry",local ? "mailbox_verified" : "inbox_verified");
        if (!local) FalseFlags(root,"tls_handshake_verified");
    }

    private static Observation Transport(JsonElement row, bool local, string source)
    {
        string submission = Field(row,"submission"), transport = Field(row,"transport");
        string positive = local ? "local_agent_accepted" : "exchange_relay_accepted";
        string unverified = local ? "local_destination_unverified" : "smtp_sent_destination_unverified";
        if (submission is not ("not_attempted" or "attempted" or "local_submission_accepted" or "submission_uncertain") ||
            !(transport == positive || transport == unverified || transport is "not_attempted" or
                "correlation_unavailable" or "unknown" or "deferred" or "bounced") ||
            (submission == "not_attempted") != (transport == "not_attempted"))
            throw new InvalidDataException("Invalid submission or transport state.");
        bool correlated = transport is not ("not_attempted" or "correlation_unavailable");
        bool hasId = row.TryGetProperty("queue_id",out var id);
        bool hasQueue = row.TryGetProperty("queue",out var queue);
        bool hasDsn = row.TryGetProperty("dsn",out var dsn);
        var fields = new List<string> { "submission","transport" };
        if (hasId) fields.Add("queue_id");
        if (hasQueue) fields.Add("queue");
        if (hasDsn) fields.Add("dsn");
        Exact(row,fields.ToArray());
        if (hasId != correlated || hasQueue != correlated ||
            (hasId && !Regex.IsMatch(id.GetString() ?? "", @"\A[A-Za-z0-9]{5,80}\z")) ||
            (hasQueue && queue.GetString() is not ("unavailable" or "not_observed" or "active" or "deferred" or "incoming" or "hold" or "maildrop" or "other")) ||
            (hasDsn && (!correlated || !Regex.IsMatch(dsn.GetString() ?? "", @"\A[245]\.[0-9]{1,3}\.[0-9]{1,3}\z"))) ||
            (transport == positive && (!hasDsn || !dsn.GetString()!.StartsWith("2.",StringComparison.Ordinal) ||
                source != "journal_recent_only")))
            throw new InvalidDataException("Inconsistent transport evidence.");
        string detail = "Submission: " + submission + "; journal: " + source +
            (hasId ? "; Queue ID: " + id.GetString() + "; queue: " + queue.GetString() : "") +
            (hasDsn ? "; DSN: " + dsn.GetString() : "") +
            (transport == positive ? (local ? "; local agent, not mailbox confirmation" : "; SMTP acceptance, not inbox confirmation") : "");
        return new(transport,detail,transport == positive);
    }

    internal static Observation LocalTrace(string json,string request)
    {
        using var doc = Parse(json);
        var root = doc.RootElement;
        Exact(root,"status","run_id","source","request_sha256","started_unix","outcome","mailbox_verified","automatic_retry");
        TraceContext(root,request,true);
        return Transport(root.GetProperty("outcome"),true,Field(root,"source"));
    }

    internal static (Observation Internal,Observation External) RelayTrace(string json,string request)
    {
        using var doc = Parse(json);
        var root = doc.RootElement;
        Exact(root,"status","run_id","source","request_sha256","started_unix","outcomes","inbox_verified","tls_handshake_verified","automatic_retry");
        TraceContext(root,request,false);
        var outcomes = root.GetProperty("outcomes");
        Exact(outcomes,"internal","external");
        return (Transport(outcomes.GetProperty("internal"),false,Field(root,"source")),
                Transport(outcomes.GetProperty("external"),false,Field(root,"source")));
    }

    internal static Observation Mailbox(string json,string request)
    {
        using var doc = Parse(json);
        var root = doc.RootElement;
        Exact(root,"status","run_id","request_sha256","mailbox_kind","observation","mailbox_verified",
            "mail_sent","mailbox_modified","content_exported","automatic_retry");
        FalseFlags(root,"mail_sent","mailbox_modified","content_exported","automatic_retry");
        if (Field(root,"status") != "local_mailbox_observation" || Field(root,"run_id") != Run(request) ||
            Field(root,"request_sha256") != RequestSha(request,["recipient","run_id"]))
            throw new InvalidDataException("Mailbox context mismatch.");
        string state = Field(root,"observation");
        string? kind = root.GetProperty("mailbox_kind").GetString();
        bool found = root.GetProperty("mailbox_verified").GetBoolean();
        if (state is not ("message_observed" or "not_observed" or "scan_incomplete" or "mailbox_not_present" or "review_context_changed" or "not_attempted") ||
            found != (state == "message_observed") ||
            (state is "review_context_changed" or "not_attempted" ? kind is not null : kind is not ("maildir" or "system_spool")))
            throw new InvalidDataException("Inconsistent mailbox observation.");
        return new(state,"Storage: " + (kind ?? "not inspected") +
            (found ? "; matching test headers observed at sample time" : "; absence does not establish delivery failure"),found);
    }

    internal static (Observation Internal,Observation External) Exchange(string json,string request,
        Observation internalTransport,Observation externalTransport)
    {
        using var doc = Parse(json);
        var root = doc.RootElement;
        Exact(root,"tenant_id","run_id","outcomes","inbox_verified","changes_applied");
        FalseFlags(root,"inbox_verified","changes_applied");
        if (Field(root,"run_id") != Run(request) || !Guid.TryParseExact(Field(root,"tenant_id"),"D",out var tenant) || tenant == Guid.Empty)
            throw new InvalidDataException("Exchange context mismatch.");
        var outcomes = root.GetProperty("outcomes");
        Exact(outcomes,"internal","external");
        Observation Read(string role, Observation transport)
        {
            var row = outcomes.GetProperty(role);
            Exact(row,"state","count");
            string state = Field(row,"state");
            int count = row.GetProperty("count").GetInt32();
            if (state is not ("not_attempted" or "not_observed" or "ambiguous" or "delivered" or "pending" or "failed" or
                "quarantined" or "expanded" or "filtered_as_spam" or "getting_status" or "recalled" or "unknown_status") ||
                count is < 0 or > 100 || (state == "not_attempted") != (transport.State == "not_attempted") ||
                ((state is "not_attempted" or "not_observed") ? count != 0 : state == "ambiguous" ? count < 1 : count != 1))
                throw new InvalidDataException("Inconsistent Exchange result.");
            return new(state,"Tenant: " + tenant.ToString("D") + "; trace records: " + count +
                "; service-reported status, not inbox verification. Not observed may mean trace latency.",state == "delivered");
        }
        return (Read("internal",internalTransport),Read("external",externalTransport));
    }

    internal static Observation Queue(string json,string domain,string mx)
    {
        // Reuse the primary audit validator, including identity, flags, exact
        // settings, queue sums and configuration hashes.
        var (_,review) = MainForm.FormatPrimaryPostfixAudit(json,domain,mx);
        using var doc = Parse(json);
        var root = doc.RootElement;
        var queue = root.GetProperty("queue");
        string service = Field(root,"service");
        if (Field(queue,"status") == "unavailable")
            return new("unavailable","Service: " + service + "; queue not sampled. Do not assume it is empty.");
        int total = queue.GetProperty("total").GetInt32();
        var counts = queue.GetProperty("counts");
        string detail = "Service: " + service + "; total: " + total + "; " +
            string.Join("; ",new[] {"active","deferred","incoming","hold","maildrop","other"}
                .Select(k => k + ": " + counts.GetProperty(k).GetInt32())) +
            (review ? "; primary audit has review items" : "; basic audit observed") + "; moving sample only.";
        return new(total == 0 ? "sampled_empty" : "sampled_nonempty",detail,total == 0 && !review);
    }
}
