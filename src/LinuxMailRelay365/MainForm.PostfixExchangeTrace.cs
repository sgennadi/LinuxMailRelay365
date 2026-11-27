using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task<string> ReadPostfixExchangeTraceAsync(string context, string request, string localTrace)
    {
        if (!Guid.TryParse(tenant.Text.Trim(), out Guid id) || id == Guid.Empty ||
            (discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption))
            throw new InvalidOperationException("Select the exact Microsoft 365 tenant first.");
        using var inputs = JsonDocument.Parse(request);
        using var local = JsonDocument.Parse(localTrace);
        var req = inputs.RootElement;
        var proof = local.RootElement;
        string runId = req.GetProperty("run_id").GetString() ?? "";
        string domain = req.GetProperty("accepted_domain").GetString() ?? "";
        void Guard()
        {
            CheckCloudTenant(id);
            if (TryCurrentIdentity() != context || mailTransport.SelectedIndex != 1 ||
                !string.Equals(acceptedDomain.Text.Trim(), domain, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Linux, tenant or sender domain changed.");
        }
        Guard();
        if (!Regex.IsMatch(runId, @"\A[a-f0-9]{32}\z") ||
            proof.GetProperty("status").GetString() != "trace_observed" ||
            proof.GetProperty("run_id").GetString() != runId ||
            proof.GetProperty("inbox_verified").GetBoolean())
            throw new InvalidDataException("Matching local ledger evidence required.");

        // Python canonical() sorts keys and emits ASCII compact JSON. Inputs
        // were validated on Linux as ASCII addresses and DNS names.
        var canonical = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (string key in new[] { "accepted_domain", "external", "internal", "mx", "run_id", "sender" })
        {
            string value = req.GetProperty(key).GetString() ?? "";
            if (value.Length == 0 || value.Any(c => c < 32 || c > 126))
                throw new InvalidDataException("Invalid probe input.");
            canonical.Add(key, value);
        }
        byte[] raw = JsonSerializer.SerializeToUtf8Bytes(canonical,
            new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        string requestSha = Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant();
        if (proof.GetProperty("request_sha256").GetString() != requestSha)
            throw new InvalidDataException("Local ledger request does not match the trace input.");

        long started = proof.GetProperty("started_unix").GetInt64();
        var now = DateTimeOffset.UtcNow;
        var time = DateTimeOffset.FromUnixTimeSeconds(started);
        if (time < now.AddDays(-7) || time > now.AddMinutes(5))
            throw new InvalidOperationException("Trace supports recorded runs from the last seven days.");
        string[] roles = ["internal", "external"];
        var attempted = new List<string>();
        foreach (string role in roles)
        {
            string? submission = proof.GetProperty("outcomes").GetProperty(role).GetProperty("submission").GetString();
            if (submission is "attempted" or "local_submission_accepted" or "submission_uncertain")
                attempted.Add(role);
            else if (submission != "not_attempted")
                throw new InvalidDataException("Invalid local submission evidence.");
        }
        if (attempted.Count == 0) throw new InvalidOperationException("No recorded submission to trace.");
        var payload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["run_id"] = runId, ["accepted_domain"] = domain,
            ["sender"] = canonical["sender"], ["internal"] = canonical["internal"],
            ["external"] = canonical["external"], ["started_unix"] = started, ["attempted"] = attempted
        });
        Directory.CreateDirectory(dataDirectory);
        string prefix = Path.Combine(dataDirectory, "message-trace-" + Guid.NewGuid().ToString("N"));
        string script = prefix + ".ps1", input = prefix + "-request.json", output = prefix + "-result.json";
        try
        {
            WriteRestrictedGraphPayload(script, EmbeddedAssets.ExchangeMessageTrace);
            WriteRestrictedGraphPayload(input, payload);
            WriteRestrictedGraphPayload(output, "");
            var psi = new ProcessStartInfo("pwsh.exe") { UseShellExecute = true, WorkingDirectory = dataDirectory };
            foreach (string part in new[] { "-NoLogo", "-NoProfile", "-File", script,
                         "-TenantId", id.ToString("D"), "-RequestPath", input, "-ResultPath", output })
                psi.ArgumentList.Add(part);
            using var process = Process.Start(psi) ?? throw new IOException("Cannot start PowerShell 7.");
            await process.WaitForExitAsync();
            if (process.ExitCode != 0 || new FileInfo(output).Length > 8192)
                throw new InvalidOperationException("Exchange trace unavailable; review module, permissions and sign-in.");
            Guard();
            using var response = JsonDocument.Parse(await File.ReadAllTextAsync(output));
            var root = response.RootElement;
            if (root.GetProperty("version").GetInt32() != 1 ||
                root.GetProperty("status").GetString() != "exchange_trace_observed" ||
                root.GetProperty("tenant_id").GetString() != id.ToString("D") ||
                root.GetProperty("run_id").GetString() != runId ||
                root.GetProperty("inbox_verified").GetBoolean() || root.GetProperty("changes_applied").GetBoolean())
                throw new InvalidDataException("Invalid Exchange trace evidence.");
            var outcomes = new Dictionary<string, object>();
            foreach (string role in roles)
            {
                var item = root.GetProperty("outcomes").GetProperty(role);
                string? state = item.GetProperty("state").GetString();
                int count = item.GetProperty("count").GetInt32();
                if (state is not ("not_attempted" or "not_observed" or "ambiguous" or "delivered" or "pending"
                    or "failed" or "quarantined" or "expanded" or "filtered_as_spam" or "getting_status" or "recalled" or "unknown_status") ||
                    count is < 0 or > 100 ||
                    (attempted.Contains(role) == (state == "not_attempted")) ||
                    ((state is "not_attempted" or "not_observed") ? count != 0 : state == "ambiguous" ? count < 1 : count != 1))
                    throw new InvalidDataException("Inconsistent trace status.");
                outcomes.Add(role, new { state, count });
            }
            return JsonSerializer.Serialize(new { tenant_id = id.ToString("D"), run_id = runId,
                outcomes, inbox_verified = false, changes_applied = false },
                new JsonSerializerOptions { WriteIndented = true });
        }
        finally
        {
            foreach (string path in new[] { input, output, script })
                if (File.Exists(path)) File.Delete(path);
        }
    }
}
