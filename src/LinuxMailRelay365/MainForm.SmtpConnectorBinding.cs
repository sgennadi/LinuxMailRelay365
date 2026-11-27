using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    // This is deliberately read-only: a compatible Connector observation is not
    // delivery proof, and never sets the existing route approval checkbox.
    private async Task ReviewManagedConnectorBindingAsync(Form owner, string context, string dns)
    {
        if (!Guid.TryParse(tenant.Text.Trim(), out Guid id) || id == Guid.Empty)
            throw new InvalidOperationException("Select the Microsoft 365 tenant first.");
        string senderDomain = acceptedDomain.Text.Trim().ToLowerInvariant();
        string name = outboundConnectorName.Text.Trim();
        var options = (Tenant: id, Domain: senderDomain, Name: name, Ip: "", Certificate: dns);
        if (Uri.CheckHostName(senderDomain) != UriHostNameType.Dns ||
            !Regex.IsMatch(name, @"\A[A-Za-z0-9][A-Za-z0-9._ -]{2,69}\z"))
            throw new InvalidOperationException("Review the accepted domain and connector name first.");
        void Guard()
        {
            CheckCloudTenant(id);
            if (owner.IsDisposed || TryCurrentIdentity() != context || mailTransport.SelectedIndex != 1 ||
                acceptedDomain.Text.Trim().ToLowerInvariant() != senderDomain ||
                outboundConnectorName.Text.Trim() != name)
                throw new InvalidOperationException("Binding context changed; review again.");
        }
        async Task<(string Sha, string Generation, string Details, string Security)> LocalAsync()
        {
            Guard();
            string script = EmbeddedAssets.BuildSmtpTlsRotation("binding-preview", null, dns, null);
            var endpoint = Endpoint();
            var timeout = TimeSpan.FromSeconds(180);
            var result = endpoint.Username == "root"
                ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script, timeout)
                : await SshRemote.RunRootScriptAsync(endpoint, script, timeout);
            result.EnsureSuccess();
            Guard();
            using var json = JsonDocument.Parse(result.StdOut);
            var root = json.RootElement;
            string sha = root.GetProperty("binding_sha256").GetString() ?? "";
            string generation = root.GetProperty("generation").GetString() ?? "";
            if (root.GetProperty("status").GetString() != "local_binding_reviewed" ||
                root.GetProperty("domain").GetString() != dns ||
                root.GetProperty("mail_sent").GetBoolean() ||
                !Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z") ||
                !Regex.IsMatch(generation, @"\Acandidate-[a-f0-9]{64}\z"))
                throw new InvalidDataException("Invalid local certificate binding evidence.");
            return (sha, generation, root.GetProperty("certificate_details").GetString() ?? "",
                root.GetProperty("smtp_tls_security_level").GetString() ?? "");
        }
        Guard();
        var local = await LocalAsync();
        string cloud = await RunTenantConnectorManagerAsync(options, "Inspect");
        Guard();
        if ((await LocalAsync()).Sha != local.Sha)
            throw new InvalidOperationException("Linux certificate changed during Exchange review.");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in cloud.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            int i = line.IndexOf('=');
            if (i < 1 || !fields.TryAdd(line[..i], line[(i+1)..]))
                throw new InvalidDataException("Invalid Exchange binding report.");
        }
        string[] expected = ["EXO_CONNECTOR_TENANT", "EXO_CONNECTOR_ACCEPTED_DOMAIN",
            "EXO_CONNECTOR_CERTIFICATE_DOMAIN", "EXO_CONNECTOR_BINDING",
            "EXO_CONNECTOR_EXACT_COUNT", "EXO_CONNECTOR_CONFLICT_COUNT", "EXO_CONNECTOR_NAME_TAKEN",
            "EXO_CONNECTOR_DELIVERY_VERIFIED", "CHANGES_APPLIED"];
        if (fields.Count != expected.Length || expected.Any(key => !fields.ContainsKey(key)) ||
            fields["EXO_CONNECTOR_TENANT"] != "exact_match" ||
            fields["EXO_CONNECTOR_ACCEPTED_DOMAIN"] != "verified" ||
            fields["EXO_CONNECTOR_CERTIFICATE_DOMAIN"] != "verified" ||
            fields["EXO_CONNECTOR_DELIVERY_VERIFIED"] != "no" || fields["CHANGES_APPLIED"] != "no" ||
            fields["EXO_CONNECTOR_BINDING"] is not ("exact_enabled_connector_observed" or
                "no_matching_connector" or "manual_review_required") ||
            new[] { "EXO_CONNECTOR_EXACT_COUNT", "EXO_CONNECTOR_CONFLICT_COUNT", "EXO_CONNECTOR_NAME_TAKEN" }
                .Any(key => !int.TryParse(fields[key], out int value) || value is < 0 or > 500))
            throw new InvalidDataException("Incomplete Exchange binding evidence.");
        // Only configuration observation; no route or approval is changed.
        string binding = fields["EXO_CONNECTOR_BINDING"];
        string next = binding switch
        {
            "exact_enabled_connector_observed" => "An exact enabled OnPremises Connector was observed. Test actual delivery separately.",
            "no_matching_connector" => "No exact Connector was found. Use the existing Preview NEW tenant Connector workflow; enter this exact certificate DNS name.",
            _ => "Ambiguous, disabled, wildcard or differently scoped Connector; review in Exchange before any change."
        };
        MessageBox.Show(owner, "Tenant: " + id.ToString("D") + Environment.NewLine +
            "Sender accepted domain: " + senderDomain + Environment.NewLine +
            "Certificate accepted domain: " + dns + Environment.NewLine +
            "Active Linux generation: " + local.Generation + Environment.NewLine +
            "SMTP TLS security level: " + local.Security + Environment.NewLine +
            local.Details + Environment.NewLine +
            "Local review SHA-256: " + local.Sha + Environment.NewLine +
            "Exchange: " + binding + Environment.NewLine +
            "Exact matches: " + fields["EXO_CONNECTOR_EXACT_COUNT"] +
            "; possible conflicts: " + fields["EXO_CONNECTOR_CONFLICT_COUNT"] + Environment.NewLine +
            next + Environment.NewLine + "No Exchange or Linux settings were changed.",
            "Microsoft 365 certificate binding review", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
}
