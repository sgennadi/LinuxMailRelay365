using System.Net;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private Task<string> OpenPublicIpConnectorAsync(Form owner, string context, string sessionMx)
    {
        if (TryCurrentIdentity() != context || mailTransport.SelectedIndex != 1)
            throw new InvalidOperationException("Select the Microsoft 365 Connector route and Linux host.");
        string senderDomain = acceptedDomain.Text.Trim().ToLowerInvariant();
        string name = outboundConnectorName.Text.Trim();
        if (!Regex.IsMatch(senderDomain, @"\A[a-z0-9.-]{1,253}\z") ||
            Uri.CheckHostName(senderDomain) != UriHostNameType.Dns)
            throw new InvalidOperationException("Select the exact accepted domain first.");
        void Guard()
        {
            if (owner.IsDisposed || TryCurrentIdentity() != context || mailTransport.SelectedIndex != 1 ||
                acceptedDomain.Text.Trim().ToLowerInvariant() != senderDomain ||
                outboundConnectorName.Text.Trim() != name)
                throw new InvalidOperationException("Linux or route selection changed. Reopen the wizard.");
        }
        async Task<string> LinuxAsync(string script, int seconds)
        {
            Guard();
            var result = await SshRemote.ExecuteAsync(Endpoint(), script, "", TimeSpan.FromSeconds(seconds));
            result.EnsureSuccess();
            Guard();
            return result.StdOut;
        }
        using var dialog = new SmtpPublicIpConnectorDialog(senderDomain, name, outboundPublicIp.Text.Trim(), sessionMx,
            () => LinuxAsync(EmbeddedAssets.BuildM365PublicIpv4Observation(), 35),
            () => LinuxAsync(EmbeddedAssets.BuildM365MxDiscovery(senderDomain), 30),
            mx => LinuxAsync(EmbeddedAssets.BuildM365StartTlsDiagnosis(mx), 75),
            async (form, ip, create) =>
            {
                Guard();
                await ReviewPublicIpConnectorAsync(form, Guard, senderDomain, name, ip, create);
            });
        dialog.ShowDialog(owner);
        return Task.FromResult(dialog.SessionMx);
    }

    private async Task ReviewPublicIpConnectorAsync(Form owner, Action routeGuard,
        string senderDomain, string name, string ip, bool create)
    {
        routeGuard();
        if (!Guid.TryParse(tenant.Text.Trim(), out Guid id) || id == Guid.Empty ||
            (discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption))
            throw new InvalidOperationException("Select the exact Microsoft 365 tenant first.");
        if (!SmtpPublicIpConnectorDialog.IsPublicIpv4(ip) ||
            !Regex.IsMatch(name, @"\A[A-Za-z0-9][A-Za-z0-9._ -]{2,69}\z"))
            throw new InvalidOperationException("An exact public IPv4 and connector name are required.");
        void Guard()
        {
            routeGuard();
            CheckCloudTenant(id);
            if (owner.IsDisposed || (create && !acceptedDomainApproved.Checked))
                throw new InvalidOperationException("Accepted domain approval or context unavailable.");
        }
        static Dictionary<string, string> ParseFields(string report)
        {
            if (report.Length > 4096 || report.Contains('\0'))
                throw new InvalidDataException("Invalid connector report.");
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string line in report.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                int split = line.IndexOf('=');
                if (split < 1 || !fields.TryAdd(line[..split], line[(split + 1)..]))
                    throw new InvalidDataException("Malformed connector evidence.");
            }
            return fields;
        }
        static string CreationSha(string report, bool applied)
        {
            var fields = ParseFields(report);
            string[] keys = ["EXO_CONNECTOR_PLAN", "EXO_CONNECTOR_TENANT", "EXO_CONNECTOR_ACCEPTED_DOMAIN",
                "EXO_CONNECTOR_REVIEW_SHA256", "EXO_CONNECTOR_DELIVERY_VERIFIED", "CHANGES_APPLIED"];
            if (fields.Count != keys.Length + (applied ? 1 : 0) || keys.Any(k => !fields.ContainsKey(k)) ||
                fields["EXO_CONNECTOR_PLAN"] != "ready" || fields["EXO_CONNECTOR_TENANT"] != "exact_match" ||
                fields["EXO_CONNECTOR_ACCEPTED_DOMAIN"] != "verified" || fields["EXO_CONNECTOR_DELIVERY_VERIFIED"] != "no" ||
                fields["CHANGES_APPLIED"] != (applied ? "tenant_new_connector_only" : "no") ||
                (applied && (!fields.TryGetValue("EXO_CONNECTOR_CREATED", out string? created) || created != "yes")) ||
                !Regex.IsMatch(fields["EXO_CONNECTOR_REVIEW_SHA256"], @"\A[a-f0-9]{64}\z"))
                throw new InvalidDataException("Incomplete connector creation evidence.");
            return fields["EXO_CONNECTOR_REVIEW_SHA256"];
        }
        Guard();
        var options = (Tenant: id, Domain: senderDomain, Name: name, Ip: ip, Certificate: "");
        string description = "Tenant: " + id.ToString("D") + Environment.NewLine +
            "Accepted domain: " + senderDomain + Environment.NewLine + "Connector name: " + name +
            Environment.NewLine + "Public IPv4: " + ip + Environment.NewLine;
        if (!create)
        {
            var fields = ParseFields(await RunTenantConnectorManagerAsync(options, "Inspect"));
            Guard();
            string[] keys = ["EXO_CONNECTOR_TENANT", "EXO_CONNECTOR_ACCEPTED_DOMAIN",
                "EXO_CONNECTOR_PUBLIC_IPV4", "EXO_CONNECTOR_BINDING", "EXO_CONNECTOR_EXACT_COUNT",
                "EXO_CONNECTOR_CONFLICT_COUNT", "EXO_CONNECTOR_NAME_TAKEN", "EXO_CONNECTOR_DELIVERY_VERIFIED", "CHANGES_APPLIED"];
            if (fields.Count != keys.Length || keys.Any(k => !fields.ContainsKey(k)) ||
                fields["EXO_CONNECTOR_TENANT"] != "exact_match" || fields["EXO_CONNECTOR_ACCEPTED_DOMAIN"] != "verified" ||
                fields["EXO_CONNECTOR_PUBLIC_IPV4"] != ip || fields["EXO_CONNECTOR_DELIVERY_VERIFIED"] != "no" ||
                fields["CHANGES_APPLIED"] != "no" ||
                fields["EXO_CONNECTOR_BINDING"] is not ("exact_enabled_connector_observed" or "no_matching_connector" or "manual_review_required") ||
                new[] { "EXO_CONNECTOR_EXACT_COUNT", "EXO_CONNECTOR_CONFLICT_COUNT", "EXO_CONNECTOR_NAME_TAKEN" }
                    .Any(k => !int.TryParse(fields[k], out int n) || n is < 0 or > 500))
                throw new InvalidDataException("Incomplete IP connector evidence.");
            MessageBox.Show(owner, description + Environment.NewLine +
                "Exchange: " + fields["EXO_CONNECTOR_BINDING"] + Environment.NewLine +
                "Exact matches: " + fields["EXO_CONNECTOR_EXACT_COUNT"] + "; possible conflicts: " +
                fields["EXO_CONNECTOR_CONFLICT_COUNT"] + "; name matches: " + fields["EXO_CONNECTOR_NAME_TAKEN"] +
                Environment.NewLine + "Configuration only. SMTP egress, exclusivity and delivery are not verified.",
                "Public IP Connector review", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        string sha = CreationSha(await RunTenantConnectorManagerAsync(options, "Preview"), false);
        Guard();
        if (!ConfirmDestructive("LinuxMailRelay365 | Create Public IP Connector",
            description + Environment.NewLine + "Review SHA-256: " + sha + Environment.NewLine +
            "Create a NEW ENABLED OnPremises Connector. Confirm this IPv4 is static, exclusively under your organization's " +
            "control, and is the actual public SMTP egress of the intended sending server. HTTPS observations and TCP 25 tests " +
            "do not establish that identity. This grants relay privileges; do not authorize shared or dynamic addresses. " +
            "Existing connectors, local Postfix and saved route settings are not changed. Actual delivery remains unverified.",
            "CREATE M365 IP CONNECTOR", owner)) return;
        Guard();
        connectorApproved.Checked = false;
        previewedTenantConnectorSha = previewedTenantConnectorContext = null;
        if (CreationSha(await RunTenantConnectorManagerAsync(options, "Apply", sha), true) != sha)
            throw new InvalidDataException("Creation fingerprint changed.");
        Guard();
        WriteLine("Public IPv4 Connector creation verified. SMTP source identity and delivery remain unverified.");
        MessageBox.Show(owner, description + Environment.NewLine +
            "Connector created and observed. Enter the approved IP and MX in the route configuration, if needed, and review actual Postfix delivery separately.",
            "Public IP Connector created", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
}
