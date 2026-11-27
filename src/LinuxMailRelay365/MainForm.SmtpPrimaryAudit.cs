using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task OpenPrimaryPostfixAuditAsync(Form owner, string context, string selectedMx)
    {
        string domain = acceptedDomain.Text.Trim().ToLowerInvariant();
        string mx = selectedMx.Trim().ToLowerInvariant();
        var endpoint = Endpoint();
        void Guard()
        {
            if (owner.IsDisposed || TryCurrentIdentity() != context || mailTransport.SelectedIndex != 1 ||
                !string.Equals(acceptedDomain.Text.Trim(), domain, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Linux host or accepted domain changed.");
        }
        Guard();
        using var dialog = new Form
        {
            Text = "Primary Postfix | Configuration and queue audit",
            StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(Screen.FromControl(owner).WorkingArea.Size, DeviceDpi, 820, 650),
            MinimumSize = PreferredDialogSize(Screen.FromControl(owner).WorkingArea.Size, DeviceDpi, 460, 350)
        };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(12) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var status = new Label { AutoSize = true, Text = "Read-only primary Postfix configuration and queue sample." };
        var report = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
            ScrollBars = ScrollBars.Both, WordWrap = false };
        var refresh = new Button { Text = "Refresh audit", AutoSize = true };
        var copy = new Button { Text = "Copy summary", AutoSize = true, Enabled = false };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true };
        actions.Controls.AddRange([refresh, copy, close]);
        bool running = false;
        dialog.FormClosing += (_, e) => { if (running) e.Cancel = true; };
        async Task RefreshAsync()
        {
            if (running) return;
            running = true;
            refresh.Enabled = copy.Enabled = close.Enabled = false;
            report.Clear();
            status.Text = "Reading primary Postfix configuration and queue...";
            status.ForeColor = SystemColors.ControlText;
            try
            {
                Guard();
                string request = JsonSerializer.Serialize(new { accepted_domain = domain, mx });
                string script = EmbeddedAssets.BuildPostfixM365DeliveryProbe("audit", request, null);
                var result = endpoint.Username == "root"
                    ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script, TimeSpan.FromSeconds(240))
                    : await SshRemote.RunRootScriptAsync(endpoint, script, TimeSpan.FromSeconds(240));
                result.EnsureSuccess();
                Guard();
                var (summary, review) = FormatPrimaryPostfixAudit(result.StdOut, domain, mx);
                report.Text = summary;
                status.Text = review ? "Review required — existing configuration unchanged." :
                    "Basic route observed — delivery and approval remain unverified.";
                status.ForeColor = review ? Color.DarkOrange : Color.SeaGreen;
                copy.Enabled = true;
            }
            catch (Exception ex)
            {
                status.ForeColor = Color.DarkOrange;
                status.Text = "Audit refused or incomplete: " + ex.GetType().Name;
                report.Text = "No settings or queue operations requested. Check the selected Linux host, privileges, Postfix version and service.";
            }
            finally { running = false; refresh.Enabled = close.Enabled = true; }
        }
        refresh.Click += async (_, _) => await RefreshAsync();
        copy.Click += (_, _) => { if (report.Text.Length > 0 && !running) Clipboard.SetText(report.Text); };
        layout.Controls.Add(status, 0, 0);
        layout.Controls.Add(report, 0, 1);
        layout.Controls.Add(actions, 0, 2);
        dialog.Controls.Add(layout);
        dialog.CancelButton = close;
        dialog.Shown += async (_, _) => await RefreshAsync();
        dialog.ShowDialog(owner);
    }

    private static (string Summary, bool Review) FormatPrimaryPostfixAudit(string json, string domain, string mx)
    {
        if (json.Length > 65536 || json.Contains('\0')) throw new InvalidDataException("Invalid audit size.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 10 });
        var root = doc.RootElement;
        static void Exact(JsonElement obj, params string[] names)
        {
            var keys = obj.EnumerateObject().Select(p => p.Name).ToArray();
            if (keys.Length != names.Length || keys.Distinct(StringComparer.Ordinal).Count() != keys.Length ||
                keys.Except(names, StringComparer.Ordinal).Any())
                throw new InvalidDataException("Unexpected audit fields.");
        }
        Exact(root, "version", "status", "accepted_domain", "mx", "settings", "declared",
            "service_overrides", "single_instance", "service", "queue", "blockers", "config_sha256",
            "postfix_modified", "queue_modified", "mail_sent", "apply_supported", "exchange_acceptance_verified");
        if (root.GetProperty("version").GetInt32() != 1 || root.GetProperty("accepted_domain").GetString() != domain ||
            root.GetProperty("mx").GetString() != mx)
            throw new InvalidDataException("Audit context mismatch.");
        foreach (string flag in new[] { "postfix_modified", "queue_modified", "mail_sent", "apply_supported", "exchange_acceptance_verified" })
            if (root.GetProperty(flag).ValueKind != JsonValueKind.False) throw new InvalidDataException("Unexpected mutation claim.");
        string[] keys = ["myhostname", "mydomain", "myorigin", "mydestination", "relay_domains",
            "inet_interfaces", "inet_protocols", "relayhost", "smtp_bind_address", "smtp_bind_address6",
            "smtp_tls_security_level", "smtp_sasl_auth_enable", "default_transport", "relay_transport",
            "local_transport", "virtual_transport"];
        var settings = root.GetProperty("settings");
        Exact(settings, keys);
        var values = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (string key in keys)
        {
            string? value = settings.GetProperty(key).GetString();
            // Backend emits only literal configuration tokens, not arbitrary map
            // expressions, paths, credentials or native command output.
            if (value is not null && (value.Length > 10240 || !Regex.IsMatch(value, @"\A[a-zA-Z0-9.,:\[\] _%-]*\z")))
                throw new InvalidDataException("Unexpected configuration token.");
            values.Add(key, value);
        }
        string[] allowedFlags = ["transport_maps", "sender_dependent_relayhost_maps",
            "sender_dependent_default_transport_maps", "smtp_fallback_relay", "content_filter", "virtual_alias_maps",
            "virtual_alias_domains", "virtual_mailbox_domains", "canonical_maps", "sender_canonical_maps",
            "recipient_canonical_maps", "smtp_generic_maps", "header_checks", "mime_header_checks",
            "nested_header_checks", "body_checks", "non_smtpd_milters", "smtp_tls_policy_maps",
            "multi_instance_directories", "smtpd_milters", "masquerade_domains", "relocated_maps",
            "smtp_tls_chain_files", "smtp_tls_cert_file", "smtp_tls_key_file", "smtp_tls_eccert_file", "smtp_tls_eckey_file"];
        string[] knownBlockers = ["not_default_single_instance", "service_status_unverified", "service_specific_overrides",
            "unsupported_setting_syntax", "routing_or_rewrite_policy", "custom_transport",
            "smtp_auth_configured_or_unknown", "mandatory_tls_not_established", "public_ipv4_connector_protocol_review",
            "explicit_source_bind_review", "accepted_domain_local_delivery_review", "queue_unverified",
            "queue_not_empty", "mx_not_selected", "relayhost_differs"];
        static string[] Codes(JsonElement array, string[] allowed)
        {
            var rows = array.EnumerateArray().Select(x => x.GetString() ?? "").ToArray();
            if (rows.Length > allowed.Length || rows.Distinct(StringComparer.Ordinal).Count() != rows.Length ||
                rows.Any(x => !allowed.Contains(x, StringComparer.Ordinal)))
                throw new InvalidDataException("Unknown audit code.");
            return rows;
        }
        var declared = Codes(root.GetProperty("declared"), allowedFlags);
        var blockers = Codes(root.GetProperty("blockers"), knownBlockers);
        bool single = root.GetProperty("single_instance").GetBoolean();
        bool overrides = root.GetProperty("service_overrides").GetBoolean();
        string service = root.GetProperty("service").GetString() ?? "";
        if (service is not ("running" or "unverified")) throw new InvalidDataException();
        string state = root.GetProperty("status").GetString() ?? "";
        bool review = blockers.Length > 0;
        if (state != (review ? "review_required" : "basic_route_observed") ||
            (!single) != blockers.Contains("not_default_single_instance") ||
            overrides != blockers.Contains("service_specific_overrides") ||
            (service != "running") != blockers.Contains("service_status_unverified") ||
            values.Values.Any(x => x is null) != blockers.Contains("unsupported_setting_syntax"))
            throw new InvalidDataException("Inconsistent audit state.");
        var queue = root.GetProperty("queue");
        Exact(queue, "status", "total", "counts");
        var counts = queue.GetProperty("counts");
        string qstate = queue.GetProperty("status").GetString() ?? "";
        var lines = new List<string> { "READ-ONLY PRIMARY POSTFIX AUDIT", "Accepted domain: " + domain,
            "Requested MX: " + (mx.Length == 0 ? "(not selected)" : mx),
            "Service: " + service, "Single default instance: " + single,
            "Service overrides: " + (overrides ? "present — review" : "not observed"), "", "EFFECTIVE SETTINGS" };
        foreach (string key in keys)
            lines.Add(key + " = " + (values[key] is null ? "(unsupported / withheld)" : values[key]!.Length == 0 ? "(empty)" : values[key]));
        lines.Add("");
        lines.Add("QUEUE (moving sample, no message addresses or IDs)");
        if (qstate == "sampled")
        {
            string[] names = ["active", "deferred", "incoming", "hold", "maildrop", "other"];
            Exact(counts, names);
            int total = queue.GetProperty("total").GetInt32();
            long sum = 0;
            foreach (string name in names)
            {
                int count = counts.GetProperty(name).GetInt32();
                if (count is < 0 or > 100000) throw new InvalidDataException();
                sum += count;
                lines.Add(name + ": " + count);
            }
            if (total < 0 || total > 100000 || total != sum || !single || service != "running" ||
                blockers.Contains("queue_unverified") || (total > 0) != blockers.Contains("queue_not_empty"))
                throw new InvalidDataException("Inconsistent queue totals.");
            lines.Add("Total: " + total);
        }
        else
        {
            if (qstate != "unavailable" || queue.GetProperty("total").ValueKind != JsonValueKind.Null ||
                counts.EnumerateObject().Any() || !blockers.Contains("queue_unverified"))
                throw new InvalidDataException("Invalid queue evidence.");
            lines.Add("Unavailable — do not assume the queue is empty.");
        }
        lines.Add("");
        lines.Add("DECLARED POLICIES / CERTIFICATES (presence only)");
        lines.AddRange(declared.Length == 0 ? new[] { "(none observed in sampled fields)" } : declared);
        lines.Add("");
        lines.Add("REVIEW ITEMS");
        lines.AddRange(blockers.Length == 0 ? new[] { "(no basic audit blockers)" } : blockers.Select(x => x.Replace('_', ' ')));
        var hashes = root.GetProperty("config_sha256");
        Exact(hashes, "main.cf", "master.cf");
        lines.Add("");
        foreach (string name in new[] { "main.cf", "master.cf" })
        {
            string sha = hashes.GetProperty(name).GetString() ?? "";
            if (!Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z")) throw new InvalidDataException();
            lines.Add(name + " SHA-256: " + sha);
        }
        lines.Add("");
        lines.Add("No Apply operation. Existing relayhost, local destinations, listeners, queue and TLS configuration are preserved.");
        lines.Add("If the MX differs, review every affected sender/recipient route and local delivery before considering a global change.");
        lines.Add("A basic route observation does not verify Postfix process state, SMTP egress, tenant connector, or actual delivery.");
        return (string.Join(Environment.NewLine, lines), review);
    }
}
