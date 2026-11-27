using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class PostfixM365DeliveryDialog : Form
{
    internal PostfixM365DeliveryDialog(Func<string, string, string?, Task<string>> remote,
        string acceptedDomain, string sender, string mx, Func<string, string, Task<string>> exchangeTrace,
        Func<string, Task<string>> diagnoseTls)
    {
        Text = "Primary Postfix | Microsoft 365 delivery probe";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(800, 620);
        MinimumSize = new Size(480, 380);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1,
            RowCount = 14, Padding = new Padding(12), AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 12; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var domain = new TextBox { Text = acceptedDomain, Dock = DockStyle.Top };
        var from = new TextBox { Text = sender, Dock = DockStyle.Top };
        var host = new TextBox { Text = mx, Dock = DockStyle.Top };
        var internalRecipient = new TextBox { Dock = DockStyle.Top };
        var externalRecipient = new TextBox { Dock = DockStyle.Top };
        var run = new TextBox { Text = Guid.NewGuid().ToString("N"), Dock = DockStyle.Top };
        var status = new Label { Text = "Review the active route before submitting two test messages.", AutoSize = true };
        var report = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true,
            ScrollBars = ScrollBars.Both, WordWrap = false, MinimumSize = new Size(0, 130) };
        var preview = new Button { Text = "Review route", AutoSize = true };
        var submit = new Button { Text = "Send two reviewed tests", AutoSize = true, Enabled = false };
        var trace = new Button { Text = "Refresh trace (no send)", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        var cloudTrace = new Button { Text = "Exchange Message Trace", AutoSize = true };
        var tls = new Button { Text = "Diagnose STARTTLS (no mail)", AutoSize = true };
        buttons.Controls.AddRange([preview, submit, trace, cloudTrace, tls, close]);
        TextBox[] inputs = [domain, from, host, internalRecipient, externalRecipient, run];
        string? approvedSha = null, approvedRequest = null;
        bool busy = false;
        string Request() => JsonSerializer.Serialize(new
        {
            accepted_domain = domain.Text.Trim().ToLowerInvariant(),
            sender = from.Text.Trim(),
            mx = host.Text.Trim().ToLowerInvariant(),
            internal_ = internalRecipient.Text.Trim(),
            external = externalRecipient.Text.Trim(),
            run_id = run.Text.Trim()
        }).Replace("\"internal_\":", "\"internal\":", StringComparison.Ordinal);
        void Invalidate()
        {
            approvedSha = approvedRequest = null;
            submit.Enabled = false;
        }
        foreach (var input in inputs) input.TextChanged += (_, _) => Invalidate();
        void SetBusy(bool value)
        {
            busy = value;
            foreach (var input in inputs) input.Enabled = !value;
            preview.Enabled = trace.Enabled = cloudTrace.Enabled = tls.Enabled = close.Enabled = !value;
            submit.Enabled = !value && approvedSha is not null;
        }
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };

        preview.Click += async (_, _) =>
        {
            if (busy) return;
            Invalidate();
            string request = Request();
            SetBusy(true);
            status.Text = "Reviewing the actual primary Postfix route...";
            try
            {
                using var json = JsonDocument.Parse(await remote("preview", request, null));
                var root = json.RootElement;
                string sha = root.GetProperty("plan_sha256").GetString() ?? "";
                if (root.GetProperty("status").GetString() != "review_ready" ||
                    root.GetProperty("mail_sent").GetBoolean() ||
                    root.GetProperty("run_id").GetString() != run.Text.Trim() ||
                    !Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z"))
                    throw new InvalidDataException();
                approvedSha = sha;
                approvedRequest = request;
                report.Text = JsonSerializer.Serialize(root, new JsonSerializerOptions { WriteIndented = true });
                status.Text = "Local route reviewed. Confirm recipient roles and permission to send.";
            }
            catch (Exception ex) { status.Text = "Route review refused: " + ex.GetType().Name + ". Custom routes require manual review."; }
            finally { SetBusy(false); }
        };
        submit.Click += async (_, _) =>
        {
            if (busy || approvedSha is null || approvedRequest is null || approvedRequest != Request()) return;
            if (MessageBox.Show(this, "Submit exactly two real test messages via primary Postfix as a local root sender?" +
                Environment.NewLine + "From: " + from.Text + Environment.NewLine +
                "Internal: " + internalRecipient.Text + Environment.NewLine +
                "External: " + externalRecipient.Text + Environment.NewLine +
                "MX: " + host.Text + Environment.NewLine +
                "Ensure you control or have permission to use both recipients. Domain comparison alone does not prove recipient tenant membership." +
                Environment.NewLine + "Postfix may queue or retry normal delivery. This app will not submit the same run ID again.",
                "Confirm two live delivery tests", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string sha = approvedSha, request = approvedRequest;
            Invalidate();
            SetBusy(true);
            status.Text = "Submitting approved messages...";
            try
            {
                using var json = JsonDocument.Parse(await remote("submit", request, sha));
                var root = json.RootElement;
                if (root.GetProperty("status").GetString() != "submission_recorded" ||
                    root.GetProperty("run_id").GetString() != run.Text.Trim() ||
                    root.GetProperty("plan_sha256").GetString() != sha ||
                    root.GetProperty("inbox_verified").GetBoolean()) throw new InvalidDataException();
                report.Text = JsonSerializer.Serialize(root, new JsonSerializerOptions { WriteIndented = true });
                status.Text = "Submission attempts recorded. Refresh trace; local acceptance is not delivery.";
            }
            catch { status.Text = "Outcome uncertain. Keep this run ID and refresh trace. Do not resubmit."; }
            finally { SetBusy(false); }
        };
        trace.Click += async (_, _) =>
        {
            if (busy) return;
            Invalidate();
            string request = Request();
            SetBusy(true);
            status.Text = "Reading matching ledger, journal and queue...";
            try
            {
                using var json = JsonDocument.Parse(await remote("trace", request, null));
                var root = json.RootElement;
                if (root.GetProperty("status").GetString() != "trace_observed" ||
                    root.GetProperty("run_id").GetString() != run.Text.Trim() ||
                    root.GetProperty("inbox_verified").GetBoolean()) throw new InvalidDataException();
                report.Text = JsonSerializer.Serialize(root, new JsonSerializerOptions { WriteIndented = true });
                status.Text = "Trace observed. No new message sent; inbox arrival and TLS handshake remain unverified.";
            }
            catch { status.Text = "Trace unavailable. Check the original request/run ID and Linux logs; do not resend automatically."; }
            finally { SetBusy(false); }
        };
        cloudTrace.Click += async (_, _) =>
        {
            if (busy) return;
            Invalidate();
            string request = Request();
            SetBusy(true);
            status.Text = "Validating local run before querying Exchange Online...";
            try
            {
                string local = await remote("trace", request, null);
                using var proof = JsonDocument.Parse(local);
                report.Text = "Local Postfix trace" + Environment.NewLine +
                    JsonSerializer.Serialize(proof.RootElement, new JsonSerializerOptions { WriteIndented = true });
                status.Text = "Sign in to the selected Exchange tenant if prompted...";
                string cloud = await exchangeTrace(request, local);
                report.AppendText(Environment.NewLine + Environment.NewLine + "Exchange Online trace" +
                    Environment.NewLine + cloud);
                status.Text = "Read-only trace complete. Delivered is service-reported delivery, not verified inbox arrival. Not observed may mean trace latency.";
            }
            catch (Exception ex)
            {
                status.Text = "Exchange trace unavailable: " + ex.GetType().Name +
                    ". Check permissions, tenant, original run and trace latency. No resend.";
            }
            finally { SetBusy(false); }
        };
        tls.Click += async (_, _) =>
        {
            if (busy) return;
            string mxName = host.Text.Trim().ToLowerInvariant();
            Invalidate();
            SetBusy(true);
            status.Text = "Testing DNS, TCP/25, EHLO and verified STARTTLS from Linux...";
            try
            {
                using var json = JsonDocument.Parse(await diagnoseTls(mxName));
                var root = json.RootElement;
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("host").GetString() != mxName ||
                    root.GetProperty("port").GetInt32() != 25 ||
                    root.GetProperty("mail_sent").GetBoolean() ||
                    root.GetProperty("auth_attempted").GetBoolean() ||
                    root.GetProperty("client_certificate_loaded").GetBoolean() ||
                    root.GetProperty("postfix_process_tested").GetBoolean() ||
                    root.GetProperty("exchange_connector_verified").GetBoolean())
                    throw new InvalidDataException("Unexpected TLS diagnostic evidence.");
                var lines = new List<string> {
                    "MX: " + mxName + ":25",
                    "DNS: " + root.GetProperty("dns").GetString(),
                    "Diagnostic status: " + root.GetProperty("status").GetString(),
                    "Resolved addresses: " + (root.TryGetProperty("resolved_count", out var count) ? count.GetInt32().ToString() : "unknown"),
                    "", "Sampled endpoints (one per IP family at most):"
                };
                int samples = 0, verified = 0;
                foreach (var row in root.GetProperty("observations").EnumerateArray())
                {
                    samples++;
                    string? state = row.GetProperty("status").GetString();
                    if (state == "tls_verified") verified++;
                    lines.Add("");
                    lines.Add(row.GetProperty("family").GetString() + " | " + row.GetProperty("address").GetString() +
                        " | " + state + " | stage: " + row.GetProperty("stage").GetString());
                    foreach (var field in row.EnumerateObject())
                        if (field.Name is not ("family" or "address" or "status" or "stage"))
                            lines.Add("    " + field.Name + ": " + field.Value.ToString());
                }
                lines.Add("");
                lines.Add("System trust and hostname verification are required. No insecure fallback.");
                lines.Add("This is a separate Linux process, without the Postfix client certificate.");
                lines.Add("Actual Postfix TLS policy, connector recognition and mail delivery remain unverified.");
                report.Text = string.Join(Environment.NewLine, lines);
                status.Text = samples == 0 ? "No endpoint result; review DNS and local trust." :
                    $"{verified}/{samples} sampled endpoints passed verified STARTTLS and EHLO. No mail sent.";
            }
            catch (Exception ex)
            {
                status.Text = "STARTTLS diagnostic unavailable: " + ex.GetType().Name;
            }
            finally { SetBusy(false); }
        };
        string[] labels = ["Accepted sender domain", "Envelope sender", "Microsoft 365 MX",
            "Internal recipient (same domain)", "External recipient (different domain)", "Run ID (retain for later trace)"];
        for (int i = 0; i < inputs.Length; i++)
        {
            // Keep each field and label in a compact row so high-DPI layout
            // does not hide the result area.
            var row = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 2, AutoSize = true };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
            row.Controls.Add(new Label { Text = labels[i], AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
            row.Controls.Add(inputs[i], 1, 0);
            layout.Controls.Add(row, 0, i);
        }
        layout.RowCount = 9;
        layout.RowStyles.Clear();
        for (int i = 0; i < 7; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(status, 0, 6);
        layout.Controls.Add(report, 0, 7);
        layout.Controls.Add(buttons, 0, 8);
        Controls.Add(layout);
        CancelButton = close;
    }
}
