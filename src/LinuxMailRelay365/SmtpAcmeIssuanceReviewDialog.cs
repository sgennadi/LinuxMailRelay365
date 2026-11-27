using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class SmtpAcmeIssuanceReviewDialog : Form
{
    internal SmtpAcmeIssuanceReviewDialog(Func<string, string, Task<string>> review, string acceptedDomain,
        string certificateName, string provider)
    {
        Text = "ACME | Local issuance review";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(680, 500);
        MinimumSize = new Size(440, 340);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1,
            Padding = new Padding(12), RowCount = 10, AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 8; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var environment = new ComboBox { Dock = DockStyle.Top, DropDownStyle = ComboBoxStyle.DropDownList };
        environment.Items.AddRange(["staging", "production"]);
        environment.SelectedIndex = 0;
        var email = new TextBox { Dock = DockStyle.Top, MaxLength = 320 };
        var credential = new TextBox { Dock = DockStyle.Top, MaxLength = 1024,
            PlaceholderText = "/etc/linuxmailrelay365/dns-credentials.ini" };
        var result = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
            ScrollBars = ScrollBars.Vertical, WordWrap = true, MinimumSize = new Size(0, 130) };
        var run = new Button { Text = "Check local readiness", AutoSize = true };
        var challenge = new Button { Text = "Test staging DNS-01", AutoSize = true, Enabled = false };
        var production = new Button { Text = "Issue production evaluation", AutoSize = true, Enabled = false };
        var inspectExisting = new Button { Text = "Inspect existing evaluation", AutoSize = true };
        var stageExisting = new Button { Text = "Stage reviewed certificate", AutoSize = true, Enabled = false };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        bool busy = false;
        string? reviewedRequest = null, reviewedSha = null, receipt = null, stageFingerprint = null;
        DateTimeOffset receiptUntil = DateTimeOffset.MinValue;
        void InvalidateReport()
        {
            reviewedRequest = reviewedSha = null;
            stageFingerprint = null;
            challenge.Enabled = production.Enabled = stageExisting.Enabled = false;
            result.Clear();
            result.ForeColor = SystemColors.WindowText;
        }
        void InvalidateInputs()
        {
            receipt = null;
            receiptUntil = DateTimeOffset.MinValue;
            InvalidateReport();
        }
        email.TextChanged += (_, _) => InvalidateInputs();
        credential.TextChanged += (_, _) => InvalidateInputs();
        environment.SelectedIndexChanged += (_, _) => InvalidateReport();
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        run.Click += async (_, _) =>
        {
            if (busy) return;
            InvalidateReport();
            string path = credential.Text.Trim(), contact = email.Text.Trim();
            string target = environment.SelectedItem?.ToString() ?? "";
            if (!Regex.IsMatch(path, @"\A/[A-Za-z0-9_./-]{1,1023}\z") ||
                !Regex.IsMatch(contact, @"\A[A-Za-z0-9][A-Za-z0-9._+%-]{0,63}@[A-Za-z0-9.-]{1,253}\z"))
            {
                result.Text = "Enter a valid contact email and absolute Linux credential-file path (ASCII, no spaces). Do not paste DNS secrets.";
                return;
            }
            busy = true;
            inspectExisting.Enabled = run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = false;
            result.Text = "Checking the existing credential file and installed plugin on Linux...";
            try
            {
                string request = JsonSerializer.Serialize(new
                {
                    accepted_domain = acceptedDomain, certificate_name = certificateName,
                    provider, environment = target, email = contact, credentials_path = path
                });
                using var response = JsonDocument.Parse(await review(request, "review"));
                var root = response.RootElement;
                string ca = target == "staging" ? "https://acme-staging-v02.api.letsencrypt.org/directory" :
                    "https://acme-v02.api.letsencrypt.org/directory";
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("status").GetString() != "local_review_complete" ||
                    root.GetProperty("accepted_domain").GetString() != acceptedDomain ||
                    root.GetProperty("certificate_name").GetString() != certificateName ||
                    root.GetProperty("provider").GetString() != provider ||
                    root.GetProperty("environment").GetString() != target ||
                    root.GetProperty("ca_directory").GetString() != ca ||
                    root.GetProperty("challenge").GetString() != "_acme-challenge." + certificateName ||
                    !Regex.IsMatch(root.GetProperty("review_sha256").GetString() ?? "", @"\A[a-f0-9]{64}\z"))
                    throw new InvalidDataException("Unexpected issuance review.");
                foreach (string flag in new[] { "api_permissions_verified", "dns_ownership_verified", "ca_client_tls_verified",
                         "accepted_domain_verified", "issuance_supported", "dns_modified", "certificate_issued", "postfix_modified" })
                    if (root.GetProperty(flag).GetBoolean()) throw new InvalidDataException("Unexpected issuance claim.");
                string? file = root.GetProperty("credential_file").GetString();
                string? plugin = root.GetProperty("plugin").GetString();
                bool ready = root.GetProperty("local_preflight_passed").GetBoolean();
                if (file is not ("unverified" or "refused" or "local_structure_passed") ||
                    plugin is not ("unverified" or "not_registered" or "registered") ||
                    ready != (file == "local_structure_passed" && plugin == "registered"))
                    throw new InvalidDataException("Inconsistent preflight result.");
                if (ready && target == "staging")
                {
                    reviewedRequest = request;
                    reviewedSha = root.GetProperty("review_sha256").GetString();
                    challenge.Enabled = true;
                }
                else if (ready && target == "production" && receipt is not null && DateTimeOffset.UtcNow < receiptUntil)
                {
                    reviewedRequest = request;
                    reviewedSha = root.GetProperty("review_sha256").GetString();
                    production.Enabled = true;
                }
                result.ForeColor = ready ? Color.SeaGreen : Color.DarkOrange;
                result.Text = string.Join(Environment.NewLine, new[] {
                    ready ? "Local preflight passed (not issuance approval)." : "Local preflight incomplete.",
                    "CA: " + ca, "DNS challenge: _acme-challenge." + certificateName,
                    "Credential file: " + file, "Certbot authenticator: " + plugin, "",
                    "The credential check is structural only; DNS API permissions and ownership are not tested.",
                    "CA client-auth eligibility and Exchange accepted-domain status remain unverified.",
                    "Staging is a test environment, not a production SMTP identity.",
                    target == "production" ? (production.Enabled ? "Staging evidence available. Explicit production evaluation may be requested." : "Run a successful staging test first with these same inputs.") : "A successful staging test with unchanged observed TXT enables a separate production review.",
                    "No certificate issued, no DNS or Postfix changes. No secrets returned to Windows."
                });
            }
            catch (Exception ex)
            {
                result.ForeColor = Color.DarkOrange;
                result.Text = "Local review unavailable: " + ex.GetType().Name + ". Check the path, root access and installed plugin.";
            }
            finally
            {
                busy = false;
                if (!IsDisposed) inspectExisting.Enabled = run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = true;
            }
        };
        challenge.Click += async (_, _) =>
        {
            if (busy || reviewedRequest is null || reviewedSha is null) return;
            if (MessageBox.Show(this,
                "Run a real Let's Encrypt STAGING DNS-01 test for _acme-challenge." + certificateName +
                " using " + provider + "?" + Environment.NewLine + Environment.NewLine +
                "The DNS plugin may create and remove public TXT records. Confirm that you are authorized to modify this zone and no other challenge or renewal is running." +
                Environment.NewLine + "The test agrees to the staging CA terms, uses isolated temporary state and does not activate or issue a production certificate." +
                Environment.NewLine + "If interrupted, temporary DNS records may remain. Review the provider before retrying.",
                "Confirm public DNS changes", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string sha = reviewedSha;
            using var request = JsonDocument.Parse(reviewedRequest);
            string payload = JsonSerializer.Serialize(new {
                request = request.RootElement, confirm = "TEST_PUBLIC_DNS_CHALLENGE", review_sha256 = sha
            });
            InvalidateInputs();
            busy = true;
            inspectExisting.Enabled = run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = false;
            result.Text = "Running approved staging DNS-01 test. Checking the public TXT snapshot before and after...";
            try
            {
                using var response = JsonDocument.Parse(await review(payload, "staging"));
                var root = response.RootElement;
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("review_sha256").GetString() != sha ||
                    root.GetProperty("accepted_domain").GetString() != acceptedDomain ||
                    root.GetProperty("certificate_name").GetString() != certificateName ||
                    root.GetProperty("provider").GetString() != provider ||
                    root.GetProperty("ca_directory").GetString() != "https://acme-staging-v02.api.letsencrypt.org/directory" ||
                    root.GetProperty("challenge").GetString() != "_acme-challenge." + certificateName)
                    throw new InvalidDataException("Unexpected challenge evidence.");
                foreach (string flag in new[] { "txt_cleanup_verified", "production_certificate_modified",
                         "postfix_modified", "exchange_acceptance_verified" })
                    if (root.GetProperty(flag).GetBoolean()) throw new InvalidDataException("Unexpected challenge claim.");
                string? state = root.GetProperty("status").GetString();
                bool attempted = root.GetProperty("attempted").GetBoolean();
                bool passed = root.GetProperty("dns_challenge_verified").GetBoolean();
                if (state is not ("passed" or "failed" or "outcome_unverified" or "refused" or
                    "baseline_unverified" or "existing_txt_requires_review") ||
                    passed != (state == "passed") ||
                    attempted != (state is "passed" or "failed" or "outcome_unverified"))
                    throw new InvalidDataException("Inconsistent challenge status.");
                var snapshot = root.GetProperty("txt_snapshot");
                string? observation = snapshot.GetProperty("status").GetString();
                if (snapshot.GetProperty("txt_cleanup_verified").GetBoolean() ||
                    observation is not ("unchanged" or "changed" or "unverified"))
                    throw new InvalidDataException("Unexpected TXT observation.");
                string counts = "";
                if (observation != "unverified")
                {
                    int added = snapshot.GetProperty("added_count").GetInt32();
                    int missing = snapshot.GetProperty("missing_count").GetInt32();
                    if (added < 0 || missing < 0 || added > 64 || missing > 64 ||
                        snapshot.GetProperty("observed_snapshot_restored").GetBoolean() != (observation == "unchanged") ||
                        (observation == "unchanged") != (added == 0 && missing == 0))
                        throw new InvalidDataException("Inconsistent TXT snapshot.");
                    counts = Environment.NewLine + $"Observed TXT added: {added}; missing: {missing}";
                }
                if (passed && observation == "unchanged" && root.TryGetProperty("staging_receipt", out var proof) &&
                    proof.ValueKind == JsonValueKind.String && Regex.IsMatch(proof.GetString() ?? "", @"\A[a-f0-9]{64}\z"))
                {
                    receipt = proof.GetString();
                    receiptUntil = DateTimeOffset.UtcNow.AddMinutes(14);
                }
                result.ForeColor = passed && observation == "unchanged" ? Color.SeaGreen : Color.DarkOrange;
                result.Text = "Staging DNS-01: " + state + Environment.NewLine +
                    "Attempted: " + (attempted ? "Yes" : "No") + Environment.NewLine +
                    "TXT snapshot via 1.1.1.1: " + observation + counts + Environment.NewLine + Environment.NewLine +
                    "Matching observations do not prove authoritative cleanup; caches and concurrent updates may hide changes." +
                    Environment.NewLine + "Review public DNS and the provider before retrying if cleanup is uncertain." +
                    Environment.NewLine + (receipt is not null ? "Switch to Production and run local readiness within 14 minutes for evaluation." : "No usable staging evidence for production evaluation.") +
                    Environment.NewLine + "No production certificate activation or Postfix configuration change requested.";
            }
            catch (Exception ex)
            {
                result.ForeColor = Color.DarkOrange;
                result.Text = "Challenge outcome unavailable: " + ex.GetType().Name +
                    ". DNS changes may have occurred. Review the provider and TXT records before retrying.";
            }
            finally
            {
                busy = false;
                if (!IsDisposed) inspectExisting.Enabled = run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = true;
            }
        };
        production.Click += async (_, _) =>
        {
            if (busy || reviewedRequest is null || reviewedSha is null || receipt is null) return;
            if (DateTimeOffset.UtcNow >= receiptUntil)
            {
                InvalidateInputs();
                result.Text = "Staging evidence expired. Repeat the staging test.";
                return;
            }
            if (MessageBox.Show(this,
                "Issue a real production Let's Encrypt certificate for " + certificateName + " using " + provider + "?" +
                Environment.NewLine + Environment.NewLine +
                "You authorize public DNS changes, CA registration/terms and production issuance (subject to CA rate limits)." +
                Environment.NewLine + "The certificate and key will remain in a new private evaluation directory on Linux. Existing lineages, Postfix and Exchange will not be changed." +
                Environment.NewLine + "Client TLS suitability is not guaranteed. Exclude any concurrent DNS validation or renewal." +
                Environment.NewLine + "An interrupted or failed attempt retains its evaluation directory; review it before any retry.",
                "Confirm production certificate issuance", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string sha = reviewedSha;
            using var request = JsonDocument.Parse(reviewedRequest);
            string payload = JsonSerializer.Serialize(new {
                request = request.RootElement, confirm = "ISSUE_PRODUCTION_FOR_EVALUATION",
                review_sha256 = sha, staging_receipt = receipt
            });
            InvalidateInputs();
            busy = true;
            inspectExisting.Enabled = run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = false;
            result.Text = "Issuing the explicitly approved production certificate into isolated evaluation state...";
            try
            {
                using var response = JsonDocument.Parse(await review(payload, "production"));
                var root = response.RootElement;
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("review_sha256").GetString() != sha ||
                    root.GetProperty("certificate_name").GetString() != certificateName ||
                    root.GetProperty("accepted_domain").GetString() != acceptedDomain ||
                    root.GetProperty("provider").GetString() != provider ||
                    root.GetProperty("ca_directory").GetString() != "https://acme-v02.api.letsencrypt.org/directory")
                    throw new InvalidDataException("Unexpected production evidence.");
                foreach (string flag in new[] { "postfix_modified", "activation_supported", "exchange_acceptance_verified", "txt_cleanup_verified" })
                    if (root.GetProperty(flag).GetBoolean()) throw new InvalidDataException("Unexpected activation claim.");
                string? state = root.GetProperty("status").GetString();
                bool attempted = root.GetProperty("attempted").GetBoolean();
                bool reserved = root.GetProperty("state_reserved").GetBoolean();
                bool issued = root.GetProperty("certificate_issued").GetBoolean();
                bool material = root.GetProperty("local_chain_name_key_verified").GetBoolean();
                string? path = root.GetProperty("evaluation_path").GetString();
                string? eku = root.GetProperty("client_auth_eku").GetString();
                string? purpose = root.GetProperty("local_sslclient").GetString();
                string? fingerprint = root.GetProperty("certificate_sha256").GetString();
                string expectedPath = "/var/lib/linuxmailrelay365/smtp-acme-evaluation/" + certificateName;
                if (state is not ("evaluation_complete" or "issued_unverified" or "failed" or "outcome_unverified" or
                    "refused" or "baseline_unverified" or "existing_txt_requires_review" or "evaluation_exists") ||
                    issued != (state == "evaluation_complete") || material != issued ||
                    attempted != (state is "evaluation_complete" or "issued_unverified" or "failed" or "outcome_unverified") ||
                    (attempted && !reserved) || (reserved ? path != expectedPath : path is not null) ||
                    (issued ? (eku is not ("explicit" or "not_explicit") || purpose is not ("passed" or "refused_or_unverified") ||
                        !Regex.IsMatch(fingerprint ?? "", @"\A[a-f0-9]{64}\z")) :
                        (eku != "unverified" || purpose != "unverified" || fingerprint is not null)))
                    throw new InvalidDataException("Inconsistent production evaluation.");
                var snapshot = root.GetProperty("txt_snapshot");
                string? observation = snapshot.GetProperty("status").GetString();
                if (snapshot.GetProperty("txt_cleanup_verified").GetBoolean() ||
                    observation is not ("unchanged" or "changed" or "unverified"))
                    throw new InvalidDataException("Unexpected TXT observation.");
                result.ForeColor = issued && purpose == "passed" && observation == "unchanged" ? Color.SeaGreen : Color.DarkOrange;
                result.Text = "Production evaluation: " + state + Environment.NewLine +
                    "Directory: " + (path ?? (state == "evaluation_exists" ? expectedPath + " (already exists; review manually)" : "not reserved")) +
                    Environment.NewLine + "Certificate chain / name / key: " + (material ? "verified locally" : "unverified") +
                    Environment.NewLine + "SHA-256: " + (fingerprint ?? "unverified") +
                    Environment.NewLine + "Client Authentication EKU: " + eku +
                    Environment.NewLine + "OpenSSL sslclient purpose: " + purpose +
                    Environment.NewLine + "TXT snapshot (public resolver only): " + observation +
                    Environment.NewLine + Environment.NewLine +
                    "No certificate staged or activated. Existing Postfix TLS checks remain mandatory. Exchange acceptance is unverified." +
                    Environment.NewLine + "Review retained evaluation state and DNS before any retry.";
            }
            catch (Exception ex)
            {
                result.ForeColor = Color.DarkOrange;
                result.Text = "Production outcome unavailable: " + ex.GetType().Name +
                    ". DNS changes or certificate issuance may have occurred. Review the evaluation directory and DNS before retrying.";
            }
            finally
            {
                busy = false;
                if (!IsDisposed) inspectExisting.Enabled = run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = true;
            }
        };
        inspectExisting.Click += async (_, _) =>
        {
            if (busy) return;
            InvalidateReport();
            busy = true;
            inspectExisting.Enabled = run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = false;
            result.Text = "Checking retained evaluation material on Linux. No DNS or CA operation...";
            try
            {
                string payload = JsonSerializer.Serialize(new { accepted_domain = acceptedDomain, certificate_name = certificateName });
                using var response = JsonDocument.Parse(await review(payload, "inspect"));
                var root = response.RootElement;
                string expectedPath = "/var/lib/linuxmailrelay365/smtp-acme-evaluation/" + certificateName;
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("accepted_domain").GetString() != acceptedDomain ||
                    root.GetProperty("certificate_name").GetString() != certificateName ||
                    root.GetProperty("evaluation_path").GetString() != expectedPath)
                    throw new InvalidDataException("Unexpected evaluation identity.");
                foreach (string flag in new[] { "postfix_modified", "activation_supported",
                    "exchange_acceptance_verified", "issuance_attempted", "dns_modified" })
                    if (root.GetProperty(flag).GetBoolean()) throw new InvalidDataException("Unexpected mutation claim.");
                string? state = root.GetProperty("status").GetString();
                bool material = root.GetProperty("local_chain_name_key_verified").GetBoolean();
                string? purpose = root.GetProperty("local_sslclient").GetString();
                string? eku = root.GetProperty("client_auth_eku").GetString();
                string? fingerprint = root.GetProperty("certificate_sha256").GetString();
                if (state is not ("material_verified" or "not_found" or "unverified") ||
                    material != (state == "material_verified") ||
                    (material ? (purpose is not ("passed" or "refused_or_unverified") ||
                        eku is not ("explicit" or "not_explicit") ||
                        !Regex.IsMatch(fingerprint ?? "", @"\A[a-f0-9]{64}\z")) :
                        (purpose != "unverified" || eku != "unverified" || fingerprint is not null)))
                    throw new InvalidDataException("Inconsistent evaluation result.");
                if (material && purpose == "passed")
                {
                    stageFingerprint = fingerprint;
                    stageExisting.Enabled = true;
                }
                result.ForeColor = material && purpose == "passed" ? Color.SeaGreen : Color.DarkOrange;
                result.Text = "Retained production evaluation: " + state + Environment.NewLine +
                    "Expected directory: " + expectedPath + Environment.NewLine +
                    "Certificate chain / name / key: " + (material ? "verified locally" : "unverified") + Environment.NewLine +
                    "SHA-256: " + (fingerprint ?? "unverified") + Environment.NewLine +
                    "Client Authentication EKU: " + eku + Environment.NewLine +
                    "OpenSSL sslclient purpose: " + purpose + Environment.NewLine + Environment.NewLine +
                    (state == "unverified" ? "Material is incomplete, unsafe or unverifiable. Preserve state for manual review." + Environment.NewLine : "") +
                    "This inspection does not establish original CA issuance outcome, DNS cleanup or Exchange acceptance." + Environment.NewLine +
                    "No renewal, issuance, staging, activation or deletion was requested." + Environment.NewLine +
                    (stageExisting.Enabled ? "Eligible for separate reviewed staging." : "Staging is unavailable until all local checks pass.");
            }
            catch (Exception ex)
            {
                result.ForeColor = Color.DarkOrange;
                result.Text = "Existing evaluation inspection unavailable: " + ex.GetType().Name +
                    ". Another reviewed ACME operation may be running. Preserve the directory for review.";
            }
            finally
            {
                busy = false;
                if (!IsDisposed) inspectExisting.Enabled = run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = true;
            }
        };
        stageExisting.Click += async (_, _) =>
        {
            if (busy || stageFingerprint is null) return;
            string fingerprint = stageFingerprint;
            if (MessageBox.Show(this,
                "Stage the reviewed certificate for " + certificateName + "?" + Environment.NewLine +
                "SHA-256: " + fingerprint + Environment.NewLine + Environment.NewLine +
                "This copies validated material into a protected Postfix candidate directory. It does not change active settings, reload Postfix, or modify Exchange. Exclude concurrent certificate maintenance.",
                "Confirm candidate staging", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            InvalidateReport();
            busy = true;
            inspectExisting.Enabled = run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = false;
            result.Text = "Revalidating reviewed certificate and staging a protected candidate...";
            try
            {
                string payload = JsonSerializer.Serialize(new {
                    request = new { accepted_domain = acceptedDomain, certificate_name = certificateName },
                    confirm = "STAGE_REVIEWED_EVALUATION", certificate_sha256 = fingerprint
                });
                using var response = JsonDocument.Parse(await review(payload, "stage"));
                var root = response.RootElement;
                if (root.GetProperty("version").GetInt32() != 1 ||
                    root.GetProperty("accepted_domain").GetString() != acceptedDomain ||
                    root.GetProperty("certificate_name").GetString() != certificateName ||
                    root.GetProperty("certificate_sha256").GetString() != fingerprint)
                    throw new InvalidDataException("Unexpected staging identity.");
                foreach (string flag in new[] { "postfix_config_modified", "postfix_reloaded",
                    "issuance_attempted", "dns_modified", "exchange_acceptance_verified" })
                    if (root.GetProperty(flag).GetBoolean()) throw new InvalidDataException("Unexpected mutation claim.");
                string? state = root.GetProperty("status").GetString();
                string? candidate = root.GetProperty("candidate").GetString();
                bool attempted = root.GetProperty("staging_attempted").GetBoolean();
                if (state is not ("staged" or "refused" or "staging_unverified") ||
                    attempted != (state is "staged" or "staging_unverified") ||
                    (state == "staged" ? !Regex.IsMatch(candidate ?? "", @"\Acandidate-[a-f0-9]{64}\z") : candidate is not null))
                    throw new InvalidDataException("Inconsistent staging result.");
                result.ForeColor = state == "staged" ? Color.SeaGreen : Color.DarkOrange;
                result.Text = "Candidate staging: " + state + Environment.NewLine +
                    "Candidate: " + (candidate ?? "unverified") + Environment.NewLine +
                    "Certificate SHA-256: " + fingerprint + Environment.NewLine +
                    (state == "staged" ? "Use Review staged TLS deployment for a separate activation review." :
                        "Reinspect the retained material and candidate inventory before any retry.") + Environment.NewLine +
                    "No active Postfix configuration, reload, issuance, DNS or Exchange change was requested.";
            }
            catch (Exception ex)
            {
                result.ForeColor = Color.DarkOrange;
                result.Text = "Staging outcome unavailable: " + ex.GetType().Name +
                    ". Inspect candidate inventory before retrying.";
            }
            finally
            {
                busy = false;
                if (!IsDisposed) inspectExisting.Enabled = run.Enabled = close.Enabled = environment.Enabled = email.Enabled = credential.Enabled = true;
            }
        };
        layout.Controls.Add(new Label { Text = "DNS identity: " + certificateName + " | " + provider, AutoSize = true }, 0, 0);
        layout.Controls.Add(new Label { Text = "CA environment (production evaluation is separately confirmed)", AutoSize = true }, 0, 1);
        layout.Controls.Add(environment, 0, 2);
        layout.Controls.Add(new Label { Text = "ACME account contact email", AutoSize = true }, 0, 3);
        layout.Controls.Add(email, 0, 4);
        layout.Controls.Add(new Label { Text = "Existing private credential file on Linux (path only)", AutoSize = true }, 0, 5);
        layout.Controls.Add(credential, 0, 6);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        actions.Controls.AddRange([run, challenge, production, inspectExisting, stageExisting]);
        layout.Controls.Add(actions, 0, 7);
        layout.Controls.Add(result, 0, 8);
        layout.Controls.Add(close, 0, 9);
        Controls.Add(layout);
        CancelButton = close;
    }
}
