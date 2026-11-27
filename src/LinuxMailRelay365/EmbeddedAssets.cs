using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal static class EmbeddedAssets
{
    private static string Text(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
            ?? throw new FileNotFoundException("Embedded installer resource is missing: " + name);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        // Embedded .sh assets may carry CRLF after a Windows checkout.
        // Restore canonical LF before shipping them over SSH or base64.
        string text = reader.ReadToEnd().Replace("\r\n", "\n", StringComparison.Ordinal);
        if (text.IndexOf('\r') >= 0 || text.IndexOf('\0') >= 0)
            throw new InvalidDataException("Embedded script has invalid line endings.");
        return text;
    }

    internal static string BuildSmtpCertificateCheck(string cert, string chain, string key, string domain, string ca)
    {
        static string Quote(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > 4096 || value.Any(char.IsControl))
                throw new ArgumentException("Invalid certificate check argument.");
            return "'" + value.Replace("'", "'\"'\"'") + "'";
        }
        return "set -eu\n/usr/bin/python3 - --cert=" + Quote(cert) +
            " --chain=" + Quote(chain) + " --key=" + Quote(key) +
            " --domain=" + Quote(domain) + " --ca-file=" + Quote(ca) +
            " <<'LMR365_CERT_CHECK'\n" + Text("LinuxMailRelay365.linux.smtp-cert-check.py") +
            "\nLMR365_CERT_CHECK\n";
    }
    // Command arguments contain only shipped public helper source and the DNS name.
    // The private key package must stay on SSH stdin, never in argv or command logs.
    internal static string BuildSmtpCertificateImportCommand(string domain)
    {
        if (Uri.CheckHostName(domain) != UriHostNameType.Dns ||
            !Regex.IsMatch(domain, @"\A[A-Za-z0-9.-]{1,253}\z"))
            throw new ArgumentException("Invalid certificate DNS name.");
        string EncodeAsset(string name) => Convert.ToBase64String(Encoding.UTF8.GetBytes(Text(name)));
        string launcher = EncodeAsset("LinuxMailRelay365.linux.smtp-cert-import-launcher.py");
        string command = "/usr/bin/python3 -I -B -c 'import base64;exec(base64.b64decode(\"" +
            launcher + "\"))' --domain=" + domain + " " +
            string.Join(" ", new[] {
                "LinuxMailRelay365.linux.smtp-cert-check.py",
                "LinuxMailRelay365.linux.smtp-cert-stage.py",
                "LinuxMailRelay365.linux.smtp-cert-receive.py"
            }.Select(EncodeAsset));
        if (command.Length > 65536)
            throw new InvalidDataException("Certificate helper bundle exceeds command size limit.");
        return command;
    }

    internal static string SmtpAcmeInspectCommand =>
        "/usr/bin/python3 -I -B -c 'import base64;exec(base64.b64decode(\"" +
        Convert.ToBase64String(Encoding.UTF8.GetBytes(Text("LinuxMailRelay365.linux.smtp-acme-plan.py"))) +
        "\"))' --inspect";

    internal static string BuildSmtpAcmeProviderDiscovery(string acceptedDomain, string name)
    {
        foreach (string value in new[] { acceptedDomain, name })
            if (Uri.CheckHostName(value) != UriHostNameType.Dns ||
                !Regex.IsMatch(value, @"\A[a-z0-9.-]{1,253}\z"))
                throw new ArgumentException("Invalid ACME discovery DNS name.");
        var script = new StringBuilder("set -eu\numask 077\nwork=$(mktemp -d /run/lmr365-acme-discovery.XXXXXXXX)\ntrap 'rm -rf -- \"$work\"' EXIT\n");
        foreach (string file in new[] { "discover-smtp-acme-wizard.py", "discover-smtp-public-dns.py",
                     "inspect-smtp-acme-delegation.py", "probe-smtp-acme-plugins.py",
                     "recommend-smtp-acme-provider.py", "smtp-tls-postfix.py", "plan-smtp-certificate-acme.py" })
        {
            string resource = file == "plan-smtp-certificate-acme.py" ? "smtp-acme-plan.py" : file;
            script.Append("base64 -d > \"$work/").Append(file).Append("\" <<'LMR365_ACME_DISCOVERY_ASSET'\n")
                .Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(Text("LinuxMailRelay365.linux." + resource))))
                .Append("\nLMR365_ACME_DISCOVERY_ASSET\n");
        }
        return script.Append("/usr/bin/python3 -I -B \"$work/discover-smtp-acme-wizard.py\" --domain=")
            .Append(acceptedDomain).Append(" --name=").Append(name).Append('\n').ToString();
    }

    internal static string BuildSmtpAcmeIssuanceReview(string request)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(request);
        if (bytes.Length > 8192) throw new ArgumentException("ACME review request too large.");
        var script = new StringBuilder("set -eu\numask 077\nwork=$(mktemp -d /run/lmr365-acme-review.XXXXXXXX)\ntrap 'rm -rf -- \"$work\"' EXIT\n");
        foreach (string file in new[] { "review-smtp-acme-issuance.py", "plan-smtp-certificate-acme.py",
                     "check-smtp-acme-credentials.py", "probe-smtp-acme-plugins.py" })
        {
            string resource = file == "plan-smtp-certificate-acme.py" ? "smtp-acme-plan.py" : file;
            script.Append("base64 -d > \"$work/").Append(file).Append("\" <<'LMR365_ISSUANCE_ASSET'\n")
                .Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(Text("LinuxMailRelay365.linux." + resource))))
                .Append("\nLMR365_ISSUANCE_ASSET\n");
        }
        return script.Append("base64 -d <<'LMR365_ISSUANCE_REQUEST' | /usr/bin/python3 -I -B \"$work/review-smtp-acme-issuance.py\"\n")
            .Append(Convert.ToBase64String(bytes)).Append("\nLMR365_ISSUANCE_REQUEST\n").ToString();
    }

    internal static string BuildSmtpAcmeStagingChallenge(string request, bool production = false, bool inspectExisting = false, bool stageExisting = false)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(request);
        if (bytes.Length > 12288) throw new ArgumentException("ACME challenge request too large.");
        var script = new StringBuilder("set -eu\numask 077\nwork=$(mktemp -d /run/lmr365-acme-challenge.XXXXXXXX)\ntrap 'rm -rf -- \"$work\"' EXIT\n");
        foreach (string file in new[] { "reviewed-smtp-acme-challenge.py", "review-smtp-acme-issuance.py",
                     "reviewed-smtp-acme-production.py", "smtp-acme-staging-receipt.py", "check-smtp-relay-certificate.py",
                     "stage-smtp-relay-certificate.py",
                     "plan-smtp-certificate-acme.py", "check-smtp-acme-credentials.py", "probe-smtp-acme-plugins.py",
                     "smtp-tls-postfix.py", "plan-smtp-acme-challenge-test.py", "check-smtp-acme-txt-cleanup.py",
                     "issue-smtp-acme-azure.py", "issue-smtp-acme-cloudflare.py", "issue-smtp-acme-route53.py",
                     "issue-smtp-acme-google.py", "issue-smtp-acme-rfc2136.py" })
        {
            string resource = file switch
            {
                "plan-smtp-certificate-acme.py" => "smtp-acme-plan.py",
                "check-smtp-relay-certificate.py" => "smtp-cert-check.py",
                "stage-smtp-relay-certificate.py" => "smtp-cert-stage.py",
                _ => file
            };
            script.Append("base64 -d > \"$work/").Append(file).Append("\" <<'LMR365_CHALLENGE_ASSET'\n")
                .Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(Text("LinuxMailRelay365.linux." + resource))))
                .Append("\nLMR365_CHALLENGE_ASSET\n");
        }
        string helper = production || inspectExisting || stageExisting ? "reviewed-smtp-acme-production.py" : "reviewed-smtp-acme-challenge.py";
        return script.Append("base64 -d <<'LMR365_CHALLENGE_REQUEST' | /usr/bin/python3 -I -B \"$work/").Append(helper)
            .Append(stageExisting ? "\" --stage\n" : inspectExisting ? "\" --inspect\n" : "\"\n")
            .Append(Convert.ToBase64String(bytes)).Append("\nLMR365_CHALLENGE_REQUEST\n").ToString();
    }

    internal static string BuildSmtpAcmeDryRun(string? expectedSha)
    {
        if (expectedSha is not null && !Regex.IsMatch(expectedSha, @"\A[a-f0-9]{64}\z"))
            throw new ArgumentException("Invalid renewal plan SHA.");
        var script = new StringBuilder("set -eu\numask 077\nwork=$(mktemp -d /run/lmr365-renew-test.XXXXXXXX)\ntrap 'rm -rf -- \"$work\"' EXIT\n");
        foreach (string file in new[] { "review-smtp-acme-dry-run.py", "smtp-tls-renewal-profile.py",
                     "smtp-tls-postfix.py", "check-smtp-acme-credentials.py" })
        {
            script.Append("base64 -d > \"$work/").Append(file).Append("\" <<'LMR365_DRY_RUN_ASSET'\n")
                .Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(Text("LinuxMailRelay365.linux." + file))))
                .Append("\nLMR365_DRY_RUN_ASSET\n");
        }
        script.Append("/usr/bin/python3 -I -B \"$work/review-smtp-acme-dry-run.py\" ")
            .Append(expectedSha is null ? "preview" : "run --expected-sha=" + expectedSha).Append('\n');
        return script.ToString();
    }

    internal static string BuildSmtpTlsAvcDiagnosis()
    {
        var script = new StringBuilder("set -eu\numask 077\nwork=$(mktemp -d /run/lmr365-tls-avc.XXXXXXXX)\ntrap 'rm -rf -- \"$work\"' EXIT\n");
        foreach (string file in new[] { "check-smtp-tls-avc.py", "smtp-tls-postfix.py" })
        {
            script.Append("base64 -d > \"$work/").Append(file).Append("\" <<'LMR365_AVC_ASSET'\n")
                .Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(Text("LinuxMailRelay365.linux." + file))))
                .Append("\nLMR365_AVC_ASSET\n");
        }
        return script.Append("/usr/bin/python3 -I -B \"$work/check-smtp-tls-avc.py\" --recent\n").ToString();
    }

    internal static string BuildSmtpTlsRotation(string action, string? candidate, string? domain, string? expectedSha)
    {
        if (action is not ("inventory" or "preview" or "activate" or "recovery-preview" or "recover" or "binding-preview" or "candidate-binding-preview" or "selinux-preview" or "selinux-restore"))
            throw new ArgumentException("Invalid TLS action.");
        if (action is "inventory" or "recovery-preview")
        {
            if (candidate is not null || domain is not null || expectedSha is not null)
                throw new ArgumentException("Unexpected read-only arguments.");
        }
        else if (action is "selinux-preview" or "selinux-restore")
        {
            if (candidate is null || !Regex.IsMatch(candidate, @"\Acandidate-[a-f0-9]{64}\z") ||
                domain is not null ||
                (action == "selinux-restore" ? expectedSha is null || !Regex.IsMatch(expectedSha, @"\A[a-f0-9]{64}\z") : expectedSha is not null))
                throw new ArgumentException("Invalid reviewed SELinux action.");
        }
        else if (action == "binding-preview")
        {
            if (candidate is not null || expectedSha is not null || domain is null ||
                Uri.CheckHostName(domain) != UriHostNameType.Dns ||
                !Regex.IsMatch(domain, @"\A[a-z0-9.-]{1,253}\z"))
                throw new ArgumentException("Invalid certificate binding review.");
        }
        else if (action == "recover")
        {
            if (candidate is not null || domain is not null || expectedSha is null ||
                !Regex.IsMatch(expectedSha, @"\A[a-f0-9]{64}\z"))
                throw new ArgumentException("Invalid reviewed recovery arguments.");
        }
        else if (candidate is null || !Regex.IsMatch(candidate, @"\Acandidate-[a-f0-9]{64}\z") ||
                 domain is null || Uri.CheckHostName(domain) != UriHostNameType.Dns ||
                 !Regex.IsMatch(domain, @"\A[a-z0-9.-]{1,253}\z") ||
                 (action == "activate" ? expectedSha is null || !Regex.IsMatch(expectedSha, @"\A[a-f0-9]{64}\z") : expectedSha is not null))
            throw new ArgumentException("Invalid reviewed TLS action.");
        var script = new StringBuilder("set -eu\numask 077\nwork=$(mktemp -d /run/lmr365-tls-review.XXXXXXXX)\ntrap 'rm -rf -- \"$work\"' EXIT\n");
        foreach (string file in new[] { "review-smtp-tls-rotation.py", "smtp-tls-generation.py",
                     "smtp-tls-transaction.py", "smtp-tls-activate.py", "smtp-tls-validate-generation.py",
                     "plan-smtp-tls-initial.py", "smtp-tls-postfix.py", "check-smtp-relay-certificate.py",
                     "smtp-tls-initial-deploy.py", "smtp-tls-initial-backup.py",
                     "smtp-tls-initial-candidate.py", "smtp-tls-initial-journal.py", "review-smtp-tls-selinux.py" })
        {
            string resource = file == "check-smtp-relay-certificate.py" ? "LinuxMailRelay365.linux.smtp-cert-check.py" :
                "LinuxMailRelay365.linux." + file;
            script.Append("base64 -d > \"$work/").Append(file).Append("\" <<'LMR365_TLS_REVIEW_ASSET'\n")
                .Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(Text(resource))))
                .Append("\nLMR365_TLS_REVIEW_ASSET\n");
        }
        script.Append("/usr/bin/python3 -I -B \"$work/review-smtp-tls-rotation.py\" ").Append(action);
        if (candidate is not null) script.Append(" --candidate=").Append(candidate);
        if (domain is not null) script.Append(" --domain=").Append(domain);
        if (expectedSha is not null) script.Append(" --expected-sha=").Append(expectedSha);
        return script.Append('\n').ToString();
    }

    internal static string BuildSmtpTlsSystemd(string action, string? expectedSha)
    {
        if (action is not ("inspect" or "install" or "enable-recovery" or "enable-timer" or "start-timer"
                           or "stop-timer" or "disable-timer" or "renew-now") ||
            (expectedSha is not null && (!Regex.IsMatch(expectedSha, @"\A[a-f0-9]{64}\z") || action == "inspect")))
            throw new ArgumentException("Invalid systemd review action.");
        var script = new StringBuilder("set -eu\numask 077\nwork=$(mktemp -d /run/lmr365-tls-systemd.XXXXXXXX)\ntrap 'rm -rf -- \"$work\"' EXIT\nmkdir -m 700 \"$work/systemd\"\n");
        (string File, string Resource)[] files =
        [
            ("review-smtp-tls-systemd.py", "LinuxMailRelay365.linux.review-smtp-tls-systemd.py"),
            ("review-smtp-tls-rotation.py", "LinuxMailRelay365.linux.review-smtp-tls-rotation.py"),
            ("review-smtp-acme-dry-run.py", "LinuxMailRelay365.linux.review-smtp-acme-dry-run.py"),
            ("manage-smtp-tls-systemd.py", "LinuxMailRelay365.linux.manage-smtp-tls-systemd.py"),
            ("plan-smtp-tls-systemd.py", "LinuxMailRelay365.linux.plan-smtp-tls-systemd.py"),
            ("install-smtp-tls-systemd.py", "LinuxMailRelay365.linux.install-smtp-tls-systemd.py"),
            ("test-smtp-acme-renewal.py", "LinuxMailRelay365.linux.test-smtp-acme-renewal.py"),
            ("manage-smtp-tls-process-renewal.py", "LinuxMailRelay365.linux.manage-smtp-tls-process-renewal.py"),
            ("manage-smtp-tls-renewal.py", "LinuxMailRelay365.linux.manage-smtp-tls-renewal.py"),
            ("manage-smtp-tls-initial.py", "LinuxMailRelay365.linux.manage-smtp-tls-initial.py"),
            ("smtp-tls-renewal-profile.py", "LinuxMailRelay365.linux.smtp-tls-renewal-profile.py"),
            ("check-smtp-acme-credentials.py", "LinuxMailRelay365.linux.check-smtp-acme-credentials.py"),
            ("smtp-tls-postfix.py", "LinuxMailRelay365.linux.smtp-tls-postfix.py"),
            ("smtp-tls-generation.py", "LinuxMailRelay365.linux.smtp-tls-generation.py"),
            ("smtp-tls-transaction.py", "LinuxMailRelay365.linux.smtp-tls-transaction.py"),
            ("smtp-tls-activate.py", "LinuxMailRelay365.linux.smtp-tls-activate.py"),
            ("smtp-tls-validate-generation.py", "LinuxMailRelay365.linux.smtp-tls-validate-generation.py"),
            ("smtp-tls-selinux-prepare.py", "LinuxMailRelay365.linux.smtp-tls-selinux-prepare.py"),
            ("smtp-tls-process-renewal.py", "LinuxMailRelay365.linux.smtp-tls-process-renewal.py"),
            ("stage-smtp-relay-certificate.py", "LinuxMailRelay365.linux.smtp-cert-stage.py"),
            ("check-smtp-relay-certificate.py", "LinuxMailRelay365.linux.smtp-cert-check.py"),
            ("smtp-tls-initial-backup.py", "LinuxMailRelay365.linux.smtp-tls-initial-backup.py"),
            ("smtp-tls-initial-candidate.py", "LinuxMailRelay365.linux.smtp-tls-initial-candidate.py"),
            ("smtp-tls-initial-journal.py", "LinuxMailRelay365.linux.smtp-tls-initial-journal.py"),
            ("smtp-tls-initial-deploy.py", "LinuxMailRelay365.linux.smtp-tls-initial-deploy.py"),
            ("plan-smtp-tls-initial.py", "LinuxMailRelay365.linux.plan-smtp-tls-initial.py"),
            ("check-smtp-tls-health.py", "LinuxMailRelay365.linux.check-smtp-tls-health.py"),
            ("smtp-tls-health-alerts.py", "LinuxMailRelay365.linux.smtp-tls-health-alerts.py"),
            ("systemd/linuxmailrelay365-smtp-acme-renew.service", "LinuxMailRelay365.linux.systemd/linuxmailrelay365-smtp-acme-renew.service"),
            ("systemd/linuxmailrelay365-smtp-acme-renew.timer", "LinuxMailRelay365.linux.systemd/linuxmailrelay365-smtp-acme-renew.timer"),
            ("systemd/linuxmailrelay365-smtp-tls-initial-recovery.service", "LinuxMailRelay365.linux.systemd/linuxmailrelay365-smtp-tls-initial-recovery.service"),
            ("systemd/linuxmailrelay365-smtp-tls-prestart.service", "LinuxMailRelay365.linux.systemd/linuxmailrelay365-smtp-tls-prestart.service"),
            ("systemd/linuxmailrelay365-smtp-tls-recovery.service", "LinuxMailRelay365.linux.systemd/linuxmailrelay365-smtp-tls-recovery.service"),
            ("systemd/linuxmailrelay365-smtp-tls-health.service", "LinuxMailRelay365.linux.systemd/linuxmailrelay365-smtp-tls-health.service"),
            ("systemd/linuxmailrelay365-smtp-tls-health.timer", "LinuxMailRelay365.linux.systemd/linuxmailrelay365-smtp-tls-health.timer")
        ];
        foreach (var file in files)
        {
            script.Append("base64 -d > \"$work/").Append(file.File).Append("\" <<'LMR365_SYSTEMD_ASSET'\n")
                .Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(Text(file.Resource))))
                .Append("\nLMR365_SYSTEMD_ASSET\n");
        }
        script.Append("/usr/bin/python3 -I -B \"$work/review-smtp-tls-systemd.py\" ").Append(action);
        if (expectedSha is not null) script.Append(" --expected-sha=").Append(expectedSha);
        return script.Append('\n').ToString();
    }

    internal static string BuildM365ManagedStartTlsDiagnosis(string mx, string? candidate = null, string? domain = null)
    {
        if (!Regex.IsMatch(mx, @"\A[a-z0-9.-]{1,253}\z") ||
            Uri.CheckHostName(mx) != UriHostNameType.Dns ||
            !mx.EndsWith(".mail.protection.outlook.com", StringComparison.Ordinal))
            throw new ArgumentException("Invalid Microsoft 365 MX name.");
        bool staged = candidate is not null || domain is not null;
        if (staged && (!Regex.IsMatch(candidate ?? "", @"\Acandidate-[a-f0-9]{64}\z") ||
            !Regex.IsMatch(domain ?? "", @"\A[a-z0-9.-]{1,253}\z") ||
            Uri.CheckHostName(domain ?? "") != UriHostNameType.Dns))
            throw new ArgumentException("Invalid staged certificate identity.");
        var script = new StringBuilder("set -eu\numask 077\nwork=$(mktemp -d /run/lmr365-managed-tls.XXXXXXXX)\ntrap 'rm -rf -- \"$work\"' EXIT\n");
        (string File, string Resource)[] files =
        [
            ("inspect-m365-managed-starttls.py", "LinuxMailRelay365.linux.m365-managed-starttls.py"),
            ("inspect-m365-starttls.py", "LinuxMailRelay365.linux.m365-starttls-diagnosis.py"),
            ("review-smtp-tls-rotation.py", "LinuxMailRelay365.linux.review-smtp-tls-rotation.py"),
            ("smtp-tls-postfix.py", "LinuxMailRelay365.linux.smtp-tls-postfix.py"),
            ("smtp-tls-transaction.py", "LinuxMailRelay365.linux.smtp-tls-transaction.py"),
            ("smtp-tls-generation.py", "LinuxMailRelay365.linux.smtp-tls-generation.py"),
            ("smtp-tls-validate-generation.py", "LinuxMailRelay365.linux.smtp-tls-validate-generation.py"),
            ("check-smtp-relay-certificate.py", "LinuxMailRelay365.linux.smtp-cert-check.py")
        ];
        foreach (var file in files)
        {
            script.Append("base64 -d > \"$work/").Append(file.File).Append("\" <<'LMR365_MANAGED_TLS_ASSET'\n")
                .Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(Text(file.Resource))))
                .Append("\nLMR365_MANAGED_TLS_ASSET\n");
        }
        return script.Append("/usr/bin/python3 -I -B \"$work/inspect-m365-managed-starttls.py\" <<'LMR365_MANAGED_TLS_REQUEST'\n")
            .Append(staged ? System.Text.Json.JsonSerializer.Serialize(new { mx, candidate, domain, confirm = "TEST_STAGED_CLIENT_CERTIFICATE" }) :
                System.Text.Json.JsonSerializer.Serialize(new { mx }))
            .Append("\nLMR365_MANAGED_TLS_REQUEST\n").ToString();
    }

    internal static string BuildM365StartTlsDiagnosis(string mx)
    {
        if (!Regex.IsMatch(mx, @"\A[a-z0-9.-]{1,253}\z") ||
            Uri.CheckHostName(mx) != UriHostNameType.Dns ||
            !mx.EndsWith(".mail.protection.outlook.com", StringComparison.Ordinal))
            throw new ArgumentException("Invalid Microsoft 365 MX name.");
        string payload = System.Text.Json.JsonSerializer.Serialize(new { mx });
        return "/usr/bin/python3 -I -B -c 'import base64;exec(base64.b64decode(\"" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(Text("LinuxMailRelay365.linux.m365-starttls-diagnosis.py"))) +
            "\"))' <<'LMR365_STARTTLS_REQUEST'\n" + payload + "\nLMR365_STARTTLS_REQUEST\n";
    }

    internal static string BuildM365PublicIpv4Observation()
    {
        return "/usr/bin/python3 -I -B -c 'import base64;exec(base64.b64decode(\"" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(Text("LinuxMailRelay365.linux.m365-starttls-diagnosis.py"))) +
            "\"))' <<'LMR365_PUBLIC_IPV4_REQUEST'\n{\"observe_public_ipv4\":true}\nLMR365_PUBLIC_IPV4_REQUEST\n";
    }

    internal static string BuildM365MxDiscovery(string acceptedDomain)
    {
        if (!Regex.IsMatch(acceptedDomain, @"\A[a-z0-9.-]{1,253}\z") ||
            Uri.CheckHostName(acceptedDomain) != UriHostNameType.Dns)
            throw new ArgumentException("Invalid accepted domain.");
        string payload = System.Text.Json.JsonSerializer.Serialize(new { accepted_domain = acceptedDomain });
        return "/usr/bin/python3 -I -B -c 'import base64;exec(base64.b64decode(\"" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(Text("LinuxMailRelay365.linux.m365-starttls-diagnosis.py"))) +
            "\"))' <<'LMR365_MX_REQUEST'\n" + payload + "\nLMR365_MX_REQUEST\n";
    }

    internal static string BuildPostfixM365DeliveryProbe(string action, string request, string? sha)
    {
        if (action is not ("preview" or "submit" or "trace") || request.Length > 4096 ||
            (action == "submit" ? sha is null || !Regex.IsMatch(sha, @"\A[a-f0-9]{64}\z") : sha is not null))
            throw new ArgumentException("Invalid reviewed delivery probe.");
        var script = new StringBuilder("set -eu\numask 077\nwork=$(mktemp -d /run/lmr365-postfix-probe.XXXXXXXX)\ntrap 'rm -rf -- \"$work\"' EXIT\n");
        foreach (string file in new[] { "review-postfix-m365-delivery.py", "smtp-tls-postfix.py" })
        {
            script.Append("base64 -d > \"$work/").Append(file).Append("\" <<'LMR365_POSTFIX_PROBE_ASSET'\n")
                .Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(Text("LinuxMailRelay365.linux." + file))))
                .Append("\nLMR365_POSTFIX_PROBE_ASSET\n");
        }
        script.Append("base64 -d <<'LMR365_POSTFIX_PROBE_REQUEST' | /usr/bin/python3 -I -B \"$work/review-postfix-m365-delivery.py\" ").Append(action);
        if (sha is not null) script.Append(" --expected-sha=").Append(sha);
        return script.Append('\n').Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(request)))
            .Append("\nLMR365_POSTFIX_PROBE_REQUEST\n").ToString();
    }

    internal static string SmtpRenewalInventory =>
        "set -eu\n/usr/bin/python3 -I -B - <<'LMR365_RENEWAL_INVENTORY'\n" +
        Text("LinuxMailRelay365.linux.smtp-renewal-inventory.py") +
        "\nLMR365_RENEWAL_INVENTORY\n";

    internal static string SmtpCertificateDiscovery => "set -eu\n/usr/bin/python3 - <<'LMR365_CERT_DISCOVERY'\n" + Text("LinuxMailRelay365.linux.smtp-cert-discovery.py") + "\nLMR365_CERT_DISCOVERY\n";
    internal static string Installer => Text("LinuxMailRelay365.linux.install.sh");
    internal static string Transport => Text("LinuxMailRelay365.linux.transport.py");
    internal static string OAuthSenderMapAudit => Text("LinuxMailRelay365.linux.oauth-sender-map-audit.py");
    internal static string MultiMailboxIdentityInspector => Text("LinuxMailRelay365.linux.multi-mailbox-identity-inventory.py");
    internal static string MultiMailboxSourceEditor => Text("LinuxMailRelay365.linux.multi-mailbox-source-editor.py");
    internal static string MultiMailboxIdentityPreparer => Text("LinuxMailRelay365.linux.multi-mailbox-identity-prepare.py");
    internal static string MultiMailboxNewApp => Text("LinuxMailRelay365.linux.multi-mailbox-new-app.py");
    internal static string MultiMailboxSmtpAuth => Text("LinuxMailRelay365.linux.multi-mailbox-smtp-auth.py");
    internal static string MultiMailboxGraphPairReviewer => Text("LinuxMailRelay365.linux.multi-mailbox-graph-pair.py");
    internal static string OAuthIngressAudit => Text("LinuxMailRelay365.linux.oauth-ingress-audit.py");
    internal static string OAuthIdentitySigningAudit => Text("LinuxMailRelay365.linux.oauth-identity-signing-audit.py");
    internal static string HardwareSigner => Text("LinuxMailRelay365.linux.hardware-signer.py");
    internal static string TpmDependencies => Text("LinuxMailRelay365.linux.tpm-dependencies.py");
    internal static string HardwareOAuthDiagnostics => Text("LinuxMailRelay365.linux.hardware-oauth-diagnostics.py");
    internal static string HardwareOAuthCutover => Text("LinuxMailRelay365.linux.hardware-oauth-cutover.py");
    internal static string DeliveryAcceptance => Text("LinuxMailRelay365.linux.delivery-acceptance.py");
    internal static string TpmOauthProvision => Text("LinuxMailRelay365.linux.tpm-oauth-provision.py");
    internal static string MultiMailboxTpmPrepare => Text("LinuxMailRelay365.linux.multi-mailbox-tpm-prepare.py");
    internal static string EntraPublicCertificateExporter => Text("LinuxMailRelay365.linux.entra-public-cert-export.py");
    internal static string InstalledPostfixRouteInspector => Text("LinuxMailRelay365.linux.inspect-postfix-route.py");
    internal static string PrimaryOAuthRotator => Text("LinuxMailRelay365.linux.primary-oauth-rotation.py");
    internal static string EntraCertificateManager => Text("LinuxMailRelay365.windows.entra-oauth-cert-manager.ps1");
    internal static string Recovery => Text("LinuxMailRelay365.linux.recovery.sh");
    internal static string SidecarConfigRecovery => Text("LinuxMailRelay365.linux.sidecar-config-recovery.py");
    internal static string SidecarInstaller => Text("LinuxMailRelay365.linux.sidecar.sh");
    internal static string CleanPostfixPreparation => Text("LinuxMailRelay365.linux.prepare-clean-postfix.py");
    internal static string PostfixBasicsManager => Text("LinuxMailRelay365.linux.manage-postfix-basics.py");
    internal static string DirectSendSidecarInstaller => Text("LinuxMailRelay365.linux.direct-send-sidecar.sh");
    internal static string ConnectorSidecarInstaller => Text("LinuxMailRelay365.linux.connector-sidecar.sh");
    internal static string ForeignMtaGuard => Text("LinuxMailRelay365.linux.foreign-mta-guard.py");
    internal static string ForeignMtaBackup => Text("LinuxMailRelay365.linux.foreign-mta-backup.py");
    internal static string ForeignMtaRestore => Text("LinuxMailRelay365.linux.foreign-mta-restore.py");
    internal static string NetworkFirewall => Text("LinuxMailRelay365.linux.network-firewall.sh");
    internal static string ExistingSmtpAuditScript => Text("LinuxMailRelay365.linux.existing-smtp-audit.py");
    internal static string MailHostInspector => Text("LinuxMailRelay365.linux.inspect-mail-host.py");
    internal static string MailQueueInspector => Text("LinuxMailRelay365.linux.inspect-mail-queue.py");
    internal static string MailSubmissionInspector => Text("LinuxMailRelay365.linux.inspect-mail-submission.sh");
    internal static string GoogleSmtpProbe => Text("LinuxMailRelay365.linux.check-google-smtp.py");
    internal static string CustomSmtpProbe => Text("LinuxMailRelay365.linux.check-custom-smtp.py");
    internal static string GooglePostfixRoute => Text("LinuxMailRelay365.linux.manage-google-relay.py");
    internal static string CustomPostfixRoute => Text("LinuxMailRelay365.linux.manage-custom-relay.py");
    internal static string PrimaryMailboxRoutePreview => Text("LinuxMailRelay365.linux.primary-mailbox-route-preview.py");
    internal static string ConditionalStageManager => Text("LinuxMailRelay365.linux.stage-conditional-postfix-maps.py");
    internal static string ConditionalTransactionManager => Text("LinuxMailRelay365.linux.conditional-postfix-transaction.py");
    internal static string ConditionalActivationPreflight => Text("LinuxMailRelay365.linux.inspect-conditional-postfix-activation.py");
    internal static string ConditionalOfflineManager => Text("LinuxMailRelay365.linux.manage-conditional-postfix-offline.py");
    internal static string ConditionalTransportCompiler => Text("LinuxMailRelay365.linux.compile-conditional-transports.py");
    internal static string ConditionalTransportSnapshot => Text("LinuxMailRelay365.linux.conditional-transport-recovery.py");
    internal static string ConditionalTransportTransaction => Text("LinuxMailRelay365.linux.conditional-transport-transaction.py");
    internal static string ConditionalTransportHost => Text("LinuxMailRelay365.linux.manage-conditional-transports-offline.py");
    internal static string ConditionalTransportRecovery => Text("LinuxMailRelay365.linux.inspect-conditional-transport-recovery.py");
    internal static string ConditionalTransportRotation => Text("LinuxMailRelay365.linux.conditional-transport-rotation.py");
    internal static string ConditionalTransportRotationHost => Text("LinuxMailRelay365.linux.manage-conditional-transport-rotation.py");
    internal static string ConditionalTransportEdit => Text("LinuxMailRelay365.linux.conditional-transport-edit.py");
    internal static string ConditionalTransportEditTransaction => Text("LinuxMailRelay365.linux.conditional-transport-edit-transaction.py");
    internal static string ConditionalTransportEditHost => Text("LinuxMailRelay365.linux.manage-conditional-transport-edit.py");
    internal static string ConditionalTransportSelinuxLabels => Text("LinuxMailRelay365.linux.inspect-conditional-transport-selinux.py");
    internal static string ConditionalTransportSelinuxReadiness => Text("LinuxMailRelay365.linux.inspect-conditional-transport-selinux-readiness.py");
    internal static string ConditionalTransportSelinuxAvc => Text("LinuxMailRelay365.linux.inspect-conditional-transport-selinux-avc.py");
    internal static string ConditionalRecoveryManager => Text("LinuxMailRelay365.linux.inspect-conditional-postfix-recovery.py");
    internal static string MailBindInspector => Text("LinuxMailRelay365.linux.audit-mail-bindings.py");
    internal static string PlatformCompat => Text("LinuxMailRelay365.linux.platform-compat.py");
    internal static string MtaCoexistenceDoctor => Text("LinuxMailRelay365.linux.mta-coexistence-doctor.py");
    internal static string RhelSelinuxDoctor => Text("LinuxMailRelay365.linux.rhel-selinux-doctor.py");
    internal static string RhelEnforcingLiveSmoke => Text("LinuxMailRelay365.linux.rhel-enforcing-live-smoke.py");
    internal static string RhelSelinuxPortManager => Text("LinuxMailRelay365.linux.rhel-selinux-port-manager.py");
    internal static string PublicSmtpManager => Text("LinuxMailRelay365.linux.public-smtp-manager.py");
    internal static string SmtpAccountManager => Text("LinuxMailRelay365.linux.smtp-account-manager.py");
    internal static string SmtpCredentialGenerator => Text("LinuxMailRelay365.linux.smtp-credential-generator.py");
    internal static string RelayHealth => Text("LinuxMailRelay365.linux.relay-health.py");
    internal static string HealthAlerts => Text("LinuxMailRelay365.linux.health-alerts.py");
    internal static string M365DnsAudit => Text("LinuxMailRelay365.linux.m365-dns-audit.py");
    internal static string HealthMonitorInstaller => Text("LinuxMailRelay365.linux.health-monitor-installer.sh");
    internal static string RebootContinuity => Text("LinuxMailRelay365.linux.reboot-continuity.py");
    internal static string OutboundModePreflight => Text("LinuxMailRelay365.linux.outbound-mode-preflight.py");
    internal static string EopRouteManager => Text("LinuxMailRelay365.linux.eop-route-manager.py");
    internal static string FromOwnerMilter => Text("LinuxMailRelay365.linux.from-owner-milter.py");
    internal static string FromOwnerGuardInstaller => Text("LinuxMailRelay365.linux.from-owner-guard-installer.sh");
    internal static string SidecarTlsRotator => Text("LinuxMailRelay365.linux.sidecar-tls-rotator.sh");
    internal static string AuthTlsInstaller => Text("LinuxMailRelay365.linux.auth-tls-installer.sh");
    internal static string AuthTlsRestore => Text("LinuxMailRelay365.linux.auth-tls-restore.sh");
    internal static string InstalledSidecarAudit => Text("LinuxMailRelay365.linux.installed-sidecar-audit.py");
    internal static string AuthArchiveAudit => Text("LinuxMailRelay365.linux.auth-archive-audit.py");
    internal static string TlsIdentityProbe => Text("LinuxMailRelay365.linux.tls-identity-probe.py");
    internal static string Provisioner => Text("LinuxMailRelay365.windows.provision.ps1");
    internal static string SecurityProbe => Text("LinuxMailRelay365.linux.security-probe.sh");
    internal static string CloudSecurityProbe => Text("LinuxMailRelay365.windows.cloud-security-probe.ps1");
    internal static string ExchangeMessageTrace => Text("LinuxMailRelay365.windows.exchange-message-trace.ps1");
    internal static string TenantConnectorManager => Text("LinuxMailRelay365.windows.tenant-connector-manager.ps1");
    internal static string CloudObjectsInspector => Text("LinuxMailRelay365.windows.cloud-objects-inspector.ps1");
    internal static string MultiMailboxSmtpScopeManager => Text("LinuxMailRelay365.windows.multi-mailbox-smtp-scope.ps1");
    internal static string CloudConnectorManager => Text("LinuxMailRelay365.windows.cloud-connector-manager.ps1");

    private static string Encode(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    internal static string BuildPrimaryMailboxRoutePreviewBundle(string request)
    {
        if (Encoding.UTF8.GetByteCount(request)>2048) throw new ArgumentException("Primary route request too large.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-primary-mailbox.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/export-hardware-oauth-cert.py\" <<'LMR365_PRIMARY_ROUTE_SUPPORT'\n" +
               Encode(EntraPublicCertificateExporter) + "\nLMR365_PRIMARY_ROUTE_SUPPORT\n" +
               "base64 -d > \"$work/preview-primary-mailbox-route.py\" <<'LMR365_PRIMARY_ROUTE'\n" +
               Encode(PrimaryMailboxRoutePreview) + "\nLMR365_PRIMARY_ROUTE\n" +
               "printf '%s' '" + Encode(request) + "' | base64 -d | /usr/bin/python3 -I -B \"$work/preview-primary-mailbox-route.py\"\n";
    }

    internal static string BuildInstalledPostfixRouteBundle(string request)
    {
        if (request.Length > 4096) throw new ArgumentException("Route request too large.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-route-inspect.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/export-hardware-oauth-cert.py\" <<'LMR365_ROUTE_SUPPORT'\n" +
               Encode(EntraPublicCertificateExporter) + "\nLMR365_ROUTE_SUPPORT\n" +
               "base64 -d > \"$work/inspect-postfix-route.py\" <<'LMR365_ROUTE_INSPECTOR'\n" +
               Encode(InstalledPostfixRouteInspector) + "\nLMR365_ROUTE_INSPECTOR\n" +
               "printf '%s' '" + Encode(request) + "' | base64 -d | python3 \"$work/inspect-postfix-route.py\"\n";
    }

    internal static string BuildActiveOAuthCertificateBundle(string target)
    {
        if (target is not ("primary" or "sidecar"))
            throw new ArgumentException("Select the exact installed OAuth identity.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-active-oauth.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/export-hardware-oauth-cert.py\" <<'LMR365_ACTIVE_OAUTH'\n" +
               Encode(EntraPublicCertificateExporter) + "\nLMR365_ACTIVE_OAUTH\n" +
               "python3 \"$work/export-hardware-oauth-cert.py\" --target " + target + " --active-inventory\n";
    }

    internal static string BuildEntraPublicCertificateBundle(string target,
        string? objectId = null, string? activeSha = null,
        string? stageSha = null, string? activeCertificateSha = null,
        string? candidateCertificateSha = null)
    {
        if (target is not ("sidecar" or "primary" or "primary-rotation"))
            throw new ArgumentException("Unsupported Entra OAuth certificate source.");
        string args = "--target " + target + " --inventory";
        if (objectId is not null)
        {
            bool validGuid = Guid.TryParseExact(objectId, "D", out var id) &&
                             id != Guid.Empty && objectId == id.ToString("D");
            bool validSha = new[] { activeSha, stageSha, activeCertificateSha, candidateCertificateSha }
                .All(x => x is not null && Regex.IsMatch(x, @"\A[a-f0-9]{64}\z",
                                                       RegexOptions.CultureInvariant));
            if (!validGuid || !validSha)
                throw new ArgumentException("A matching Entra application object and all reviewed identity hashes are required.");
            args = "--target " + target + " --proof --object-id " + objectId +
                   " --expected-active-sha " + activeSha +
                   " --expected-stage-sha " + stageSha +
                   " --expected-active-cert-sha " + activeCertificateSha +
                   " --expected-candidate-cert-sha " + candidateCertificateSha;
        }
        else if (activeSha is not null || stageSha is not null ||
                 activeCertificateSha is not null || candidateCertificateSha is not null)
            throw new ArgumentException("Partial Entra proof parameters are prohibited.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-entra-export.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/export-hardware-oauth-cert.py\" <<'LMR365_ENTRA_PUBLIC_EXPORT'\n" +
               Encode(EntraPublicCertificateExporter) + "\nLMR365_ENTRA_PUBLIC_EXPORT\n" +
               "python3 \"$work/export-hardware-oauth-cert.py\" " + args + "\n";
    }

    internal static string BuildPrimaryOAuthRotationBundle(string action,
        int days = 365, string? approvedSha = null)
    {
        if (days is < 1 or > 365)
            throw new ArgumentOutOfRangeException(nameof(days));
        string arguments = action switch
        {
            "plan" when approvedSha is null =>
                "--plan --days " + days,
            "stage" when approvedSha is not null &&
                Regex.IsMatch(approvedSha, @"\A[a-f0-9]{64}\z",
                    RegexOptions.CultureInvariant) =>
                "--stage --days " + days +
                " --expect-sha256 " + approvedSha +
                " --confirm STAGE_PRIMARY_OAUTH_CERT",
            "status" when approvedSha is null && days == 365 =>
                "--status",
            "preflight" when days == 365 && approvedSha is not null &&
                Regex.IsMatch(approvedSha, @"\A[a-f0-9]{64}\z",
                    RegexOptions.CultureInvariant) =>
                "--preflight --expect-sha256 " + approvedSha +
                " --confirm VERIFY_PRIMARY_OAUTH_CANDIDATE",
            "activate" when days == 365 && approvedSha is not null &&
                Regex.IsMatch(approvedSha, @"\A[a-f0-9]{64}\z",
                    RegexOptions.CultureInvariant) =>
                "--activate --expect-sha256 " + approvedSha +
                " --confirm ACTIVATE_PRIMARY_OAUTH_CERT",
            _ => throw new ArgumentException("Invalid primary OAuth rotation action or SHA256.")
        };
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-pem-rotation.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "chgrp m365mailer \"$work\"\n" +
               "chmod 0750 \"$work\"\n" +
               "base64 -d > \"$work/manage-primary-oauth-rotation.py\" <<'LMR365_PEM_ROTATOR'\n" +
               Encode(PrimaryOAuthRotator) + "\nLMR365_PEM_ROTATOR\n" +
               "base64 -d > \"$work/m365_xoauth2_transport.py\" <<'LMR365_PEM_TRANSPORT'\n" +
               Encode(Transport) + "\nLMR365_PEM_TRANSPORT\n" +
               "base64 -d > \"$work/m365_hardware_signer.py\" <<'LMR365_PEM_SIGNER'\n" +
               Encode(HardwareSigner) + "\nLMR365_PEM_SIGNER\n" +
               "chmod 0644 \"$work/m365_xoauth2_transport.py\" \"$work/m365_hardware_signer.py\"\n" +
               "python3 \"$work/manage-primary-oauth-rotation.py\" " + arguments + "\n";
    }

    internal static string BuildTpmOauthProvisionBundle(string target, string handle,
        string? approvedSha = null)
    {
        if (target is not ("sidecar" or "primary"))
            throw new ArgumentException("Unsupported TPM2 provisioning target.");
        if (!Regex.IsMatch(handle, @"\A0x8101[a-f0-9]{4}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("TPM2 owner persistent handle must be 0x8101xxxx.");
        string args = "--target " + target + " --handle " + handle + " --plan";
        if (approvedSha is not null)
        {
            if (!Regex.IsMatch(approvedSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
                throw new ArgumentException("TPM2 provisioning requires the exact reviewed SHA256.");
            args = "--target " + target + " --handle " + handle + " --apply" +
                   " --approve-sha256 " + approvedSha +
                   " --confirm CREATE_TPM2_OAUTH_KEY";
        }
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-tpm-key.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/manage-tpm-oauth-key.py\" <<'LMR365_TPM_PROVISION'\n" +
               Encode(TpmOauthProvision) + "\nLMR365_TPM_PROVISION\n" +
               "python3 \"$work/manage-tpm-oauth-key.py\" " + args + "\n";
    }

    internal static string BuildDeliveryAcceptanceBundle(
        string target, string runId, string internalRecipient, string externalRecipient,
        string? approvalSha = null)
    {
        if (target is not ("sidecar" or "primary"))
            throw new ArgumentException("Unknown active OAuth acceptance target.");
        if (!Regex.IsMatch(runId, @"\A[a-f0-9]{32}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Invalid unique acceptance run ID.");
        const string email = @"\A(?![^@]*\.\.)(?:[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9_+-])?)@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z";
        if (internalRecipient.Length > 254 || externalRecipient.Length > 254 ||
            !Regex.IsMatch(internalRecipient, email, RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(externalRecipient, email, RegexOptions.CultureInvariant) ||
            string.Equals(internalRecipient, externalRecipient, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Two distinct, well-formed SMTP acceptance recipients are required.");
        if (approvalSha is not null &&
            !Regex.IsMatch(approvalSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Exact reviewed acceptance SHA256 is required for sending.");
        var request = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["internal"] = internalRecipient,
            ["external"] = externalRecipient,
            ["run_id"] = runId
        });
        string requestB64 = Encode(request);
        string args = "--target " + target + (approvalSha is null
            ? " --plan"
            : " --apply --approve-sha256 " + approvalSha +
              " --confirm SEND_TWO_ACCEPTANCE_TESTS");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-delivery.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/manage-m365-delivery-acceptance.py\" <<'LMR365_ACCEPTANCE_SCRIPT'\n" +
               Encode(DeliveryAcceptance) + "\nLMR365_ACCEPTANCE_SCRIPT\n" +
               // The actual addresses are sent over SSH stdin inside Base64;
               // never command arguments or diagnostic logs.
               "printf '%s' '" + requestB64 + "' | base64 -d | " +
               "python3 \"$work/manage-m365-delivery-acceptance.py\" " + args + "\n";
    }

    internal static string BuildHardwareOAuthCutoverBundle(
        string target, string operation, string? approvalSha = null, string? backupId = null,
        string? stageProvider = null, string? stageKeyRef = null)
    {
        if (target is not ("sidecar" or "primary"))
            throw new ArgumentException("Unsupported hardware OAuth target.");
        string args = "--target " + target;
        string stageArgs = "";
        if (operation is "stage-plan" or "stage-apply")
        {
            if (stageProvider is not ("tpm2" or "pkcs11") || stageKeyRef is null)
                throw new ArgumentException("Choose a supported hardware provider and key reference.");
            bool validRef = stageProvider == "tpm2"
                ? Regex.IsMatch(stageKeyRef, @"\Ahandle:0x81[a-fA-F0-9]{6}\z",
                                RegexOptions.CultureInvariant) ||
                  stageKeyRef == (target == "sidecar"
                      ? "/etc/linuxmailrelay365/sidecar-identity/tpm2-app.key"
                      : "/etc/postfix/m365-oauth/tpm2-app.key")
                : Regex.IsMatch(stageKeyRef,
                    @"\Apkcs11:[A-Za-z0-9%._+;=:@-]{5,230}\z",
                    RegexOptions.CultureInvariant) &&
                  !Regex.IsMatch(stageKeyRef, @"pin|module-path|module-name",
                                 RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) &&
                  (stageKeyRef.Contains("object=", StringComparison.Ordinal) ||
                   stageKeyRef.Contains("id=", StringComparison.Ordinal)) &&
                  stageKeyRef.Contains("type=private", StringComparison.Ordinal);
            if (!validRef || stageKeyRef.Length > 240)
                throw new ArgumentException("Invalid TPM2/PKCS#11 key reference or embedded secret.");
            // The strict provider/key-ref alphabets exclude shell quotes,
            // whitespace, control bytes and command substitutions.
            stageArgs = " --stage-provider " + stageProvider +
                        " --stage-key-ref '" + stageKeyRef + "'";
        }
        else if (stageProvider is not null || stageKeyRef is not null)
            throw new ArgumentException("Stage key parameters are not valid for this operation.");
        switch (operation)
        {
            case "stage-plan" when approvalSha is null && backupId is null:
                args += " --stage-plan" + stageArgs;
                break;
            case "stage-apply" when backupId is null && approvalSha is not null &&
                                    Regex.IsMatch(approvalSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant):
                args += " --stage-apply" + stageArgs + " --approve-sha256 " +
                        approvalSha + " --confirm STAGE_HARDWARE_OAUTH";
                break;
            case "token-preflight" when backupId is null && approvalSha is not null &&
                                          Regex.IsMatch(approvalSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant):
                args += " --token-preflight --approve-sha256 " + approvalSha +
                        " --confirm VERIFY_STAGED_ENTRA_TOKEN";
                break;
            case "smtp-auth-preflight" when backupId is null && approvalSha is not null &&
                                               Regex.IsMatch(approvalSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant):
                args += " --smtp-auth-preflight --approve-sha256 " + approvalSha +
                        " --confirm VERIFY_STAGED_SMTP_AUTH";
                break;
            case "plan" when approvalSha is null && backupId is null:
                args += " --plan";
                break;
            case "list" when approvalSha is null && backupId is null:
                args += " --list";
                break;
            case "apply" when backupId is null && approvalSha is not null &&
                              Regex.IsMatch(approvalSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant):
                args += " --apply --approve-sha256 " + approvalSha +
                        " --confirm ACTIVATE_HARDWARE_OAUTH";
                break;
            case "rollback" when approvalSha is null && backupId is not null &&
                                 Regex.IsMatch(backupId, @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z",
                                               RegexOptions.CultureInvariant):
                args += " --rollback " + backupId + " --confirm ROLLBACK_HARDWARE_OAUTH";
                break;
            default:
                throw new ArgumentException("Invalid hardware OAuth cutover operation or reviewed inputs.");
        }
        // Protected temp code only; the current/previous identity, public
        // certificate and TPM references never leave the Linux machine.
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-hwoauth-switch.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/manage-hardware-oauth-cutover.py\" <<'LMR365_HWOAUTH_CUTOVER'\n" +
               Encode(HardwareOAuthCutover) + "\nLMR365_HWOAUTH_CUTOVER\n" +
               "python3 \"$work/manage-hardware-oauth-cutover.py\" " + args + "\n";
    }

    internal static string BuildHardwareOAuthDiagnosticBundle(bool verifySigning)
    {
        // Stage code in a root-only temporary directory; no identity or key
        // material is transferred to Windows or embedded in shell arguments.
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-hwauth.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/verify-hardware-oauth.py\" <<'LMR365_HW_OAUTH'\n" +
               Encode(HardwareOAuthDiagnostics) + "\nLMR365_HW_OAUTH\n" +
               "python3 \"$work/verify-hardware-oauth.py\" " +
               (verifySigning ? "" : "--inventory-only") + "\n";
    }

    internal static string BuildTpmDependenciesBundle(string profile, string? reviewedSha = null, bool inspectProvider = false)
    {
        if (profile is not ("auto" or "runtime" or "build-prereqs" or "pkcs11" or "native-provider"))
            throw new ArgumentException("Unsupported TPM dependency profile.");
        if (reviewedSha is not null && inspectProvider)
            throw new ArgumentException("TPM provider inspection cannot apply packages.");
        if (reviewedSha is not null &&
            !Regex.IsMatch(reviewedSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Expected a reviewed TPM dependencies SHA256.");
        string args = "--profile " + profile;
        if (reviewedSha is not null)
            args += " --apply --approve-sha256 " + reviewedSha +
                    " --confirm INSTALL_TPM2_DEPENDENCIES";
        else if (inspectProvider)
            args += " --inspect-provider";
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-tpmdeps.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/manage-tpm-dependencies.py\" <<'LMR365_TPM_DEPENDENCIES'\n" +
               Encode(TpmDependencies) + "\nLMR365_TPM_DEPENDENCIES\n" +
               "python3 \"$work/manage-tpm-dependencies.py\" " + args + "\n";
    }


    internal static string MultiMailboxPostfixInstaller => Text("LinuxMailRelay365.linux.multi-mailbox-postfix.py");
    internal static string MultiMailboxTransport => Text("LinuxMailRelay365.linux.multi-mailbox-transport.py");
    internal static string MultiMailboxIngressProof => Text("LinuxMailRelay365.linux.multi-mailbox-ingress-proof.py");
    internal static string MultiMailboxProofTimer => Text("LinuxMailRelay365.linux.multi-mailbox-proof-timer.py");
    internal static string MultiMailboxRestore => Text("LinuxMailRelay365.linux.multi-mailbox-restore.py");
    internal static string MultiMailboxAcceptance => Text("LinuxMailRelay365.linux.multi-mailbox-acceptance.py");

    // Explicitly stage code only. This is a Linux filesystem change, not
    // an SMTP route change. Never install into an existing directory.
    internal static string BuildMultiMailboxRuntimeStageBundle()
    {
        var files = new (string Name, string Content)[]
        {
            ("manage-multi-mailbox-postfix.py", MultiMailboxPostfixInstaller),
            ("restore-multi-mailbox-postfix.py", MultiMailboxRestore),
            ("m365-multi-mailbox-transport.py", MultiMailboxTransport),
            ("refresh-multi-mailbox-proof.py", MultiMailboxIngressProof),
            ("manage-multi-mailbox-proof-timer.py", MultiMailboxProofTimer),
            ("manage-multi-mailbox-acceptance.py", MultiMailboxAcceptance),
            ("audit-oauth-sender-map.py", OAuthSenderMapAudit),
            ("audit-oauth-ingress.py", OAuthIngressAudit),
            ("m365_xoauth2_transport.py", Transport),
            ("m365_hardware_signer.py", HardwareSigner)
        };
        var script = new StringBuilder(
            "set -Eeuo pipefail\numask 077\n" +
            "test \"$(id -u)\" = 0 || { echo 'MULTI_SOURCE_STAGE=root_required' >&2; exit 2; }\n" +
            "test -d /opt && test ! -L /opt || { echo 'MULTI_SOURCE_STAGE=unsafe_opt' >&2; exit 2; }\n" +
            "parent=/opt/linuxmailrelay365\n" +
            "target=$parent/multi-oauth\n" +
            "if test -e \"$target\" || test -L \"$target\"; then echo 'MULTI_SOURCE_STAGE=already_exists_no_overwrite' >&2; exit 2; fi\n" +
            "if test -e /usr/local/libexec/linuxmailrelay365-multi-oauth || " +
                "test -L /usr/local/libexec/linuxmailrelay365-multi-oauth || " +
                "test -e /etc/linuxmailrelay365/oauth-runtime-senders.tsv; then " +
                "echo 'MULTI_SOURCE_STAGE=existing_runtime_requires_review' >&2; exit 2; fi\n" +
            "if test ! -e \"$parent\" && test ! -L \"$parent\"; then mkdir -m 0755 \"$parent\"; fi\n" +
            "test -d \"$parent\" && test ! -L \"$parent\" && " +
                "test \"$(stat -c '%u' \"$parent\")\" = 0 && " +
                "test \"$(stat -c '%a' \"$parent\")\" = 755 || " +
                "{ echo 'MULTI_SOURCE_STAGE=unsafe_parent' >&2; exit 2; }\n" +
            "work=$(mktemp -d \"$parent/.multi-oauth.XXXXXXXX\")\n" +
            "trap 'test -z \"${work:-}\" || rm -rf -- \"$work\"' EXIT\n" +
            "chmod 0755 \"$work\"\n");
        foreach (var (name, source) in files)
        {
            script.Append("base64 -d > \"$work/").Append(name)
                .Append("\" <<'LMR365_MULTI_SOURCE_EOF'\n")
                .Append(Encode(source)).Append("\nLMR365_MULTI_SOURCE_EOF\n");
        }
        script.Append(
            "chmod 0644 \"$work\"/*.py\n" +
            "if test -e \"$target\" || test -L \"$target\"; then " +
                "echo 'MULTI_SOURCE_STAGE=concurrent_change' >&2; exit 2; fi\n" +
            "mv -T -- \"$work\" \"$target\"\n" +
            "work=\n" +
            "echo 'MULTI_SOURCE_STAGE=created_no_service_changes'\n" +
            "echo 'MULTI_SOURCE_MAIL_SENT=no'\n" +
            "echo 'MULTI_SOURCE_PRIMARY_MTA_CHANGED=no'\n");
        return script.ToString();
    }




    internal static string BuildMultiMailboxAcceptanceStatusBundle(string runId)
    {
        if (!Regex.IsMatch(runId, @"\A[a-f0-9]{32}\z",
                RegexOptions.CultureInvariant))
            throw new ArgumentException("An exact previous acceptance run ID is required.");
        return "set -Eeuo pipefail\numask 077\n" +
               "python3 /opt/linuxmailrelay365/multi-oauth/manage-multi-mailbox-acceptance.py " +
               "--status --run-id " + runId + "\n";
    }

    internal static string BuildMultiMailboxAcceptanceBundle(
        string runId, string sender, string internalRecipient, string externalRecipient,
        string? approvedSha = null)
    {
        const string email =
            @"\A(?![^@]*\.\.)(?:[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9_+-])?)@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z";
        if (!Regex.IsMatch(runId, @"\A[a-f0-9]{32}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("A fresh unique acceptance run ID is required.");
        if (sender.Length > 254 || internalRecipient.Length > 254 || externalRecipient.Length > 254 ||
            !Regex.IsMatch(sender, email, RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(internalRecipient, email, RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(externalRecipient, email, RegexOptions.CultureInvariant))
            throw new ArgumentException("All reviewed sender/recipient addresses must be well formed.");
        if (string.Equals(sender, internalRecipient, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(sender, externalRecipient, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(internalRecipient, externalRecipient, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Sender, internal and external test recipients must be distinct.");
        string domain = sender.Split('@')[1].ToLowerInvariant();
        if (!string.Equals(domain, internalRecipient.Split('@')[1], StringComparison.OrdinalIgnoreCase) ||
            string.Equals(domain, externalRecipient.Split('@')[1], StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Internal recipient must share sender domain; external must differ.");
        if (approvedSha is not null &&
            !Regex.IsMatch(approvedSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Reviewed Multi-mailbox acceptance SHA-256 required.");
        var request = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["sender"] = sender.ToLowerInvariant(),
            ["internal"] = internalRecipient.ToLowerInvariant(),
            ["external"] = externalRecipient.ToLowerInvariant(),
            ["run_id"] = runId
        });
        string action = approvedSha is null ? "--plan" :
            "--apply --approve-sha256 " + approvedSha +
            " --confirm SEND_MULTI_MAILBOX_TWO_TESTS";
        // Recipient values never become shell command arguments or log lines.
        // Root validates and SHA-binds the request again before issuing a token.
        return "set -Eeuo pipefail\numask 077\n" +
               "printf '%s' '" + Encode(request) + "' | base64 -d | " +
               "python3 /opt/linuxmailrelay365/multi-oauth/manage-multi-mailbox-acceptance.py " +
               action + "\n";
    }

    internal static string BuildMultiMailboxRestoreBundle(
        string action, string? approvedSha = null, string? backupId = null)
    {
        string arguments = action switch
        {
            "preview" when approvedSha is null && backupId is null =>
                "--preview",
            "restore" when approvedSha is not null && backupId is not null &&
                Regex.IsMatch(approvedSha, @"\A[a-f0-9]{64}\z",
                    RegexOptions.CultureInvariant) &&
                Regex.IsMatch(backupId, @"\Apre-multi-[A-Za-z0-9_-]{8}\z",
                    RegexOptions.CultureInvariant) =>
                "--restore-offline --backup-id " + backupId +
                " --approve-sha256 " + approvedSha +
                " --confirm RESTORE_MULTI_MAILBOX_OFFLINE",
            _ => throw new ArgumentException(
                "Verified multi-mailbox Restore SHA-256 and exact backup ID are required.")
        };
        return "set -Eeuo pipefail\numask 077\n" +
               "python3 /opt/linuxmailrelay365/multi-oauth/restore-multi-mailbox-postfix.py " +
               arguments + "\n";
    }

    internal static string BuildMultiMailboxProofTimerBundle(string action, string? approvedSha = null)
    {
        string parameters = action switch
        {
            "plan" when approvedSha is null => "--plan",
            "status" when approvedSha is null => "--status",
            "enable" when approvedSha is not null &&
                Regex.IsMatch(approvedSha, @"\A[a-f0-9]{64}\z",
                    RegexOptions.CultureInvariant) =>
                "--enable-reviewed --approve-sha256 " + approvedSha +
                " --confirm ENABLE_REVIEWED_MULTI_INGRESS_TIMER",
            "disable" when approvedSha is null =>
                "--disable-reviewed --confirm DISABLE_AND_REVOKE_MULTI_INGRESS_TIMER",
            _ => throw new ArgumentException("Invalid timer action or reviewed SHA-256.")
        };
        return "set -Eeuo pipefail\numask 077\n" +
               "python3 /usr/local/libexec/linuxmailrelay365-multi-oauth/manage-multi-mailbox-proof-timer.py " +
               parameters + "\n";
    }

    internal static string BuildMultiMailboxProofRefreshBundle(string senderMapSha)
    {
        if (!Regex.IsMatch(senderMapSha, @"\A[a-f0-9]{64}\z",
                RegexOptions.CultureInvariant))
            throw new ArgumentException("Reviewed sender map SHA-256 required.");
        return "set -Eeuo pipefail\numask 077\n" +
               "python3 /opt/linuxmailrelay365/multi-oauth/refresh-multi-mailbox-proof.py " +
               "--map-sha256 " + senderMapSha +
               " --confirm REFRESH_PRIVILEGED_MULTI_INGRESS_PROOF\n";
    }

    internal static string BuildMultiMailboxRouteBundle(string action, string? reviewedSha = null)
    {
        string parameters = action switch
        {
            "plan" when reviewedSha is null => "--plan",
            "apply" when reviewedSha is not null &&
                Regex.IsMatch(reviewedSha, @"\A[a-f0-9]{64}\z",
                    RegexOptions.CultureInvariant) =>
                "--apply-offline --approve-sha256 " + reviewedSha +
                " --confirm INSTALL_MULTI_MAILBOX_OFFLINE",
            _ => throw new ArgumentException("A verified multi-mailbox plan SHA is required for offline apply.")
        };
        return "set -Eeuo pipefail\numask 077\n" +
               "python3 /opt/linuxmailrelay365/multi-oauth/manage-multi-mailbox-postfix.py " +
               parameters + "\n";
    }

    internal static string BuildMultiMailboxSourceEditBundle(string request)
    {
        if (Encoding.UTF8.GetByteCount(request) > 4096) throw new ArgumentException("Source edit request too large.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-source-edit.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit-oauth-sender-map.py\" <<'LMR365_SOURCE_MAP'\n" +
               Encode(OAuthSenderMapAudit) + "\nLMR365_SOURCE_MAP\n" +
               "base64 -d > \"$work/export-hardware-oauth-cert.py\" <<'LMR365_SOURCE_CERT'\n" +
               Encode(EntraPublicCertificateExporter) + "\nLMR365_SOURCE_CERT\n" +
               "base64 -d > \"$work/inspect-multi-mailbox-identities.py\" <<'LMR365_SOURCE_INVENTORY'\n" +
               Encode(MultiMailboxIdentityInspector) + "\nLMR365_SOURCE_INVENTORY\n" +
               "base64 -d > \"$work/prepare-multi-mailbox-identity.py\" <<'LMR365_SOURCE_LABEL_POLICY'\n" +
               Encode(MultiMailboxIdentityPreparer) + "\nLMR365_SOURCE_LABEL_POLICY\n" +
               "base64 -d > \"$work/edit-multi-mailbox-source.py\" <<'LMR365_SOURCE_EDITOR'\n" +
               Encode(MultiMailboxSourceEditor) + "\nLMR365_SOURCE_EDITOR\n" +
               "printf '%s' '" + Encode(request) + "' | base64 -d | python3 \"$work/edit-multi-mailbox-source.py\"\n";
    }

    internal static string BuildMultiMailboxTpmPrepareBundle(string request)
    {
        if (Encoding.UTF8.GetByteCount(request)>8192) throw new ArgumentException("TPM identity request too large.");
        var files=new (string Name,string Content)[] {
            ("prepare-multi-mailbox-tpm.py",MultiMailboxTpmPrepare),
            ("prepare-multi-mailbox-identity.py",MultiMailboxIdentityPreparer),
            ("manage-tpm-oauth-key.py",TpmOauthProvision),
            ("inspect-multi-mailbox-identities.py",MultiMailboxIdentityInspector),
            ("audit-oauth-sender-map.py",OAuthSenderMapAudit),
            ("export-hardware-oauth-cert.py",EntraPublicCertificateExporter)
        };
        var script=new StringBuilder("set -Eeuo pipefail\numask 077\n" +
            "work=$(mktemp -d /tmp/lmr365-mapped-tpm.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n");
        foreach(var (name,content) in files)
            script.Append("base64 -d > \"$work/").Append(name).Append("\" <<'LMR365_MAPPED_TPM'\n")
                .Append(Encode(content)).Append("\nLMR365_MAPPED_TPM\n");
        script.Append("printf '%s' '").Append(Encode(request))
            .Append("' | base64 -d | /usr/bin/python3 \"$work/prepare-multi-mailbox-tpm.py\"\n");
        return script.ToString();
    }

    internal static string BuildMultiMailboxIdentityPrepareBundle(string request)
    {
        if (Encoding.UTF8.GetByteCount(request) > 4096) throw new ArgumentException("Identity preparation request too large.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-identity-prepare.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit-oauth-sender-map.py\" <<'LMR365_SOURCE_MAP'\n" +
               Encode(OAuthSenderMapAudit) + "\nLMR365_SOURCE_MAP\n" +
               "base64 -d > \"$work/export-hardware-oauth-cert.py\" <<'LMR365_SOURCE_CERT'\n" +
               Encode(EntraPublicCertificateExporter) + "\nLMR365_SOURCE_CERT\n" +
               "base64 -d > \"$work/inspect-multi-mailbox-identities.py\" <<'LMR365_SOURCE_INVENTORY'\n" +
               Encode(MultiMailboxIdentityInspector) + "\nLMR365_SOURCE_INVENTORY\n" +
               "base64 -d > \"$work/prepare-multi-mailbox-identity.py\" <<'LMR365_SOURCE_EDITOR'\n" +
               Encode(MultiMailboxIdentityPreparer) + "\nLMR365_SOURCE_EDITOR\n" +
               "printf '%s' '" + Encode(request) + "' | base64 -d | python3 \"$work/prepare-multi-mailbox-identity.py\"\n";
    }

    internal static string BuildMultiMailboxNewAppBundle(string request)
    {
        if (Encoding.UTF8.GetByteCount(request) > 4096) throw new ArgumentException("New app request too large.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-new-app.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit-oauth-sender-map.py\" <<'LMR365_SOURCE_MAP'\n" +
               Encode(OAuthSenderMapAudit) + "\nLMR365_SOURCE_MAP\n" +
               "base64 -d > \"$work/export-hardware-oauth-cert.py\" <<'LMR365_SOURCE_CERT'\n" +
               Encode(EntraPublicCertificateExporter) + "\nLMR365_SOURCE_CERT\n" +
               "base64 -d > \"$work/inspect-multi-mailbox-identities.py\" <<'LMR365_SOURCE_INVENTORY'\n" +
               Encode(MultiMailboxIdentityInspector) + "\nLMR365_SOURCE_INVENTORY\n" +
               "base64 -d > \"$work/prepare-multi-mailbox-identity.py\" <<'LMR365_SOURCE_EDITOR'\n" +
               Encode(MultiMailboxIdentityPreparer) + "\nLMR365_SOURCE_EDITOR\n" +
               "base64 -d > \"$work/manage-tpm-oauth-key.py\" <<'LMR365_NEW_APP_TPM_TOOLS'\n" +
               Encode(TpmOauthProvision) + "\nLMR365_NEW_APP_TPM_TOOLS\n" +
               "base64 -d > \"$work/prepare-multi-mailbox-tpm.py\" <<'LMR365_NEW_APP_TPM'\n" +
               Encode(MultiMailboxTpmPrepare) + "\nLMR365_NEW_APP_TPM\n" +
               "base64 -d > \"$work/prepare-multi-mailbox-new-app.py\" <<'LMR365_NEW_APP'\n" +
               Encode(MultiMailboxNewApp) + "\nLMR365_NEW_APP\n" +
               "printf '%s' '" + Encode(request) + "' | base64 -d | python3 \"$work/prepare-multi-mailbox-new-app.py\"\n";
    }

    internal static string BuildMultiMailboxGraphPairBundle(string request)
    {
        if (Encoding.UTF8.GetByteCount(request) > 4096) throw new ArgumentException("Graph pair request too large.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-graph-pair.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit-oauth-sender-map.py\" <<'LMR365_SOURCE_MAP'\n" +
               Encode(OAuthSenderMapAudit) + "\nLMR365_SOURCE_MAP\n" +
               "base64 -d > \"$work/export-hardware-oauth-cert.py\" <<'LMR365_SOURCE_CERT'\n" +
               Encode(EntraPublicCertificateExporter) + "\nLMR365_SOURCE_CERT\n" +
               "base64 -d > \"$work/inspect-multi-mailbox-identities.py\" <<'LMR365_SOURCE_INVENTORY'\n" +
               Encode(MultiMailboxIdentityInspector) + "\nLMR365_SOURCE_INVENTORY\n" +
               "base64 -d > \"$work/manage-tpm-oauth-key.py\" <<'LMR365_GRAPH_TPM'\n" +
               Encode(TpmOauthProvision) + "\nLMR365_GRAPH_TPM\n" +
               "base64 -d > \"$work/review-multi-mailbox-graph-pair.py\" <<'LMR365_SOURCE_EDITOR'\n" +
               Encode(MultiMailboxGraphPairReviewer) + "\nLMR365_SOURCE_EDITOR\n" +
               "printf '%s' '" + Encode(request) + "' | base64 -d | python3 \"$work/review-multi-mailbox-graph-pair.py\"\n";
    }

    internal static string BuildMultiMailboxSmtpAuthBundle(string request)
    {
        if (Encoding.UTF8.GetByteCount(request)>4096) throw new ArgumentException("SMTP AUTH request too large.");
        var files=new (string Name,string Content)[] {
            ("check-multi-mailbox-smtp-auth.py",MultiMailboxSmtpAuth),
            ("inspect-multi-mailbox-identities.py",MultiMailboxIdentityInspector),
            ("audit-oauth-sender-map.py",OAuthSenderMapAudit),
            ("export-hardware-oauth-cert.py",EntraPublicCertificateExporter),
            ("m365_xoauth2_transport.py",Transport),
            ("m365_hardware_signer.py",HardwareSigner)
        };
        var script=new StringBuilder("set -Eeuo pipefail\numask 077\n" +
            "test \"$(id -u)\" = 0 && test -d /run && test ! -L /run\n" +
            "work=$(mktemp -d /run/lmr365-mailbox-auth.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n");
        foreach(var (name,content) in files)
            script.Append("base64 -d > \"$work/").Append(name).Append("\" <<'LMR365_AUTH_CODE'\n")
                .Append(Encode(content)).Append("\nLMR365_AUTH_CODE\n");
        // Code only, no identity or token files. Service account can traverse
        // and read the immutable root-owned diagnostic modules.
        script.Append("chmod 0644 \"$work\"/*.py\nchmod 0755 \"$work\"\n")
            .Append("printf '%s' '").Append(Encode(request))
            .Append("' | base64 -d | /usr/bin/python3 -I -B \"$work/check-multi-mailbox-smtp-auth.py\"\n");
        return script.ToString();
    }

    internal static string BuildMultiMailboxIdentityInventoryBundle(string nonce)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(nonce, @"\A[a-f0-9]{64}\z"))
            throw new ArgumentException("Invalid identity inventory nonce.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-multi-identities.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit-oauth-sender-map.py\" <<'LMR365_MULTI_IDENTITY_MAP'\n" +
               Encode(OAuthSenderMapAudit) + "\nLMR365_MULTI_IDENTITY_MAP\n" +
               "base64 -d > \"$work/export-hardware-oauth-cert.py\" <<'LMR365_MULTI_IDENTITY_CERT'\n" +
               Encode(EntraPublicCertificateExporter) + "\nLMR365_MULTI_IDENTITY_CERT\n" +
               "base64 -d > \"$work/inspect-multi-mailbox-identities.py\" <<'LMR365_MULTI_IDENTITY_READ'\n" +
               Encode(MultiMailboxIdentityInspector) + "\nLMR365_MULTI_IDENTITY_READ\n" +
               "printf '%s' '" + nonce + "' | python3 \"$work/inspect-multi-mailbox-identities.py\"\n";
    }

    internal static string BuildOAuthSenderMapAuditBundle(string mapPath)
    {
        // This is a read-only root-only audit. Do not pass sender address,
        // OAuth token, certificate content or SMTP password in this bundle.
        if (mapPath.Length > 256 ||
            !Regex.IsMatch(mapPath, @"\A/etc/linuxmailrelay365/[A-Za-z0-9_./-]{1,240}\.tsv\z",
                           RegexOptions.CultureInvariant) ||
            mapPath.Split('/').Skip(1).Any(part => part is "." or ".." or ""))
            throw new ArgumentException("Only an absolute /etc/linuxmailrelay365/ sender map TSV path is allowed.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-sender-audit.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit-oauth-sender-map.py\" <<'LMR365_OAUTH_MAP_AUDIT'\n" +
               Encode(OAuthSenderMapAudit) + "\nLMR365_OAUTH_MAP_AUDIT\n" +
               "python3 \"$work/audit-oauth-sender-map.py\" --map-path " + mapPath + "\n";
    }

    internal static string BuildOAuthIngressAuditBundle(string mapPath)
    {
        // The Linux handler only inspects protected local files and reads
        // Postfix parameters. No token, certificate or sender address is sent
        // from Windows; no SMTP message is submitted.
        if (mapPath.Length > 256 ||
            !Regex.IsMatch(mapPath, @"\A/etc/linuxmailrelay365/[A-Za-z0-9_./-]{1,240}\.tsv\z",
                           RegexOptions.CultureInvariant) ||
            mapPath.Split('/').Skip(1).Any(part => part is "." or ".." or ""))
            throw new ArgumentException("Only an absolute /etc/linuxmailrelay365/ sender map TSV path is allowed.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-ingress-audit.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit-oauth-sender-map.py\" <<'LMR365_OAUTH_SENDER_MAP_LIB'\n" +
               Encode(OAuthSenderMapAudit) + "\nLMR365_OAUTH_SENDER_MAP_LIB\n" +
               "base64 -d > \"$work/audit-oauth-ingress.py\" <<'LMR365_OAUTH_INGRESS_AUDIT'\n" +
               Encode(OAuthIngressAudit) + "\nLMR365_OAUTH_INGRESS_AUDIT\n" +
               "python3 \"$work/audit-oauth-ingress.py\" --map-path " + mapPath + "\n";
    }

    internal static string BuildOAuthIdentitySigningAuditBundle(string mapPath)
    {
        // Bounded root-only map review: the actual PS256 probe runs as
        // m365mailer. It has no SMTP, Graph, Postfix, or Entra operations.
        if (mapPath.Length > 256 ||
            !Regex.IsMatch(mapPath, @"\A/etc/linuxmailrelay365/[A-Za-z0-9_./-]{1,240}\.tsv\z",
                           RegexOptions.CultureInvariant) ||
            mapPath.Split('/').Skip(1).Any(part => part is "." or ".." or ""))
            throw new ArgumentException("Only an absolute /etc/linuxmailrelay365/ map TSV path is allowed.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-offline-signing.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit-oauth-sender-map.py\" <<'LMR365_SIGN_MAP'\n" +
               Encode(OAuthSenderMapAudit) + "\nLMR365_SIGN_MAP\n" +
               "base64 -d > \"$work/m365_hardware_signer.py\" <<'LMR365_SIGN_BACKEND'\n" +
               Encode(HardwareSigner) + "\nLMR365_SIGN_BACKEND\n" +
               "base64 -d > \"$work/m365_xoauth2_transport.py\" <<'LMR365_SIGN_TRANSPORT'\n" +
               Encode(Transport) + "\nLMR365_SIGN_TRANSPORT\n" +
               "base64 -d > \"$work/audit-oauth-identity-signing.py\" <<'LMR365_SIGN_AUDITOR'\n" +
               Encode(OAuthIdentitySigningAudit) + "\nLMR365_SIGN_AUDITOR\n" +
               "chmod 0755 \"$work\"\n" +
               "chmod 0644 \"$work\"/*.py\n" +
               "python3 \"$work/audit-oauth-identity-signing.py\" --map-path " + mapPath + "\n";
    }

    internal static string BuildLinuxBundle(string[] args)
    {
        foreach (string item in args)
        {
            if (item.Length > 320 || item.Any(c => !(char.IsAsciiLetterOrDigit(c) ||
                    c is '.' or '-' or '_' or '@' or ':' or '/')))
                throw new ArgumentException("Invalid installer argument format.");
        }
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/m365pm.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/install-postfix-m365-xoauth2.sh\" <<'M365_INSTALL'\n" +
               Encode(Installer) + "\nM365_INSTALL\n" +
               "base64 -d > \"$work/m365_xoauth2_transport.py\" <<'M365_TRANSPORT'\n" +
               Encode(Transport) + "\nM365_TRANSPORT\n" +
               "base64 -d > \"$work/m365_hardware_signer.py\" <<'LMR365_HARDWARE_SIGNER'\n" +
               Encode(HardwareSigner) + "\nLMR365_HARDWARE_SIGNER\n" +
               "base64 -d > \"$work/mail-config-recovery.sh\" <<'LMR365_RECOVERY'\n" +
               Encode(Recovery) + "\nLMR365_RECOVERY\n" +
               "bash \"$work/install-postfix-m365-xoauth2.sh\" " + string.Join(" ", args) + "\n";
    }

    internal static string BuildDirectSendSidecarBundle(int port, string mxHost,
        string acceptedDomain, string sender, string listenIpv4,
        string[] trustedNetworks, bool apply, string foreignMta = "", string sidecarHostname = "")
    {
        if (!SmtpIngressPort.Supported(port) || trustedNetworks.Length > 8)
            throw new ArgumentException("Invalid private SMTP custom port or CIDR count.");
        const string dns = @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z";
        const string email = @"\A[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9.-]{4,253}\z";
        if (!Regex.IsMatch(mxHost, dns, RegexOptions.CultureInvariant) ||
            !mxHost.EndsWith(".mail.protection.outlook.com", StringComparison.OrdinalIgnoreCase) ||
            !Regex.IsMatch(acceptedDomain, dns, RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(sender, email, RegexOptions.CultureInvariant) ||
            !sender.EndsWith("@" + acceptedDomain, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Enter a valid EOP MX, accepted domain and fixed sender.");
        var args = new List<string> { apply ? "--apply" : "--check-only",
            "--smtp-port", port.ToString(), "--mx-host", mxHost,
            "--accepted-domain", acceptedDomain, "--fixed-sender", sender };
        if (!string.IsNullOrWhiteSpace(listenIpv4))
        {
            if (!System.Net.IPAddress.TryParse(listenIpv4, out var ip) ||
                ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new ArgumentException("Invalid RFC1918 listener IPv4.");
            args.Add("--listen-ip");
            args.Add(listenIpv4);
        }
        foreach (var cidr in trustedNetworks)
        {
            if (!Regex.IsMatch(cidr, @"\A[0-9./]{9,18}\z"))
                throw new ArgumentException("Invalid client CIDR.");
            args.Add("--trusted-network");
            args.Add(cidr);
        }
        if (foreignMta.Length > 0)
        {
            if (foreignMta is not ("exim" or "sendmail") ||
                !Regex.IsMatch(sidecarHostname, dns, RegexOptions.CultureInvariant) ||
                sidecarHostname.Length > 253)
                throw new ArgumentException("Foreign MTA preservation requires explicit Exim/Sendmail mode and an FQDN.");
            args.AddRange(["--preserve-primary-mta", foreignMta,
                           "--sidecar-hostname", sidecarHostname]);
            if (apply)
                args.AddRange(["--confirm-preserve-primary-mta",
                               "PRESERVE_EXISTING_" + foreignMta.ToUpperInvariant()]);
        }
        else if (sidecarHostname.Length != 0)
            throw new ArgumentException("Foreign sidecar hostname requires an explicitly selected existing Exim/Sendmail.");
        if (apply) args.AddRange(["--confirm-accepted-domain", "TENANT_DOMAIN_CHECKED"]);
        foreach (string item in args)
            if (item.Length > 256 || item.Any(c => !(char.IsAsciiLetterOrDigit(c) ||
                c is '.' or '-' or '_' or '@' or ':' or '/')))
                throw new ArgumentException("Invalid Direct Send installer argument.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-directsend.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/install.sh\" <<'LMR365_DIRECT_SEND'\n" +
               Encode(DirectSendSidecarInstaller) + "\nLMR365_DIRECT_SEND\n" +
               "base64 -d > \"$work/guard-foreign-mta.py\" <<'LMR365_FOREIGN_MTA'\n" +
               Encode(ForeignMtaGuard) + "\nLMR365_FOREIGN_MTA\n" +
               "bash \"$work/install.sh\" " + string.Join(" ", args) + "\n";
    }

    internal static string BuildFreshConnectorBundle(int port, string mxHost,
        string acceptedDomain, string sender, string listenIpv4,
        string[] trustedNetworks, string publicIp, string certPath, string keyPath, bool apply,
        string foreignMta = "", string sidecarHostname = "")
    {
        if (!SmtpIngressPort.Supported(port) || trustedNetworks.Length > 8)
            throw new ArgumentException("Connector custom SMTP port must be 25 or 1024-65535.");
        const string dns = @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z";
        const string email = @"\A[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9.-]{4,253}\z";
        if (!Regex.IsMatch(mxHost, dns, RegexOptions.CultureInvariant) ||
            !mxHost.EndsWith(".mail.protection.outlook.com", StringComparison.OrdinalIgnoreCase) ||
            !Regex.IsMatch(acceptedDomain, dns, RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(sender, email, RegexOptions.CultureInvariant) ||
            !sender.EndsWith("@" + acceptedDomain, StringComparison.OrdinalIgnoreCase) ||
            (string.IsNullOrEmpty(publicIp) && (string.IsNullOrEmpty(certPath) || string.IsNullOrEmpty(keyPath))) ||
            (string.IsNullOrEmpty(certPath) != string.IsNullOrEmpty(keyPath)))
            throw new ArgumentException("Exact accepted domain, fixed sender and verified Connector IP or certificate are required.");
        var args = new List<string> { apply ? "--apply" : "--check-only",
            "--smtp-port", port.ToString(), "--mx-host", mxHost,
            "--accepted-domain", acceptedDomain, "--fixed-sender", sender };
        if (listenIpv4.Length > 0)
        {
            args.Add("--listen-ip");
            args.Add(listenIpv4);
        }
        foreach (var cidr in trustedNetworks)
        {
            args.Add("--trusted-network");
            args.Add(cidr);
        }
        if (publicIp.Length > 0)
        {
            args.Add("--public-ip");
            args.Add(publicIp);
        }
        if (certPath.Length > 0)
        {
            args.Add("--tls-cert");
            args.Add(certPath);
            args.Add("--tls-key");
            args.Add(keyPath);
        }
        if (foreignMta.Length > 0)
        {
            if (foreignMta is not ("exim" or "sendmail") ||
                !Regex.IsMatch(sidecarHostname, dns, RegexOptions.CultureInvariant) ||
                sidecarHostname.Length > 253)
                throw new ArgumentException("Foreign MTA preservation requires explicit Exim/Sendmail mode and an FQDN.");
            args.AddRange(["--preserve-primary-mta", foreignMta,
                           "--sidecar-hostname", sidecarHostname]);
            if (apply)
                args.AddRange(["--confirm-preserve-primary-mta",
                               "PRESERVE_EXISTING_" + foreignMta.ToUpperInvariant()]);
        }
        else if (sidecarHostname.Length != 0)
            throw new ArgumentException("Foreign sidecar hostname requires an explicitly selected existing Exim/Sendmail.");
        if (apply)
            args.AddRange(["--confirm-accepted-domain", "TENANT_DOMAIN_CHECKED",
                           "--confirm-connector", "TENANT_CONNECTOR_CHECKED"]);
        foreach (var item in args)
        {
            if (item.Length > 256 || item.Any(c => !(char.IsAsciiLetterOrDigit(c) ||
                c is '.' or '-' or '_' or '/' or ':' or '@')) || item.Contains(".."))
                throw new ArgumentException("Untrusted Connector installation argument.");
        }
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-connector.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/install.sh\" <<'LMR365_FRESH_CONNECTOR'\n" +
               Encode(ConnectorSidecarInstaller) + "\nLMR365_FRESH_CONNECTOR\n" +
               "base64 -d > \"$work/guard-foreign-mta.py\" <<'LMR365_FOREIGN_MTA'\n" +
               Encode(ForeignMtaGuard) + "\nLMR365_FOREIGN_MTA\n" +
               "bash \"$work/install.sh\" " + string.Join(" ", args) + "\n";
    }

    internal static string BuildSidecarBundle(string[] args)
    {
        // A secure, separate Postfix instance. No primary MTA configuration
        // or default queue is touched by this installer.
        foreach (string item in args)
        {
            if (item.Length > 320 || item.Any(c => !(char.IsAsciiLetterOrDigit(c) ||
                    c is '.' or '-' or '_' or '@' or ':' or '/')))
                throw new ArgumentException("Invalid sidecar installer argument.");
        }
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-sidecar.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/install-sidecar.sh\" <<'LMR365_SIDECAR'\n" +
               Encode(SidecarInstaller) + "\nLMR365_SIDECAR\n" +
               "base64 -d > \"$work/m365_xoauth2_transport.py\" <<'LMR365_TRANSPORT'\n" +
               Encode(Transport) + "\nLMR365_TRANSPORT\n" +
               "base64 -d > \"$work/m365_hardware_signer.py\" <<'LMR365_HARDWARE_SIGNER'\n" +
               Encode(HardwareSigner) + "\nLMR365_HARDWARE_SIGNER\n" +
               "bash \"$work/install-sidecar.sh\" " + string.Join(" ", args) + "\n";
    }

    internal static string BuildPostfixBasicsBundle(
        string hostname, string domain, string listener, string? approvedSha = null)
    {
        const string fqdn = @"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z";
        if (hostname.Length > 253 || domain.Length > 253 ||
            !Regex.IsMatch(hostname, fqdn, RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(domain, fqdn, RegexOptions.CultureInvariant) ||
            !hostname.EndsWith("." + domain, StringComparison.Ordinal) ||
            listener is not ("loopback-only" or "all"))
            throw new ArgumentException("Choose a valid Postfix FQDN, domain and listener.");
        if (approvedSha is not null &&
            !Regex.IsMatch(approvedSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Invalid Postfix baseline approval SHA.");
        string args = approvedSha is null ? "--preview" :
            "--apply --expected-sha256 " + approvedSha +
            " --confirm MODIFY_PRIMARY_POSTFIX --recovery-script \"$work/recovery.sh\"";
        return "set -Eeuo pipefail\numask 077\n" +
            "work=$(mktemp -d /tmp/lmr365-postfix-basic.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/postfix-basics.py\" <<'LMR365_POSTFIX_BASICS'\n" +
            Encode(PostfixBasicsManager) + "\nLMR365_POSTFIX_BASICS\n" +
            "base64 -d > \"$work/recovery.sh\" <<'LMR365_POSTFIX_RECOVERY'\n" +
            Encode(Recovery) + "\nLMR365_POSTFIX_RECOVERY\n" +
            "python3 \"$work/postfix-basics.py\" " + args +
            " --hostname " + hostname + " --domain " + domain +
            " --listener " + listener + "\n";
    }

    internal static string BuildCleanPostfixBundle(
        int port, string operation, string? expectedSha = null)
    {
        if (!SmtpIngressPort.Supported(port) ||
            operation is not ("check" or "apply" or "verify"))
            throw new ArgumentException("Invalid clean Postfix bootstrap operation or port.");
        if (operation == "apply")
        {
            if (expectedSha is null ||
                !Regex.IsMatch(expectedSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
                throw new ArgumentException("Clean package installation requires a reviewed SHA256.");
        }
        else if (expectedSha is not null)
            throw new ArgumentException("Read-only clean Linux action cannot accept an approval fingerprint.");
        var action = operation == "apply"
            ? "--apply --expected-plan-sha256 " + expectedSha +
              " --confirm INSTALL_CLEAN_POSTFIX_PACKAGES"
            : operation == "verify" ? "--verify-prepared" : "--check-only";
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-clean-postfix.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/prepare.py\" <<'LMR365_CLEAN_POSTFIX'\n" +
               Encode(CleanPostfixPreparation) + "\nLMR365_CLEAN_POSTFIX\n" +
               "python3 \"$work/prepare.py\" --smtp-port " + port + " " + action + "\n";
    }

    // Passing null inspects effective MTA configuration independently of the
    // selected wizard port; it does not silently substitute TCP 2525.
    internal static string BuildMailQueueInspectionBundle(string scope, bool messages = false, string? selectionNonce = null)
    {
        if (scope is not ("postfix" or "exim" or "sendmail" or "sidecar") ||
            (messages && scope is not ("postfix" or "sidecar")) ||
            (selectionNonce is not null && (!messages || !QueueRetryReview.ValidSha(selectionNonce))))
            throw new ArgumentException("Unsupported native mail queue scope or selection context.");
        return BuildQueueReadOnlyBundle(scope, (messages ? " --messages" : "") +
            (selectionNonce is null ? "" : " --selection-nonce " + selectionNonce));
    }

    internal static string BuildQueueRetryReviewBundle(string scope, string nonce, long sampledAt, string fingerprint)
    {
        if (scope is not ("postfix" or "sidecar") || !QueueRetryReview.ValidSha(nonce) ||
            !QueueRetryReview.ValidSha(fingerprint) || sampledAt is < 1 or > 9999999999)
            throw new ArgumentException("Invalid read-only Retry review context.");
        return BuildQueueReadOnlyBundle(scope, " --selection-nonce " + nonce +
            " --sampled-at " + sampledAt.ToString(System.Globalization.CultureInfo.InvariantCulture) +
            " --retry-plan " + fingerprint);
    }

    internal static string BuildQueueRetryPrepareBundle(string scope, string nonce, long sampledAt, string fingerprint)
    {
        if (scope is not ("postfix" or "sidecar") || !QueueRetryReview.ValidSha(nonce) ||
            !QueueRetryReview.ValidSha(fingerprint) || sampledAt is < 1 or > 9999999999)
            throw new ArgumentException("Invalid selected Retry preparation context.");
        return BuildQueueReadOnlyBundle(scope, " --selection-nonce " + nonce +
            " --sampled-at " + sampledAt.ToString(System.Globalization.CultureInfo.InvariantCulture) +
            " --retry-prepare " + fingerprint);
    }

    internal static string BuildQueueRetryApplyBundle(string scope, string nonce, long sampledAt,
        string fingerprint, long preparedAt, string planSha)
    {
        if (scope is not ("postfix" or "sidecar") || !QueueRetryReview.ValidSha(nonce) ||
            !QueueRetryReview.ValidSha(fingerprint) || !QueueRetryReview.ValidSha(planSha) ||
            sampledAt is < 1 or > 9999999999 || preparedAt < sampledAt ||
            preparedAt > 9999999999 || preparedAt - sampledAt > 300)
            throw new ArgumentException("Invalid selected Retry approval context.");
        return BuildQueueBundle(scope, " --selection-nonce " + nonce +
            " --sampled-at " + sampledAt.ToString(System.Globalization.CultureInfo.InvariantCulture) +
            " --retry-apply " + fingerprint +
            " --prepared-at " + preparedAt.ToString(System.Globalization.CultureInfo.InvariantCulture) +
            " --approve-sha256 " + planSha + " --confirm " + QueueRetryApplyReceipt.Confirmation);
    }

    internal static string BuildQueueMaintenanceBundle(string scope, string action, string nonce,
        long sampledAt, string fingerprint, long? preparedAt = null, string? planSha = null)
    {
        QueueMaintenanceReceipt.ValidateContext(scope, action, nonce, sampledAt, fingerprint);
        if ((preparedAt is null) != (planSha is null) ||
            (preparedAt is long time && (time < 1 || time > 9999999999 ||
                time < sampledAt || (action != "flush" && time - sampledAt > 300) ||
                !QueueRetryReview.ValidSha(planSha))))
            throw new ArgumentException("Invalid queue maintenance approval.");
        var culture = System.Globalization.CultureInfo.InvariantCulture;
        string arguments = " --maintenance " + action + " --selection-nonce " + nonce;
        if (action != "flush")
            arguments += " --sampled-at " + sampledAt.ToString(culture) + " --target-fingerprint " + fingerprint;
        if (preparedAt is long prepared)
            arguments += " --maintenance-apply --prepared-at " + prepared.ToString(culture) +
                " --approve-sha256 " + planSha + " --confirm " + QueueMaintenanceReceipt.Confirmation(action);
        return BuildQueueBundle(scope, arguments);
    }

    internal static string BuildSendmailQueueInventoryBundle(string queue, string nonce, bool reviewable = false,
        bool quarantine = false)
    {
        if (queue is not ("mta" or "msp") || !QueueRetryReview.ValidSha(nonce))
            throw new ArgumentException("Invalid Sendmail queue inventory context.");
        return BuildQueueReadOnlyBundle("sendmail", " --sendmail-inventory " + queue + " --selection-nonce " + nonce +
            (reviewable ? " --sendmail-reviewable" : "") + (quarantine ? " --sendmail-quarantine" : ""));
    }

    internal static string BuildSendmailQueueActionBundle(string queue, string action, string nonce,
        long sampled, string fingerprint, long? prepared = null, string? sha = null)
    {
        SendmailQueueAction.Validate(queue, action, nonce, sampled, fingerprint);
        if ((prepared is null) != (sha is null) || (prepared is long time &&
            (time < Math.Max(1, sampled) || time > 9999999999 ||
             (action != "flush" && time - sampled > 300) || !QueueRetryReview.ValidSha(sha))))
            throw new ArgumentException("Invalid Sendmail approval.");
        var culture = System.Globalization.CultureInfo.InvariantCulture;
        string args = " --sendmail-action " + action + " --sendmail-queue " + queue + " --selection-nonce " + nonce;
        if (action != "flush")
            args += " --sampled-at " + sampled.ToString(culture) + " --target-fingerprint " + fingerprint;
        if (prepared is long t)
            args += " --sendmail-apply --prepared-at " + t.ToString(culture) + " --approve-sha256 " +
                sha + " --confirm " + SendmailQueueAction.Confirmation(action);
        return BuildQueueBundle("sendmail", args);
    }

    internal static string BuildEximQueueInventoryBundle(string nonce)
    {
        if (!QueueRetryReview.ValidSha(nonce)) throw new ArgumentException("Invalid Exim nonce.");
        return BuildQueueReadOnlyBundle("exim", " --exim-inventory --selection-nonce " + nonce);
    }

    internal static string BuildEximQueueActionBundle(string action, string nonce, long sampledAt,
        string fingerprint, long? preparedAt = null, string? planSha = null)
    {
        if (action is not ("freeze" or "thaw" or "retry" or "flush" or "delete") ||
            !QueueRetryReview.ValidSha(nonce) ||
            (action == "flush" ? sampledAt != 0 || fingerprint != "-" :
                !QueueRetryReview.ValidSha(fingerprint) || sampledAt is < 1 or > 9999999999) ||
            (preparedAt is null) != (planSha is null) ||
            (preparedAt is long time && (time < Math.Max(1, sampledAt) ||
                (action != "flush" && time - sampledAt > 300) ||
                time > 9999999999 || !QueueRetryReview.ValidSha(planSha))))
            throw new ArgumentException("Invalid Exim queue action context.");
        var culture = System.Globalization.CultureInfo.InvariantCulture;
        string args = " --exim-action " + action + " --selection-nonce " + nonce;
        if (action != "flush")
            args += " --sampled-at " + sampledAt.ToString(culture) + " --target-fingerprint " + fingerprint;
        if (preparedAt is long prepared)
            args += " --exim-apply --prepared-at " + prepared.ToString(culture) +
                " --approve-sha256 " + planSha + " --confirm " + EximQueueAction.Confirmation(action);
        return BuildQueueBundle("exim", args);
    }

    private static string BuildQueueReadOnlyBundle(string scope, string fixedArguments) =>
        BuildQueueBundle(scope, fixedArguments);

    private static string BuildQueueBundle(string scope, string fixedArguments) =>
        "set -Eeuo pipefail\numask 077\n" +
            "export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C\n" +
            "work=$(mktemp -d /tmp/lmr365-queue.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/inspect-mail-queue.py\" <<'LMR365_QUEUE_READ'\n" +
            Encode(MailQueueInspector) + "\nLMR365_QUEUE_READ\n" +
            "python3 \"$work/inspect-mail-queue.py\" --scope " + scope + fixedArguments + "\n";

    internal static string BuildMailHostInspectionBundle(int? selectedPort = null,
        string currentMta = "unknown")
    {
        if ((selectedPort.HasValue && !SmtpIngressPort.Supported(selectedPort.Value)) ||
            currentMta is not ("postfix" or "exim" or "sendmail" or "none" or "unknown"))
            throw new ArgumentException("Invalid selected SMTP port or discovered MTA.");
        return "set -Eeuo pipefail\numask 077\n" +
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}\nexport PATH\n" +
            "work=$(mktemp -d /tmp/lmr365-mail-host.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/inspect-mail-host.py\" <<'LMR365_MAIL_HOST'\n" +
            Encode(MailHostInspector) + "\nLMR365_MAIL_HOST\n" +
            "base64 -d > \"$work/audit-mail-bindings.py\" <<'LMR365_MAIL_BIND'\n" +
            Encode(MailBindInspector) + "\nLMR365_MAIL_BIND\n" +
            "mail_host_report=$(python3 \"$work/inspect-mail-host.py\" --inspect)\n" +
            "printf '%s\\n' \"$mail_host_report\"\n" +
            "mail_host_ports=$(printf '%s\\n' \"$mail_host_report\" | sed -n 's/^MAIL_HOST_SMTP_CONFIG_PORTS=//p')\n" +
            "test -n \"$mail_host_ports\" || mail_host_ports=unverified\n" +
            "python3 \"$work/audit-mail-bindings.py\" " +
            (selectedPort.HasValue ? "--smtp-port " + selectedPort.Value + " " : "") +
            "--mta " + currentMta +
            " --configured-ports \"$mail_host_ports\"\n";
    }

    internal static string BuildExistingSmtpAuditBundle()
    {
        // No input options or network traffic. Existing Postfix files are only
        // queried for status; NO raw configuration is returned to the GUI.
        return "set -Eeuo pipefail\numask 077\n" +
               "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}\nexport PATH\n" +
               "work=$(mktemp -d /tmp/lmr365-audit.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit-smtp.py\" <<'LMR365_SMTP_AUDIT'\n" +
               Encode(ExistingSmtpAuditScript) + "\nLMR365_SMTP_AUDIT\n" +
               "python3 \"$work/audit-smtp.py\"\n";
    }

    internal static string BuildPublicSmtpBundle(int port, string listener, string dns,
        string operation = "check", string? expectedSha = null, bool approved = false)
    {
        if (!SmtpIngressPort.Supported(port))
            throw new ArgumentOutOfRangeException(nameof(port));
        if (operation is not ("check" or "apply" or "status" or "restore"))
            throw new ArgumentException("Unsupported public SMTP operation.");
        if (!Regex.IsMatch(listener, @"\A(?:[0-9]{1,3}\.){3}[0-9]{1,3}\z") ||
            !Regex.IsMatch(dns,
                @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z"))
            throw new ArgumentException("Explicit private listener IPv4 and exact certificate DNS name required.");
        if (operation is "apply" or "restore")
        {
            if (expectedSha is null || !Regex.IsMatch(expectedSha, @"\A[a-f0-9]{64}\z"))
                throw new ArgumentException("Public SMTP requires reviewed configuration SHA-256.");
            if (operation == "apply" && !approved)
                throw new InvalidOperationException("Security acceptance and abuse-control testing required.");
        }
        else if (expectedSha is not null)
            throw new ArgumentException("Unexpected public SMTP configuration SHA.");
        string args = (operation switch
        {
            "apply" => "--apply", "status" => "--status", "restore" => "--restore", _ => "--check-only"
        }) + " --smtp-port " + port + " --listen-ip " + listener + " --server-name " + dns;
        if (operation is "apply" or "restore")
        {
            args += " --expect-main-sha256 " + expectedSha + " --confirm " +
                (operation == "apply" ? "ENABLE_REVIEWED_PUBLIC_AUTH_SUBMISSION" : "RESTORE_PRIVATE_SMTP_ACCESS");
            if (operation == "apply")
                args += " --risk-attestation TESTED_BANS_AND_PUBLIC_EXPOSURE";
        }
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-public-smtp.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/public.py\" <<'LMR365_PUBLIC_SMTP'\n" +
               Encode(PublicSmtpManager) + "\nLMR365_PUBLIC_SMTP\n" +
               "python3 \"$work/public.py\" " + args + "\n";
    }

    internal static string BuildNetworkFirewallBundle(string[] args)
    {
        foreach (string item in args)
        {
            if (item.Length > 320 || item.Any(c => !(char.IsAsciiLetterOrDigit(c) ||
                c is '.' or '-' or '_' or '/' or ':' or '@')))
                throw new ArgumentException("Invalid network/firewall argument.");
        }
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-network.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/network-firewall.sh\" <<'LMR365_NETWORK'\n" +
               Encode(NetworkFirewall) + "\nLMR365_NETWORK\n" +
               "bash \"$work/network-firewall.sh\" " + string.Join(" ", args) + "\n";
    }

    internal static string BuildTlsIdentityProbeBundle(int selectedPort, string serverName, string? linuxCaFile)
    {
        if (!SmtpIngressPort.Supported(selectedPort))
            throw new ArgumentOutOfRangeException(nameof(selectedPort));
        if (serverName.Length is < 4 or > 253 ||
            !Regex.IsMatch(serverName,
                @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z"))
            throw new ArgumentException("SMTP TLS verification requires an exact DNS name from the server certificate.");
        if (!string.IsNullOrWhiteSpace(linuxCaFile) &&
            (linuxCaFile.Length > 256 ||
             !Regex.IsMatch(linuxCaFile, @"\A/[A-Za-z0-9_./-]+\z") ||
             linuxCaFile.Split('/').Contains("..")))
            throw new ArgumentException("The Linux CA file must be a safe absolute path.");
        string caArg = string.IsNullOrWhiteSpace(linuxCaFile)
            ? "" : " --ca-file " + linuxCaFile;
        // The protocol test performs STARTTLS against 127.0.0.1 ONLY, but
        // authenticates the certificate for serverName via DNS/SNI.
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-tls-identity.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/tls.py\" <<'LMR365_TLS_IDENTITY'\n" +
               Encode(TlsIdentityProbe) + "\nLMR365_TLS_IDENTITY\n" +
               "python3 \"$work/tls.py\" --smtp-port " + selectedPort +
               " --server-name " + serverName + caArg + "\n";
    }

    internal static string BuildAuthArchiveAuditBundle()
    {
        // Read-only root-owned archive metadata, never expose backup files,
        // salted hashes, TLS keys or credential contents over SSH.
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-archive-audit.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit.py\" <<'LMR365_ARCHIVE_AUDIT'\n" +
               Encode(AuthArchiveAudit) + "\nLMR365_ARCHIVE_AUDIT\n" +
               "python3 \"$work/audit.py\"\n";
    }

    internal static string BuildInstalledSidecarAuditBundle(int selectedPort)
    {
        if (!SmtpIngressPort.Supported(selectedPort))
            throw new ArgumentOutOfRangeException(nameof(selectedPort));
        // The audit only queries local instance metadata and a loopback SMTP
        // greeting. It never authenticates, queues mail or changes firewall.
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-sidecar-audit.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit.py\" <<'LMR365_INSTALLED_AUDIT'\n" +
               Encode(InstalledSidecarAudit) + "\nLMR365_INSTALLED_AUDIT\n" +
               "python3 \"$work/audit.py\" --smtp-port " + selectedPort + "\n";
    }

    internal static string BuildAuthTlsRestoreBundle(int selectedPort, string? expectedMainSha = null)
    {
        if (!SmtpIngressPort.Supported(selectedPort))
            throw new ArgumentOutOfRangeException(nameof(selectedPort));
        if (expectedMainSha is not null &&
            !Regex.IsMatch(expectedMainSha, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Invalid expected isolated Postfix SHA-256.");
        string args = expectedMainSha is null
            ? "--check-only --smtp-port " + selectedPort
            : "--restore --smtp-port " + selectedPort +
              " --expect-main-sha256 " + expectedMainSha +
              " --confirm RESTORE_TRUSTED_NETWORK_SMTP";
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-auth-restore.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/restore-auth.sh\" <<'LMR365_AUTH_RESTORE'\n" +
               Encode(AuthTlsRestore) + "\nLMR365_AUTH_RESTORE\n" +
               "bash \"$work/restore-auth.sh\" " + args + "\n";
    }

    internal static string BuildAuthTlsBundle(string[] args)
    {
        // The Linux SSH script receives Linux FILE PATHS only, never the actual
        // SMTP password, salted hash or TLS private key content.
        foreach (string item in args)
        {
            if (item.Length is < 1 or > 320 ||
                item.Any(c => !(char.IsAsciiLetterOrDigit(c) ||
                    c is '.' or '-' or '_' or '@' or ':' or '/')))
                throw new ArgumentException("Invalid SMTP AUTH/TLS argument.");
        }
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-auth-tls.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/enable-auth-tls.sh\" <<'LMR365_AUTH_TLS'\n" +
               Encode(AuthTlsInstaller) + "\nLMR365_AUTH_TLS\n" +
               "bash \"$work/enable-auth-tls.sh\" " + string.Join(" ", args) + "\n";
    }

    internal static string BuildTlsRotationBundle(int selectedPort, string serverName,
        string certificate, string privateKey, string? trustCaFile, string? expectedCertSha = null)
    {
        if (!SmtpIngressPort.Supported(selectedPort))
            throw new ArgumentOutOfRangeException(nameof(selectedPort));
        if (!Regex.IsMatch(serverName,
             @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z"))
            throw new ArgumentException("Enter a valid TLS server DNS name.");
        foreach (string candidate in new[] { certificate, privateKey, trustCaFile ?? "" })
        {
            if (candidate.Length == 0) continue;
            if (candidate.Length > 256 ||
                !Regex.IsMatch(candidate, @"\A/[A-Za-z0-9_./-]+\z") ||
                candidate.Split('/').Contains(".."))
                throw new ArgumentException("Enter a safe absolute Linux certificate/key/CA path.");
        }
        if (string.IsNullOrWhiteSpace(certificate) || string.IsNullOrWhiteSpace(privateKey))
            throw new ArgumentException("Enter the new public TLS certificate and private-key Linux paths.");
        if (expectedCertSha is not null &&
            !Regex.IsMatch(expectedCertSha, @"\A[a-f0-9]{64}\z"))
            throw new ArgumentException("Invalid preflight certificate fingerprint.");
        string args = (expectedCertSha is null ? "--check-only" : "--apply") +
                      " --smtp-port " + selectedPort + " --server-name " + serverName +
                      " --tls-cert " + certificate + " --tls-key " + privateKey;
        if (!string.IsNullOrWhiteSpace(trustCaFile)) args += " --ca-file " + trustCaFile;
        if (expectedCertSha is not null)
            args += " --expect-cert-sha256 " + expectedCertSha +
                    " --confirm ROTATE_PRIVATE_SMTP_TLS";
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-tls-rotate.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/rotate.sh\" <<'LMR365_TLS_ROTATE'\n" +
               Encode(SidecarTlsRotator) + "\nLMR365_TLS_ROTATE\n" +
               "base64 -d > \"$work/verify-sidecar-tls-identity.py\" <<'LMR365_TLS_VERIFY'\n" +
               Encode(TlsIdentityProbe) + "\nLMR365_TLS_VERIFY\n" +
               "bash \"$work/rotate.sh\" " + args + "\n";
    }

    internal static string BuildFromOwnerGuardBundle(int port, string senderOwnerFile,
        string? expectedOwnerSha = null, string? expectedEngineSha = null)
    {
        if (!SmtpIngressPort.Supported(port))
            throw new ArgumentOutOfRangeException(nameof(port));
        if (string.IsNullOrWhiteSpace(senderOwnerFile) || senderOwnerFile.Length > 255 ||
            !Regex.IsMatch(senderOwnerFile, @"\A/[A-Za-z0-9_./-]{1,255}\z",
                RegexOptions.CultureInvariant) ||
            senderOwnerFile.Split('/').Contains(".."))
            throw new ArgumentException("Use a root-owned 0600 sender-owner map on Linux.");
        bool apply = expectedOwnerSha is not null || expectedEngineSha is not null;
        if (apply && (expectedOwnerSha is null || expectedEngineSha is null ||
            !Regex.IsMatch(expectedOwnerSha, @"\A[a-f0-9]{64}\z",
                RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(expectedEngineSha, @"\A[a-f0-9]{64}\z",
                RegexOptions.CultureInvariant)))
            throw new ArgumentException("Both reviewed policy and filter SHA-256 are required.");
        string args = (apply ? "--apply" : "--check-only") +
            " --smtp-port " + port +
            " --owner-file " + senderOwnerFile +
            " --engine-file \"$work/engine.py\"";
        if (apply)
            args += " --expect-owner-sha256 " + expectedOwnerSha +
                    " --expect-engine-sha256 " + expectedEngineSha +
                    " --confirm ACTIVATE_PRIVATE_FROM_OWNER_GUARD";
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-from-owner.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/engine.py\" <<'LMR365_FROM_OWNER_ENGINE'\n" +
               Encode(FromOwnerMilter) + "\nLMR365_FROM_OWNER_ENGINE\n" +
               "base64 -d > \"$work/install.sh\" <<'LMR365_FROM_OWNER_INSTALL'\n" +
               Encode(FromOwnerGuardInstaller) + "\nLMR365_FROM_OWNER_INSTALL\n" +
               "bash \"$work/install.sh\" " + args + "\n";
    }

    internal static string BuildEopRouteBundle(int port, string mode, string mxHost,
        string fixedSender, string acceptedDomain, string publicIp, string certPath,
        string keyPath, string? expectedMainSha = null, bool restore = false,
        bool status = false, bool connectorApproved = false,
        string senderPolicy = "fixed-mailbox", string senderOwnerFile = "",
        string? expectedOwnerSha = null)
    {
        if (!SmtpIngressPort.Supported(port))
            throw new ArgumentOutOfRangeException(nameof(port));
        if (status && (restore || expectedMainSha is not null))
            throw new ArgumentException("Invalid EOP route action.");
        if (expectedMainSha is not null &&
            !Regex.IsMatch(expectedMainSha, @"\A[a-f0-9]{64}\z"))
            throw new ArgumentException("Invalid reviewed Postfix main.cf SHA-256.");

        string args;
        if (status)
            args = "--status --smtp-port " + port;
        else if (restore)
        {
            if (expectedMainSha is null) throw new ArgumentException("Restore requires a reviewed fingerprint.");
            args = "--restore --smtp-port " + port +
                   " --expect-main-sha256 " + expectedMainSha +
                   " --confirm RESTORE_PRIVATE_EOP_ROUTE";
        }
        else
        {
            const string dns = @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z";
            const string email = @"\A[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9.-]{4,253}\z";
            if (senderPolicy is not ("fixed-mailbox" or "preserve-domain" or "masquerade") ||
                (mode == "direct-send" && senderPolicy != "fixed-mailbox") ||
                mode is not ("direct-send" or "connector") ||
                !Regex.IsMatch(mxHost, dns, RegexOptions.CultureInvariant) ||
                !mxHost.EndsWith(".mail.protection.outlook.com", StringComparison.OrdinalIgnoreCase) ||
                !Regex.IsMatch(acceptedDomain, dns, RegexOptions.CultureInvariant) ||
                !Regex.IsMatch(fixedSender, email, RegexOptions.CultureInvariant) ||
                !fixedSender.EndsWith("@" + acceptedDomain, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Enter exact Microsoft 365 MX, allowed domain and fixed sender.");
            if (!string.IsNullOrEmpty(publicIp) &&
                !Regex.IsMatch(publicIp, @"\A[0-9.]{7,15}\z"))
                throw new ArgumentException("Static IPv4 must be four decimal octets.");
            foreach (var path in new[] { certPath, keyPath })
                if (!string.IsNullOrEmpty(path) &&
                    (!Regex.IsMatch(path, @"\A/[A-Za-z0-9_./-]{1,255}\z") ||
                     path.Split('/').Contains("..")))
                    throw new ArgumentException("Invalid absolute Linux certificate path.");
            if (senderPolicy != "fixed-mailbox" && mode == "connector")
            {
                if (expectedMainSha is not null &&
                    (expectedOwnerSha is null || !Regex.IsMatch(expectedOwnerSha, @"\A[a-f0-9]{64}\z")))
                    throw new ArgumentException("Reviewed sender-owner SHA-256 required for Apply.");
                if (string.IsNullOrEmpty(senderOwnerFile) || senderOwnerFile.Length > 255 ||
                    !Regex.IsMatch(senderOwnerFile, @"\A/[A-Za-z0-9_./-]{1,255}\z") ||
                    senderOwnerFile.Split('/').Contains(".."))
                    throw new ArgumentException("Connector sender preservation needs Linux root-owned sender-login map path.");
            }
            else if (!string.IsNullOrEmpty(senderOwnerFile) || expectedOwnerSha is not null)
                throw new ArgumentException("Sender login map is for Connector preserve/masquerade only.");
            if (mode == "connector" && expectedMainSha is not null && !connectorApproved)
                throw new InvalidOperationException("Confirm the existing tenant Connector first.");
            args = (expectedMainSha is null ? "--check-only" : "--apply") +
                   " --smtp-port " + port + " --mode " + mode +
                   " --mx-host " + mxHost + " --sender " + fixedSender +
                   " --recipient-domain " + acceptedDomain +
                   " --sender-policy " + senderPolicy;
            if (!string.IsNullOrEmpty(senderOwnerFile)) args += " --sender-owner-file " + senderOwnerFile;
            if (expectedOwnerSha is not null) args += " --expect-owner-sha256 " + expectedOwnerSha;
            if (!string.IsNullOrEmpty(publicIp)) args += " --public-ip " + publicIp;
            if (!string.IsNullOrEmpty(certPath)) args += " --tls-cert " + certPath;
            if (!string.IsNullOrEmpty(keyPath)) args += " --tls-key " + keyPath;
            if (expectedMainSha is not null)
            {
                args += " --expect-main-sha256 " + expectedMainSha +
                        " --confirm DEPLOY_PRIVATE_EOP_ROUTE";
                if (mode == "connector")
                    args += " --connector-attestation TENANT_CONNECTOR_CHECKED";
            }
        }
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-eop-route.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/route.py\" <<'LMR365_EOP_ROUTE'\n" +
               Encode(EopRouteManager) + "\nLMR365_EOP_ROUTE\n" +
               "python3 \"$work/route.py\" " + args + "\n";
    }

    internal static string BuildOutboundModePreflightBundle(string mode, int customPort,
        string mxHost, string acceptedDomain, string publicIpv4, string linuxCert, bool checkNetwork)
    {
        if (mode is not ("connector" or "direct-send") ||
            !SmtpIngressPort.Supported(customPort))
            throw new ArgumentException("Invalid Microsoft 365 outbound plan.");
        const string dns = @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z";
        if (!Regex.IsMatch(mxHost, dns, RegexOptions.CultureInvariant) ||
            !mxHost.EndsWith(".mail.protection.outlook.com", StringComparison.OrdinalIgnoreCase) ||
            !Regex.IsMatch(acceptedDomain, dns, RegexOptions.CultureInvariant))
            throw new ArgumentException("Enter a Microsoft 365 MX endpoint and accepted domain.");
        if (!string.IsNullOrWhiteSpace(publicIpv4) &&
            !System.Net.IPAddress.TryParse(publicIpv4, out _))
            throw new ArgumentException("Invalid outbound public IPv4.");
        if (!string.IsNullOrWhiteSpace(linuxCert) &&
            (!Regex.IsMatch(linuxCert, @"\A/[A-Za-z0-9_./-]{1,255}\z") ||
             linuxCert.Split('/').Contains("..")))
            throw new ArgumentException("Invalid Linux connector certificate path.");
        string args = "--mode " + mode + " --smtp-port " + customPort +
                      " --mx-host " + mxHost + " --accepted-domain " + acceptedDomain;
        if (!string.IsNullOrWhiteSpace(publicIpv4)) args += " --public-ip " + publicIpv4;
        if (!string.IsNullOrWhiteSpace(linuxCert)) args += " --cert-file " + linuxCert;
        if (checkNetwork) args += " --check-network";
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-outbound-plan.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/plan.py\" <<'LMR365_OUTBOUND'\n" +
               Encode(OutboundModePreflight) + "\nLMR365_OUTBOUND\n" +
               "python3 \"$work/plan.py\" " + args + "\n";
    }

    internal static string BuildRebootContinuityBundle(int selectedPort, bool prepare)
    {
        if (!SmtpIngressPort.Supported(selectedPort))
            throw new ArgumentOutOfRangeException(nameof(selectedPort));
        string mode = prepare ? "--record-baseline" : "--verify-after-reboot";
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-reboot-continuity.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/check.py\" <<'LMR365_REBOOT_CHECK'\n" +
               Encode(RebootContinuity) + "\nLMR365_REBOOT_CHECK\n" +
               "python3 \"$work/check.py\" " + mode +
               " --smtp-port " + selectedPort + "\n";
    }

    internal static string BuildHealthMonitorBundle(int selectedPort, bool install)
    {
        if (!SmtpIngressPort.Supported(selectedPort))
            throw new ArgumentOutOfRangeException(nameof(selectedPort));
        string args = install
            ? "--install --smtp-port " + selectedPort + " --confirm ENABLE_PRIVATE_SMTP_MONITOR"
            : "--check-only --smtp-port " + selectedPort;
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-health-monitor.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/install.sh\" <<'LMR365_HEALTH_TIMER'\n" +
               Encode(HealthMonitorInstaller) + "\nLMR365_HEALTH_TIMER\n" +
               "base64 -d > \"$work/relay-health.py\" <<'LMR365_HEALTH_PROBE'\n" +
               Encode(RelayHealth) + "\nLMR365_HEALTH_PROBE\n" +
               "bash \"$work/install.sh\" " + args + "\n";
    }

    internal static string BuildM365DnsAuditBundle(string domain, string mxHost = "")
    {
        if (domain.Length is < 4 or > 253 ||
            !Regex.IsMatch(domain,
                @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z"))
            throw new ArgumentException("Exact accepted-domain DNS name required.");
        if (!string.IsNullOrEmpty(mxHost) &&
            (mxHost.Length > 253 || !Regex.IsMatch(mxHost,
                @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.mail\.protection\.outlook\.com\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)))
            throw new ArgumentException("Invalid EOP MX hostname.");
        string args = "--domain " + domain.ToLowerInvariant();
        if (mxHost.Length > 0)
            args += " --mx-host " + mxHost.ToLowerInvariant();
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-dns-audit.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/dns.py\" <<'LMR365_DNS_AUDIT'\n" +
               Encode(M365DnsAudit) + "\nLMR365_DNS_AUDIT\n" +
               "python3 \"$work/dns.py\" " + args + "\n";
    }

    internal static string BuildHealthAlertsBundle(int port, string action, string? configSha = null)
    {
        if (!SmtpIngressPort.Supported(port))
            throw new ArgumentOutOfRangeException(nameof(port));
        if (action is not ("check" or "enable" or "disable" or "status"))
            throw new ArgumentException("Unsupported health alert operation.");
        if (action == "enable")
        {
            if (configSha is null || !Regex.IsMatch(configSha, @"\A[a-f0-9]{64}\z"))
                throw new ArgumentException("Reviewed webhook configuration SHA-256 required.");
        }
        else if (configSha is not null)
            throw new ArgumentException("Unexpected webhook configuration hash.");
        string operation = action switch
        {
            "enable" => "--enable", "disable" => "--disable",
            "status" => "--status", _ => "--check-only"
        };
        string args = operation + " --smtp-port " + port;
        if (action == "enable")
            args += " --expect-config-sha256 " + configSha +
                    " --confirm ENABLE_SMTP_HEALTH_WEBHOOK";
        if (action == "disable")
            args += " --confirm DISABLE_SMTP_HEALTH_WEBHOOK";
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-health-alerts.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/health-alerts.py\" <<'LMR365_HEALTH_ALERTS'\n" +
               Encode(HealthAlerts) + "\nLMR365_HEALTH_ALERTS\n" +
               "python3 \"$work/health-alerts.py\" " + args + "\n";
    }

    internal static string BuildRelayHealthBundle(int selectedPort)
    {
        if (!SmtpIngressPort.Supported(selectedPort))
            throw new ArgumentOutOfRangeException(nameof(selectedPort));
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-health.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/health.py\" <<'LMR365_HEALTH'\n" +
               Encode(RelayHealth) + "\nLMR365_HEALTH\n" +
               "python3 \"$work/health.py\" --smtp-port " + selectedPort + "\n";
    }

    internal static string BuildSmtpCredentialGeneratorBundle(string username, bool generate)
    {
        if (!Regex.IsMatch(username, @"\A[A-Za-z0-9][A-Za-z0-9._@-]{2,63}\z"))
            throw new ArgumentException("SMTP account name must have 3-64 safe ASCII characters.");
        var option = generate ? "--generate --confirm GENERATE_ONE_TIME_SMTP_PASSWORD" : "--check-only";
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-smtp-secret.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/generate.py\" <<'LMR365_SMTP_SECRET'\n" +
               Encode(SmtpCredentialGenerator) + "\nLMR365_SMTP_SECRET\n" +
               "python3 \"$work/generate.py\" " + option + " --username " + username + "\n";
    }

    internal static string BuildSmtpAccountManagerBundle(
        int selectedPort, string operation, string username, string? hashPath, string? stateSha = null)
    {
        if (!SmtpIngressPort.Supported(selectedPort))
            throw new ArgumentOutOfRangeException(nameof(selectedPort));
        if (operation is not ("add" or "rotate" or "revoke" or "status"))
            throw new ArgumentException("Unsupported client account change.");
        if (operation != "status" && !Regex.IsMatch(username,
             @"\A[A-Za-z0-9][A-Za-z0-9._@-]{2,63}\z"))
            throw new ArgumentException("Invalid SMTP client username.");
        if (operation is "add" or "rotate")
        {
            if (string.IsNullOrWhiteSpace(hashPath) || hashPath.Length > 256 ||
                !Regex.IsMatch(hashPath, @"\A/[A-Za-z0-9_./-]+\z") ||
                hashPath.Split('/').Contains(".."))
                throw new ArgumentException("Invalid root-protected hash source path on Linux.");
        }
        if (stateSha is not null && !Regex.IsMatch(stateSha, @"\A[a-f0-9]{64}\z"))
            throw new ArgumentException("Invalid expected account file SHA-256.");
        string args = "--smtp-port " + selectedPort + " --operation " + operation;
        if (operation != "status") args += " --username " + username;
        if (operation is "add" or "rotate") args += " --hash-file " + hashPath;
        if (stateSha is not null)
            args += " --apply --expected-state-sha256 " + stateSha +
                    " --confirm CHANGE_PRIVATE_SMTP_ACCOUNT";
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-account-change.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/manage.py\" <<'LMR365_ACCOUNTS'\n" +
               Encode(SmtpAccountManager) + "\nLMR365_ACCOUNTS\n" +
               "python3 \"$work/manage.py\" " + args + "\n";
    }

    internal static string BuildRhelEnforcingLiveSmokeBundle(int port, string serverDns, string linuxCa = "")
    {
        if (!SmtpIngressPort.Supported(port) ||
            serverDns.Length is < 4 or > 253 ||
            !Regex.IsMatch(serverDns,
                @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z"))
            throw new ArgumentException("Use exact installed custom port and TLS DNS hostname.");
        if (!string.IsNullOrEmpty(linuxCa) &&
            (!Regex.IsMatch(linuxCa, @"\A/[A-Za-z0-9_./-]{1,255}\z") ||
             linuxCa.Split('/').Contains("..")))
            throw new ArgumentException("Invalid reviewed Linux CA path.");
        string args = "--smtp-port " + port + " --server-name " + serverDns.ToLowerInvariant();
        if (linuxCa.Length > 0) args += " --ca-file " + linuxCa;
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-enforcing.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/probe.py\" <<'LMR365_ENFORCING_PROBE'\n" +
               Encode(RhelEnforcingLiveSmoke) + "\nLMR365_ENFORCING_PROBE\n" +
               "python3 \"$work/probe.py\" " + args + "\n";
    }

    internal static string BuildRhelSelinuxDoctorBundle(int selectedPort)
    {
        if (!SmtpIngressPort.Supported(selectedPort))
            throw new ArgumentOutOfRangeException(nameof(selectedPort));
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-selinux-doctor.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/doctor.py\" <<'LMR365_RHEL_SELINUX'\n" +
               Encode(RhelSelinuxDoctor) + "\nLMR365_RHEL_SELINUX\n" +
               "python3 \"$work/doctor.py\" --smtp-port " + selectedPort + "\n";
    }

    internal static string BuildRhelSelinuxPortBundle(int selectedPort, string operation = "check",
        string? expectedSha = null)
    {
        if (!SmtpIngressPort.Supported(selectedPort))
            throw new ArgumentOutOfRangeException(nameof(selectedPort));
        if (operation is not ("check" or "apply" or "status" or "restore"))
            throw new ArgumentException("Unsupported SELinux port action.");
        if (operation is "apply" or "restore")
        {
            if (expectedSha is null || !Regex.IsMatch(expectedSha, @"\A[a-f0-9]{64}\z"))
                throw new ArgumentException("Reviewed policy SHA-256 is required.");
        }
        else if (expectedSha is not null)
            throw new ArgumentException("Unexpected SELinux policy fingerprint.");
        string args = (operation switch
        {
            "apply" => "--apply",
            "status" => "--status",
            "restore" => "--restore",
            _ => "--check-only"
        }) + " --smtp-port " + selectedPort;
        if (operation is "apply" or "restore")
            args += " --expect-policy-sha256 " + expectedSha +
                " --confirm " + (operation == "apply" ? "ADD_REVIEWED_RHEL_SMTP_PORT" :
                    "REMOVE_MANAGED_RHEL_SMTP_PORT");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-selinux-port.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/selinux-port.py\" <<'LMR365_PORT_POLICY'\n" +
               Encode(RhelSelinuxPortManager) + "\nLMR365_PORT_POLICY\n" +
               "python3 \"$work/selinux-port.py\" " + args + "\n";
    }

    internal static string BuildMtaCoexistenceBundle(int port)
    {
        if (!SmtpIngressPort.Supported(port))
            throw new ArgumentOutOfRangeException(nameof(port));
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-mta-audit.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/mta.py\" <<'LMR365_MTA_AUDIT'\n" +
               Encode(MtaCoexistenceDoctor) + "\nLMR365_MTA_AUDIT\n" +
               "python3 \"$work/mta.py\" --smtp-port " + port + "\n";
    }

    internal static string BuildPlatformCompatBundle(int smtpPort)
    {
        if (!SmtpIngressPort.Supported(smtpPort))
            throw new ArgumentOutOfRangeException(nameof(smtpPort));
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-platform.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/platform-compat.py\" <<'LMR365_PLATFORM'\n" +
               Encode(PlatformCompat) + "\nLMR365_PLATFORM\n" +
               "python3 \"$work/platform-compat.py\" --smtp-port " + smtpPort.ToString() + "\n";
    }

    internal static string BuildForeignMtaBackupBundle(string mta,
        string action, string? backupId = null)
    {
        if (mta is not ("exim" or "sendmail") ||
            action is not ("backup" or "list" or "verify" or
                           "preview-recovery" or "offline-preflight" or "export-offline"))
            throw new ArgumentException("Unsupported foreign MTA backup operation.");
        bool selected = action is ("verify" or "preview-recovery" or "offline-preflight" or "export-offline");
        if (selected != (backupId is not null) ||
            (backupId is not null && !Regex.IsMatch(backupId,
                @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z",
                RegexOptions.CultureInvariant)))
            throw new ArgumentException("A checked backup identifier is required for the selected operation.");
        string operation = action switch
        {
            "backup" => "--backup",
            "list" => "--list",
            "preview-recovery" => "--preview-recovery " + backupId,
            "offline-preflight" => "--offline-preflight " + backupId,
            "export-offline" => "--export-offline " + backupId +
                " --confirm EXTRACT_VERIFIED_FOREIGN_MTA_SNAPSHOT",
            _ => "--verify " + backupId
        };
        return "set -Eeuo pipefail\numask 077\n" +
            "work=$(mktemp -d /tmp/lmr365-foreign-backup.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/foreign-mta-config-backup.py\" <<'LMR365_FOREIGN_BACKUP'\n" +
            Encode(ForeignMtaBackup) + "\nLMR365_FOREIGN_BACKUP\n" +
            "python3 \"$work/foreign-mta-config-backup.py\" --mta " + mta +
            " " + operation + "\n";
    }

    internal static string BuildForeignMtaNativeCheckBundle(string mta)
    {
        if (mta is not ("exim" or "sendmail"))
            throw new ArgumentException("Verified Exim/Sendmail selection is required.");
        // The independent read-only CLI mode never accepts a restore ID,
        // confirmation, SHA approval or a write switch from Windows.
        return "set -Eeuo pipefail\numask 077\n" +
            "work=$(mktemp -d /tmp/lmr365-foreign-static.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/foreign-mta-config-backup.py\" <<'LMR365_NATIVE_BACKUP_LIB'\n" +
            Encode(ForeignMtaBackup) + "\nLMR365_NATIVE_BACKUP_LIB\n" +
            "base64 -d > \"$work/restore-foreign-mta-config.py\" <<'LMR365_NATIVE_STATIC'\n" +
            Encode(ForeignMtaRestore) + "\nLMR365_NATIVE_STATIC\n" +
            "python3 \"$work/restore-foreign-mta-config.py\" --mta " + mta +
            " --static-check\n";
    }

    internal static string BuildSendmailV2RestoreApplyBundle(string backupId, string sha)
    {
        if (!Regex.IsMatch(backupId ?? "", @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("A verified Sendmail v2 archive is required.");
        RequireSendmailV2Sha(sha);
        return BuildSendmailV2RecoveryBundle(" --sendmail-v2-apply " + backupId +
            " --approve-sha256 " + sha + " --confirm " + SendmailV2RecoveryReceipt.RestoreConfirmation);
    }

    internal static string BuildSendmailV2RollbackPlanBundle() =>
        BuildSendmailV2RecoveryBundle(" --sendmail-v2-rollback-plan");

    internal static string BuildSendmailV2RollbackApplyBundle(string sha)
    {
        RequireSendmailV2Sha(sha);
        return BuildSendmailV2RecoveryBundle(" --sendmail-v2-rollback-apply --approve-sha256 " + sha +
            " --confirm " + SendmailV2RecoveryReceipt.RollbackConfirmation);
    }

    private static void RequireSendmailV2Sha(string sha)
    {
        if (!Regex.IsMatch(sha ?? "", @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("An exact reviewed Sendmail v2 SHA-256 is required.");
    }

    // Callers can use only the three validated fixed-action builders above.
    private static string BuildSendmailV2RecoveryBundle(string command) =>
        "set -Eeuo pipefail\numask 077\n" +
        "work=$(mktemp -d /tmp/lmr365-sendmail-v2-recovery.XXXXXXXX)\n" +
        "trap 'rm -rf -- \"$work\"' EXIT\n" +
        "base64 -d > \"$work/foreign-mta-config-backup.py\" <<'LMR365_V2_RECOVERY_BACKUP'\n" +
        Encode(ForeignMtaBackup) + "\nLMR365_V2_RECOVERY_BACKUP\n" +
        "base64 -d > \"$work/restore-foreign-mta-config.py\" <<'LMR365_V2_RECOVERY_NATIVE'\n" +
        Encode(ForeignMtaRestore) + "\nLMR365_V2_RECOVERY_NATIVE\n" +
        "python3 \"$work/restore-foreign-mta-config.py\" --mta sendmail" + command + "\n";

    internal static string BuildSendmailV2ReviewBundle(string backupId)
    {
        if (!Regex.IsMatch(backupId ?? "", @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("A verified Sendmail v2 backup ID is required.");
        return "set -Eeuo pipefail\numask 077\n" +
            "work=$(mktemp -d /tmp/lmr365-sendmail-v2.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/foreign-mta-config-backup.py\" <<'LMR365_V2_BACKUP'\n" +
            Encode(ForeignMtaBackup) + "\nLMR365_V2_BACKUP\n" +
            "base64 -d > \"$work/restore-foreign-mta-config.py\" <<'LMR365_V2_NATIVE'\n" +
            Encode(ForeignMtaRestore) + "\nLMR365_V2_NATIVE\n" +
            "python3 \"$work/restore-foreign-mta-config.py\" --mta sendmail --sendmail-v2-plan " + backupId + "\n";
    }

    internal static string BuildEximNativeRestoreApplyBundle(string backupId, string reviewedSha256)
    {
        if (backupId is null ||
            !Regex.IsMatch(backupId, @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z", RegexOptions.CultureInvariant) ||
            reviewedSha256 is null ||
            !Regex.IsMatch(reviewedSha256, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("A verified Exim archive and exact reviewed SHA-256 are required.");
        return "set -Eeuo pipefail\numask 077\n" +
            "work=$(mktemp -d /tmp/lmr365-exim-restore.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/foreign-mta-config-backup.py\" <<'LMR365_EXIM_RESTORE_BACKUP'\n" +
            Encode(ForeignMtaBackup) + "\nLMR365_EXIM_RESTORE_BACKUP\n" +
            "base64 -d > \"$work/restore-foreign-mta-config.py\" <<'LMR365_EXIM_RESTORE_NATIVE'\n" +
            Encode(ForeignMtaRestore) + "\nLMR365_EXIM_RESTORE_NATIVE\n" +
            "python3 \"$work/restore-foreign-mta-config.py\" --mta exim --apply " + backupId +
            " --approve-sha256 " + reviewedSha256 +
            " --confirm RESTORE_STOPPED_FOREIGN_MTA_CONFIG\n";
    }

    internal static string BuildEximPendingRollbackPlanBundle() =>
        BuildEximPendingRollbackBundle(null);

    internal static string BuildEximPendingRollbackApplyBundle(string reviewedSha256)
    {
        if (reviewedSha256 is null ||
            !Regex.IsMatch(reviewedSha256, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("A reviewed Exim rollback SHA-256 is required.");
        return BuildEximPendingRollbackBundle(reviewedSha256);
    }

    private static string BuildEximPendingRollbackBundle(string? reviewedSha256)
    {
        string command = reviewedSha256 is null ? " --pending-rollback-plan" :
            " --pending-rollback-apply --approve-sha256 " + reviewedSha256 +
            " --confirm ROLLBACK_INTERRUPTED_EXIM_CONFIG";
        return "set -Eeuo pipefail\numask 077\n" +
            "work=$(mktemp -d /tmp/lmr365-exim-rollback.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/foreign-mta-config-backup.py\" <<'LMR365_ROLLBACK_BACKUP'\n" +
            Encode(ForeignMtaBackup) + "\nLMR365_ROLLBACK_BACKUP\n" +
            "base64 -d > \"$work/restore-foreign-mta-config.py\" <<'LMR365_ROLLBACK_NATIVE'\n" +
            Encode(ForeignMtaRestore) + "\nLMR365_ROLLBACK_NATIVE\n" +
            "python3 \"$work/restore-foreign-mta-config.py\" --mta exim" + command + "\n";
    }

    internal static string BuildForeignMtaPendingInspectBundle()
    {
        // The CLI requires an MTA argument for compatibility. Pending
        // inspection is global and takes the real MTA from the marker.
        // There is deliberately no caller-controlled command or selector.
        return "set -Eeuo pipefail\numask 077\n" +
            "work=$(mktemp -d /tmp/lmr365-foreign-pending.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/foreign-mta-config-backup.py\" <<'LMR365_PENDING_BACKUP'\n" +
            Encode(ForeignMtaBackup) + "\nLMR365_PENDING_BACKUP\n" +
            "base64 -d > \"$work/restore-foreign-mta-config.py\" <<'LMR365_PENDING_NATIVE'\n" +
            Encode(ForeignMtaRestore) + "\nLMR365_PENDING_NATIVE\n" +
            "python3 \"$work/restore-foreign-mta-config.py\" --mta exim --pending-inspect\n";
    }

    internal static string BuildForeignMtaRestorePlanBundle(string mta, string backupId)
    {
        if (mta is not ("exim" or "sendmail") ||
            !Regex.IsMatch(backupId ?? "", @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("A verified native MTA and backup ID are required.");
        return "set -Eeuo pipefail\numask 077\n" +
            "work=$(mktemp -d /tmp/lmr365-foreign-plan.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/foreign-mta-config-backup.py\" <<'LMR365_PLAN_BACKUP'\n" +
            Encode(ForeignMtaBackup) + "\nLMR365_PLAN_BACKUP\n" +
            "base64 -d > \"$work/restore-foreign-mta-config.py\" <<'LMR365_PLAN_NATIVE'\n" +
            Encode(ForeignMtaRestore) + "\nLMR365_PLAN_NATIVE\n" +
            "python3 \"$work/restore-foreign-mta-config.py\" --mta " + mta +
            " --plan " + backupId + "\n";
    }

    internal static string BuildRecoveryBundle(string command, string? backupId = null)
    {
        if (command is not ("--backup" or "--list" or "--verify" or "--restore"))
            throw new ArgumentException("Unsupported recovery operation.");
        if (command is "--verify" or "--restore")
        {
            if (backupId is null || !Regex.IsMatch(backupId,
                    @"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$", RegexOptions.CultureInvariant))
                throw new ArgumentException("Invalid backup identifier.");
        }
        else if (backupId is not null)
            throw new ArgumentException("Unexpected backup identifier.");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-restore.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/recovery.sh\" <<'LMR365_RECOVERY'\n" +
               Encode(Recovery) + "\nLMR365_RECOVERY\n" +
               "bash \"$work/recovery.sh\" " + command +
               (backupId is null ? "" : " " + backupId) +
               (command == "--restore" ? " --confirm RESTORE_POSTFIX_CONFIGURATION" : "") + "\n";
    }
    internal static string BuildSidecarConfigRecoveryBundle(
        string command, string? backupId = null, string? currentSha256 = null)
    {
        if (command is not ("--backup" or "--list" or "--verify" or "--preview-restore" or "--restore"))
            throw new ArgumentException("Unsupported isolated SMTP recovery operation.");
        bool needsId = command is "--verify" or "--preview-restore" or "--restore";
        if (needsId != (backupId is not null) ||
            (needsId && !Regex.IsMatch(backupId!,
                @"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\z", RegexOptions.CultureInvariant)))
            throw new ArgumentException("Invalid isolated recovery backup identifier.");
        if (command == "--restore")
        {
            if (currentSha256 is null || !Regex.IsMatch(currentSha256,
                @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant))
                throw new ArgumentException("Review current isolated configuration SHA-256 before Restore.");
        }
        else if (currentSha256 is not null)
            throw new ArgumentException("Current SHA-256 is allowed only for Restore.");
        string args = command + (backupId is null ? "" : " " + backupId) +
            (command == "--restore" ?
                " --expect-current-sha256 " + currentSha256 +
                " --confirm RESTORE_ISOLATED_RELAY_CONFIGURATION" : "");
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-sidecar-recovery.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/sidecar-config-recovery.py\" <<'LMR365_SIDECAR_RECOVERY'\n" +
               Encode(SidecarConfigRecovery) + "\nLMR365_SIDECAR_RECOVERY\n" +
               "python3 \"$work/sidecar-config-recovery.py\" " + args + "\n";
    }

}
