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
        return reader.ReadToEnd();
    }

    internal static string Installer => Text("LinuxMailRelay365.linux.install.sh");
    internal static string Transport => Text("LinuxMailRelay365.linux.transport.py");
    internal static string OAuthSenderMapAudit => Text("LinuxMailRelay365.linux.oauth-sender-map-audit.py");
    internal static string OAuthIngressAudit => Text("LinuxMailRelay365.linux.oauth-ingress-audit.py");
    internal static string HardwareSigner => Text("LinuxMailRelay365.linux.hardware-signer.py");
    internal static string TpmDependencies => Text("LinuxMailRelay365.linux.tpm-dependencies.py");
    internal static string HardwareOAuthDiagnostics => Text("LinuxMailRelay365.linux.hardware-oauth-diagnostics.py");
    internal static string HardwareOAuthCutover => Text("LinuxMailRelay365.linux.hardware-oauth-cutover.py");
    internal static string DeliveryAcceptance => Text("LinuxMailRelay365.linux.delivery-acceptance.py");
    internal static string TpmOauthProvision => Text("LinuxMailRelay365.linux.tpm-oauth-provision.py");
    internal static string EntraPublicCertificateExporter => Text("LinuxMailRelay365.linux.entra-public-cert-export.py");
    internal static string EntraCertificateManager => Text("LinuxMailRelay365.windows.entra-oauth-cert-manager.ps1");
    internal static string Recovery => Text("LinuxMailRelay365.linux.recovery.sh");
    internal static string SidecarConfigRecovery => Text("LinuxMailRelay365.linux.sidecar-config-recovery.py");
    internal static string SidecarInstaller => Text("LinuxMailRelay365.linux.sidecar.sh");
    internal static string CleanPostfixPreparation => Text("LinuxMailRelay365.linux.prepare-clean-postfix.py");
    internal static string PostfixBasicsManager => Text("LinuxMailRelay365.linux.manage-postfix-basics.py");
    internal static string DirectSendSidecarInstaller => Text("LinuxMailRelay365.linux.direct-send-sidecar.sh");
    internal static string ConnectorSidecarInstaller => Text("LinuxMailRelay365.linux.connector-sidecar.sh");
    internal static string ForeignMtaGuard => Text("LinuxMailRelay365.linux.foreign-mta-guard.py");
    internal static string NetworkFirewall => Text("LinuxMailRelay365.linux.network-firewall.sh");
    internal static string ExistingSmtpAuditScript => Text("LinuxMailRelay365.linux.existing-smtp-audit.py");
    internal static string MailHostInspector => Text("LinuxMailRelay365.linux.inspect-mail-host.py");
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
    internal static string TenantDiscoveryScript => Text("LinuxMailRelay365.windows.tenant-discovery.ps1");
    internal static string TenantConnectorManager => Text("LinuxMailRelay365.windows.tenant-connector-manager.ps1");

    private static string Encode(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    internal static string BuildEntraPublicCertificateBundle(string target,
        string? objectId = null, string? activeSha = null,
        string? stageSha = null, string? activeCertificateSha = null,
        string? candidateCertificateSha = null)
    {
        if (target is not ("sidecar" or "primary"))
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
        if (port is < 1024 or > 65535 || trustedNetworks.Length > 8)
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
        if (port is < 1024 or > 65535 || trustedNetworks.Length > 8)
            throw new ArgumentException("Connector custom SMTP port must be 1024-65535.");
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
        if (port is < 1024 or > 65535 ||
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

    internal static string BuildMailHostInspectionBundle(int selectedPort = 2525,
        string currentMta = "unknown")
    {
        if (selectedPort is < 1024 or > 65535 ||
            currentMta is not ("postfix" or "exim" or "sendmail" or "none" or "unknown"))
            throw new ArgumentException("Invalid selected SMTP port or discovered MTA.");
        return "set -Eeuo pipefail\numask 077\n" +
            "work=$(mktemp -d /tmp/lmr365-mail-host.XXXXXXXX)\n" +
            "trap 'rm -rf -- \"$work\"' EXIT\n" +
            "base64 -d > \"$work/inspect-mail-host.py\" <<'LMR365_MAIL_HOST'\n" +
            Encode(MailHostInspector) + "\nLMR365_MAIL_HOST\n" +
            "base64 -d > \"$work/audit-mail-bindings.py\" <<'LMR365_MAIL_BIND'\n" +
            Encode(MailBindInspector) + "\nLMR365_MAIL_BIND\n" +
            "python3 \"$work/inspect-mail-host.py\" --inspect\n" +
            "python3 \"$work/audit-mail-bindings.py\" --smtp-port " + selectedPort +
            " --mta " + currentMta + "\n";
    }

    internal static string BuildExistingSmtpAuditBundle()
    {
        // No input options or network traffic. Existing Postfix files are only
        // queried for status; NO raw configuration is returned to the GUI.
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-audit.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/audit-smtp.py\" <<'LMR365_SMTP_AUDIT'\n" +
               Encode(ExistingSmtpAuditScript) + "\nLMR365_SMTP_AUDIT\n" +
               "python3 \"$work/audit-smtp.py\"\n";
    }

    internal static string BuildPublicSmtpBundle(int port, string listener, string dns,
        string operation = "check", string? expectedSha = null, bool approved = false)
    {
        if (port is < 1024 or > 65535)
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
        if (selectedPort is < 1024 or > 65535)
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
        if (selectedPort is < 1024 or > 65535)
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
        if (selectedPort is < 1024 or > 65535)
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
        if (selectedPort is < 1024 or > 65535)
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
        if (port is < 1024 or > 65535)
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
        if (port is < 1024 or > 65535)
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
            customPort is < 1024 or > 65535)
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
        if (selectedPort is < 1024 or > 65535)
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
        if (selectedPort is < 1024 or > 65535)
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
        if (port is < 1024 or > 65535)
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
        if (selectedPort is < 1024 or > 65535)
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
        if (selectedPort is < 1024 or > 65535)
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
        if (port is < 1024 or > 65535 ||
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
        if (selectedPort is < 1024 or > 65535)
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
        if (selectedPort is < 1024 or > 65535)
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
        if (port is < 1024 or > 65535)
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
        if (smtpPort is < 1024 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(smtpPort));
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/lmr365-platform.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/platform-compat.py\" <<'LMR365_PLATFORM'\n" +
               Encode(PlatformCompat) + "\nLMR365_PLATFORM\n" +
               "python3 \"$work/platform-compat.py\" --smtp-port " + smtpPort.ToString() + "\n";
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
