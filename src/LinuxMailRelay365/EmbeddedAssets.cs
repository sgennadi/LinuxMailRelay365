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
    internal static string Recovery => Text("LinuxMailRelay365.linux.recovery.sh");
    internal static string SidecarInstaller => Text("LinuxMailRelay365.linux.sidecar.sh");
    internal static string NetworkFirewall => Text("LinuxMailRelay365.linux.network-firewall.sh");
    internal static string ExistingSmtpAuditScript => Text("LinuxMailRelay365.linux.existing-smtp-audit.py");
    internal static string PlatformCompat => Text("LinuxMailRelay365.linux.platform-compat.py");
    internal static string RhelSelinuxDoctor => Text("LinuxMailRelay365.linux.rhel-selinux-doctor.py");
    internal static string AuthTlsInstaller => Text("LinuxMailRelay365.linux.auth-tls-installer.sh");
    internal static string AuthTlsRestore => Text("LinuxMailRelay365.linux.auth-tls-restore.sh");
    internal static string InstalledSidecarAudit => Text("LinuxMailRelay365.linux.installed-sidecar-audit.py");
    internal static string AuthArchiveAudit => Text("LinuxMailRelay365.linux.auth-archive-audit.py");
    internal static string TlsIdentityProbe => Text("LinuxMailRelay365.linux.tls-identity-probe.py");
    internal static string Provisioner => Text("LinuxMailRelay365.windows.provision.ps1");
    internal static string SecurityProbe => Text("LinuxMailRelay365.linux.security-probe.sh");
    internal static string CloudSecurityProbe => Text("LinuxMailRelay365.windows.cloud-security-probe.ps1");
    internal static string TenantDiscoveryScript => Text("LinuxMailRelay365.windows.tenant-discovery.ps1");

    private static string Encode(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

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
               "base64 -d > \"$work/mail-config-recovery.sh\" <<'LMR365_RECOVERY'\n" +
               Encode(Recovery) + "\nLMR365_RECOVERY\n" +
               "bash \"$work/install-postfix-m365-xoauth2.sh\" " + string.Join(" ", args) + "\n";
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
               "bash \"$work/install-sidecar.sh\" " + string.Join(" ", args) + "\n";
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
               (backupId is null ? "" : " " + backupId) + "\n";
    }
}
