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
