using System.Reflection;
using System.Text;

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
    internal static string Provisioner => Text("LinuxMailRelay365.windows.provision.ps1");
    internal static string SecurityProbe => Text("LinuxMailRelay365.linux.security-probe.sh");
    internal static string CloudSecurityProbe => Text("LinuxMailRelay365.windows.cloud-security-probe.ps1");
    internal static string TenantDiscoveryScript => Text("LinuxMailRelay365.windows.tenant-discovery.ps1");

    internal static string BuildLinuxBundle(string[] args)
    {
        // Only validated, fixed-format arguments; never interpolate untrusted shell text.
        foreach (string item in args)
        {
            if (item.Length > 320 || item.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or '@' or ':' or '/')))
                throw new ArgumentException("Invalid installer argument format.");
        }
        string enc(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        return "set -Eeuo pipefail\numask 077\n" +
               "work=$(mktemp -d /tmp/m365pm.XXXXXXXX)\n" +
               "trap 'rm -rf -- \"$work\"' EXIT\n" +
               "base64 -d > \"$work/install-postfix-m365-xoauth2.sh\" <<'M365_INSTALL'\n" + enc(Installer) + "\nM365_INSTALL\n" +
               "base64 -d > \"$work/m365_xoauth2_transport.py\" <<'M365_TRANSPORT'\n" + enc(Transport) + "\nM365_TRANSPORT\n" +
               "bash \"$work/install-postfix-m365-xoauth2.sh\" " + string.Join(" ", args) + "\n";
    }
}
