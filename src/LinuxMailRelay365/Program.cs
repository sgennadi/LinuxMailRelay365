using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--self-test")
            return SecurityOptionsSelfTest.Run() && TenantDiscovery.SelfTest() &&
                DiagnosticJournal.SelfTest()
#if !USE_UNIVERSAL_UPDATER
                && ReleaseVersion.SelfTest()
#endif
                ? 0 : 1;
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetDefaultFont(new Font("Segoe UI", 10));
        Application.Run(new MainForm());
        return 0;
    }
}
