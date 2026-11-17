using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal static class Program
{
    private static int RunSelfTests(string? reportPath)
    {
        // WinExe has no guaranteed attached console. Explicit file reporting
        // makes failures inspectable in unattended GitHub Actions runs.
        var checks = new List<(string Name, Func<bool> Run)>
        {
            ("Security plans", SecurityOptionsSelfTest.Run),
            ("Mail routing safety", MailRoutingPlanStore.SelfTest),
            ("Embedded backup / restore", () =>
            {
                var listing = EmbeddedAssets.BuildRecoveryBundle("--list");
                var embedded = EmbeddedAssets.BuildLinuxBundle(["--prepare-only", "--certificate-days", "1"]);
                try
                {
                    EmbeddedAssets.BuildRecoveryBundle("--restore", "../etc");
                    return false;
                }
                catch (ArgumentException) { }
                return listing.Contains("LMR365_RECOVERY", StringComparison.Ordinal) &&
                       embedded.Contains("LMR365_RECOVERY", StringComparison.Ordinal);
            }),
            ("Tenant discovery", TenantDiscovery.SelfTest),
            ("Diagnostic privacy", DiagnosticJournal.SelfTest)
        };
#if !USE_UNIVERSAL_UPDATER
        checks.Add(("Release ordering", ReleaseVersion.SelfTest));
#endif
        var results = new List<string>();
        bool success = true;
        foreach (var (name, run) in checks)
        {
            try
            {
                bool passed = run();
                results.Add(name + ": " + (passed ? "PASS" : "FAIL"));
                success &= passed;
            }
            catch (Exception ex)
            {
                results.Add(name + ": FAIL (" + ex.GetType().Name + ")");
                success = false;
            }
        }
        if (!string.IsNullOrWhiteSpace(reportPath))
        {
            var path = Path.GetFullPath(reportPath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllLines(path, results);
        }
        return success ? 0 : 1;
    }

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--self-test")
        {
            if (args.Length == 1) return RunSelfTests(null);
            if (args.Length == 3 && args[1] == "--report") return RunSelfTests(args[2]);
            return 2;
        }
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetDefaultFont(new Font("Segoe UI", 10));
        Application.Run(new MainForm());
        return 0;
    }
}
