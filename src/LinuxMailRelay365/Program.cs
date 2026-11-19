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
            ("Entra public certificate bridge", () =>
            {
                var preview = EmbeddedAssets.BuildEntraPublicCertificateBundle("sidecar");
                var proof = EmbeddedAssets.BuildEntraPublicCertificateBundle(
                    "primary", "11111111-1111-1111-1111-111111111111",
                    new string('a', 64), new string('b', 64),
                    new string('c', 64), new string('d', 64));
                bool rejected;
                try
                {
                    EmbeddedAssets.BuildEntraPublicCertificateBundle("sidecar",
                        "11111111-1111-1111-1111-111111111111", "../invalid", null, null, null);
                    rejected = false;
                }
                catch (ArgumentException) { rejected = true; }
                return EntraCertificateReview.SelfTest() &&
                       preview.Contains("--target sidecar --inventory", StringComparison.Ordinal) &&
                       proof.Contains("--target primary --proof", StringComparison.Ordinal) &&
                       proof.Contains("--expected-candidate-cert-sha", StringComparison.Ordinal) &&
                       EmbeddedAssets.EntraCertificateManager.Contains("Invoke-MgGraphRequest", StringComparison.Ordinal) &&
                       rejected;
            }),
            ("TPM2 OAuth provisioning bundle", () =>
            {
                var plan = EmbeddedAssets.BuildTpmOauthProvisionBundle("sidecar", "0x81010001");
                var apply = EmbeddedAssets.BuildTpmOauthProvisionBundle("primary", "0x8101a001", new string('b', 64));
                bool invalidRejected;
                try
                {
                    EmbeddedAssets.BuildTpmOauthProvisionBundle("sidecar", "0x81010001;rm -rf /");
                    invalidRejected = false;
                }
                catch (ArgumentException) { invalidRejected = true; }
                return plan.Contains("LMR365_TPM_PROVISION", StringComparison.Ordinal) &&
                       plan.Contains("--handle 0x81010001 --plan", StringComparison.Ordinal) &&
                       apply.Contains("--confirm CREATE_TPM2_OAUTH_KEY", StringComparison.Ordinal) &&
                       invalidRejected;
            }),
            ("Hardware OAuth candidate stage bundle", () =>
            {
                var preview = EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                    "sidecar", "stage-plan", stageProvider: "tpm2", stageKeyRef: "handle:0x81000001");
                var apply = EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                    "sidecar", "stage-apply", approvalSha: new string('a', 64),
                    stageProvider: "tpm2", stageKeyRef: "handle:0x81000001");
                var pkcs11 = EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                    "primary", "stage-plan", stageProvider: "pkcs11",
                    stageKeyRef: "pkcs11:object=smtp;type=private");
                bool rejected;
                try
                {
                    EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                        "sidecar", "stage-plan", stageProvider: "pkcs11",
                        stageKeyRef: "pkcs11:object=smtp;pin-value=123;type=private");
                    rejected = false;
                }
                catch (ArgumentException) { rejected = true; }
                return preview.Contains("--stage-plan", StringComparison.Ordinal) &&
                       preview.Contains("--stage-provider tpm2", StringComparison.Ordinal) &&
                       apply.Contains("--confirm STAGE_HARDWARE_OAUTH", StringComparison.Ordinal) &&
                       pkcs11.Contains("'pkcs11:object=smtp;type=private'", StringComparison.Ordinal) &&
                       rejected;
            }),
            ("Hardware OAuth reviewed cutover bundle", () =>
            {
                var plan = EmbeddedAssets.BuildHardwareOAuthCutoverBundle("sidecar", "plan");
                var apply = EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                    "sidecar", "apply", approvalSha: new string('a', 64));
                var rollback = EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                    "primary", "rollback", backupId: "20261119T100000Z-abcdef012345");
                bool rejected;
                try
                {
                    EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                        "primary;echo unsafe", "rollback", backupId: "../etc/passwd");
                    rejected = false;
                }
                catch (ArgumentException) { rejected = true; }
                return plan.Contains("LMR365_HWOAUTH_CUTOVER", StringComparison.Ordinal) &&
                       plan.Contains("--target sidecar --plan", StringComparison.Ordinal) &&
                       apply.Contains("--confirm ACTIVATE_HARDWARE_OAUTH", StringComparison.Ordinal) &&
                       rollback.Contains("--confirm ROLLBACK_HARDWARE_OAUTH", StringComparison.Ordinal) &&
                       rejected;
            }),
            ("Hardware OAuth diagnostics bundle", () =>
            {
                var inventory = EmbeddedAssets.BuildHardwareOAuthDiagnosticBundle(false);
                var signing = EmbeddedAssets.BuildHardwareOAuthDiagnosticBundle(true);
                return inventory.Contains("LMR365_HW_OAUTH", StringComparison.Ordinal) &&
                       inventory.Contains("--inventory-only", StringComparison.Ordinal) &&
                       signing.Contains("LMR365_HW_OAUTH", StringComparison.Ordinal) &&
                       !signing.Contains("--inventory-only", StringComparison.Ordinal);
            }),
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
            ("Isolated SMTP sidecar bundle", () =>
            {
                var bundle = EmbeddedAssets.BuildSidecarBundle(
                    ["--tenant-id", "11111111-1111-1111-1111-111111111111",
                     "--client-id", "22222222-2222-2222-2222-222222222222",
                     "--mailbox", "smtp@example.com"]);
                return bundle.Contains("LMR365_SIDECAR", StringComparison.Ordinal)
                    && bundle.Contains("LMR365_TRANSPORT", StringComparison.Ordinal);
            }),
            ("Preserve mail diagram", PreserveFlowSnapshot.SelfTest),
            ("Existing public SMTP audit", () =>
            {
                var bundle = EmbeddedAssets.BuildExistingSmtpAuditBundle();
                return bundle.Contains("LMR365_SMTP_AUDIT", StringComparison.Ordinal)
                    && ExistingSmtpAudit.SelfTest();
            }),
            ("Network/firewall bundle", () =>
            {
                var script = EmbeddedAssets.BuildNetworkFirewallBundle(
                    ["--check", "--smtp-port", "2525", "--public-internet"]);
                if (!script.Contains("LMR365_NETWORK", StringComparison.Ordinal)) return false;
                try
                {
                    EmbeddedAssets.BuildNetworkFirewallBundle(["--check", "2525;rm"]);
                    return false;
                }
                catch (ArgumentException) { return true; }
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
