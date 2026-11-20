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
            ("SSH optional host key requires explicit approval before password AUTH", () =>
            {
                const string hostKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
                int approvals = 0;
                var firstUse = new SshEndpoint("relay.example.org", 22, "root", "", "fake-test-password")
                {
                    ConfirmFirstUseHostKey = (_, offered) =>
                    {
                        approvals++;
                        return offered == hostKey;
                    }
                };
                firstUse.Validate(); // Empty pinned fingerprint is valid with a callback.
                if (!SshRemote.IsPasswordHostKeyTrusted(firstUse, hostKey) ||
                    approvals != 1 ||
                    SshRemote.IsPasswordHostKeyTrusted(firstUse, "invalid-sha256") ||
                    approvals != 1) return false;
                var denied = firstUse with { ConfirmFirstUseHostKey = (_, _) => false };
                if (SshRemote.IsPasswordHostKeyTrusted(denied, hostKey)) return false;
                var manuallyPinned = firstUse with
                {
                    HostKeySha256 = "SHA256:" + hostKey,
                    ConfirmFirstUseHostKey = (_, _) => throw new Exception("Pinned SSH must never ask again")
                };
                manuallyPinned.Validate();
                if (!SshRemote.IsPasswordHostKeyTrusted(manuallyPinned, hostKey) ||
                    SshRemote.IsPasswordHostKeyTrusted(manuallyPinned,
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")) return false;
                try
                {
                    new SshEndpoint("relay.example.org", 22, "root", "", "fake-test-password").Validate();
                    return false; // No fingerprint and no callback MUST be refused.
                }
                catch (ArgumentException) { return true; }
            }),
            ("Responsive window sizing and high-DPI readable wizard", () =>
            {
                var fullHd = MainForm.PreferredWizardSize(new Size(1920, 1080), 96);
                var highDpi = MainForm.PreferredWizardSize(new Size(1920, 1080), 192);
                var compact = MainForm.PreferredWizardSize(new Size(1000, 730), 96);
                var minimum = MainForm.MinimumWizardSize(new Size(1000, 730), 96);
                return fullHd.Width >= 1200 && fullHd.Height >= 860 &&
                       highDpi.Width > fullHd.Width && highDpi.Height >= 900 &&
                       compact.Width <= 1000 && compact.Height <= 730 &&
                       minimum.Width <= compact.Width && minimum.Height <= compact.Height;
            }),
            ("DPI-aware dialogs remain within the working desktop", () =>
            {
                var small = MainForm.PreferredDialogSize(new Size(900, 680), 96, 880, 580);
                var high = MainForm.PreferredDialogSize(new Size(1920, 1080), 192, 880, 580);
                return small.Width <= 900 && small.Height <= 680 &&
                       high.Width <= 1920 && high.Height <= 1080 &&
                       small.Width >= 630 && small.Height >= 500;
            }),
            ("Responsive SSH layout breakpoints", () =>
                MainForm.UseWideConnectionLayout(1050, 96) &&
                !MainForm.UseWideConnectionLayout(760, 96) &&
                !MainForm.UseWideConnectionLayout(1050, 192) &&
                MainForm.UseWideConnectionLayout(1900, 192)),
            ("Responsive delivery cards breakpoints", () =>
                MainForm.UseWideDeliveryChoices(800, 96) &&
                !MainForm.UseWideDeliveryChoices(600, 96) &&
                !MainForm.UseWideDeliveryChoices(760, 192) &&
                MainForm.UseWideDeliveryChoices(1500, 192)),
            ("Delivery route chooser guidance", DeliveryModeOverview.SelfTest),
            ("Recipient-aware read-only delivery recommendations", MailDeliveryAdvisor.SelfTest),
            ("Read-only MTA discovery recommendations", MailServerDiscoveryDecision.SelfTest),
            ("Read-only hostname/domain and MTA settings report", MailHostInspection.SelfTest),
            ("SSH mail-host inspection embedded resource", () =>
                EmbeddedAssets.BuildMailHostInspectionBundle().Contains("LMR365_MAIL_HOST",
                    StringComparison.Ordinal) &&
                EmbeddedAssets.BuildMailHostInspectionBundle().Contains("--inspect",
                    StringComparison.Ordinal) &&
                EmbeddedAssets.BuildMailHostInspectionBundle(2526, "exim").Contains(
                    "--smtp-port 2526 --mta exim", StringComparison.Ordinal)),
            ("Guarded primary Postfix main.cf profile bundle", () =>
            {
                string preview = EmbeddedAssets.BuildPostfixBasicsBundle(
                    "mail.example.com", "example.com", "loopback-only");
                string apply = EmbeddedAssets.BuildPostfixBasicsBundle(
                    "mail.example.com", "example.com", "loopback-only", new string('a', 64));
                if (!preview.Contains("--preview", StringComparison.Ordinal) ||
                    !apply.Contains("--apply --expected-sha256", StringComparison.Ordinal) ||
                    !apply.Contains("MODIFY_PRIMARY_POSTFIX", StringComparison.Ordinal) ||
                    !apply.Contains("LMR365_POSTFIX_RECOVERY", StringComparison.Ordinal))
                    return false;
                try
                {
                    EmbeddedAssets.BuildPostfixBasicsBundle(
                        "mail.example.com;id", "example.com", "all");
                    return false;
                }
                catch (ArgumentException) { return true; }
            }),
            ("Clean Postfix bootstrap approval contract", () =>
            {
                var preview = EmbeddedAssets.BuildCleanPostfixBundle(2525, "check");
                var verify = EmbeddedAssets.BuildCleanPostfixBundle(2525, "verify");
                var apply = EmbeddedAssets.BuildCleanPostfixBundle(2525, "apply", new string('a', 64));
                bool rejects;
                try { EmbeddedAssets.BuildCleanPostfixBundle(2525, "apply"); rejects = false; }
                catch (ArgumentException) { rejects = true; }
                return preview.Contains("--check-only", StringComparison.Ordinal) &&
                       verify.Contains("--verify-prepared", StringComparison.Ordinal) &&
                       apply.Contains("INSTALL_CLEAN_POSTFIX_PACKAGES", StringComparison.Ordinal) &&
                       rejects;
            }),
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
            ("Microsoft 365 reviewed delivery acceptance bundle", () =>
            {
                var preview = EmbeddedAssets.BuildDeliveryAcceptanceBundle(
                    "sidecar", new string('a', 32), "internal@example.org", "external@outside.net");
                var approved = EmbeddedAssets.BuildDeliveryAcceptanceBundle(
                    "primary", new string('b', 32), "internal@example.org", "external@outside.net",
                    new string('c', 64));
                bool rejected;
                try
                {
                    EmbeddedAssets.BuildDeliveryAcceptanceBundle(
                        "sidecar", new string('a', 32), "internal@example.org",
                        "attacker@outside.net\r\nBcc:secret@outside.net");
                    rejected = false;
                }
                catch (ArgumentException) { rejected = true; }
                return preview.Contains("--target sidecar --plan", StringComparison.Ordinal) &&
                       approved.Contains("--target primary --apply", StringComparison.Ordinal) &&
                       approved.Contains("--confirm SEND_TWO_ACCEPTANCE_TESTS", StringComparison.Ordinal) &&
                       !preview.Contains("internal@example.org", StringComparison.Ordinal) &&
                       !approved.Contains("external@outside.net", StringComparison.Ordinal) &&
                       rejected;
            }),
            ("Hardware OAuth reviewed cutover bundle", () =>
            {
                var plan = EmbeddedAssets.BuildHardwareOAuthCutoverBundle("sidecar", "plan");
                var apply = EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                    "sidecar", "apply", approvalSha: new string('a', 64));
                var rollback = EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                    "primary", "rollback", backupId: "20261119T100000Z-abcdef012345");
                var preflight = EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                    "sidecar", "token-preflight", approvalSha: new string('f', 64));
                var smtpAuth = EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                    "sidecar", "smtp-auth-preflight", approvalSha: new string('a', 64));
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
                       preflight.Contains("--token-preflight", StringComparison.Ordinal) &&
                       preflight.Contains("--confirm VERIFY_STAGED_ENTRA_TOKEN", StringComparison.Ordinal) &&
                       smtpAuth.Contains("--smtp-auth-preflight", StringComparison.Ordinal) &&
                       smtpAuth.Contains("--confirm VERIFY_STAGED_SMTP_AUTH", StringComparison.Ordinal) &&
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
            ("Multi-mailbox sender map audit bundle", () =>
            {
                const string safe = "/etc/linuxmailrelay365/oauth-senders.tsv";
                string bundle = EmbeddedAssets.BuildOAuthSenderMapAuditBundle(safe);
                if (!bundle.Contains("LMR365_OAUTH_MAP_AUDIT", StringComparison.Ordinal) ||
                    !bundle.Contains("--map-path " + safe, StringComparison.Ordinal) ||
                    bundle.Contains("--apply", StringComparison.Ordinal) ||
                    bundle.Contains("--send", StringComparison.Ordinal) ||
                    bundle.Contains("--grant", StringComparison.Ordinal))
                    return false;
                foreach (string unsafePath in new[] {
                    "../../tmp/map.tsv",
                    "/tmp/map.tsv",
                    "/etc/linuxmailrelay365/../etc/passwd.tsv",
                    "/etc/linuxmailrelay365/map.tsv;echo BAD",
                    "/etc/linuxmailrelay365/map.json"
                })
                {
                    try
                    {
                        EmbeddedAssets.BuildOAuthSenderMapAuditBundle(unsafePath);
                        return false;
                    }
                    catch (ArgumentException) { }
                }
                return true;
            }),
            ("Read-only XOAUTH2 ingress comparison bundle", () =>
            {
                const string path = "/etc/linuxmailrelay365/oauth-senders.tsv";
                string bundle = EmbeddedAssets.BuildOAuthIngressAuditBundle(path);
                if (!bundle.Contains("LMR365_OAUTH_INGRESS_AUDIT", StringComparison.Ordinal) ||
                    !bundle.Contains("LMR365_OAUTH_SENDER_MAP_LIB", StringComparison.Ordinal) ||
                    !bundle.Contains("--map-path " + path, StringComparison.Ordinal))
                    return false;
                foreach (string unsafePath in new[] {
                    "/tmp/any.tsv",
                    "/etc/linuxmailrelay365/../other.tsv",
                    "/etc/linuxmailrelay365/map.tsv;curl",
                    "/etc/linuxmailrelay365/senders.json"
                })
                {
                    try { EmbeddedAssets.BuildOAuthIngressAuditBundle(unsafePath); return false; }
                    catch (ArgumentException) { }
                }
                return true;
            }),
            ("Offline mapped OAuth certificate signer bundle", () =>
            {
                const string good = "/etc/linuxmailrelay365/oauth-senders.tsv";
                var bundle = EmbeddedAssets.BuildOAuthIdentitySigningAuditBundle(good);
                if (!bundle.Contains("LMR365_SIGN_AUDITOR", StringComparison.Ordinal) ||
                    !bundle.Contains("LMR365_SIGN_TRANSPORT", StringComparison.Ordinal) ||
                    !bundle.Contains("LMR365_SIGN_BACKEND", StringComparison.Ordinal) ||
                    !bundle.Contains("--map-path " + good, StringComparison.Ordinal) ||
                    !bundle.Contains("chmod 0755 \"$work\"", StringComparison.Ordinal))
                    return false;
                foreach (string path in new[] {
                    "/tmp/map.tsv", "/etc/linuxmailrelay365/../etc/passwd.tsv",
                    "/etc/linuxmailrelay365/m.tsv;id", "/etc/linuxmailrelay365/map.json"
                })
                {
                    try { EmbeddedAssets.BuildOAuthIdentitySigningAuditBundle(path); return false; }
                    catch (ArgumentException) { }
                }
                return true;
            }),
            ("Preserve mail diagram", PreserveFlowSnapshot.SelfTest),
            ("Live delivery route explanations", MailRoutingGuidance.SelfTest),
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
        checks.Add(("Updater release trust and channel rules", UpdateCheck.SelfTest));
#endif
        checks.Add(("Publisher-pinned updater safety contracts", SignedPortableUpdater.SelfTest));
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
        if (args.Length > 0 && args[0] == "--apply-signed-update")
            return SignedPortableUpdater.ApplyFromHelper(args[1..]);
        if (args.Length > 0 && args[0] == "--apply-preview-update")
            return SignedPortableUpdater.ApplyFromHelper(args[1..], unsignedPreview: true);
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
        if (args.Length > 0 && args[0] == "--capture-wizard-screens")
        {
            if (args.Length != 2 ||
                Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
                string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("RUNNER_TEMP")))
                return 2;
            int result = 0;
            using var form = new MainForm();
            form.Shown += (_, _) => form.BeginInvoke(new Action(() =>
            {
                try
                {
                    if (form.CaptureWizardScreens(args[1]) != 24)
                        result = 1;
                }
                catch (Exception)
                {
                    // No credential, path, tenant, or confidential exception
                    // material is written to the artifacts.
                    result = 1;
                }
                finally { form.Close(); }
            }));
            Application.Run(form);
            return result;
        }
        Application.Run(new MainForm());
        return 0;
    }
}
