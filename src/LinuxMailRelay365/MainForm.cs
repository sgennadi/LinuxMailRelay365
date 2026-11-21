using System.Diagnostics;
using System.Drawing;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm : Form
{
    private readonly TextBox host = Field("linux.example.net");
    private readonly TextBox sshPort = Field("22");
    private readonly TextBox sshUser = Field("admin");
    private readonly TextBox sshKey = Field("");
    private readonly TextBox sshPassword = Field("");
    private readonly TextBox sudoPassword = Field("");
    private readonly TextBox sshFingerprint = Field("");
    private readonly ComboBox sshAuthMode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 420 };
    private readonly TextBox tenant = Field("");
    private readonly ComboBox tenantSelector = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private IReadOnlyList<TenantOption> discoveredTenants = Array.Empty<TenantOption>();
    private bool tenantSelectionLoading;
    private readonly TextBox applicationName = Field("Linux Mail Relay 365");
    private readonly TextBox existingAppId = Field("");
    private readonly TextBox certificateDays = Field("365");
    private string? reviewedPrimaryRotationPlanSha;
    private string? reviewedPrimaryRotationPlanContext;
    private string? reviewedPrimaryRotationStageSha;
    private string? reviewedPrimaryRotationStageContext;
    private string? primaryRotationGraphContext;
    private string? primaryRotationGraphCertificateSha;
    private string? verifiedPrimaryRotationSmtpSha;
    private string? verifiedPrimaryRotationSmtpContext;
    private string primaryRotationSummary = "";
    private readonly TextBox mailbox = Field("");
    private readonly TextBox testRecipient = Field("");
    private readonly CheckBox allowExisting = new() { AutoSize = true };
    private readonly ComboBox backupSelector = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private readonly ComboBox foreignBackupSelector = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private string? foreignBackupListContext;
    private readonly ComboBox sidecarBackupSelector = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private string? reviewedSidecarRestoreSha;
    private string? reviewedSidecarRestoreId;
    private string? reviewedSidecarRestoreIdentity;
    private MailRoutingInventory? inspectedMail;
    private string? inspectedServerIdentity;
    private ExistingSmtpAudit? existingSmtpAudit;
    private string? existingSmtpAuditIdentity;
    private bool? discoveredIsolatedRelay;
    private string? discoveredMailIdentity;
    private MailHostInspection? inspectedHost;
    private string? inspectedHostIdentity;
    private string? previewedCleanBootstrapSha;
    private string? previewedCleanBootstrapIdentity;
    private int previewedCleanBootstrapPort;
    private string cleanBootstrapSummary = "";
    // Evidence is bound to the current SSH identity and the exact operator
    // inputs; no previous preview can authorize a changed Postfix baseline.
    private string? previewedPostfixBasicsSha;
    private string? previewedPostfixBasicsContext;
    private string postfixBasicsSummary = "";
    private readonly ComboBox mailTransport = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private readonly ComboBox recipientScope = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private readonly ComboBox senderPolicy = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private readonly ComboBox oauthSenderMode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private readonly TextBox oauthSenderMapPath = Field("");
    private string oauthSenderAuditSummary = "";
    private string oauthIngressAuditSummary = "";
    private string oauthSignerAuditSummary = "";
    private readonly TextBox deliveryModeExplanation = new()
    {
        Width = 890, Height = 185, Multiline = true, ReadOnly = true,
        ScrollBars = ScrollBars.Vertical, BorderStyle = BorderStyle.FixedSingle,
        BackColor = Color.White, Font = new Font("Segoe UI", 9.5f),
        AccessibleName = "Selected Microsoft 365 delivery method, sender rights and routing explanation"
    };
    private readonly CheckBox preserveExistingMail = new() { AutoSize = true, Checked = true };
    private readonly TextBox acceptedDomain = Field("");
    private readonly TextBox outboundMxHost = Field("");
    private readonly TextBox outboundPublicIp = Field("");
    private readonly TextBox outboundConnectorName = Field("LinuxMailRelay365 SMTP Relay");
    private string? previewedTenantConnectorSha;
    private string? previewedTenantConnectorContext;
    private readonly TextBox outboundCertPath = Field("");
    private readonly TextBox outboundCertKeyPath = Field("");
    private readonly TextBox outboundFixedSender = Field("");
    private readonly TextBox outboundSenderOwnerFile = Field("");
    private readonly CheckBox connectorApproved = new() { AutoSize = true, Checked = false };
    private readonly CheckBox acceptedDomainApproved = new() { AutoSize = true, Checked = false };
    private readonly TextBox smtpListenIp = Field("");
    private readonly TextBox smtpTrustedCidrs = Field("");
    private readonly TextBox isolatedSmtpPort = Field("2525");
    private readonly TextBox foreignSidecarHostname = Field("");
    private readonly TextBox postfixBasicsHostname = Field("");
    private readonly TextBox postfixBasicsDomain = Field("");
    private readonly ComboBox postfixBasicsInterfaces = new()
        { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    // Paths refer to files already prepared on the Linux host. No passwords,
    // private key contents, or hashes are entered into or persisted by the GUI.
    private readonly TextBox privateAuthDns = Field("");
    private readonly TextBox privateAuthCertPath = Field("");
    private readonly TextBox privateAuthKeyPath = Field("");
    private readonly TextBox privateAuthHashPath = Field("");
    private readonly TextBox privateTlsCaPath = Field("");
    private readonly ComboBox smtpAccountOperation = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 420 };
    private readonly TextBox smtpAccountName = Field("");
    private readonly TextBox smtpAccountHashPath = Field("");
    private readonly PreserveMailFlowPreview preserveFlowPreview = new();
    private readonly TextBox preserveMailInstructions = new()
    {
        Width = 890, Height = 210, Multiline = true, ReadOnly = true,
        ScrollBars = ScrollBars.Vertical, BorderStyle = BorderStyle.FixedSingle,
        BackColor = Color.White, Font = new Font("Segoe UI", 9.5f),
        AccessibleName = "Preserve Existing Mail: client SMTP settings generated from entered values"
    };
    private readonly CheckBox publicInternetRequested = new() { AutoSize = true, Checked = false };
    private readonly CheckBox advancedSmtpTools = new() { AutoSize = true, Checked = false };
    private MailRoutingPlan routingPlan = new();
    private string? routingIdentity;
    private bool routingLoading;
    private readonly CheckBox hardwareRequest = new() { AutoSize = true };
    private readonly CheckBox ipRequest = new() { AutoSize = true };
    private readonly CheckBox monitoringRequest = new() { AutoSize = true };
    private bool securityLoading;
    private string? securityServerIdentity;
    private SecurityOptions securityOptions = new();
    private LinuxSecurityInventory? linuxSecurity;
    private readonly ComboBox tpmDependencyProfile = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 560 };
    private string? reviewedTpmPlanSha;
    private string? reviewedTpmPlanContext;
    private string tpmPlanSummary = "";
    private string hardwareOAuthSummary = "";
    private EntraCertificateReview? reviewedEntraPublicCertificates;
    private string? reviewedEntraCertPlanSha;
    private string? reviewedEntraCertContext;
    private string? reviewedEntraCertObjectId;
    private string? reviewedEntraCertTarget;
    private string entraCertificateSummary = "";
    private readonly TextBox tpmKeyHandle = Field("0x81010001");
    private string tpmKeySummary = "";
    private string? reviewedTpmKeyPlanSha;
    private string? reviewedTpmKeyPlanContext;
    private readonly ComboBox hardwareStageProvider = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 560 };
    private readonly TextBox hardwareStageKeyRef = Field("");
    private string hardwareStageSummary = "";
    private string? reviewedHardwareStageSha;
    private string? reviewedHardwareStageContext;
    private readonly ComboBox hardwareCutoverTarget = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 560 };
    private readonly ComboBox hardwareCutoverBackup = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 560 };
    private string hardwareCutoverSummary = "";
    private readonly TextBox acceptanceInternalRecipient = Field("");
    private readonly TextBox acceptanceExternalRecipient = Field("");
    private string? acceptanceRunId;
    private string? reviewedAcceptanceSha;
    private string? reviewedAcceptanceContext;
    private string acceptanceSummary = "";
    private string? verifiedHardwarePreflightSha;
    private string? verifiedHardwarePreflightContext;
    private string? verifiedHardwareSmtpAuthSha;
    private string? verifiedHardwareSmtpAuthContext;
    private string? reviewedHardwareCutoverSha;
    private string? reviewedHardwareCutoverContext;
    private string? listedHardwareBackupsContext;
    private string cloudSecuritySummary = "Не проверено";
    private readonly CheckBox previewUpdates = new() { AutoSize = true, Checked = false };
    private readonly CheckBox advancedSecurityTools = new() { AutoSize = true, Checked = false,
        ForeColor = UiTheme.Navy, Margin = new Padding(0, 12, 0, 12) };
    private readonly ComboBox language = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
    private readonly Label headline = UiTheme.Text("", true);
    private readonly Label subheading = UiTheme.Text("");
    private readonly Label brandHeading = UiTheme.Text(
        "LINUX MAIL RELAY 365  ·  " + UpdateCheck.Version, true);
    private TableLayoutPanel? footerLayout;
    private TableLayoutPanel? footerStatusLayout;
    private TableLayoutPanel? contentShell;
    private Panel? wizardFrame;
    private bool arrangingWizardPanels;
    private bool relabelingSshMethods;
    private bool localizingAdvancedChoices;
    private readonly Panel pageHost = new() { Dock = DockStyle.Fill, AutoScroll = true, BackColor = UiTheme.Canvas };
    private readonly FlowLayoutPanel navigation = new()
    {
        Dock = DockStyle.Fill, AutoSize = true,
        WrapContents = false, FlowDirection = FlowDirection.RightToLeft
    };
    private readonly Panel activityPanel = new() { Dock = DockStyle.Fill, Height = 124, Visible = false };
    private readonly LinkLabel activityToggle = new()
    {
        AutoSize = true, LinkColor = UiTheme.Navy,
        Font = new Font("Segoe UI", 9f),
        Margin = new Padding(10, 2, 0, 2)
    };
    private readonly CheckBox specifyHostKeyManually = new()
    {
        AutoSize = true, ForeColor = UiTheme.Navy,
        Margin = new Padding(0, 5, 0, 6)
    };
    private bool connectionWideLayout;
    private bool resizingConnectionLayout;
    // Trust-on-first-use pins are never reused for a different Linux endpoint.
    private (string Host, int Port, string User)? approvedSshIdentity;
    private string? automaticallyPinnedSshFingerprint;
    private readonly DiagnosticJournal journal = new();
    private readonly TextBox activity = new()
    {
        ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Vertical,
        Dock = DockStyle.Fill, BackColor = Color.White, BorderStyle = BorderStyle.FixedSingle,
        Font = new Font("Consolas", 9)
    };
    private readonly Label status = UiTheme.Text("");
    private readonly string dataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LinuxMailRelay365");
    private int step;
    private bool busy;
    private bool updateShuttingDown;
    private string? lastStatus;
    private bool lastFailed;
    private string? publicCertificatePath;
    private string? releaseUrl;

    private static TextBox Field(string initial) => new()
    {
        Text = initial,
        Width = 690,
        Margin = new Padding(0, 3, 0, 12),
        Font = new Font("Segoe UI", 10),
        AccessibleDescription = "Configuration field"
    };

    internal MainForm()
    {
        Text = "Linux Mail Relay 365  ·  " + UpdateCheck.Version;
        using (var iconStream = typeof(MainForm).Assembly.GetManifestResourceStream("LinuxMailRelay365.BrandIcon"))
        {
            if (iconStream is not null) Icon = new Icon(iconStream);
        }
        BackColor = UiTheme.Canvas;
        ForeColor = UiTheme.Navy;
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.Sizable;
        MaximizeBox = true;
        AutoScaleMode = AutoScaleMode.Dpi;

        var work = Screen.FromPoint(Cursor.Position).WorkingArea;
        int dpi = Math.Max(96, DeviceDpi);
        MinimumSize = MinimumWizardSize(work.Size, dpi);
        Size = PreferredWizardSize(work.Size, dpi);

        Directory.CreateDirectory(dataDirectory);
        sshPassword.UseSystemPasswordChar = true;
        sudoPassword.UseSystemPasswordChar = true;
        foreach (var field in new[] { host, sshPort, sshUser })
            field.TextChanged += (_, _) => ClearAutomaticSshHostKeyOnIdentityChange();
        specifyHostKeyManually.CheckedChanged += (_, _) =>
        {
            if (step == 0 && !busy) RenderPage();
        };
        activityToggle.LinkClicked += (_, _) =>
        {
            activityPanel.Visible = !activityPanel.Visible;
            if (footerLayout is not null)
                footerLayout.RowStyles[2].Height = activityPanel.Visible
                    ? (int)Math.Round(145 * Math.Max(1f, DeviceDpi / 96f)) : 0;
            activityToggle.Text = activityPanel.Visible
                ? T("Скрыть журнал", "Hide activity", "הסתר יומן")
                : T("Показать журнал", "Show activity", "הצג יומן");
            footerLayout?.PerformLayout();
            FitFooterHeight();
        };
        sshFingerprint.AccessibleDescription = "Optional SHA256 fingerprint. Leave blank to review the server key before sending the SSH password.";
        advancedSecurityTools.CheckedChanged += (_, _) =>
        {
            if (step == 1 && !busy && !securityLoading) RenderPage();
        };
        sshAuthMode.Items.AddRange(["SSH key / ssh-agent", "SSH username + password"]);
        postfixBasicsInterfaces.Items.AddRange([
            "loopback-only (local clients only)",
            "all (PREVIEW ONLY; external/public SMTP needs separate security setup)"
        ]);
        postfixBasicsInterfaces.SelectedIndex = 0;
        mailTransport.Items.AddRange([
            "XOAUTH2 · sender mailbox (available)",
            "M365 SMTP Connector · existing tenant Connector (Advanced apply)",
            "Direct Send · internal recipients only (Advanced apply)"
        ]);
        recipientScope.Items.AddRange(["Not sure yet", "Internal M365 only", "Internal and external recipients"]);
        recipientScope.SelectedIndex = 0;
        senderPolicy.Items.AddRange([
            "One fixed approved sender address",
            "Preserve original sender (Connector; SMTP AUTH + From Guard required)",
            "Masquerade verified subdomain (Connector; From Guard required)"
        ]);
        oauthSenderMode.Items.AddRange([
            "One M365 mailbox for all local mail (current implementation; rewrites From)",
            "Preserve multiple users' From (experimental offline configuration)"
        ]);
        oauthSenderMode.SelectedIndex = 0;
        tpmDependencyProfile.Items.AddRange([
            "Automatic TPM2 RPM profile (no third-party repositories)",
            "TPM2 utilities (RHEL/Oracle/Rocky/Alma 8-10)",
            "TPM2 development/build prerequisites (RHEL 8-10)",
            "TPM2 PKCS#11 OpenSSL 3 path (RHEL 9/10)",
            "Native TPM2 OpenSSL provider (RHEL 10 only)"
        ]);
        tpmDependencyProfile.SelectedIndex = 0;
        tpmKeyHandle.TextChanged += (_, _) =>
        {
            reviewedTpmKeyPlanSha = null;
            reviewedTpmKeyPlanContext = null;
            tpmKeySummary = "";
        };
        hardwareStageProvider.Items.AddRange([
            "TPM2 OpenSSL provider (existing TPM2 key)",
            "PKCS#11 OpenSSL provider (existing HSM/TPM key)"
        ]);
        hardwareStageProvider.SelectedIndex = 0;
        hardwareStageProvider.SelectedIndexChanged += (_, _) =>
        {
            if (localizingAdvancedChoices) return;
            reviewedHardwareStageSha = null;
            reviewedHardwareStageContext = null;
            hardwareStageSummary = "";
            if (step == 1 && !busy) RenderPage();
        };
        hardwareStageKeyRef.TextChanged += (_, _) =>
        {
            reviewedHardwareStageSha = null;
            reviewedHardwareStageContext = null;
            hardwareStageSummary = "";
        };
        void ResetDeliveryAcceptance()
        {
            acceptanceRunId = null;
            reviewedAcceptanceSha = null;
            reviewedAcceptanceContext = null;
            acceptanceSummary = "";
        }
        acceptanceInternalRecipient.TextChanged += (_, _) => ResetDeliveryAcceptance();
        acceptanceExternalRecipient.TextChanged += (_, _) => ResetDeliveryAcceptance();
        multiTestSender.TextChanged += (_, _) => ResetMultiMailboxTestReview();
        multiTestInternal.TextChanged += (_, _) => ResetMultiMailboxTestReview();
        multiTestExternal.TextChanged += (_, _) => ResetMultiMailboxTestReview();
        hardwareCutoverTarget.Items.AddRange([
            "Isolated sidecar (existing primary Postfix untouched)",
            "Primary Postfix XOAUTH2 transport (advanced)"
        ]);
        hardwareCutoverTarget.SelectedIndex = 0;
        hardwareCutoverTarget.SelectedIndexChanged += (_, _) =>
        {
            if (localizingAdvancedChoices) return;
            reviewedHardwareCutoverSha = null;
            reviewedHardwareCutoverContext = null;
            hardwareCutoverSummary = "";
            verifiedHardwarePreflightSha = null;
            verifiedHardwarePreflightContext = null;
            verifiedHardwareSmtpAuthSha = null;
            verifiedHardwareSmtpAuthContext = null;
            listedHardwareBackupsContext = null;
            hardwareCutoverBackup.Items.Clear();
            reviewedHardwareStageSha = null;
            reviewedHardwareStageContext = null;
            hardwareStageSummary = "";
            hardwareStageKeyRef.Text = "";
            reviewedTpmKeyPlanSha = null;
            reviewedTpmKeyPlanContext = null;
            tpmKeySummary = "";
            ResetDeliveryAcceptance();
            reviewedEntraPublicCertificates = null;
            reviewedEntraCertPlanSha = null;
            reviewedEntraCertContext = null;
            reviewedEntraCertObjectId = null;
            entraCertificateSummary = "";
            if (step == 1 && !busy) RenderPage();
        };
        tpmDependencyProfile.SelectedIndexChanged += (_, _) =>
        {
            if (localizingAdvancedChoices) return;
            reviewedTpmPlanSha = null;
            reviewedTpmPlanContext = null;
            tpmPlanSummary = "";
            if (step == 1 && !busy) RenderPage();
        };
        smtpAccountOperation.Items.AddRange(["Add", "Rotate", "Revoke"]);
        smtpAccountOperation.SelectedIndex = 0;
        mailTransport.SelectedIndex = 0;
        senderPolicy.SelectedIndex = 0;
        oauthSenderMode.SelectedIndexChanged += (_, _) =>
        {
            if (!routingLoading)
            {
                ResetMultiMailboxRouteReview();
                oauthSenderAuditSummary = "";
                oauthIngressAuditSummary = "";                oauthSignerAuditSummary = "";

            }
            SaveRoutingChoices();
            UpdatePreserveFlowPreview();
            if (step == 3 && !routingLoading && !busy)
            {
                int scroll = -pageHost.AutoScrollPosition.Y;
                RenderPage();
                pageHost.AutoScrollPosition = new Point(0, scroll);
            }
        };
        oauthSenderMapPath.TextChanged += (_, _) =>
        {
            ResetMultiMailboxRouteReview();
            if (!routingLoading)
            {
                oauthSenderAuditSummary = "";
                oauthIngressAuditSummary = "";                oauthSignerAuditSummary = "";

            }
            SaveRoutingChoices();
            UpdatePreserveFlowPreview();
        };
        isolatedSmtpPort.TextChanged += (_, _) => ResetMultiMailboxRouteReview();
        foreach (var endpointField in new[] { host, sshPort, sshUser })
        {
            endpointField.TextChanged += (_, _) =>
            {
                ResetMultiMailboxRouteReview();
                oauthSenderAuditSummary = "";
                oauthIngressAuditSummary = "";                oauthSignerAuditSummary = "";

                // Never show evidence from the previous host as current.
                discoveredIsolatedRelay = null;
                discoveredMailIdentity = null;
                inspectedHost = null;
                inspectedHostIdentity = null;
                previewedCleanBootstrapSha = null;
                previewedCleanBootstrapIdentity = null;
                cleanBootstrapSummary = "";
                previewedPostfixBasicsSha = null;
                previewedPostfixBasicsContext = null;
                postfixBasicsSummary = "";
                inspectedMail = null;
                inspectedServerIdentity = null;
                foreignBackupListContext = null;
                foreignBackupSelector.Items.Clear();
                existingSmtpAudit = null;
                existingSmtpAuditIdentity = null;
            };
        }
        mailTransport.SelectedIndexChanged += (_, _) => {
            if (!routingLoading) {
                ResetMultiMailboxRouteReview();
                oauthSenderAuditSummary = "";
                oauthIngressAuditSummary = "";                oauthSignerAuditSummary = "";

                acceptedDomainApproved.Checked = false;
                connectorApproved.Checked = false;
                if (mailTransport.SelectedIndex != 1)
                    senderPolicy.SelectedIndex = 0;
            }
            SaveRoutingChoices(); UpdatePreserveFlowPreview();
            if (step is 2 or 3 && !routingLoading && !busy)
            {
                int previousScroll = -pageHost.AutoScrollPosition.Y;
                RenderPage();
                pageHost.AutoScrollPosition = new Point(0, previousScroll);
            }
        };
        recipientScope.SelectedIndexChanged += (_, _) =>
        {
            if (routingLoading) return;
            SaveRoutingChoices();
            if (step is 1 or 2 && !busy) RenderPage();
        };
        senderPolicy.SelectedIndexChanged += (_, _) =>
        {
            SaveRoutingChoices(); UpdatePreserveFlowPreview();
            if (step == 3 && !busy && !routingLoading) RenderPage();
        };
        preserveExistingMail.CheckedChanged += (_, _) =>
        {
            SaveRoutingChoices();
            if (step == 3 && !routingLoading && !busy)
            {
                int previousScroll = -pageHost.AutoScrollPosition.Y;
                RenderPage();
                pageHost.AutoScrollPosition = new Point(0, previousScroll);
            }
        };
        acceptedDomain.Leave += (_, _) => SaveRoutingChoices();
        acceptedDomain.TextChanged += (_, _) =>
        {
            if (!routingLoading) {
                acceptedDomainApproved.Checked = false;
                connectorApproved.Checked = false;
            }
        };
        outboundFixedSender.TextChanged += (_, _) =>
        {
            if (!routingLoading) acceptedDomainApproved.Checked = false;
        };
        foreach (var item in new[] { outboundMxHost, outboundPublicIp,
                                     outboundCertPath, outboundCertKeyPath })
            item.TextChanged += (_, _) =>
            {
                if (!routingLoading) connectorApproved.Checked = false;
            };
        outboundMxHost.Leave += (_, _) => SaveRoutingChoices();
        outboundFixedSender.Leave += (_, _) => SaveRoutingChoices();
        outboundPublicIp.Leave += (_, _) => SaveRoutingChoices();
        outboundConnectorName.Leave += (_, _) => SaveRoutingChoices();
        outboundCertPath.Leave += (_, _) => SaveRoutingChoices();
        outboundCertKeyPath.Leave += (_, _) => SaveRoutingChoices();
        smtpListenIp.Leave += (_, _) => SaveRoutingChoices();
        smtpTrustedCidrs.Leave += (_, _) => SaveRoutingChoices();
        isolatedSmtpPort.Leave += (_, _) => SaveRoutingChoices();
        foreignSidecarHostname.Leave += (_, _) => UpdatePreserveFlowPreview();
        foreach (var field in new[] { postfixBasicsHostname, postfixBasicsDomain })
        {
            field.TextChanged += (_, _) =>
            {
                previewedPostfixBasicsSha = null;
                previewedPostfixBasicsContext = null;
                postfixBasicsSummary = "";
            };
            field.Leave += (_, _) => SaveRoutingChoices();
        }
        postfixBasicsInterfaces.SelectedIndexChanged += (_, _) =>
        {
            if (localizingAdvancedChoices) return;
            previewedPostfixBasicsSha = null;
            previewedPostfixBasicsContext = null;
            postfixBasicsSummary = "";
            if (routingLoading) return;
            SaveRoutingChoices();
            if (step == 3 && !busy) RenderPage();
        };
        privateAuthDns.Leave += (_, _) => SaveRoutingChoices();
        advancedSmtpTools.CheckedChanged += (_, _) =>
        {
            if (routingLoading || busy || step != 3) return;
            SaveRoutingChoices();
            int scroll = -pageHost.AutoScrollPosition.Y;
            RenderPage();
            pageHost.AutoScrollPosition = new Point(0, scroll);
        };
        foreach (TextBox item in new[] { host, mailbox, tenant, smtpListenIp,
                                         isolatedSmtpPort, smtpTrustedCidrs, acceptedDomain,
                                         outboundMxHost, outboundFixedSender })
            item.TextChanged += (_, _) => UpdatePreserveFlowPreview();
        publicInternetRequested.CheckedChanged += (_, _) =>
        {
            if (routingLoading) return;
            if (publicInternetRequested.Checked)
            {
                var response = MessageBox.Show(this, T(
                    "ПУБЛИЧНЫЙ SMTP — ВЫСОКИЙ РИСК.\n\nДаже при SMTP AUTH и обязательном TLS публичный доступ без защиты от злоупотреблений позволит злоумышленникам отправлять спам, подделывать адреса, перегружать очередь и привести к блокировке сервера/IP или репутации Microsoft 365.\n\nЭта отметка сохраняет ТОЛЬКО ПЛАН. Публичный SMTP требует отдельной проверки AUTH, CA/DNS, лимитов, Fail2ban, мониторинга и явного подтверждения. Без дополнительного действия firewall и Postfix не изменяются. Сохранить запрос?",
                    "PUBLIC SMTP — HIGH RISK.\n\nEven with SMTP AUTH and mandatory TLS, unrestricted internet users could send spam, spoof senders, exhaust the queue and cause IP/domain/Microsoft 365 reputation blocking.\n\nThis checkbox saves a PLAN only. Public SMTP requires a separate AUTH/TLS, CA/DNS, rate-limit, Fail2ban and monitoring review plus explicit approval. No firewall or Postfix changes occur by checking this box. Save the plan?",
                    "SMTP ציבורי מחייב אימות, TLS, ניטור והגנה מפני ניצול לרעה. התיבה שומרת תוכנית בלבד."),
                    "LinuxMailRelay365 | Internet SMTP risk",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (response != DialogResult.Yes)
                {
                    publicInternetRequested.Checked = false;
                    return;
                }
            }
            SaveRoutingChoices();
            UpdatePreserveFlowPreview();
            if (step == 3 && !busy)
            {
                int scroll = -pageHost.AutoScrollPosition.Y;
                RenderPage();
                pageHost.AutoScrollPosition = new Point(0, scroll);
            }
        };
        tenantSelector.AccessibleName = "Choose Microsoft Entra tenant";
        tenantSelector.SelectedIndexChanged += (_, _) =>
        {
            if (tenantSelectionLoading) return;
            if (tenantSelector.SelectedItem is TenantOption choice)
            {
                tenant.Text = choice.Id.ToString();
                WriteLine("Selected Microsoft Entra tenant: " + choice.Id);
            }
        };
        sshAuthMode.SelectedIndex = 0;
        sshAuthMode.SelectedIndexChanged += (_, _) =>
        {
            if (!relabelingSshMethods && !busy && step == 0) RenderPage();
        };
        hardwareRequest.CheckedChanged += (_, _) => SaveSecurityChoices();
        ipRequest.CheckedChanged += (_, _) => SaveSecurityChoices();
        monitoringRequest.CheckedChanged += (_, _) => SaveSecurityChoices();
        language.Items.AddRange(["Русский", "English", "עברית"]);
        language.SelectedIndex = 0;
        language.SelectedIndexChanged += (_, _) => RenderPage();
        language.AccessibleName = "Interface language";

        var top = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1,
            AutoSize = true, Padding = new Padding(18, 12, 18, 8) };
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 51));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var logo = new PictureBox { Width = 42, Height = 42, Margin = new Padding(0, 0, 8, 0),
            SizeMode = PictureBoxSizeMode.Zoom, Image = Icon?.ToBitmap() };
        top.Controls.Add(logo, 0, 0);
        top.Controls.Add(brandHeading, 1, 0);
        top.Controls.Add(language, 2, 0);

        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2,
            AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(18, 0, 18, 8)
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        header.Controls.Add(headline, 0, 0);
        header.Controls.Add(subheading, 0, 1);

        // Keep navigation in reach; hide the full log until the operator asks.
        var footerStatus = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2,
            RowCount = 1, AutoSize = true };
        footerStatus.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        footerStatus.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        footerStatus.Controls.Add(status, 0, 0);
        footerStatus.Controls.Add(activityToggle, 1, 0);
        footerStatusLayout = footerStatus;
        activityPanel.Controls.Add(activity);
        var bottom = new TableLayoutPanel
        {
            Dock = DockStyle.None, AutoSize = false,
            RowCount = 3, ColumnCount = 1,
            Padding = new Padding(18, 4, 18, 12)
        };
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bottom.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        bottom.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        bottom.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));
        footerLayout = bottom;
        navigation.WrapContents = true;
        navigation.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        navigation.Margin = new Padding(0, 2, 0, 5);
        bottom.Controls.Add(navigation, 0, 0);
        bottom.Controls.Add(footerStatus, 0, 1);
        bottom.Controls.Add(activityPanel, 0, 2);

        // A separate native Dock=Bottom panel is essential: a tall auto-sized
        // Wizard page must NEVER participate in the footer's row calculation.
        // The content shell receives only the space above the pinned footer.
        var shell = new TableLayoutPanel
        {
            Dock = DockStyle.None, RowCount = 3, ColumnCount = 1,
            AutoSize = false
        };
        shell.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        shell.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        shell.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        shell.Controls.Add(top, 0, 0);
        shell.Controls.Add(header, 0, 1);
        shell.Controls.Add(pageHost, 0, 2);
        var frame = new Panel { Dock = DockStyle.Fill, AutoScroll = false };
        frame.Controls.Add(shell);
        frame.Controls.Add(bottom);
        wizardFrame = frame;
        contentShell = shell;
        frame.SizeChanged += (_, _) => ArrangeWizardPanels();
        Controls.Add(frame);
        ArrangeWizardPanels();
        bool fittingWindowLayout = false;
        void ResizeUi()
        {
            if (fittingWindowLayout) return;
            fittingWindowLayout = true;
            try
            {
                FitHeaderText();
                FitFooterHeight();
                ResizePreserveFlowHelp();
                if (step != 0 || !IsHandleCreated || busy || resizingConnectionLayout ||
                    UseWideConnectionLayout(pageHost.ClientSize.Width, DeviceDpi) == connectionWideLayout)
                    FitCurrentPage();
                else
                {
                    resizingConnectionLayout = true;
                    try { RenderPage(); }
                    finally { resizingConnectionLayout = false; }
                }
            }
            finally { fittingWindowLayout = false; }
        }
        pageHost.SizeChanged += (_, _) => ResizeUi();
        ClientSizeChanged += (_, _) => ResizeUi();
        FitHeaderText();
        FitFooterHeight();
        RenderPage();
        WriteLine("Ready. No user passwords, app secrets, or OAuth tokens are stored by this manager.");
    }

    private string T(string russian, string english, string hebrew) =>
        language.SelectedIndex switch { 1 => english, 2 => hebrew, _ => russian };

    // Keep the window usefully large on normal monitors and nearly full-work-
    // area at high DPI. Never set a minimum larger than the available desktop.
    internal static Size PreferredWizardSize(Size workingArea, int dpi)
    {
        float scale = Math.Max(1f, dpi / 96f);
        int margin = Math.Max(16, (int)Math.Round(24 * scale));
        int availableWidth = Math.Max(360, workingArea.Width - 2 * margin);
        int availableHeight = Math.Max(340, workingArea.Height - 2 * margin);
        return new Size(Math.Min(availableWidth, (int)Math.Round(1220 * scale)),
                        Math.Min(availableHeight, (int)Math.Round(900 * scale)));
    }

    internal static Size MinimumWizardSize(Size workingArea, int dpi)
    {
        float scale = Math.Max(1f, dpi / 96f);
        var maximum = PreferredWizardSize(workingArea, dpi);
        return new Size(Math.Min(maximum.Width, (int)Math.Round(870 * scale)),
                        Math.Min(maximum.Height, (int)Math.Round(670 * scale)));
    }

    internal static Size PreferredDialogSize(Size workingArea, int dpi,
        int logicalWidth, int logicalHeight)
    {
        float scale = Math.Max(1f, dpi / 96f);
        int safeMargin = Math.Max(16, (int)Math.Round(28 * scale));
        return new Size(
            Math.Min(Math.Max(340, workingArea.Width - safeMargin * 2),
                Math.Max(360, (int)Math.Round(logicalWidth * scale))),
            Math.Min(Math.Max(300, workingArea.Height - safeMargin * 2),
                Math.Max(300, (int)Math.Round(logicalHeight * scale))));
    }

    private void FitFooterHeight()
    {
        if (footerLayout is null || footerStatusLayout is null || IsDisposed)
            return;
        float scale = Math.Max(1f, DeviceDpi / 96f);
        int freeWidth = Math.Max(280, ClientSize.Width - 48);
        int navHeight = Math.Max((int)Math.Round(45 * scale),
            navigation.GetPreferredSize(new Size(freeWidth, 0)).Height);
        int statusHeight = Math.Max((int)Math.Round(22 * scale),
            footerStatusLayout.GetPreferredSize(new Size(freeWidth, 0)).Height);
        int activityHeight = activityPanel.Visible
            ? (int)Math.Round(145 * scale) : 0;
        int desired = navHeight + statusHeight + activityHeight +
            footerLayout.Padding.Vertical + (int)Math.Round(16 * scale);
        int minimum = (int)Math.Round(118 * scale);
        int maximum = Math.Max(minimum, ClientSize.Height * 65 / 100);
        int footerHeight = Math.Clamp(desired, minimum, maximum);
        if (Math.Abs(footerLayout.Height - footerHeight) > 1)
            footerLayout.Height = footerHeight;
        ArrangeWizardPanels();
    }

    // Explicitly reserve independent bounds. Dock.Fill and Dock.Bottom can
    // be misordered by WinForms when an AutoScroll child hosts long AutoSize
    // diagrams. Only these two top-level regions use calculated bounds;
    // controls inside each region remain layout/DPI-driven.
    private void ArrangeWizardPanels()
    {
        if (arrangingWizardPanels || wizardFrame is null ||
            contentShell is null || footerLayout is null || IsDisposed)
            return;
        int width = wizardFrame.ClientSize.Width;
        int height = wizardFrame.ClientSize.Height;
        if (width <= 0 || height <= 0) return;
        arrangingWizardPanels = true;
        try
        {
            int footerHeight = Math.Min(footerLayout.Height,
                Math.Max(80, height - 120));
            var contentArea = new Rectangle(0, 0, width,
                Math.Max(0, height - footerHeight));
            var footerArea = new Rectangle(0, height - footerHeight,
                width, footerHeight);
            if (contentShell.Bounds != contentArea)
                contentShell.Bounds = contentArea;
            if (footerLayout.Bounds != footerArea)
                footerLayout.Bounds = footerArea;
            footerLayout.BringToFront();
        }
        finally { arrangingWizardPanels = false; }
    }

    private void FitHeaderText()
    {
        if (IsDisposed) return;
        int dpi = Math.Max(96, DeviceDpi);
        int total = Math.Max(350, ClientSize.Width);
        int headerWidth = Math.Max(260, total - (int)Math.Round(52 * dpi / 96f));
        int brandWidth = Math.Max(160, total - (int)Math.Round(235 * dpi / 96f));
        int footerWidth = Math.Max(240, total - (int)Math.Round(230 * dpi / 96f));
        brandHeading.MaximumSize = new Size(brandWidth, 0);
        headline.MaximumSize = new Size(headerWidth, 0);
        subheading.MaximumSize = new Size(headerWidth, 0);
        status.MaximumSize = new Size(footerWidth, 0);
    }

    private void FitCurrentPage()
    {
        if (IsDisposed || step == 0 || !IsHandleCreated || busy) return;
        if (pageHost.Controls.OfType<TableLayoutPanel>().FirstOrDefault() is not { } page)
            return;
        int width = Math.Max(270, Math.Min(
            pageHost.ClientSize.Width - 22,
            (int)Math.Round(1200 * Math.Max(1f, DeviceDpi / 96f))));
        if (page.Width != width)
        {
            page.MaximumSize = new Size(width, 0);
            page.Width = width;
        }
        int textWidth = Math.Max(230, width - page.Padding.Horizontal - 18);
        foreach (Control child in page.Controls)
        {
            if (child is Label textLabel)
                textLabel.MaximumSize = new Size(textWidth, 0);
            else if (child is TextBox or ComboBox)
                child.Width = Math.Min(Math.Max(180, textWidth), 690);
        }
    }

    private void LocalizeSshAuthMethods()
    {
        string[] labels = language.SelectedIndex switch
        {
            0 => ["SSH-ключ / ssh-agent", "SSH-пользователь и пароль"],
            2 => ["מפתח SSH / ssh-agent", "שם משתמש וסיסמה ל-SSH"],
            _ => ["SSH key / ssh-agent", "SSH username + password"]
        };
        if (sshAuthMode.Items.Count == labels.Length &&
            sshAuthMode.Items[0]?.ToString() == labels[0] &&
            sshAuthMode.Items[1]?.ToString() == labels[1])
            return;
        int selected = Math.Clamp(sshAuthMode.SelectedIndex, 0, labels.Length - 1);
        relabelingSshMethods = true;
        sshAuthMode.BeginUpdate();
        try
        {
            sshAuthMode.Items.Clear();
            sshAuthMode.Items.AddRange(labels);
            sshAuthMode.SelectedIndex = selected;
        }
        finally
        {
            sshAuthMode.EndUpdate();
            relabelingSshMethods = false;
        }
    }

    private void LocalizeAdvancedChoices()
    {
        // Language is presentation-only. Never invalidate a reviewed TPM,
        // HSM, Postfix or SMTP-account plan just by translating the menu.
        static void Relabel(ComboBox combo, string[] captions)
        {
            if (combo.Items.Count == captions.Length &&
                Enumerable.Range(0, captions.Length).All(i =>
                    string.Equals(combo.Items[i]?.ToString(), captions[i],
                        StringComparison.Ordinal)))
                return;
            int selected = Math.Clamp(combo.SelectedIndex, 0, captions.Length - 1);
            combo.BeginUpdate();
            try
            {
                combo.Items.Clear();
                combo.Items.AddRange(captions);
                combo.SelectedIndex = selected;
                int preferred = captions.Max(text =>
                    TextRenderer.MeasureText(text, combo.Font).Width) + 46;
                int screenWidth = Screen.PrimaryScreen?.WorkingArea.Width ?? 1600;
                combo.DropDownWidth = Math.Min(Math.Max(combo.Width, preferred),
                    Math.Max(combo.Width, screenWidth - 38));
            }
            finally { combo.EndUpdate(); }
        }

        int lang = language.SelectedIndex;
        localizingAdvancedChoices = true;
        try
        {
            Relabel(postfixBasicsInterfaces, lang switch
            {
                0 => ["loopback-only — только локальный SMTP",
                      "all — только просмотр, требует отдельной защиты"],
                2 => ["loopback-only — דואר מקומי בלבד",
                      "all — תצוגה בלבד; נדרשת אבטחה נפרדת"],
                _ => ["loopback-only (local clients only)",
                      "all (PREVIEW ONLY; external/public SMTP needs separate security setup)"]
            });
            Relabel(tpmDependencyProfile, lang switch
            {
                0 => ["TPM2: автоматический RPM-профиль (без сторонних репозиториев)",
                      "Утилиты TPM2 (RHEL / Oracle / Rocky / Alma 8–10)",
                      "TPM2: зависимости разработки и сборки (RHEL 8–10)",
                      "TPM2: PKCS#11 и OpenSSL 3 (RHEL 9/10)",
                      "Нативный TPM2 OpenSSL provider (только RHEL 10)"],
                2 => ["פרופיל RPM אוטומטי עבור TPM2",
                      "כלי TPM2 עבור RHEL / Oracle / Rocky / Alma",
                      "תלויות בנייה של TPM2 עבור RHEL",
                      "TPM2 עם PKCS#11 ו-OpenSSL 3",
                      "ספק TPM2 OpenSSL מובנה ב-RHEL 10"],
                _ => ["Automatic TPM2 RPM profile (no third-party repositories)",
                      "TPM2 utilities (RHEL/Oracle/Rocky/Alma 8-10)",
                      "TPM2 development/build prerequisites (RHEL 8-10)",
                      "TPM2 PKCS#11 OpenSSL 3 path (RHEL 9/10)",
                      "Native TPM2 OpenSSL provider (RHEL 10 only)"]
            });
            Relabel(hardwareStageProvider, lang switch
            {
                0 => ["TPM2 через OpenSSL (существующий TPM2-ключ)",
                      "PKCS#11 через OpenSSL (существующий HSM/TPM-ключ)"],
                2 => ["ספק TPM2 OpenSSL עם מפתח קיים",
                      "ספק PKCS#11 OpenSSL עם מפתח HSM/TPM קיים"],
                _ => ["TPM2 OpenSSL provider (existing TPM2 key)",
                      "PKCS#11 OpenSSL provider (existing HSM/TPM key)"]
            });
            Relabel(hardwareCutoverTarget, lang switch
            {
                0 => ["Отдельный SMTP Relay (основной Postfix не менять)",
                      "Основной Postfix XOAUTH2 (расширенный режим)"],
                2 => ["ממסר SMTP נפרד ללא שינוי Postfix הראשי",
                      "Postfix הראשי עם XOAUTH2 (מתקדם)"],
                _ => ["Isolated sidecar (existing primary Postfix untouched)",
                      "Primary Postfix XOAUTH2 transport (advanced)"]
            });
            Relabel(smtpAccountOperation, lang switch
            {
                0 => ["Добавить", "Ротация учётных данных", "Отозвать"],
                2 => ["הוסף", "החלף אישורים", "בטל"],
                _ => ["Add", "Rotate", "Revoke"]
            });
        }
        finally { localizingAdvancedChoices = false; }
    }

    private void LocalizeDeliveryChoices()
    {
        // Keep ComboBox selection/index identities stable across RU / EN / HE.
        // No routing plans, credentials or approvals may be modified by a
        // display-language change.
        static void Relabel(ComboBox combo, string[] values)
        {
            int index = Math.Clamp(combo.SelectedIndex, 0, values.Length - 1);
            combo.BeginUpdate();
            try
            {
                combo.Items.Clear();
                combo.Items.AddRange(values);
                combo.SelectedIndex = index;
            }
            finally { combo.EndUpdate(); }
        }

        int lang = language.SelectedIndex;
        var transportNames = lang switch
        {
            0 => new[]
            {
                "XOAUTH2 — ящик Microsoft 365, порт 587",
                "SMTP Connector — IP/сертификат, внутренняя и внешняя почта, порт 25",
                "Direct Send — только внутренние адресаты M365, порт 25"
            },
            2 => new[]
            {
                "XOAUTH2 — תיבת דואר Microsoft 365, יציאה 587",
                "SMTP Connector — כתובת IP או אישור, יציאה 25",
                "Direct Send — נמענים פנימיים בלבד, יציאה 25"
            },
            _ => new[]
            {
                "XOAUTH2 — authorized Microsoft 365 mailbox, port 587",
                "SMTP Connector — approved IP/certificate, all recipients, port 25",
                "Direct Send — internal Microsoft 365 recipients only, port 25"
            }
        };
        var senderNames = lang switch
        {
            0 => new[]
            {
                "Один фиксированный адрес From",
                "Сохранять From пользователей (SMTP AUTH и From Guard)",
                "Маскировать отправителей из поддоменов (From Guard)"
            },
            2 => new[]
            {
                "כתובת From קבועה",
                "שמירת From לכל משתמש (SMTP AUTH ו-From Guard)",
                "שכתוב כתובת From מתתי-דומיין (From Guard)"
            },
            _ => new[]
            {
                "One fixed approved sender address",
                "Preserve original From (SMTP AUTH and From Guard)",
                "Masquerade approved subdomain From (From Guard)"
            }
        };
        var oauthNames = lang switch
        {
            0 => new[]
            {
                "Один почтовый ящик для всех — From заменяется",
                "Несколько почтовых ящиков — From без замены (офлайн, эксперимент)"
            },
            2 => new[]
            {
                "תיבה אחת לכולם — כתובת From תוחלף",
                "תיבות מרובות — שמירת From (התקנה ניסיונית בלבד)"
            },
            _ => new[]
            {
                "One mailbox for all messages — From rewritten",
                "Multiple authorized mailboxes — offline experiment only"
            }
        };
        var recipientNames = lang switch
        {
            0 => new[] { "Пока не знаю", "Только внутренние M365", "Включая внешних получателей" },
            2 => new[] { "עדיין לא ידוע", "נמעני M365 פנימיים בלבד", "כולל נמענים חיצוניים" },
            _ => new[] { "Not sure yet", "Internal M365 recipients only", "Include external recipients" }
        };
        bool wasLoading = routingLoading;
        routingLoading = true;
        try
        {
            Relabel(mailTransport, transportNames);
            Relabel(senderPolicy, senderNames);
            Relabel(oauthSenderMode, oauthNames);
            Relabel(recipientScope, recipientNames);
        }
        finally { routingLoading = wasLoading; }
    }

    private static void AddLine(TableLayoutPanel table, Control control)
    {
        // Only root wizard controls must fit the scrollable viewport. Nested
        // cards/diagrams keep their own layout, while long labels wrap.
        if (table.Parent is Panel scrollingPanel && scrollingPanel.AutoScroll)
        {
            int width = Math.Max(230, table.Width - table.Padding.Horizontal - 18);
            if (control is Label label)
                label.MaximumSize = new Size(width, 0);
            else if (control is TextBox or ComboBox)
                control.Width = Math.Min(Math.Max(180, width), 690);
        }
        int row = table.RowCount++;
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        table.Controls.Add(control, 0, row);
    }

    private TableLayoutPanel NewPage()
    {
        int pageWidth = Math.Max(280, Math.Min(pageHost.ClientSize.Width - 22,
            (int)Math.Round(1200 * Math.Max(1f, DeviceDpi / 96f))));
        var page = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1, RowCount = 0,
            Width = pageWidth,
            Padding = new Padding(20, 6, 20, 20),
            BackColor = UiTheme.Canvas,
            MaximumSize = new Size(pageWidth, 0)
        };
        page.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        return page;
    }

    private void AddField(TableLayoutPanel table, string caption, TextBox input)
    {
        AddLine(table, UiTheme.Text(caption));
        AddLine(table, input);
    }

    private Button AddAction(TableLayoutPanel table, string caption, Func<Task> handler,
        bool primary = false, string glyph = "check", string category = "diagnostics")
    {
        var button = UiTheme.Action(caption, primary, glyph);
        button.Enabled = !busy;
        button.Click += async (_, _) => await RunBusyAsync(category, handler);
        AddLine(table, button);
        return button;
    }


    internal static bool UseWideConnectionLayout(int hostWidth, int dpi) =>
        (long)hostWidth * 96 >= 900L * Math.Max(96, dpi);

    private static TableLayoutPanel ConnectionCard(Color background)
    {
        var card = new TableLayoutPanel
        {
            AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1, RowCount = 0, Dock = DockStyle.Fill,
            BackColor = background,
            Margin = new Padding(0, 0, 10, 12),
            Padding = new Padding(16, 12, 16, 16)
        };
        card.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        return card;
    }

    private void AddConnectionField(TableLayoutPanel card, string caption, Control input)
    {
        var label = UiTheme.Text(caption);
        label.ForeColor = UiTheme.Navy;
        label.Margin = new Padding(0, 5, 0, 4);
        input.AccessibleName = caption;
        // Do not let global 690px TextBox preferred widths force the card
        // beyond its table column. Dock=Fill will stretch to available space.
        input.Width = 180;
        input.MinimumSize = Size.Empty;
        input.Dock = DockStyle.Fill;
        input.Margin = new Padding(0, 0, 0, 10);
        AddLine(card, label);
        AddLine(card, input);
    }

    private void AddConnectionPair(TableLayoutPanel card, string leftCaption, Control left,
        string rightCaption, Control right, float leftPercent = 60)
    {
        var pair = new TableLayoutPanel
        {
            Dock = DockStyle.Top, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 2, RowCount = 2,
            BackColor = card.BackColor, Margin = new Padding(0)
        };
        pair.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, leftPercent));
        pair.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100 - leftPercent));
        pair.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pair.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var leftLabel = UiTheme.Text(leftCaption);
        var rightLabel = UiTheme.Text(rightCaption);
        leftLabel.ForeColor = rightLabel.ForeColor = UiTheme.Navy;
        leftLabel.Margin = rightLabel.Margin = new Padding(0, 5, 0, 4);
        left.AccessibleName = leftCaption;
        right.AccessibleName = rightCaption;
        // WinForms AutoSize TableLayoutPanel uses child preferred widths;
        // shrink old fixed-width fields BEFORE docking so percent columns
        // (server + port; username + auth mode) remain responsive.
        left.Width = 150;
        right.Width = 120;
        left.MinimumSize = right.MinimumSize = Size.Empty;
        left.Dock = right.Dock = DockStyle.Fill;
        left.Margin = new Padding(0, 0, 10, 12);
        right.Margin = new Padding(0, 0, 0, 12);
        pair.Controls.Add(leftLabel, 0, 0);
        pair.Controls.Add(rightLabel, 1, 0);
        pair.Controls.Add(left, 0, 1);
        pair.Controls.Add(right, 1, 1);
        AddLine(card, pair);
    }

    private void AddConnectionHelp(TableLayoutPanel card, string text, int wrapWidth)
    {
        var label = new Label
        {
            Text = text,
            AutoSize = true, MaximumSize = new Size(Math.Max(240, wrapWidth), 0),
            Font = new Font("Segoe UI", 10f),
            ForeColor = UiTheme.Muted, Margin = new Padding(0, 9, 0, 10)
        };
        AddLine(card, label);
    }

    private void RenderConnectionStep(TableLayoutPanel page)
    {
        connectionWideLayout = UseWideConnectionLayout(pageHost.ClientSize.Width, DeviceDpi);
        // Even a single-column card can fit two short input fields at 760px,
        // avoiding unnecessary vertical scrolling to the primary action.
        bool pairFields = (long)pageHost.ClientSize.Width * 96 >=
            690L * Math.Max(DeviceDpi, 96);
        page.MaximumSize = Size.Empty;
        page.Dock = DockStyle.Top;
        page.Padding = new Padding(18, 4, 8, 12);
        int availableWidth = Math.Max(300, pageHost.ClientSize.Width - 38);
        var cards = new TableLayoutPanel
        {
            Dock = DockStyle.Top, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = connectionWideLayout ? 2 : 1,
            RowCount = connectionWideLayout ? 1 : 2,
            BackColor = UiTheme.Canvas,
            Margin = new Padding(0),
            Width = availableWidth,
            MaximumSize = new Size(availableWidth, 0)
        };
        if (connectionWideLayout)
        {
            cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 63));
            cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 37));
        }
        else
            cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var form = ConnectionCard(Color.White);
        var details = ConnectionCard(Color.FromArgb(238, 243, 248));
        form.MaximumSize = new Size(connectionWideLayout
            ? Math.Max(340, availableWidth * 63 / 100 - 12) : availableWidth, 0);
        details.MaximumSize = new Size(connectionWideLayout
            ? Math.Max(260, availableWidth * 37 / 100 - 12) : availableWidth, 0);
        cards.Controls.Add(form, 0, 0);
        cards.Controls.Add(details, connectionWideLayout ? 1 : 0,
            connectionWideLayout ? 0 : 1);

        var heading = UiTheme.Text(T("Данные сервера", "Server connection", "פרטי השרת"), true);
        AddLine(form, heading);
        AddConnectionPair(form,
            T("Linux: DNS или IPv4", "Linux DNS or IPv4", "כתובת Linux"), host,
            T("SSH-порт", "SSH port", "פורט SSH"), sshPort, 73);
        if (pairFields)
            AddConnectionPair(form,
                T("SSH-пользователь", "SSH username", "משתמש SSH"), sshUser,
                T("Способ входа", "Authentication method", "שיטת אימות"), sshAuthMode, 43);
        else
        {
            AddConnectionField(form, T("SSH-пользователь", "SSH username", "משתמש SSH"), sshUser);
            AddConnectionField(form, T("Способ входа", "Authentication method", "שיטת אימות"), sshAuthMode);
        }
        if (sshAuthMode.SelectedIndex == 1)
        {
            if (pairFields)
                AddConnectionPair(form,
                    T("SSH-пароль", "SSH password", "סיסמת SSH"), sshPassword,
                    T("Пароль sudo (если нужен)", "Sudo password (if needed)", "סיסמת sudo"), sudoPassword, 54);
            else
            {
                AddConnectionField(form, T("SSH-пароль (не сохраняется)",
                    "SSH password (not saved)", "סיסמת SSH"), sshPassword);
                AddConnectionField(form, T("Пароль sudo (если нужен)",
                    "Sudo password (if needed)", "סיסמת sudo"), sudoPassword);
            }
            specifyHostKeyManually.Text = T(
                "Указать SSH host key SHA256 вручную (необязательно)",
                "Enter SSH host key SHA256 manually (optional)",
                "הקלדת טביעת מפתח SSH ידנית (אופציונלי)");
            AddLine(form, specifyHostKeyManually);
            if (specifyHostKeyManually.Checked)
            {
                sshFingerprint.PlaceholderText = "SHA256:...";
                AddConnectionField(form, T("Подтверждённый SSH SHA256", "Verified SSH SHA256",
                    "טביעת SHA256 מאומתת"), sshFingerprint);
            }
        }
        else
        {
            if (pairFields)
                AddConnectionPair(form,
                    T("SSH-ключ / ssh-agent", "SSH key / ssh-agent", "מפתח SSH"), sshKey,
                    T("Пароль sudo (если нужен)", "Sudo password (if needed)", "סיסמת sudo"), sudoPassword, 60);
            else
            {
                AddConnectionField(form, T("SSH-ключ / ssh-agent", "SSH key / ssh-agent", "מפתח SSH"), sshKey);
                AddConnectionField(form, T("Пароль sudo (если нужен)",
                    "Sudo password (if needed)", "סיסמת sudo"), sudoPassword);
            }
        }
        // The primary SSH action is anchored in the footer so it remains
        // visible at 100–200% DPI and does not require scrolling the card.
        AddLine(form, UiTheme.Text(T(
            "После заполнения полей нажмите «Проверить подключение» внизу окна.",
            "After entering the details, select Check connection in the fixed footer.",
            "לאחר הזנת הפרטים לחצו בדיקת חיבור בתחתית החלון.")));
        AddLine(details, UiTheme.Text(T("Как это работает", "What happens next", "כיצד זה עובד"), true));
        AddConnectionHelp(details, sshAuthMode.SelectedIndex == 1
            ? T("1. Введи SSH-пароль. SHA256 вводить необязательно.\n\n2. При первом соединении программа покажет отпечаток сервера. Подтверди его перед входом.\n\n3. После проверки откроется следующий шаг.",
                "1. Enter your SSH password. SHA256 is optional.\n\n2. On first contact, verify and approve the server key before login.\n\n3. A successful check opens the next step.",
                "יש להזין סיסמת SSH; טביעת SHA256 אופציונלית ודורשת אישור בחיבור ראשון.")
            : T("1. Используется установленный Windows OpenSSH.\n\n2. SSH host key должен быть подтверждён в known_hosts.\n\n3. Успешная проверка откроет следующий шаг.",
                "1. Uses Windows OpenSSH key or agent.\n\n2. The host key must already be trusted in known_hosts.\n\n3. A successful check opens the next step.",
                "נעשה שימוש ב-Windows OpenSSH וב-known_hosts."),
            connectionWideLayout ? (int)(pageHost.Width * .34) - 56 : pageHost.Width - 100);
        AddLine(details, UiTheme.Text(T("Важно", "Security note", "הערת אבטחה"), true));
        AddConnectionHelp(details,
            T("При первом подключении сравни SHA256 с ключом на консоли Linux, если есть такая возможность. Пароли в настройках не сохраняются. Кнопка «Далее» пропускает проверку, но не подтверждает подключение.",
              "When possible, compare the SHA256 with the Linux console. Passwords are not saved. The Next button skips this check; it does not verify connectivity.",
              "רצוי להשוות את טביעת המפתח במסוף השרת. סיסמאות אינן נשמרות."),
            connectionWideLayout ? (int)(pageHost.Width * .34) - 56 : pageHost.Width - 100);
        AddLine(page, cards);
    }

    private async Task CheckSshAndContinueAsync()
    {
        await CheckSshAsync();
        EnsureSecurityLoaded();
        EnsureRoutingLoaded();
        // Read-only discovery immediately after a VERIFIED SSH login.
        // If unavailable, continue with an explicit UNVERIFIED advisory;
        // all installers already require a successful fresh MTA inventory.
        try { await InspectMailRoutingAsync(); }
        catch (Exception error)
        {
            inspectedMail = null;
            inspectedServerIdentity = null;
            existingSmtpAudit = null;
            existingSmtpAuditIdentity = null;
            discoveredIsolatedRelay = null;
            discoveredMailIdentity = null;
            WriteLine("Automatic MTA discovery incomplete; manual review required before any installation. " +
                "Read-only probe failed (" + error.GetType().Name + ").");
        }
        step = 1;
    }



    internal static bool UseWideDeliveryChoices(int hostWidth, int dpi) =>
        (long)hostWidth * 96 >= 660L * Math.Max(96, dpi);

    private TableLayoutPanel BuildDeliveryModeChoices()
    {
        // Compact mode cards replace a long dropdown on the route-selection
        // step. The existing ComboBox remains the single source of truth.
        // The handler only changes a local plan, never installs any route.
        bool horizontal = UseWideDeliveryChoices(pageHost.ClientSize.Width, DeviceDpi);
        int width = Math.Max(325, pageHost.ClientSize.Width - 45);
        var choices = new TableLayoutPanel
        {
            ColumnCount = horizontal ? 3 : 1,
            RowCount = horizontal ? 1 : 3,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Width = width,
            MaximumSize = new Size(width, 0),
            BackColor = UiTheme.Canvas,
            Margin = new Padding(0, 7, 0, 10),
            Padding = Padding.Empty
        };
        for (int i = 0; i < choices.ColumnCount; ++i)
            choices.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / choices.ColumnCount));
        for (int i = 0; i < choices.RowCount; ++i)
            choices.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var labels = language.SelectedIndex switch
        {
            0 => new[]
            {
                "XOAUTH2 · порт 587\nСертификат Entra",
                "SMTP Connector · порт 25\nIP или TLS-сертификат",
                "Direct Send · порт 25\nТолько внутри M365"
            },
            2 => new[]
            {
                "XOAUTH2 · 587\nאישור Entra",
                "SMTP Connector · 25\nIP או אישור TLS",
                "Direct Send · 25\nלנמענים פנימיים בלבד"
            },
            _ => new[]
            {
                "XOAUTH2 · port 587\nEntra certificate",
                "SMTP Connector · port 25\nApproved IP or TLS cert",
                "Direct Send · port 25\nM365 internal only"
            }
        };
        for (int mode = 0; mode < labels.Length; mode++)
        {
            int index = mode;
            bool selected = mailTransport.SelectedIndex == mode;
            var tile = new Button
            {
                Text = labels[mode],
                Width = Math.Max(175, width / choices.ColumnCount - 15),
                Height = Math.Max(79, (int)Math.Ceiling(79f * DeviceDpi / 96f)),
                AutoSize = false,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, mode == 2 || !horizontal ? 0 : 9, 7),
                Padding = new Padding(11, 5, 9, 5),
                TextAlign = ContentAlignment.MiddleLeft,
                FlatStyle = FlatStyle.Flat,
                BackColor = selected ? UiTheme.Accent : Color.White,
                ForeColor = selected ? Color.White : UiTheme.Navy,
                Font = new Font("Segoe UI", 9.5f,
                    selected ? FontStyle.Bold : FontStyle.Regular),
                Cursor = Cursors.Hand,
                AccessibleName = labels[mode].Replace('\n', ' '),
                AccessibleDescription = DeliveryModeOverview.Describe(mode,
                    language.SelectedIndex, oauthSenderMode.SelectedIndex == 1).Safety,
                TabStop = !busy,
                Enabled = !busy
            };
            tile.FlatAppearance.BorderColor = selected
                ? UiTheme.Accent : Color.FromArgb(205, 217, 230);
            tile.FlatAppearance.BorderSize = selected ? 2 : 1;
            tile.Click += (_, _) =>
            {
                if (busy || mailTransport.SelectedIndex == index) return;
                mailTransport.SelectedIndex = index; // Re-renders from existing event.
            };
            choices.Controls.Add(tile, horizontal ? mode : 0, horizontal ? 0 : mode);
        }
        return choices;
    }

    private TableLayoutPanel BuildDeliveryModeOverview()
    {
        var guide = DeliveryModeOverview.Describe(
            Math.Clamp(mailTransport.SelectedIndex, 0, 2), language.SelectedIndex,
            oauthSenderMode.SelectedIndex == 1);
        var panel = new TableLayoutPanel
        {
            AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1, RowCount = 0, BackColor = Color.White,
            Margin = new Padding(0, 13, 0, 16),
            Padding = new Padding(14, 10, 14, 13),
            MaximumSize = new Size(920, 0)
        };
        var headline = UiTheme.Text(T("Выбранный маршрут", "Selected mail route", "מסלול הדואר שנבחר") +
            " · " + guide.Name, true);
        headline.ForeColor = UiTheme.Navy;
        AddLine(panel, headline);
        void Detail(string caption, string value, bool alert = false)
        {
            int maxWidth = Math.Max(330, Math.Min(885, pageHost.ClientSize.Width - 80));
            var label = new Label
            {
                Text = caption + ": " + value,
                AutoSize = true, MaximumSize = new Size(maxWidth, 0),
                Font = new Font("Segoe UI", 10f),
                ForeColor = alert ? Color.FromArgb(142, 76, 19) : UiTheme.Muted,
                Margin = new Padding(0, 5, 0, 5)
            };
            AddLine(panel, label);
        }
        Detail(T("Схема", "Flow", "זרימה"),
            T("Программы", "Applications", "יישומים") + " → Linux SMTP:" +
            isolatedSmtpPort.Text.Trim() + " → " + guide.Target);
        Detail(T("Получатели", "Recipients", "נמענים"), guide.Audience);
        Detail(T("Авторизация", "Authentication", "אימות"), guide.Authorization);
        Detail(T("Отправитель", "Sender", "שולח"), guide.Sender);
        Detail(T("Что потребуется", "Requirements", "דרישות"), guide.Requirements);
        Detail(T("Важно", "Important", "חשוב"), guide.Safety, true);
        AddLine(panel, UiTheme.Text(T(
            "Это схема выбора, а не подтверждение настройки. Ничего не отправлено и не изменено.",
            "This is a selection preview, not proof of configuration. Nothing was sent or changed.",
            "תצוגה מקדימה בלבד; לא נשלחו הודעות ולא שונו הגדרות.")));
        return panel;
    }


    private void ShowMailDiscovery(TableLayoutPanel page, bool showRefresh)
    {
        bool sameServer = discoveredMailIdentity is not null &&
            discoveredMailIdentity == TryCurrentIdentity();
        var inventory = sameServer ? inspectedMail : null;
        var audit = sameServer ? existingSmtpAudit : null;
        bool? sidecar = sameServer ? discoveredIsolatedRelay : null;
        var decision = MailServerDiscoveryDecision.Assess(inventory, audit, sidecar);

        AddLine(page, UiTheme.Text(T("Обнаруженная почтовая конфигурация Linux",
                                    "Detected Linux mail configuration",
                                    "תצורת דואר שזוהתה בלינוקס"), true));
        var overview = new Label
        {
            AutoSize = true, MaximumSize = new Size(Math.Max(390, pageHost.ClientSize.Width - 72), 0),
            Text = decision.Explain(language.SelectedIndex, inventory, audit, sidecar),
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = decision.ManualReviewRequired
                ? Color.FromArgb(143, 72, 22) : UiTheme.Navy,
            BackColor = Color.White,
            Padding = new Padding(10, 9, 10, 9),
            Margin = new Padding(0, 7, 0, 10)
        };
        AddLine(page, overview);
        if (sameServer && inspectedHostIdentity == TryCurrentIdentity() &&
            inspectedHost is not null)
        {
            AddLine(page, new Label
            {
                AutoSize = true, MaximumSize = new Size(Math.Max(390, pageHost.ClientSize.Width - 72), 0),
                Text = inspectedHost.Summary(language.SelectedIndex),
                Font = new Font("Segoe UI", 9f), ForeColor = UiTheme.Muted,
                BackColor = Color.White, Padding = new Padding(10, 6, 10, 6),
                Margin = new Padding(0, 4, 0, 10)
            });
            if (inspectedHost.HasFqdn)
                AddAction(page, inspectedMail?.Mta is "exim" or "sendmail"
                    ? T("Предложить отдельное DNS-имя для Relay (без установки)",
                        "Suggest separate Relay DNS name (no install)",
                        "הצע שם DNS נפרד לממסר")
                    : T("Использовать найденный FQDN в настройках SMTP (без установки)",
                        "Use detected FQDN for SMTP settings (no install)",
                        "השתמש בשם המארח שהתגלה בהגדרות SMTP"),
                    UseDetectedFqdnAsync, false, "check", "mail-hostname");
            if (inspectedHost.HasDomain)
                AddAction(page, T("Подставить домен в поле M365 (потребуется подтверждение)",
                    "Prefill M365 domain (tenant verification still required)",
                    "מלא דומיין, כפוף לאימות Microsoft 365"),
                    UseDetectedDomainAsync, false, "check", "mail-domain");
        }
        else AddLine(page, UiTheme.Text(T(
            "Hostname и настройки MTA ещё не проверены.",
            "OS hostname and MTA-specific settings are not verified.",
            "שם המארח והגדרות הדואר טרם נבדקו.")));
        if (audit is not null)
        {
            var details = new Label
            {
                AutoSize = true, MaximumSize = new Size(Math.Max(390, pageHost.ClientSize.Width - 72), 0),
                Text = audit.Summary(language.SelectedIndex),
                Font = new Font("Segoe UI", 9f),
                ForeColor = UiTheme.Muted,
                Margin = new Padding(0, 0, 0, 8)
            };
            AddLine(page, details);
        }
        if (showRefresh)
            AddAction(page, T("Повторно проверить работающий MTA, SMTP и Relay (без изменений)",
                              "Reinspect active MTA, SMTP and Relay (read-only)",
                              "בדיקה חוזרת של MTA ו-SMTP ללא שינוי"),
                InspectMailRoutingAsync, false, "check", "mta-discovery");
    }

    private Task UseDetectedFqdnAsync()
    {
        if (inspectedHostIdentity != TryCurrentIdentity() || inspectedHost?.HasFqdn != true)
            throw new InvalidOperationException("Reinspect Linux hostname first.");
        bool foreign = inspectedMail?.Mta is "exim" or "sendmail";
        if (foreign && (inspectedHost.HasDomain != true ||
            inspectedServerIdentity != TryCurrentIdentity()))
            throw new InvalidOperationException(
                "Inspect the active Exim/Sendmail MTA and its domain before suggesting a distinct FQDN.");
        string name = foreign ? "relay." + inspectedHost.Domain : inspectedHost.Fqdn;
        if (foreign && string.Equals(name, inspectedHost.Fqdn, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Sidecar FQDN must differ from the existing primary MTA.");
        var confirmation = MessageBox.Show(this, T(
            "Предложить " + name + " для " + (foreign ? "отдельного SMTP Relay" : "SMTP TLS") +
            "? Это только поле мастера. Перед настройкой обязательно проверьте DNS, сертификат и отсутствие конфликта с текущим MTA.",
            "Suggest " + name + " for " + (foreign ? "the independent SMTP Relay" : "SMTP TLS") +
            "? This only fills a Wizard field. Verify DNS, certificate identity and that the primary MTA owns a different name.",
            "להציע " + name + "? אין שינוי בשרת; יש לבדוק DNS, אישור וזהות נפרדת."),
            "LinuxMailRelay365 | Use Linux hostname",
            MessageBoxButtons.YesNo, MessageBoxIcon.Information,
            MessageBoxDefaultButton.Button2);
        if (confirmation != DialogResult.Yes) return Task.CompletedTask;
        if (foreign)
            foreignSidecarHostname.Text = name;
        else
            privateAuthDns.Text = name;
        SaveRoutingChoices();
        RenderPage();
        return Task.CompletedTask;
    }

    private Task UseDetectedDomainAsync()
    {
        if (inspectedHostIdentity != TryCurrentIdentity() || inspectedHost?.HasDomain != true)
            throw new InvalidOperationException("Reinspect Linux domain first.");
        string domain = inspectedHost.Domain;
        if (MessageBox.Show(this, T(
            "Подставить " + domain + " в поле домена Microsoft 365? Это НЕ проверка accepted domain в tenant; подтверждение будет сброшено.",
            "Prefill " + domain + " as the M365 accepted domain? This is NOT tenant verification. Any previous domain approval is cleared.",
            "למלא " + domain + "? נדרש אישור בעלות ב-Microsoft 365."),
            "LinuxMailRelay365 | Domain suggestion", MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return Task.CompletedTask;
        acceptedDomainApproved.Checked = false;
        connectorApproved.Checked = false;
        acceptedDomain.Text = domain;
        SaveRoutingChoices();
        RenderPage();
        return Task.CompletedTask;
    }

    private void AddDetectedPrivateInterfacePicker(TableLayoutPanel page)
    {
        if (inspectedHostIdentity != TryCurrentIdentity() || inspectedHost is null)
            return;
        var candidates = inspectedHost.ActivePrivateIPv4s();
        if (candidates.Count == 0)
        {
            AddLine(page, UiTheme.Text(T(
                "Подходящих активных частных IPv4 не найдено. Укажите адрес вручную только после проверки ip addr и firewall.",
                "No eligible UP private IPv4 interfaces found. Enter a listener manually only after checking ip addr and firewall.",
                "לא נמצא IPv4 פרטי פעיל.")));
            return;
        }
        AddLine(page, UiTheme.Text(T(
            "Выбрать один из обнаруженных поднятых IPv4 (только заполнить поле)",
            "Pick a verified UP private IPv4 (prefill listener field only)",
            "בחר כתובת IPv4 פרטית פעילה"), true));
        var selector = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 690,
            Font = new Font("Segoe UI", 9.5f),
            Margin = new Padding(0, 4, 0, 9),
            AccessibleName = "Detected active Linux private IPv4 listeners (plan only)"
        };
        selector.Items.Add(T("Выберите интерфейс...", "Choose interface...",
            "בחר ממשק..."));
        foreach (var item in candidates)
            selector.Items.Add(item.Name + "  ·  " + item.Address);
        selector.SelectedIndex = 0;
        selector.SelectedIndexChanged += (_, _) =>
        {
            int index = selector.SelectedIndex - 1;
            if (index < 0 || index >= candidates.Count) return;
            if (inspectedHostIdentity != TryCurrentIdentity()) return;
            smtpListenIp.Text = candidates[index].Address;
            SaveRoutingChoices();
            WriteLine("Selected discovered private IPv4 for SMTP plan only. " +
                      "No Postfix, network listener or firewall changed.");
        };
        AddLine(page, selector);
        AddLine(page, UiTheme.Text(T(
            "Адрес должен оставаться назначенным и поднятым во время установки. Для клиентов других компьютеров также укажите доверенные CIDR, AUTH/TLS и отдельно проверьте firewall.",
            "The IP must remain assigned and UP at apply time. Remote clients also require trusted CIDRs, AUTH/TLS and a separately audited firewall.",
            "הכתובת חייבת להישאר פעילה. נדרשת בדיקת הרשאות ורשת.")));
    }

    private void ShowPostfixBasicsSection(TableLayoutPanel page)
    {
        if (inspectedMail?.Mta != "postfix" ||
            inspectedServerIdentity != TryCurrentIdentity())
        {
            AddLine(page, UiTheme.Text(T(
                "Настройка основного Postfix доступна только после его проверки. Exim/Sendmail не меняются: для них предусмотрен независимый Relay.",
                "Primary Postfix configuration is available only after verified Postfix discovery. Exim/Sendmail remain untouched; use an independent relay.",
                "הגדרת Postfix הראשי דורשת בדיקה. Exim/Sendmail לא ישונו.")));
            return;
        }
        AddLine(page, UiTheme.Text(T(
            "Основной Postfix — базовые параметры (отдельная рискованная операция)",
            "Primary Postfix — basic main.cf profile (separately approved operation)",
            "הגדרות בסיסיות של Postfix הראשי"), true));
        AddLine(page, UiTheme.Text(T(
            "Применение НЕ требуется для режима Preserve Existing Mail. Сначала сравните существующий main.cf, local delivery и активные интерфейсы. Профиль ограничен loopback и IPv4; изменение имени может повлиять на отправителей и сертификаты.",
            "Preserve Existing Mail does NOT require changing primary main.cf. Review current local delivery and active interfaces first. This fixed profile is loopback/IPv4 only; identity changes can affect sender addresses, TLS and mail delivery.",
            "השמירה על דואר קיים אינה דורשת שינוי main.cf. יש לבדוק ממשקים, זהות וניתוב.")));
        AddField(page, T("myhostname (FQDN основного Postfix)",
                         "myhostname (primary Postfix FQDN)", "שם מלא של Postfix"),
                 postfixBasicsHostname);
        AddField(page, T("mydomain (домен основного Postfix)",
                         "mydomain (primary Postfix domain)", "דומיין Postfix"),
                 postfixBasicsDomain);
        AddLine(page, UiTheme.Text(
            "myorigin = $mydomain; mydestination = $myhostname, localhost.$mydomain, localhost; inet_protocols = ipv4."));
        AddLine(page, UiTheme.Text(T(
            "inet_interfaces: loopback-only — только локальный SMTP. all — просмотр возможен, но изменение основного Postfix через этот профиль ЗАБЛОКИРОВАНО. Для локальной сети используйте отдельный SMTP sidecar с AUTH/TLS и доверенными IP.",
            "inet_interfaces: loopback-only = local SMTP only. all = preview only; primary-Postfix public/wildcard apply is BLOCKED here. Use the authenticated isolated sidecar for network clients.",
            "loopback-only מקומי בלבד. all לתצוגה בלבד ולא להפעלה.")));
        AddLine(page, postfixBasicsInterfaces);
        if (inspectedHostIdentity == TryCurrentIdentity() &&
            inspectedHost?.HasFqdn == true && inspectedHost.HasDomain)
            AddAction(page, T(
                "Подставить обнаруженный Linux FQDN и домен в поля Postfix",
                "Fill Postfix fields from inspected Linux hostname and domain",
                "מלא שם מארח ודומיין שנמצאו"),
                UseDetectedPostfixBasicsAsync, false, "check", "postfix-basics-prefill");
        AddAction(page, T(
            "Предпросмотр изменений main.cf (без записи)",
            "Preview primary main.cf changes (read-only)",
            "תצוגה מקדימה של main.cf ללא שינוי"),
            PreviewPostfixBasicsAsync, false, "check", "postfix-basics-preview");
        if (!string.IsNullOrEmpty(postfixBasicsSummary))
            AddLine(page, UiTheme.Text(postfixBasicsSummary));
        if (previewedPostfixBasicsSha is not null &&
            postfixBasicsInterfaces.SelectedIndex == 0)
            AddAction(page, T(
                "Применить проверенную конфигурацию Postfix (backup, restart)...",
                "Apply reviewed primary Postfix profile (backup, restart)...",
                "החל הגדרות Postfix לאחר גיבוי ואישור"),
                ApplyPostfixBasicsAsync, false, "shield", "postfix-basics-apply");
    }

    private Task UseDetectedPostfixBasicsAsync()
    {
        if (inspectedHostIdentity != TryCurrentIdentity() ||
            inspectedHost?.HasFqdn != true || !inspectedHost.HasDomain ||
            inspectedMail?.Mta != "postfix")
            throw new InvalidOperationException("Reinspect Postfix and hostname before copying.");
        if (MessageBox.Show(this, T(
                "Скопировать FQDN и домен из Linux в поля основного Postfix? Это только локальные поля Wizard, не проверка DNS/Entra. Конфигурация Linux НЕ изменится.",
                "Prefill primary Postfix hostname and domain from Linux? This only changes Wizard fields, not Postfix/DNS/Entra, and does NOT prove M365 domain ownership.",
                "למלא שם מארח ודומיין בלבד? ללא שינוי בשרת."),
                "LinuxMailRelay365 | Prefill Postfix basics",
                MessageBoxButtons.YesNo, MessageBoxIcon.Information,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return Task.CompletedTask;
        postfixBasicsHostname.Text = inspectedHost.Fqdn;
        postfixBasicsDomain.Text = inspectedHost.Domain;
        SaveRoutingChoices();
        RenderPage();
        return Task.CompletedTask;
    }

    private string PostfixBasicsContext()
    {
        string name = postfixBasicsHostname.Text.Trim().ToLowerInvariant();
        string domain = postfixBasicsDomain.Text.Trim().ToLowerInvariant();
        string listener = postfixBasicsInterfaces.SelectedIndex == 1
            ? "all" : "loopback-only";
        var current = TryCurrentIdentity();
        if (current is null || inspectedServerIdentity != current ||
            inspectedMail?.Mta != "postfix")
            throw new InvalidOperationException("Reinspect the selected Postfix host.");
        return current + "|" + name + "|" + domain + "|" + listener;
    }

    private async Task<RemoteResult> PostfixBasicsScriptAsync(string? approvalSha)
    {
        var endpoint = Endpoint();
        string listener = postfixBasicsInterfaces.SelectedIndex == 1
            ? "all" : "loopback-only";
        string script = EmbeddedAssets.BuildPostfixBasicsBundle(
            postfixBasicsHostname.Text.Trim().ToLowerInvariant(),
            postfixBasicsDomain.Text.Trim().ToLowerInvariant(),
            listener, approvalSha);
        return endpoint.Username == "root"
            ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script,
                timeout: TimeSpan.FromMinutes(approvalSha is null ? 2 : 5))
            : await SshRemote.RunRootScriptAsync(endpoint, script,
                TimeSpan.FromMinutes(approvalSha is null ? 2 : 5));
    }

    private async Task PreviewPostfixBasicsAsync()
    {
        EnsureRoutingLoaded();
        string context = PostfixBasicsContext();
        if (inspectedHostIdentity != TryCurrentIdentity() ||
            inspectedHost?.Mta != "postfix" ||
            existingSmtpAuditIdentity != TryCurrentIdentity() ||
            existingSmtpAudit is null || existingSmtpAudit.SuspectedUnsafeRelay)
            throw new InvalidOperationException(
                "First complete MTA, hostname, public SMTP and relay-safety audits. Unsafe/unknown audits block primary changes.");
        previewedPostfixBasicsSha = null;
        previewedPostfixBasicsContext = null;
        postfixBasicsSummary = "";
        var report = await PostfixBasicsScriptAsync(null);
        report.EnsureSuccess();
        var sha = System.Text.RegularExpressions.Regex.Match(report.StdOut,
            @"(?m)^POSTFIX_BASICS_PLAN_SHA256=([a-f0-9]{64})\r?$");
        var reason = System.Text.RegularExpressions.Regex.Match(report.StdOut,
            @"(?m)^POSTFIX_BASICS_PREFLIGHT=([a-z0-9_]{1,85})\r?$");
        if (!report.StdOut.Contains("POSTFIX_BASICS_VERSION=1", StringComparison.Ordinal) ||
            !report.StdOut.Contains("CHANGES_APPLIED=no", StringComparison.Ordinal) ||
            !sha.Success || !reason.Success)
            throw new InvalidDataException("Incomplete Postfix baseline preview.");
        if (reason.Groups[1].Value != "ready")
        {
            postfixBasicsSummary = T(
                "Изменение заблокировано: ", "Primary configuration change blocked: ",
                "ההגדרה חסומה: ") + reason.Groups[1].Value;
            WriteLine("Postfix basics read-only preflight: " + reason.Groups[1].Value);
            RenderPage();
            return;
        }
        previewedPostfixBasicsSha = sha.Groups[1].Value;
        previewedPostfixBasicsContext = context;
        postfixBasicsSummary = T(
            "Preview готов. При применении будет создан проверенный архив /etc/postfix и перезапущен работающий Postfix. Другие MTA, очередь, firewall и M365 не меняются.",
            "Preview ready. Apply creates a verified /etc/postfix backup and RESTARTS active primary Postfix. It does not modify other MTAs, queues, firewall or Microsoft 365.",
            "הבדיקה עברה. הפעלה תבצע גיבוי ותאתחל את Postfix.");
        WriteLine("Primary Postfix main.cf read-only plan checked; no Linux settings changed.");
        RenderPage();
    }

    private async Task ApplyPostfixBasicsAsync()
    {
        string context = PostfixBasicsContext();
        if (previewedPostfixBasicsSha is null ||
            previewedPostfixBasicsContext != context ||
            postfixBasicsInterfaces.SelectedIndex != 0)
            throw new InvalidOperationException("Preview must be repeated after changing host, fields or listener.");
        if (existingSmtpAuditIdentity != TryCurrentIdentity() ||
            existingSmtpAudit?.SuspectedUnsafeRelay != false)
            throw new InvalidOperationException("Public SMTP audit not verified or unsafe.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Modify PRIMARY Postfix main.cf",
            "RISK: this is the PRIMARY Postfix, not the isolated mail relay. " +
            "Effective myhostname, mydomain, myorigin, mydestination, inet_interfaces and inet_protocols " +
            "will change. An existing SMTP service on the primary host may restart and interrupt mail. " +
            "Local mailbox delivery and externally exposed interfaces must be inspected before approval. " +
            "A root-only verified backup is created before any changes. " +
            "An automatic rollback is attempted on error; package/delivery state is NOT guaranteed. " +
            "Public or wildcard SMTP exposure is not supported by this action. " +
            "If you do not specifically need to reconfigure the PRIMARY MTA, choose Preserve Existing Mail instead.",
            "MODIFY PRIMARY POSTFIX")) return;
        string sha = previewedPostfixBasicsSha;
        previewedPostfixBasicsSha = null;
        previewedPostfixBasicsContext = null;
        var report = await PostfixBasicsScriptAsync(sha);
        report.EnsureSuccess();
        if (!report.StdOut.Contains("POSTFIX_BASICS_APPLIED=yes", StringComparison.Ordinal))
            throw new InvalidDataException(
                "Postfix apply outcome is uncertain. Inspect /var/backups/linuxmailrelay365 and service state.");
        var backup = System.Text.RegularExpressions.Regex.Match(report.StdOut,
            @"(?m)^POSTFIX_BASICS_BACKUP_ID=([0-9]{8}T[0-9]{6}Z-[a-f0-9]{12})\r?$");
        if (!backup.Success)
            throw new InvalidDataException("Postfix apply returned no verified backup identifier.");
        postfixBasicsSummary = "Postfix basics applied. Verified restore snapshot: " +
            backup.Groups[1].Value + ". Review delivery and re-run diagnostics.";
        WriteLine(postfixBasicsSummary);
        await InspectMailRoutingAsync();
        RenderPage();
    }

    private void ShowRecipientAdvice(TableLayoutPanel page)
    {
        bool sameHost = discoveredMailIdentity is not null &&
            discoveredMailIdentity == TryCurrentIdentity();
        var discovery = MailServerDiscoveryDecision.Assess(
            sameHost ? inspectedMail : null, sameHost ? existingSmtpAudit : null,
            sameHost ? discoveredIsolatedRelay : null);
        string scope = recipientScope.SelectedIndex switch
        {
            1 => "internal-only", 2 => "external-needed", _ => "unknown"
        };
        var advice = MailDeliveryAdvisor.Assess(scope, discovery,
            sameHost ? discoveredIsolatedRelay : null);
        AddLine(page, UiTheme.Text(T("Кому отправлять почту?",
            "Who should receive the mail?", "למי יישלח הדואר?"), true));
        AddLine(page, recipientScope);
        AddLine(page, new Label
        {
            AutoSize = true,
            MaximumSize = new Size(Math.Max(390, pageHost.ClientSize.Width - 72), 0),
            Text = advice.Explain(language.SelectedIndex) + Environment.NewLine +
                T("Совет не меняет выбранный режим и не подтверждает права Microsoft 365.",
                  "Advice never selects a route or verifies Microsoft 365 permissions.",
                  "ההמלצה אינה בוחרת מסלול ואינה מאמתת הרשאות."),
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = advice.RequiresReview ? Color.FromArgb(143, 72, 22) : UiTheme.Navy,
            BackColor = Color.White, Padding = new Padding(10, 9, 10, 9),
            Margin = new Padding(0, 8, 0, 12)
        });
    }

    private void RenderPage()
    {
        if (IsDisposed) return;
        LocalizeSshAuthMethods();
        LocalizeAdvancedChoices();
        FitHeaderText();
        var titles = new[]
        {
            T("1 · Подключение к Linux", "1 · Linux connection", "1 · חיבור ל-Linux"),
            T("2 · Почтовый сервер и защита", "2 · Mail server discovery and security", "2 · גילוי שרת הדואר ואבטחה"),
            T("3 · Способ отправки", "3 · Choose delivery method", "3 · בחירת שיטת שליחה"),
            T("4 · Настройка SMTP-маршрута", "4 · Configure SMTP delivery", "4 · הגדרת נתיב SMTP"),
            T("5 · Проверка и обслуживание", "5 · Diagnostics and updates", "5 · אבחון ועדכונים")
        };
        headline.Text = titles[step];
        subheading.Text = step switch
        {
            0 => T("Любой Linux с SSH и правами sudo. Пароль Microsoft 365 не нужен.",
                   "Any Linux with SSH and sudo access. No Microsoft 365 mailbox password.",
                   "כל שרת Linux עם SSH ו-sudo. ללא סיסמת Microsoft 365."),
            1 => T("После успешного SSH мастер определяет активный MTA и состояние SMTP без изменений. TPM — отдельно, по желанию.",
                   "After SSH, read-only discovery checks the active MTA and SMTP. TPM checks are optional.",
                   "לאחר SSH מתבצעת בדיקת MTA ו-SMTP ללא שינויים. TPM אופציונלי."),
            2 => mailTransport.SelectedIndex is 1 or 2
                ? T("Для Connector/Direct Send не нужен OAuth или почтовый ящик; укажите домен и MX на следующем шаге.",
                    "Connector / Direct Send requires no OAuth or mailbox; enter the accepted domain and MX next.",
                    "ב-Connector ו-Direct Send אין צורך ב-OAuth או תיבה.")
                : T("Сертификат создаётся на Linux. В Windows передаётся только открытая часть.",
                    "The certificate is generated on Linux; only the public part is copied to Windows.",
                    "האישור נוצר בלינוקס ורק החלק הציבורי מועבר ל-Windows."),
            3 => T("Перед изменением SMTP-маршрута проверяем основной MTA и создаём резервные копии.",
                   "Before changing SMTP delivery, inspect the primary MTA and verify configuration backups.",
                   "לפני שינוי ניתוב SMTP בודקים את שרת הדואר ומגבים את התצורה."),
            _ => mailTransport.SelectedIndex is 1 or 2
                ? T("Проверка EOP/MX, отдельного SMTP, очереди и обновлений. Без отправки писем.",
                    "Check EOP/MX, isolated SMTP, queue and updates. No email is sent.",
                    "בדיקת EOP, שרת SMTP והתור ללא שליחת הודעות.")
                : oauthSenderMode.SelectedIndex == 1
                    ? T("XOAUTH2 с несколькими ящиками — только план; отправка заблокирована.",
                        "Multi-mailbox XOAUTH2 is a blocked planning mode, not an active delivery route.",
                        "ריבוי תיבות XOAUTH2 הוא תכנון בלבד; המשלוח חסום.")
                    : T("Проверка OAuth-токена, SMTP, очереди и обновлений.",
                        "Check OAuth token, SMTP, queue and updates.",
                        "בדיקת OAuth, SMTP, תור ועדכונים.")
        };
        pageHost.SuspendLayout();
        pageHost.Controls.Clear();
        AcceptButton = null;
        var page = NewPage();
        pageHost.Controls.Add(page);
        pageHost.AutoScrollPosition = Point.Empty;
        ResizePreserveFlowHelp();
        switch (step)
        {
            case 0:
                AddUpdateAccess(page);
                RenderConnectionStep(page);
                break;
            case 1:
                EnsureSecurityLoaded();
                LocalizeDeliveryChoices();
                ShowMailDiscovery(page, true);
                ShowRecipientAdvice(page);
                AddLine(page, UiTheme.Text(T(
                    "Все опции выключены. Выбор сохраняется как ПЛАН — он не меняет Entra, Postfix, сертификат или Linux. Для включения потребуются отдельные подтверждённые действия.",
                    "All options are off. Your selection is saved as a PLAN only: it does not modify Entra, Postfix, certificates or Linux. Activation requires separate approved steps.",
                    "כל האפשרויות כבויות. הבחירה נשמרת כתוכנית בלבד.")));
                AddAction(page, T("Проверить TPM, HSM и PKCS#11 (только чтение)",
                                  "Inspect TPM, HSM and PKCS#11 (read-only)",
                                  "בדוק TPM/HSM לקריאה בלבד"), CheckLinuxSecurityAsync, true, "shield", "linux-security");
                AddLine(page, UiTheme.Text(linuxSecurity?.SummaryRu() ??
                    T("Linux: проверка ещё не запускалась.", "Linux: not inspected yet.", "Linux: טרם נבדק.")));
                advancedSecurityTools.Text = T(
                    "Показать расширенные действия TPM/HSM, сертификаты и Entra",
                    "Show advanced TPM/HSM, certificate and Entra actions",
                    "הצגת פעולות מתקדמות עבור TPM/HSM ו-Entra");
                AddLine(page, advancedSecurityTools);
                if (!advancedSecurityTools.Checked)
                {
                    AddLine(page, UiTheme.Text(T(
                        "Дополнительные действия скрыты. Можно перейти далее: TPM и настройка Entra необязательны на этом шаге.",
                        "Advanced actions are hidden. Continue when ready: TPM and Entra security work is optional at this step.",
                        "אפשר להמשיך; הגדרות TPM ו-Entra מתקדמות הן אופציונליות.")));
                    break;
                }
                AddLine(page, UiTheme.Text(T(
                    "OAuth сертификат основного Postfix: безопасная ротация программного PEM-ключа. Потребуется действующая конфигурация и отдельное разрешение для каждого шага. Доставка писем во время проверок не выполняется.",
                    "Primary Postfix OAuth certificate: guarded software PEM renewal. The installed active identity must already exist. Every change needs an explicit approval. SMTP tests send NO mail.",
                    "חידוש אישור OAuth ב-Postfix: החלפה מאושרת עם אפשרות שחזור, ללא שליחת הודעות בבדיקה.")));
                AddField(page, T("Срок действия нового OAuth-сертификата (дней, 1–365)",
                    "New OAuth certificate validity (days, 1–365)",
                    "תוקף אישור OAuth החדש בימים (1–365)"), certificateDays);
                AddAction(page, T("1. Проверить план ротации (только чтение)",
                                  "1. Review primary OAuth rotation (read-only)",
                                  "1. בדיקת תוכנית לחידוש אישור"),
                    PreviewPrimaryOAuthRotationAsync, false, "check", "primary-rotation-plan");
                if (!string.IsNullOrEmpty(primaryRotationSummary))
                    AddLine(page, UiTheme.Text(primaryRotationSummary));
                if (reviewedPrimaryRotationPlanSha is not null)
                    AddAction(page, T("2. Подготовить новый сертификат (старый остаётся активным)...",
                                      "2. Stage new certificate (old remains active)...",
                                      "2. הכנת אישור חדש ללא הפעלה"),
                        StagePrimaryOAuthRotationAsync, false, "shield", "primary-rotation-stage");
                AddAction(page, T("3. Проверить подготовленный сертификат и SHA-256",
                                  "3. Inspect staged certificate and SHA-256",
                                  "3. בדיקת האישור המוכן"),
                    InspectPrimaryOAuthRotationAsync, false, "check", "primary-rotation-status");
                if (reviewedPrimaryRotationStageSha is not null)
                {
                    AddAction(page, T("4. Проверить регистрацию PUBLIC сертификата в Entra...",
                                      "4. Review PUBLIC certificate in Entra...",
                                      "4. בדיקת רישום אישור ציבורי ב-Entra"),
                        () => PreviewEntraCertificateForTargetAsync("primary-rotation"),
                        false, "check", "primary-rotation-entra-preview");
                    if (reviewedEntraCertTarget == "primary-rotation" &&
                        reviewedEntraCertPlanSha is not null)
                        AddAction(page, T("5. Подтвердить добавление PUBLIC сертификата в Entra...",
                                          "5. Approve PUBLIC certificate registration in Entra...",
                                          "5. אישור רישום האישור הציבורי"),
                            () => AddEntraCertificateForTargetAsync("primary-rotation"),
                            false, "shield", "primary-rotation-entra-apply");
                }
                if (primaryRotationGraphCertificateSha is not null &&
                    reviewedPrimaryRotationStageSha is not null)
                    AddAction(page, T("6. Проверить XOAUTH2 SMTP AUTH новым ключом (без письма)...",
                                      "6. Verify staged XOAUTH2 SMTP AUTH (no message sent)...",
                                      "6. בדיקת SMTP AUTH עם המפתח החדש ללא שליחת דואר"),
                        VerifyPrimaryOAuthRotationSmtpAsync, false, "shield", "primary-rotation-smtp");
                if (verifiedPrimaryRotationSmtpSha is not null &&
                    reviewedPrimaryRotationStageSha == verifiedPrimaryRotationSmtpSha)
                    AddAction(page, T("7. Активировать новый ключ с резервной копией и откатом...",
                                      "7. Activate with backup and automatic rollback...",
                                      "7. הפעלה עם גיבוי ושחזור אוטומטי"),
                        ActivatePrimaryOAuthRotationAsync, false, "shield", "primary-rotation-activate");
                AddLine(page, UiTheme.Text(T(
                    "НЕ удаляйте предыдущий ключ или сертификат Entra до подтверждения реальной доставки. TPM/HSM использует отдельный безопасный процесс переключения.",
                    "Keep the previous PEM and Entra credentials until actual mail delivery is independently verified. Hardware TPM/HSM uses the separate guarded cutover.",
                    "יש לשמור את המפתחות הישנים עד לאימות מסירת הדואר. ל-TPM/HSM יש תהליך נפרד.")));
                if (linuxSecurity?.HasTpm2 == true)
                {
                    AddLine(page, UiTheme.Text(T(
                        "TPM 2.0 обнаружен. Проверьте зависимости RHEL-совместимой ОС перед отдельной установкой; установка не включает аппаратное подписание ключей.",
                        "TPM 2.0 detected. Review RHEL-family dependencies before a separate approved installation; packages do not activate hardware signing.",
                        "זוהה TPM 2.0. יש לבדוק חבילות לפני התקנה מאושרת. ההתקנה אינה מפעילה חתימה חומרתית.")));
                    AddLine(page, UiTheme.Text(T("Профиль TPM2", "TPM2 dependency profile", "פרופיל TPM2")));
                    AddLine(page, tpmDependencyProfile);
                    AddAction(page, T("Проверить необходимые RPM (без изменений)",
                                      "Preview required RPM packages (read-only)",
                                      "בדיקת חבילות RPM ללא שינויים"),
                                      PreviewTpmDependenciesAsync, false, "check", "tpm-deps-preview");
                    AddAction(page, T("Проверить OpenSSL 3 и доступ m365mailer к TPM (без изменений)",
                                      "Inspect OpenSSL 3 and m365mailer TPM access (read-only)",
                                      "בדיקת גישת TPM וספק OpenSSL ללא שינוי"),
                                      InspectTpmProviderAsync, false, "check", "tpm-provider-diagnostic");
                    AddLine(page, UiTheme.Text(tpmPlanSummary));
                    if (reviewedTpmPlanSha is not null)
                        AddAction(page, T("Установить недостающие TPM2 пакеты...",
                                          "Install reviewed missing TPM2 packages...",
                                          "התקנת חבילות TPM2 לאחר אישור"),
                                          InstallTpmDependenciesAsync, false, "shield", "tpm-deps-apply");
                }
                if (linuxSecurity is not null)
                {
                    AddLine(page, UiTheme.Text(T(
                        "OAuth: проверка конфигурации и отдельная офлайн-подпись уже установленным TPM/HSM-ключом. Никаких писем и запросов в Entra.",
                        "OAuth: inspect installed identity, then optionally test offline signing with an existing TPM/HSM key. No mail or Entra requests.",
                        "בדיקת זהות OAuth וחתימה מקומית במפתח קיים ללא שליחת דואר.")));
                    AddAction(page, T("Проверить аппаратную конфигурацию OAuth",
                                      "Inspect hardware OAuth configuration (read-only)",
                                      "בדיקת תצורת OAuth ללא שינוי"),
                                      InspectHardwareOAuthAsync, false, "check", "hardware-oauth-inventory");
                    AddAction(page, T("Проверить PS256-подпись существующим TPM/HSM...",
                                      "Verify existing TPM/HSM PS256 signing offline...",
                                      "בדיקת חתימת TPM/HSM מקומית"),
                                      VerifyOfflineHardwareOAuthAsync, false, "shield", "hardware-oauth-signing");
                    if (!string.IsNullOrEmpty(hardwareOAuthSummary))
                        AddLine(page, UiTheme.Text(hardwareOAuthSummary));
                    AddLine(page, hardwareCutoverTarget);
                    if (linuxSecurity.HasTpm2)
                    {
                        AddLine(page, UiTheme.Text(T(
                            "TPM2 RSA-ключ: необратимое создание нового persistent key (без автоматического удаления). Только свободный 0x8101xxxx; требуется OpenSSL 3 + tpm2 provider, доступ m365mailer к TPM. Предварительная проверка ничего не изменяет.",
                            "TPM2 RSA key: creates a new persistent key and NEVER evicts it automatically. Only a free 0x8101xxxx handle; requires OpenSSL 3, tpm2 provider and TPM access for m365mailer. Preview is read-only.",
                            "יצירת מפתח TPM2 קבוע ללא מחיקה אוטומטית; נדרשת בדיקה ואישור.")));
                        AddField(page, T("Новый TPM2 persistent handle (0x8101xxxx)",
                                         "New TPM2 persistent handle (0x8101xxxx)",
                                         "מזהה TPM2 קבוע חדש"), tpmKeyHandle);
                        AddAction(page, T("Проверить создание TPM2 RSA-ключа (без изменений)",
                                          "Review TPM2 key provisioning (read-only)",
                                          "בדיקת יצירת מפתח TPM2"),
                                          PreviewTpmKeyAsync, false, "check", "tpm-key-plan");
                        if (!string.IsNullOrEmpty(tpmKeySummary))
                            AddLine(page, UiTheme.Text(tpmKeySummary));
                        if (reviewedTpmKeyPlanSha is not null)
                            AddAction(page, T("Подтвердить создание TPM2-ключа и сертификата...",
                                              "Approve TPM2 key and certificate creation...",
                                              "אישור יצירת מפתח TPM2 ואישור ציבורי"),
                                              ApplyTpmKeyAsync, false, "shield", "tpm-key-apply");
                    }
                    AddLine(page, UiTheme.Text(T(
                        "Подготовка hardware-staged.json: на Linux должны уже существовать защищённый TPM2/PKCS#11 провайдер (tpm2.cnf или pkcs11.cnf) и открытый сертификат hardware-app.crt. Ключ не создаётся, программный PEM-ключ не копируется. Для TPM2 введите handle:0x81...... или путь к tpm2-app.key; для PKCS#11 — URI без PIN.",
                        "Prepare hardware-staged.json: the Linux host must already have a protected provider configuration (tpm2.cnf or pkcs11.cnf) and matching public hardware-app.crt. No key is created or copied. Enter a TPM2 persistent handle/TSS2 blob path, or a PIN-free PKCS#11 URI.",
                        "להכנת זהות חומרה דרושים אישור ציבורי והגדרות ספק מאובטחות בשרת. לא נוצר מפתח חדש.")));
                    AddLine(page, hardwareStageProvider);
                    AddField(page, T("Ссылка на аппаратный ключ (без PIN и секретов)",
                                     "Existing hardware key reference (never enter PIN/secrets)",
                                     "הפניה למפתח חומרה קיים"), hardwareStageKeyRef);
                    AddAction(page, T("Проверить подготовку аппаратного OAuth (без изменений)",
                                      "Preview hardware OAuth candidate (read-only)",
                                      "תצוגה מקדימה של זהות חומרה"),
                                      PreviewHardwareStageAsync, false, "check", "hardware-stage-preview");
                    if (!string.IsNullOrEmpty(hardwareStageSummary))
                        AddLine(page, UiTheme.Text(hardwareStageSummary));
                    if (reviewedHardwareStageSha is not null)
                        AddAction(page, T("Подготовить и проверить hardware-staged.json...",
                                          "Create and verify hardware-staged.json...",
                                          "יצירה ואימות של זהות חומרה"),
                                          ApplyHardwareStageAsync, false, "shield", "hardware-stage-apply");
                    AddLine(page, UiTheme.Text(T(
                        "Активация TPM/HSM — только для заранее подготовленного hardware-staged.json. Требует успешной подписи и получения токена Entra до переключения; выполняет резервное копирование и откат при ошибке.",
                        "TPM/HSM cutover requires an existing hardware-staged.json, successful offline signature and Entra token BEFORE activation, with backup and automatic rollback on failure.",
                        "הפעלה דורשת זהות חומרה מוכנה, חתימה תקינה, אימות Entra וגיבוי עם שחזור במקרה כשל.")));
                    AddLine(page, UiTheme.Text(T(
                        "Entra OAuth certificate: новый PUBLIC X.509 добавляется через Microsoft Graph addKey, без удаления существующих ключей. Preview требует Application.Read.All, Apply — Application.ReadWrite.All + подтверждение и подпись действующим Linux-ключом. Сначала подготовьте hardware-staged.json.",
                        "Register the NEW PUBLIC X.509 certificate via Microsoft Graph addKey only. Existing credentials stay untouched. Preview needs Application.Read.All; Apply needs Application.ReadWrite.All and fresh proof from the EXISTING Linux key. Stage the hardware identity first.",
                        "רישום אישור ציבורי חדש בלבד ב-Entra; אישורים קיימים נשמרים.")));
                    AddAction(page, T("Проверить сертификат TPM/HSM в Entra (без изменений)",
                                      "Preview TPM/HSM certificate registration in Entra",
                                      "בדיקת אישור Entra ללא שינוי"),
                                      PreviewEntraCertificateAsync, false, "check", "entra-cert-preview");
                    if (!string.IsNullOrEmpty(entraCertificateSummary))
                        AddLine(page, UiTheme.Text(entraCertificateSummary));
                    if (reviewedEntraCertPlanSha is not null)
                        AddAction(page, T("Подтвердить добавление публичного сертификата в Entra...",
                                          "Approve adding public certificate to Entra...",
                                          "אישור הוספת אישור ציבורי ל-Entra"),
                                          AddEntraCertificateAsync, false, "shield", "entra-cert-add");
                    AddAction(page, T("Предпросмотр переключения TPM/HSM (без изменений)",
                                      "Review hardware OAuth cutover (read-only)",
                                      "תצוגה מקדימה של מעבר חומרה"),
                                      PreviewHardwareCutoverAsync, false, "check", "hardware-cutover-preview");
                    if (!string.IsNullOrEmpty(hardwareCutoverSummary))
                        AddLine(page, UiTheme.Text(hardwareCutoverSummary));
                    if (reviewedHardwareCutoverSha is not null)
                    {
                        if (verifiedHardwarePreflightSha == reviewedHardwareCutoverSha &&
                            verifiedHardwarePreflightContext == SecurityOptionsStore.Identity(Endpoint()) + "|" + SelectedHardwareCutoverTarget())
                            AddLine(page, UiTheme.Text(T(
                                "Последняя проверка токена Entra с подготовленным TPM/HSM прошла. Токен не сохранён; перед активацией будет выполнена новая проверка.",
                                "Staged TPM/HSM Entra token check passed. The token was not stored; activation always performs a fresh check.",
                                "בדיקת אסימון Entra הצליחה. האסימון לא נשמר, וההפעלה דורשת בדיקה נוספת.")));
                        if (verifiedHardwareSmtpAuthSha == reviewedHardwareCutoverSha &&
                            verifiedHardwareSmtpAuthContext == SecurityOptionsStore.Identity(Endpoint()) + "|" + SelectedHardwareCutoverTarget())
                            AddLine(page, UiTheme.Text(T(
                                "Exchange Online: проверка STARTTLS и AUTH XOAUTH2 прошла без MAIL/RCPT/DATA. Реальная доставка ещё не проверена.",
                                "Exchange Online STARTTLS and AUTH XOAUTH2 passed without MAIL/RCPT/DATA. Recipient delivery is still unverified.",
                                "אימות SMTP AUTH XOAUTH2 הצליח ללא שליחת דואר.")));
                        AddAction(page, T("Проверить SMTP AUTH XOAUTH2 без отправки письма...",
                                          "Test Exchange SMTP AUTH XOAUTH2 (no mail sent)...",
                                          "בדיקת SMTP AUTH ללא שליחת דואר"),
                                          VerifyStagedExchangeSmtpAuthAsync, false, "shield", "hardware-staged-smtp-auth");
                        AddAction(page, T("Проверить получение токена Entra новым TPM/HSM (без смены OAuth)...",
                                          "Verify staged TPM/HSM Entra token without switching...",
                                          "בדיקת אסימון Entra ללא שינוי זהות OAuth"),
                                          VerifyStagedHardwareEntraTokenAsync, false, "shield", "hardware-staged-entra-token");
                        AddAction(page, T("Подтвердить и активировать аппаратный OAuth...",
                                          "Approve and activate hardware OAuth...",
                                          "אישור והפעלת OAuth חומרה"),
                                          ApplyHardwareCutoverAsync, false, "shield", "hardware-cutover-apply");
                    }
                    AddAction(page, T("Показать доступные резервные копии OAuth",
                                      "List hardware OAuth rollback snapshots",
                                      "רשימת גיבויי OAuth"),
                                      ListHardwareCutoverBackupsAsync, false, "check", "hardware-cutover-list");
                    if (hardwareCutoverBackup.Items.Count > 0)
                    {
                        AddLine(page, hardwareCutoverBackup);
                        AddAction(page, T("Откатить OAuth на выбранную резервную копию...",
                                          "Restore selected OAuth backup...",
                                          "שחזור מגיבוי OAuth"),
                                          RollbackHardwareCutoverAsync, false, "shield", "hardware-cutover-rollback");
                    }
                    AddLine(page, UiTheme.Text(T(
                        "Проверка РЕАЛЬНОЙ отправки после активации TPM/HSM. Введите два согласованных тестовых адреса: внутренний — в домене активного отправителя, внешний — в другом домене. Preview ничего не отправляет. Отправка создаёт максимум два письма и отмечает SMTP-приём; наличие письма в почтовом ящике подтверждается отдельно.",
                        "REAL post-cutover SMTP delivery acceptance. Enter two consented test inboxes: internal in the active sender domain, external in a different domain. Preview sends nothing. Apply submits at most two fixed short messages. Inbox receipt must be verified independently.",
                        "בדיקת משלוח אמיתי לאחר הפעלת TPM: שתי כתובות מורשות, פנימית וחיצונית. תצוגה מקדימה אינה שולחת דואר. קבלה בתיבה דורשת אימות נפרד.")));
                    AddField(page, T("Внутренний тестовый получатель (тот же домен)",
                                     "Internal test recipient (same sender domain)",
                                     "נמען פנימי לבדיקה"), acceptanceInternalRecipient);
                    AddField(page, T("Внешний тестовый получатель (другой домен)",
                                     "External test recipient (different domain)",
                                     "נמען חיצוני לבדיקה"), acceptanceExternalRecipient);
                    AddAction(page, T("Проверить план отправки двух тестовых писем...",
                                      "Preview two test deliveries (no mail sent)",
                                      "תצוגה מקדימה למשלוח שתי הודעות"),
                                      PreviewDeliveryAcceptanceAsync, false, "check", "delivery-acceptance-preview");
                    if (!string.IsNullOrEmpty(acceptanceSummary))
                        AddLine(page, UiTheme.Text(acceptanceSummary));
                    if (reviewedAcceptanceSha is not null)
                        AddAction(page, T("Подтвердить отправку двух РЕАЛЬНЫХ тестовых писем...",
                                          "Confirm sending TWO real test messages...",
                                          "אישור שליחת שתי הודעות בדיקה אמיתיות"),
                                          ApplyDeliveryAcceptanceAsync, false, "shield", "delivery-acceptance-apply");

                }
                hardwareRequest.Text = T("Запланировать аппаратную защиту ключа (TPM/HSM) — не активировано",
                                         "Plan TPM/HSM-backed key — NOT active",
                                         "תכנון מפתח חומרה - לא פעיל");
                ipRequest.Text = T("Запланировать ограничение по IP (Entra Conditional Access) — не активировано",
                                   "Plan Entra IP restriction — NOT active",
                                   "תכנון הגבלת IP - לא פעיל");
                monitoringRequest.Text = T("Запланировать мониторинг входов приложения Entra — не активировано",
                                           "Plan Entra application sign-in monitoring — NOT active",
                                           "תכנון ניטור כניסות - לא פעיל");
                AddLine(page, hardwareRequest);
                AddLine(page, ipRequest);
                AddLine(page, monitoringRequest);
                AddField(page, T("Tenant ID для необязательной проверки Entra", "Tenant ID for optional Entra check", "Tenant ID לבדיקה"), tenant);
                AddAction(page, T("Проверить возможности Entra (вход администратора, только чтение)",
                                  "Check Entra security APIs (read-only admin sign-in)",
                                  "בדוק Entra לקריאה בלבד"), CheckCloudSecurityAsync, false, "shield", "entra");
                AddLine(page, UiTheme.Text(cloudSecuritySummary));
                AddAction(page, T("Как включить защиту вручную сейчас или позже",
                                  "How to enable protection manually now or later",
                                  "כיצד להפעיל הגנה באופן ידני"), ShowSecurityHelpAsync, false, "shield");
                AddAction(page, T("Открыть Microsoft Entra — настройка вручную",
                                  "Open Microsoft Entra — configure manually",
                                  "פתח את Microsoft Entra"), () => OpenSecurityUrlAsync("https://entra.microsoft.com/"), false, "cloud");
                break;
            case 2:
                EnsureRoutingLoaded();
                LocalizeDeliveryChoices();
                ShowMailDiscovery(page, false);
                ShowRecipientAdvice(page);
                AddLine(page, UiTheme.Text(T(
                    "Выберите, КАК Linux будет отправлять почту через Microsoft 365",
                    "First select HOW Linux will deliver mail through Microsoft 365",
                    "בחרו כיצד Linux ישלח דואר דרך Microsoft 365")));
                AddLine(page, BuildDeliveryModeChoices());
                AddLine(page, BuildDeliveryModeOverview());
                AddAction(page, T("Microsoft 365: объекты, сертификаты и Connector (только чтение)",
                    "Microsoft 365: inspect applications, credentials and connectors (read-only)",
                    "בדיקת יישומים, אישורים ומחברים ב-Microsoft 365"),
                    InspectCloudObjectsAsync, false, "cloud", "cloud-objects");
                if (mailTransport.SelectedIndex is 1 or 2)
                {
                    AddLine(page, UiTheme.Text(T(
                        "Для Connector и Direct Send приложение Entra ID, OAuth-токен и почтовый ящик НЕ требуются. Перейдите Далее, укажите принятый домен и MX и проверьте полномочия Connector или ограничение внутренних получателей. Публичный IP либо TLS-сертификат проверяется отдельно.",
                        "Connector and Direct Send do NOT require an Entra application, OAuth token or licensed mailbox. Click Next to enter the tenant-accepted domain and MX. Review Connector authority or internal-only delivery. Public IP or TLS identity is checked separately.",
                        "ב-Connector ו-Direct Send אין צורך ביישום Entra או תיבת דואר. המשיכו להגדרת דומיין ו-MX.")));
                    AddLine(page, UiTheme.Text(T(
                        "На следующем экране задайте порт, MX, домен, отправителя и параметры сохранения текущего почтового сервера.",
                        "Next configure inbound SMTP port, MX, accepted domain, sender and preservation of the existing mail server.",
                        "בשלב הבא בחרו יציאה, MX, דומיין, שולח ושמירת שרת הדואר הקיים.")));
                    break;
                }
                AddAction(page, T("Подключиться к Microsoft 365 и найти организации",
                                  "Connect to Microsoft 365 and discover tenants",
                                  "התחברות ל-Microsoft 365 וגילוי ארגונים"),
                    DiscoverTenantsAsync, true, "cloud", "tenant-discovery");
                if (discoveredTenants.Count > 0)
                {
                    AddLine(page, UiTheme.Text(discoveredTenants.Count == 1
                        ? "One Entra tenant discovered and selected automatically."
                        : "Multiple Entra tenants detected. Select the correct organization before configuring anything."));
                    AddLine(page, tenantSelector);
                    AddAction(page, T("Ввести Tenant ID вручную", "Use manual Tenant ID instead",
                                      "הזנה ידנית של Tenant ID"),
                        UseManualTenantAsync, false, "gear");
                }
                AddField(page, T("Tenant ID (автоматически или вручную)",
                                 "Selected Tenant ID (auto-filled or manual GUID)",
                                 "Tenant ID נבחר"), tenant);
                AddField(page, T("Почтовый ящик отправителя", "Sender mailbox", "תיבת דואר שולח"), mailbox);
                AddField(page, T("Имя приложения Entra (можно изменить)", "Entra application display name", "שם האפליקציה"), applicationName);
                AddField(page, T("Client ID существующего приложения (необязательно — общий для нескольких Linux)",
                                 "Existing application Client ID (optional; shared across Linux hosts)",
                                 "Client ID של יישום קיים"), existingAppId);
                AddField(page, T("Срок действия нового сертификата, дней (1–365)",
                                 "New certificate validity (days, 1–365)", "תוקף האישור בימים"), certificateDays);
                AddAction(page, T("1. Создать сертификат на Linux", "1. Create certificate on Linux", "1. יצירת אישור בלינוקס"), PrepareAsync, true, "shield", "certificate");
                AddAction(page, T("2. Настроить Entra и Exchange Online", "2. Configure Entra and Exchange Online", "2. הגדרת Entra ו-Exchange"), SetupM365Async, false, "cloud", "entra");
                AddAction(page, T("3. Проверить готовность Microsoft 365", "3. Verify Microsoft 365 state", "3. בדיקת מצב Microsoft 365"), VerifyM365Async, false, "check", "entra");
                AddLine(page, UiTheme.Text(T(
                    "Однократный Device Code для администратора. Создаётся новое приложение либо добавляется сертификат к существующему, права SMTP.SendAsApp ограничены ящиком. Security Defaults не изменяются.",
                    "One-time admin Device Code sign-in. Creates an app or adds a certificate to an existing app; scoped SMTP.SendAsApp; Security Defaults unchanged.",
                    "אימות מנהל חד-פעמי; הרשאה מוגבלת לתיבת דואר אחת.")));
                break;
            case 3:
                EnsureRoutingLoaded();
                LocalizeDeliveryChoices();
                ShowMailDiscovery(page, false);
                AddLine(page, UiTheme.Text(T("Отправка через Microsoft 365", "Microsoft 365 delivery method", "שיטת שליחה דרך Microsoft 365")));
                AddLine(page, mailTransport);
                ShowPostfixBasicsSection(page);
                if (MailDeliveryAdvisor.ConflictsWithRecipients(
                    recipientScope.SelectedIndex == 2 ? "external-needed" : "unknown",
                    mailTransport.SelectedIndex))
                    AddLine(page, UiTheme.Text(T(
                        "ВНИМАНИЕ: Direct Send не доставляет внешним получателям. Выберите Connector/XOAUTH2 либо измените требование к получателям.",
                        "WARNING: Direct Send rejects external recipients. Choose Connector/XOAUTH2 or change the intended audience.",
                        "אזהרה: Direct Send אינו שולח לנמענים חיצוניים.")));
                if (mailTransport.SelectedIndex == 0)
                {
                    AddLine(page, UiTheme.Text(T("Как обрабатывать отправителей при XOAUTH2",
                        "XOAUTH2 sender policy", "מדיניות שולחים ב-XOAUTH2")));
                    AddLine(page, oauthSenderMode);
                    if (oauthSenderMode.SelectedIndex == 1)
                    {
                        AddField(page, T("Защищённая карта отправителей Linux (аудит и офлайн-план)",
                            "Linux sender/mailbox authorization map (audit and offline plan)",
                            "מפת שולחים מוגנת לבדיקת תצורה"), oauthSenderMapPath);
                        AddLine(page, UiTheme.Text(T(
                            "Обычный установщик XOAUTH2 здесь отключён. Ниже доступна только экспериментальная подготовка и офлайн-настройка отдельного Postfix без запуска службы. Реальная доставка, Exchange и Restore пока НЕ подтверждены.",
                            "The standard XOAUTH2 installer is disabled for multiple mailboxes. Experimental actions below stage files and configure a STOPPED isolated Postfix only. Exchange delivery and a complete Restore are NOT verified.",
                            "מתקין XOAUTH2 הרגיל חסום. מותרת הכנה ניסיונית ללא הפעלת השירות בלבד.")));
                        AddAction(page, T(
                            "Проверить карту SMTP-логинов и ящиков M365 (только чтение)",
                            "Audit SMTP login → sender → M365 mailbox map (read-only)",
                            "בדיקת מיפוי משתמשים ותיבות (קריאה בלבד)"),
                            InspectOAuthSenderMapAsync, false, "check", "oauth-sender-map-audit");
                        AddAction(page, T(
                            "Сравнить карту с SMTP AUTH и From Guard на Linux (только чтение)",
                            "Compare sender map with installed SMTP AUTH and From Guard (read-only)",
                            "השוואת המפה עם SMTP AUTH ו-From Guard (קריאה בלבד)"),
                            InspectOAuthIngressAsync, false, "shield", "oauth-ingress-audit");
                        AddAction(page, T(
                            "Проверить локальную подпись сертификатов M365 (без отправки)",
                            "Verify mailbox OAuth certificate signing (offline only)",
                            "בדיקת חתימת אישורי OAuth ללא שליחה"),
                            InspectOAuthIdentitySigningAsync, false, "shield", "oauth-signing-audit");
                        AddLine(page, UiTheme.Text(string.IsNullOrEmpty(oauthSignerAuditSummary)
                            ? T("Подпись запланированных OAuth-идентичностей ещё не проверена. Отправка заблокирована.",
                                "Mapped mailbox signer proof not yet reviewed. Delivery remains disabled.",
                                "חתימות הזהויות טרם נבדקו. שליחה חסומה.")
                            : oauthSignerAuditSummary));
                        AddLine(page, UiTheme.Text(string.IsNullOrEmpty(oauthSenderAuditSummary)
                            ? T("Карта ещё не проверена. Проверка только чтение; отправка отключена.",
                                "Map not yet audited. Read-only review; mail delivery disabled.",
                                "המפה טרם נבדקה. שליחה אינה פעילה.")
                            : oauthSenderAuditSummary));
                        AddLine(page, UiTheme.Text(string.IsNullOrEmpty(oauthIngressAuditSummary)
                            ? T("Состояние Postfix/Dovecot/From Guard ещё не сверено с картой.",
                                "Postfix/Dovecot/From Guard not yet compared with the sender map.",
                                "הגדרות Postfix ו-Dovecot טרם הושוו למפה.")
                            : oauthIngressAuditSummary));
                        AddLine(page, UiTheme.Text(T(
                            "Офлайн-установка: EXPERIMENTAL. Требуются остановленный отдельный Postfix, пустая очередь и проверенный SHA-256. Права Exchange и доставка не подтверждены.",
                            "EXPERIMENTAL OFFLINE INSTALL: sidecar STOPPED, queue EMPTY and reviewed SHA-256 required. Exchange authorization and real delivery remain unverified.",
                            "התקנה ניסיונית ללא הפעלת שירותים. יש צורך בתור ריק ובאימות SHA-256.")));
                        AddAction(page, T(
                            "1. Подготовить защищённые файлы Multi-mailbox...",
                            "1. Stage protected multi-mailbox files...",
                            "1. הכנת קובצי מקור מוגנים"),
                            StageMultiMailboxRuntimeAsync, false, "shield", "multi-mailbox-stage");
                        AddAction(page, T(
                            "2. Проверить маршрут Multi-mailbox (без изменений)",
                            "2. Preview multi-mailbox route (read-only)",
                            "2. בדיקת המסלול ללא שינוי"),
                            PreviewMultiMailboxRouteAsync, false, "check", "multi-mailbox-preview");
                        AddAction(page, T(
                            "3. Применить офлайн (службы НЕ запускаются)...",
                            "3. Apply OFFLINE (services stay STOPPED)...",
                            "3. החלה ללא הפעלת השירותים"),
                            ApplyMultiMailboxRouteOfflineAsync, false, "shield", "multi-mailbox-apply-offline");
                        AddLine(page, UiTheme.Text(T(
                            "Восстановление прежнего маршрута: доступно только при точном совпадении активного Multi-mailbox и исходного защищённого архива. Служба остаётся остановленной.",
                            "Restore original route: available only for an exact active Multi-mailbox marker and verified pre-install backup. The sidecar stays stopped.",
                            "שחזור רק מתוך גיבוי מאומת. השירות נשאר עצור.")));
                        AddAction(page, T(
                            "4. Проверить Restore Multi-mailbox (без изменений)",
                            "4. Preview Multi-mailbox Restore (read-only)",
                            "4. בדיקת שחזור ללא שינוי"),
                            PreviewMultiMailboxRestoreAsync, false, "check", "multi-mailbox-restore-preview");
                        AddAction(page, T(
                            "5. Восстановить прежний маршрут OFFLINE...",
                            "5. Restore original route OFFLINE...",
                            "5. שחזור נתיב הדואר המקורי ללא הפעלת השירות"),
                            RestoreMultiMailboxRouteOfflineAsync, false, "rotate-ccw", "multi-mailbox-restore");
                        if (!string.IsNullOrEmpty(multiMailboxRestoreSummary))
                            AddLine(page, UiTheme.Text(multiMailboxRestoreSummary));

                        AddLine(page, UiTheme.Text(T(
                            "Приёмочные тесты Microsoft 365: два РЕАЛЬНЫХ письма через выбранный mailbox. " +
                            "Этот прямой тест проверяет OAuth/XOAUTH2, но НЕ проверяет локальную авторизацию SMTP AUTH через Postfix. " +
                            "Запускайте только для согласованных тестовых ящиков; подтверждение доставки выполняется отдельно.",
                            "Microsoft 365 ACCEPTANCE: two REAL messages using the selected mailbox's OAuth identity. " +
                            "This direct test checks OAuth/XOAUTH2 but NOT local Postfix SMTP AUTH ownership. " +
                            "Use consented test inboxes only; verify delivery separately.",
                            "שתי הודעות אמת דרך תיבת OAuth נבחרת. נדרש אימות משלוח בנפרד.")));
                        AddField(page, T("Разрешённый M365 mailbox отправителя",
                            "Approved M365 sender mailbox",
                            "תיבת שולח מאושרת ב-M365"), multiTestSender);
                        AddField(page, T("Внутренний тестовый адрес (домен отправителя)",
                            "Internal test inbox (sender's domain)",
                            "תיבת בדיקה פנימית"), multiTestInternal);
                        AddField(page, T("Внешний тестовый адрес (другой домен)",
                            "External test inbox (different domain)",
                            "תיבת בדיקה חיצונית"), multiTestExternal);
                        AddAction(page, T(
                            "6. Проверить план двух писем M365 (ничего не отправлять)",
                            "6. Preview two M365 messages (send nothing)",
                            "6. בדיקת שתי הודעות ללא שליחה"),
                            PreviewMultiMailboxDeliveryTestAsync, false, "check", "multi-mailbox-delivery-plan");
                        if (reviewedMultiTestSha is not null)
                            AddAction(page, T(
                                "7. Подтвердить ДВА реальных тестовых письма...",
                                "7. Confirm TWO real test messages...",
                                "7. אישור שליחת שתי הודעות אמיתיות"),
                                ApplyMultiMailboxDeliveryTestAsync, false, "shield", "multi-mailbox-delivery-apply");
                        if (!string.IsNullOrEmpty(multiTestSummary))
                            AddLine(page, UiTheme.Text(multiTestSummary));
                        if (lastMultiTestRunId is not null)
                            AddAction(page, T(
                                "8. Проверить журнал последней SMTP-попытки (без отправки)",
                                "8. Inspect last SMTP attempt ledger (read-only)",
                                "8. בדיקת יומן ניסיון SMTP ללא שליחה"),
                                InspectLastMultiMailboxDeliveryTestAsync, false, "check",
                                "multi-mailbox-delivery-ledger");
                        if (!string.IsNullOrEmpty(multiTestLedgerSummary))
                            AddLine(page, UiTheme.Text(multiTestLedgerSummary));

                        AddLine(page, UiTheme.Text(string.IsNullOrEmpty(multiMailboxRouteSummary)
                            ? T("Маршрут не активирован. Отправка Multi-mailbox в этом мастере остаётся заблокирована.",
                                "Route not activated. Multi-mailbox sending is still blocked in this Wizard.",
                                "המסלול אינו פעיל. השליחה חסומה.")
                            : multiMailboxRouteSummary));
                        AddLine(page, UiTheme.Text(T(
                            "Формат Linux TSV: smtp_login, envelope_from, m365_mailbox, identity_config_path. Карта root:root 0600; конфигурации OAuth root:m365mailer 0640. Проверка НЕ включает отправку и не подтверждает Send As.",
                            "Linux TSV columns: smtp_login, envelope_from, m365_mailbox, identity_config_path. Root-owned TSV mode 0600; OAuth identity JSON root:m365mailer 0640. Audit does NOT enable mail delivery or prove Send As.",
                            "קובץ TSV בבעלות root. הבדיקה אינה מפעילה שליחה או הרשאות Exchange.")));
                    }
                }
                else if (mailTransport.SelectedIndex == 1)
                {
                    AddLine(page, UiTheme.Text(T("Политика отправителя Connector",
                        "Connector sender policy", "מדיניות שולחים של Connector")));
                    AddLine(page, senderPolicy);
                }
                AddLine(page, UiTheme.Text(T("Как будет работать выбранный режим (схема из ваших полей)",
                    "How this route works (live preview from your fields)",
                    "כיצד יעבוד המסלול שנבחר")));
                UpdatePreserveFlowPreview();
                ResizePreserveFlowHelp();
                AddLine(page, preserveFlowPreview);
                AddLine(page, deliveryModeExplanation);
                AddField(page, T("Подтверждённый домен (необязательно для XOAUTH2)",
                                 "Verified accepted domain (not needed for XOAUTH2)",
                                 "דומיין מאומת (לא נדרש ל-XOAUTH2)"), acceptedDomain);
                if (advancedSmtpTools.Checked)
                    AddAction(page, T("Проверить DNS: MX, SPF, DKIM, DMARC (без изменений)",
                                      "Audit DNS: MX, SPF, DKIM, DMARC (read-only)",
                                      "בדיקת DNS: MX, SPF, DKIM, DMARC"),
                                      InspectM365DnsAsync, false, "check", "dns-audit");
                if (mailTransport.SelectedIndex is 1 or 2)
                {
                    AddLine(page, UiTheme.Text(T(
                        "Проверка готовности без установки: домен и Connector проверяются в Microsoft 365 отдельно.",
                        "Readiness only; accepted domain ownership and Connector require Microsoft 365 verification.",
                        "בדיקה בלבד, ללא שינויים.")));
                    AddField(page, T("MX Microsoft 365 (*.mail.protection.outlook.com)",
                                     "Microsoft 365 MX endpoint (*.mail.protection.outlook.com)",
                                     "כתובת MX ב-Microsoft 365"), outboundMxHost);
                    AddField(page, T("Фиксированный отправитель в подтверждённом домене",
                                     "Fixed sender in the tenant-accepted domain",
                                     "כתובת שולח קבועה בדומיין מאומת"), outboundFixedSender);
                    acceptedDomainApproved.Text = T(
                        "Я проверил этот принятый домен в Microsoft 365 (не сохранять согласие)",
                        "I verified this accepted domain in the intended M365 tenant (not saved)",
                        "אימתתי שהדומיין מאושר ב-Microsoft 365");
                    AddLine(page, acceptedDomainApproved);
                    if (mailTransport.SelectedIndex == 1)
                    {
                        AddField(page, T("Статический публичный IPv4 исходящего Linux",
                                         "Static public egress IPv4 (optional with certificate)",
                                         "כתובת IPv4 ציבורית"), outboundPublicIp);
                        AddField(page, T("Сертификат Connector на Linux (необязательно)",
                                         "Linux Connector TLS certificate (optional)",
                                         "אישור TLS בלינוקס"), outboundCertPath);
                        AddField(page, T("Закрытый ключ сертификата Connector на Linux",
                                         "Linux client certificate private-key path (if certificate selected)",
                                         "נתיב מפתח פרטי לאישור"), outboundCertKeyPath);
                        connectorApproved.Text = T(
                            "Я проверил действующий Inbound Connector в моём Microsoft 365 Tenant",
                            "I have personally verified the EXISTING Microsoft 365 Inbound Connector",
                            "אישרתי שה-Connector כבר קיים ב-Microsoft 365");
                        AddLine(page, connectorApproved);
                        if (advancedSmtpTools.Checked)
                        {
                            AddField(page, T("Имя нового Exchange Online Connector",
                                             "New Exchange Online Connector display name",
                                             "שם מחבר Exchange Online חדש"), outboundConnectorName);
                            AddAction(page, T("Проверить создание нового Connector (без изменений)",
                                              "Preview NEW tenant Connector (read-only)",
                                              "בדיקת יצירת Connector ללא שינוי"),
                                              PreviewTenantConnectorAsync, false, "check", "m365-connector-preview");
                            AddAction(page, T("Создать Connector в подтверждённом tenant...",
                                              "Create NEW reviewed tenant Connector...",
                                              "יצירת Connector מאומת בענן"),
                                              CreateTenantConnectorAsync, false, "shield", "m365-connector-create");
                            AddAction(page, T("Показать объекты Connector и Entra (только чтение)",
                                "Inspect Microsoft 365 Connector and Entra objects (read-only)",
                                "בדיקת מחברים ויישומים ללא שינוי"),
                                InspectCloudObjectsAsync, false, "cloud", "cloud-objects");
                        }
                        if (senderPolicy.SelectedIndex != 0)
                        {
                            AddField(page, T("Linux-файл владельцев отправителей (root 0600): адрес логин",
                                             "Linux sender ownership file (root 0600): sender@domain smtp-login",
                                             "קובץ בעלי כתובות שולח בשרת Linux"), outboundSenderOwnerFile);
                            AddLine(page, UiTheme.Text(T(
                                "Для каждого MAIL FROM укажите SMTP-логин владельца. Защита RFC5322 From требует отдельного Milter: сначала проверьте и включите From Guard; без него применение маршрута заблокировано.",
                                "Map each MAIL FROM to its SMTP login. RFC5322 From requires a separately approved From Guard: Preview and activate it before applying the multi-sender Connector. Without a running guard the route is BLOCKED.",
                                "יש להתקין ולאמת מסנן From נפרד לפני הפעלת Connector עם מספר שולחים.")));
                            if (advancedSmtpTools.Checked && mailTransport.SelectedIndex == 1)
                            {
                                AddAction(page, T("Проверить From Guard (без изменений)",
                                                  "Preview RFC5322 From Guard (read-only)",
                                                  "בדיקת מסנן From ללא שינוי"),
                                          PreviewFromOwnerGuardAsync, false, "check", "from-guard-preview");
                                AddAction(page, T("Включить защиту From на отдельном Relay...",
                                                  "Enable independent From Guard...",
                                                  "הפעלת הגנת From בממסר נפרד"),
                                          EnableFromOwnerGuardAsync, false, "shield", "from-guard-enable");
                            }
                        }
                    }
                    AddAction(page, T("Проверить Direct Send / Connector, TCP 25 (только чтение)",
                                      "Check Direct Send / Connector, outbound TCP 25 (read-only)",
                                      "בדיקת Direct Send ו-Connector"),
                                      CheckOutboundModeAsync, false, "check", "outbound-mode");
                    if (!string.IsNullOrWhiteSpace(cleanBootstrapSummary))
                        AddLine(page, UiTheme.Text(cleanBootstrapSummary));
                    if (inspectedMail?.Mta == "none")
                    {
                        AddLine(page, UiTheme.Text(T(
                            "Чистая система: сначала отдельно подготовьте пакеты Postfix. Это не запускает основной Postfix и не устанавливает Relay.",
                            "Clean Linux: prepare Postfix packages separately before installing the isolated Relay. The primary Postfix is not started.",
                            "שרת נקי: יש להכין חבילות Postfix לפני התקנת הממסר.")));
                        AddAction(page, T("Проверить подготовку Postfix-пакетов (без изменений)",
                                          "Preview clean Linux Postfix packages (read-only)",
                                          "בדיקת חבילות Postfix ללא שינויים"),
                            PreviewCleanPostfixAsync, false, "check", "clean-postfix-preview");
                        if (previewedCleanBootstrapSha is not null)
                            AddAction(page, T("Подтвердить установку пакетов Postfix...",
                                              "Confirm Postfix PACKAGE installation...",
                                              "אישור התקנת חבילות Postfix"),
                                ApplyCleanPostfixAsync, false, "shield", "clean-postfix-apply");
                    }
                    AddLine(page, UiTheme.Text(T(
                        "Создание нового отдельного SMTP Relay (требуется проверка существующего MTA, домена и разрешений)",
                        "Install a new isolated SMTP relay (existing MTA, tenant domain and permissions are checked first)",
                        "התקנת ממסר SMTP נפרד לאחר בדיקות")));
                    if (mailTransport.SelectedIndex == 1 && senderPolicy.SelectedIndex == 0)
                    {
                        AddAction(page, T("Проверить новый Connector Relay без OAuth",
                                          "Preview NEW private Connector gateway (no OAuth)",
                                          "בדיקת Connector חדש ללא OAuth"),
                                          PreviewFreshConnectorAsync, false, "check", "connector-new-preview");
                        AddAction(page, T("Установить отдельный Connector Relay без OAuth...",
                                          "Install NEW isolated Connector Relay without OAuth...",
                                          "התקנת Connector נפרד ללא OAuth"),
                                          InstallFreshConnectorAsync, false, "shield", "connector-new-install");
                    }
                    if (mailTransport.SelectedIndex == 2)
                    {
                        AddAction(page, T("Проверить новую установку Direct Send без OAuth",
                                          "Preview NEW private Direct Send (no OAuth application)",
                                          "בדיקת Direct Send חדש ללא OAuth"),
                                          PreviewFreshDirectSendAsync, false, "check", "directsend-new-preview");
                        AddAction(page, T("Установить отдельный Direct Send без Entra...",
                                          "Install NEW isolated Direct Send without Entra...",
                                          "התקנת Direct Send נפרד ללא Entra"),
                                          InstallFreshDirectSendAsync, false, "shield", "directsend-new-install");
                    }
                    if (advancedSmtpTools.Checked)
                    {
                        AddLine(page, UiTheme.Text(T(
                            "Продвинутые действия для уже установленного отдельного Postfix: предварительная проверка EOP-маршрута, применение с SHA-256 и восстановление предыдущего XOAUTH2-маршрута.",
                            "Existing sidecar only: read-only EOP route preview, SHA256-approved apply and restore of its previous XOAUTH2 route.",
                            "אפשרויות מתקדמות עבור שרת Postfix נפרד קיים.")));
                        AddAction(page, T("Проверить применение EOP-маршрута (без изменений)",
                                          "Preview isolated EOP route changes (read-only)",
                                          "בדיקת ניתוב EOP"),
                                          PreviewEopRouteAsync, false, "check", "eop-preview");
                        AddAction(page, T("Применить отдельный EOP-маршрут...",
                                          "Apply isolated Direct Send / Connector route...",
                                          "הפעלת ניתוב EOP נפרד"),
                                          ApplyEopRouteAsync, false, "shield", "eop-apply");
                        AddAction(page, T("Восстановить прежний XOAUTH2-маршрут...",
                                          "Restore original isolated XOAUTH2 outbound route...",
                                          "שחזור XOAUTH2"),
                                          RestoreEopRouteAsync, false, "rotate-ccw", "eop-restore");
                    }
                }
                if (inspectedMail?.Mta is "exim" or "sendmail")
                {
                    AddField(page, T("FQDN отдельного SMTP для Exim/Sendmail (обязательно)",
                                     "Independent Postfix hostname FQDN for Exim/Sendmail (required)",
                                     "שם שרת Postfix עצמאי עבור Exim/Sendmail"), foreignSidecarHostname);
                    AddLine(page, UiTheme.Text(T(
                        "ВНИМАНИЕ: DNS-имя отдельного SMTP должно отличаться от имени основного Sendmail/Exim. Подстановка relay.<домен> — только предложение, требуется DNS/TLS проверка; оригинальная служба и очередь не меняются.",
                        "Separate SMTP must use a DNS name DISTINCT from the active Sendmail/Exim host. Suggested relay.<domain> is only a draft: verify DNS/TLS. The original service and queue remain untouched.",
                        "לממסר נדרש שם DNS שונה מהשרת הראשי. יש לאמת DNS ו-TLS.")));
                }
                AddField(page, T("Порт отдельного SMTP (Preserve Existing Mail; по умолчанию 2525)",
                                 "Isolated SMTP port (Preserve Existing Mail; default 2525)",
                                 "פורט SMTP נפרד (ברירת מחדל 2525)"), isolatedSmtpPort);
                AddField(page, T("Локальный IPv4 для SMTP (пусто = только loopback)",
                                 "Local IPv4 SMTP listener (blank = loopback only)",
                                 "כתובת IPv4 מקומית לקבלת SMTP"), smtpListenIp);
                AddDetectedPrivateInterfacePicker(page);
                AddField(page, T("Доверенные сети RFC1918, CIDR через запятую (необязательно)",
                                 "Trusted RFC1918 client CIDRs, comma separated (optional)",
                                 "רשתות מקומיות מורשות, CIDR"), smtpTrustedCidrs);
                publicInternetRequested.Text = T(
                    "Публичный SMTP (экспертный план, применение только после проверки)",
                    "Public Internet SMTP (expert opt-in; separately reviewed apply)",
                    "SMTP ציבורי (תכנון מתקדם; הפעלה לאחר בדיקה)");
                AddLine(page, publicInternetRequested);
                AddLine(page, UiTheme.Text(T(
                    "Публичный SMTP опасен: злоупотребления, утечка учётных данных и блокировки IP/M365. Отметка ничего не открывает; отдельная операция доступна только при проверенном XOAUTH2, AUTH/STARTTLS, Fail2ban, лимитах и мониторинге.",
                    "Public SMTP can attract spam attacks, credential theft and IP/M365 blocking. This checkbox does not open the port; the separate guarded flow requires XOAUTH2, AUTH/STARTTLS, Fail2ban, limits and monitoring.",
                    "SMTP ציבורי מחייב אימות, STARTTLS, הגבלת קצב וניטור. סימון האפשרות אינו פותח יציאה אוטומטית.")));
                AddAction(page, T("Проверить порты 443/587, SMTP и firewall (без изменений)",
                                  "Check ports 443/587, SMTP and firewall (read-only)",
                                  "בדיקת יציאות וחומת אש (קריאה בלבד)"),
                                  CheckNetworkFirewallAsync, false, "check", "network");
                advancedSmtpTools.Text = T(
                    "Показать расширенные инструменты SMTP и диагностику",
                    "Show advanced SMTP operations and diagnostics",
                    "הצגת כלי SMTP מתקדמים ובדיקות");
                AddLine(page, advancedSmtpTools);
                if (advancedSmtpTools.Checked)
                {
                AddAction(page, T("Проверить Linux / SELinux для выбранного SMTP-порта",
                                  "Check Linux / SELinux for the selected SMTP port",
                                  "בדיקת לינוקס ו-SELinux עבור יציאת SMTP שנבחרה"),
                                  InspectPlatformAsync, false, "check", "platform");
                AddAction(page, T("Проверить Sendmail/Exim/Postfix без изменения MTA",
                                  "Audit Postfix / Sendmail / Exim coexistence (read-only)",
                                  "בדיקת קיום Postfix / Sendmail / Exim ללא שינוי"),
                                  InspectMtaCoexistenceAsync, false, "check", "mta-coexistence");
                AddAction(page, T("Диагностика SELinux Enforcing для RHEL (только чтение)",
                                  "RHEL SELinux Enforcing acceptance report (read-only)",
                                  "דוח SELinux Enforcing ל-RHEL ללא שינויים"),
                                  InspectRhelSelinuxAsync, false, "shield", "selinux-doctor");
                AddAction(page, T("Проверить STARTTLS и AUTH при SELinux Enforcing (без отправки письма)",
                                  "Test live SELinux Enforcing SMTP STARTTLS/AUTH (no mail)",
                                  "בדיקת SMTP TLS ואימות ב-SELinux ללא שליחת דואר"),
                                  ProbeEnforcingSmtpAsync, false, "shield", "selinux-enforcing-live");
                AddAction(page, T("Подготовить SELinux-метку выбранного SMTP-порта (с подтверждением)",
                                  "Prepare RHEL SELinux custom SMTP port label (review + apply)",
                                  "הכן תווית SELinux ליציאת SMTP"),
                                  PrepareRhelSelinuxPortAsync, false, "shield", "selinux-port-apply");
                AddAction(page, T("Восстановить ранее изменённую метку SELinux-порта",
                                  "Restore managed RHEL SELinux SMTP port label",
                                  "שחזר תווית יציאת SELinux"),
                                  RestoreRhelSelinuxPortAsync, false, "rotate-ccw", "selinux-port-restore");
                AddAction(page, T("Проверить установленный SMTP: AUTH/TLS, порт, SELinux (без изменений)",
                                  "Audit installed SMTP: AUTH/TLS, port, SELinux (read-only)",
                                  "בדיקת SMTP מותקן: AUTH/TLS, יציאה ו-SELinux"),
                                  AuditInstalledPrivateSmtpAsync, false, "shield", "smtp-live-audit");
                AddAction(page, T("Проверить здоровье SMTP, очередь и сертификаты",
                                  "Check SMTP health, queue and certificate expiry (read-only)",
                                  "בדיקת SMTP, תור ואישורים"),
                                  InspectRelayHealthAsync, false, "activity", "smtp-health");
                AddAction(page, T("Включить мониторинг SMTP каждые 15 минут (journald)...",
                                  "Enable local SMTP health timer every 15 minutes...",
                                  "הפעלת ניטור SMTP כל 15 דקות"),
                                  InstallHealthMonitorAsync, false, "activity", "health-monitor");
                AddLine(page, UiTheme.Text(T(
                    "Уведомления: на Linux создайте /etc/linuxmailrelay365/health-alerts.json (root:root, 0600) с HTTPS webhook. Секретный URL не вводится в мастер.",
                    "Optional alerts: create /etc/linuxmailrelay365/health-alerts.json on Linux (root:root, 0600) with a private HTTPS webhook URL. Do not enter its token in the Wizard.",
                    "התראות: צור קובץ webhook מוגן בשרת Linux. אין להזין סוד באשף.")));
                AddAction(page, T("Включить HTTPS-уведомления SMTP...",
                                  "Enable HTTPS SMTP health alerts...",
                                  "הפעל התראות SMTP ב-HTTPS"),
                                  EnableHealthAlertsAsync, false, "activity", "health-alerts-enable");
                AddAction(page, T("Отключить внешние уведомления...",
                                  "Disable external SMTP alerts...",
                                  "השבת התראות חיצוניות"),
                                  DisableHealthAlertsAsync, false, "shield", "health-alerts-disable");
                AddAction(page, T("Открыть порт только доверенным сетям...",
                                  "Open SMTP port for trusted networks only...",
                                  "פתיחת יציאה לרשתות מהימנות בלבד"),
                                  OpenTrustedFirewallAsync, false, "shield", "firewall");
                }
                AddLine(page, UiTheme.Text(T(
                    "По умолчанию только 127.0.0.1. Сетевые клиенты допускаются только с указанной локальной IPv4 и из доверенных подсетей. Существующий Postfix не изменяется без отдельного разрешения.",
                    "Default: 127.0.0.1 only. Remote SMTP requires an explicit private listener IP and trusted client subnets. Existing Postfix is never changed without approval.",
                    "ברירת מחדל: חיבור מקומי בלבד. נדרש אישור נפרד לכל שינוי בשרת קיים.")));
                preserveExistingMail.Text = T(
                    "Сохранять существующий MTA и его маршруты (по умолчанию, безопасно)",
                    "Preserve existing MTA and routes (safe default)",
                    "שמירה על שרת דואר קיים והניתוב שלו");
                AddLine(page, preserveExistingMail);
                UpdatePreserveFlowPreview();
                ResizePreserveFlowHelp();
                AddLine(page, UiTheme.Text(T(
                    "Инструкции для новых SMTP-клиентов — только план, до проверки установленного сервера",
                    "Proposed SMTP client instructions — verify installed server first",
                    "הוראות SMTP מוצעות — יש לאמת את השרת")));
                AddLine(page, preserveMailInstructions);
                var copyInstructions = UiTheme.Action(
                    T("Копировать параметры SMTP",
                      "Copy proposed SMTP client settings",
                      "העתקת הגדרות SMTP"), false, "copy");
                copyInstructions.Enabled = !busy;
                copyInstructions.Click += (_, _) => CopyPreserveInstructions();
                AddLine(page, copyInstructions);
                if (preserveExistingMail.Checked)
                {
                    AddLine(page, UiTheme.Text(T(
                        "Старые приложения сохраняют прежний SMTP. Новые можно переключать на выбранный отдельный Postfix только после подтверждения действующей конфигурации и реальной доставки.",
                        "Existing applications keep their current SMTP. New clients may use the isolated Postfix only after installed route and real delivery are verified.",
                        "יישומים קיימים נשארים במסלול הקודם; יש לאמת מסירה לפני שינוי.")));
                    if (advancedSmtpTools.Checked)
                    {
                    AddLine(page, UiTheme.Text(T(
                        "Режим без аутентификации требует доверенной подсети. Дополнительное включение STARTTLS и SMTP AUTH ниже доступно только для уже установленного отдельного Postfix; публичный SMTP остаётся заблокирован.",
                        "Initial private SMTP uses trusted networks. Enable STARTTLS + SMTP AUTH first. Public SMTP has a separate expert-only preflight, apply and restore flow; a checked plan never opens firewall automatically.",
                        "שרת SMTP מקומי מהימן בלבד. אפשר להפעיל STARTTLS ו-SMTP AUTH במופע מבודד קיים; גישה ציבורית חסומה.")));
                    AddLine(page, UiTheme.Text(T(
                        "SMTP AUTH + STARTTLS (отдельный Postfix, дополнительная защита)",
                        "SMTP AUTH + STARTTLS (optional private sidecar hardening)",
                        "SMTP AUTH + STARTTLS לשרת הנפרד")));
                    AddField(page, T("DNS-имя SMTP-сервера (точное имя в сертификате)",
                                     "SMTP server DNS name (must match certificate SAN)",
                                     "שם DNS של שרת SMTP"), privateAuthDns);
                    AddField(page, T("Путь к TLS-сертификату на Linux (.pem)",
                                     "Linux path to TLS certificate / full chain (.pem)",
                                     "נתיב אישור TLS בלינוקס"), privateAuthCertPath);
                    AddField(page, T("Путь к закрытому TLS-ключу на Linux (0600)",
                                     "Linux path to TLS private key (0600)",
                                     "נתיב המפתח הפרטי בלינוקס"), privateAuthKeyPath);
                    AddField(page, T("Путь к файлу Linux с 1–64 хешированными SMTP-пользователями (0600)",
                                     "Linux path to 1–64 hashed SMTP accounts (0600)",
                                     "נתיב לחשבון SMTP עם hash"), privateAuthHashPath);
                    AddField(page, T("Файл доверенного CA на Linux (необязательно; пусто = системное хранилище)",
                                     "Trusted CA file on Linux (optional; blank = system trust store)",
                                     "קובץ רשות אישורים מהימנה בלינוקס (אופציונלי)"), privateTlsCaPath);
                    AddLine(page, UiTheme.Text(T(
                        "После установки проверка установленного SMTP проверяет STARTTLS, цепочку CA и DNS-имя сертификата через loopback. Доверие на клиентском компьютере проверяется отдельно.",
                        "Installed SMTP audit can verify STARTTLS, trusted CA chain and certificate DNS name via loopback. Each real client's trust store must still be checked separately.",
                        "בדיקת TLS ברשת המקומית אינה מחליפה בדיקת אמון במחשבי הלקוחות.")));
                    AddLine(page, UiTheme.Text(T(
                        "Создайте хеш на сервере интерактивно: doveadm pw -s SHA512-CRYPT. Сохраните 1–64 строки user:{SHA512-CRYPT}$6$... в закрытый файл root:root 0600, по одной на приложение. Пароль и хеш не вводятся в мастер. Для TLS нужен действительный сертификат с SAN и проверкой доверия на клиентах. На SELinux Enforcing применение блокируется до проверенной настройки меток.",
                        "On Linux create the hash interactively: doveadm pw -s SHA512-CRYPT. Save 1–64 unique user:{SHA512-CRYPT}$6$... entries, one per app, as root:root 0600. Never enter passwords or hashes in the Wizard. TLS requires a valid DNS SAN certificate trusted by client machines. SELinux Enforcing is blocked pending verified socket labels.",
                        "יש ליצור hash ב-Linux ולשמור בקובץ מוגן; אין להזין סיסמה באשף.")));
                    AddAction(page, T("Проверить SMTP AUTH/STARTTLS (без изменений)",
                                      "Check SMTP AUTH/STARTTLS prerequisites (read-only)",
                                      "בדיקת SMTP AUTH/STARTTLS ללא שינויים"),
                                      CheckAuthTlsAsync, false, "check", "auth-tls-check");
                    AddAction(page, T("Включить SMTP AUTH + STARTTLS на отдельном Postfix...",
                                      "Enable SMTP AUTH + STARTTLS on isolated Postfix...",
                                      "הפעלת SMTP AUTH + STARTTLS בשרת נפרד"),
                                      EnableAuthTlsAsync, false, "shield", "auth-tls-apply");
                    AddAction(page, T("Восстановить прежний SMTP без AUTH/STARTTLS... (опасное ослабление защиты)",
                                      "Restore previous SMTP without AUTH/STARTTLS... (security downgrade)",
                                      "שחזור SMTP ללא אימות והצפנה (הפחתת אבטחה)"),
                                      RestoreAuthTlsAsync, false, "rotate-ccw", "auth-tls-restore");
                    AddAction(page, T("Заменить TLS-сертификат отдельного Postfix...",
                                      "Rotate isolated SMTP TLS certificate (verified + rollback)...",
                                      "החלפת אישור TLS של SMTP"),
                                      RotateTlsCertificateAsync, false, "shield", "tls-rotate");
                    AddLine(page, UiTheme.Text(T(
                        "SMTP-клиенты: управление отдельными логинами (без изменения Microsoft 365)",
                        "SMTP client accounts: individual access (Microsoft 365 sender unchanged)",
                        "חשבונות SMTP נפרדים לכל יישום")));
                    AddLine(page, smtpAccountOperation);
                    AddAction(page, T("Создать SMTP-пароль и хеш на Linux (показать один раз)...",
                                      "Generate SMTP password + hash (show once)...",
                                      "צור סיסמת SMTP והצג פעם אחת"),
                                      GenerateSmtpCredentialAsync, false, "shield", "smtp-secret-generate");
                    AddField(page, T("Имя SMTP-учётной записи", "SMTP client username", "שם חשבון SMTP"), smtpAccountName);
                    AddField(page, T("Linux-файл с одним хешем (для Add/Rotate)",
                                     "Existing Linux file containing one salted hash (Add/Rotate)",
                                     "קובץ hash בלינוקס"), smtpAccountHashPath);
                    AddLine(page, UiTheme.Text(T(
                        "Хеш создаётся на Linux командой doveadm pw -s SHA512-CRYPT. Пароль не передаётся в мастер. Отзыв не допускает удаления последнего пользователя. Изменение — только после проверки и подтверждения.",
                        "Generate the hash on Linux with doveadm pw -s SHA512-CRYPT. No password enters the Wizard. The final account cannot be revoked. Preview and typed confirmation are mandatory.",
                        "יש ליצור hash בלינוקס. פעולה דורשת אישור, ללא סיסמה באשף.")));
                    AddAction(page, T("Проверить SMTP-пользователей (без изменений)",
                                      "Preview SMTP client account change (read-only)",
                                      "בדיקת שינוי חשבון SMTP"),
                                      PreviewSmtpAccountChangeAsync, false, "check", "account-check");
                    AddAction(page, T("Применить изменение SMTP-пользователя...",
                                      "Apply SMTP client account change...",
                                      "ביצוע שינוי חשבון SMTP"),
                                      ApplySmtpAccountChangeAsync, false, "shield", "account-apply");
                    AddLine(page, UiTheme.Text(T(
                        "Публичный SMTP: отдельное включение после проверки защиты (не рекомендуется без необходимости)",
                        "Public SMTP: separately reviewed exposure (avoid unless necessary)",
                        "SMTP ציבורי: פתיחה לאחר בדיקת אבטחה")));
                    AddAction(page, T("Аудит публичного SMTP без изменений",
                                      "Preview public SMTP safety (read-only)",
                                      "בדיקה בלבד: SMTP ציבורי"),
                                      PreviewPublicSmtpAsync, false, "check", "public-smtp-preview");
                    if (publicInternetRequested.Checked)
                        AddAction(page, T("Открыть SMTP для интернета после подтверждения...",
                                          "Enable reviewed public AUTH + TLS SMTP...",
                                          "אפשר SMTP מאובטח לציבור לאחר אישור"),
                                          ApplyPublicSmtpAsync, false, "shield", "public-smtp-apply");
                    AddAction(page, T("Закрыть публичный доступ и восстановить конфигурацию...",
                                      "Close public SMTP and restore private configuration...",
                                      "סגור SMTP ציבורי ושחזר הגדרות"),
                                      RestorePublicSmtpAsync, false, "rotate-ccw", "public-smtp-restore");
                    }
                }
                if (inspectedMail is not null && inspectedServerIdentity == TryCurrentIdentity())
                {
                    AddLine(page, UiTheme.Text("Detected MTA: " + inspectedMail.Mta +
                        "; relay: " + inspectedMail.CurrentRelay +
                        "; default transport: " + inspectedMail.CurrentTransport));
                    if (inspectedMail.Mta == "postfix" &&
                        System.Text.RegularExpressions.Regex.IsMatch(inspectedMail.ConfigSha256,
                            @"^[a-f0-9]{64}$"))
                    {
                        allowExisting.Text = T("Force Replace Configuration (опасно, только после backup)",
                            "Force Replace Configuration (destructive; verified backup required)",
                            "החלפה כפויה של תצורת Postfix (מסוכן)");
                        AddLine(page, allowExisting);
                        AddLine(page, UiTheme.Text(T(
                            "ВНИМАНИЕ: будет заменена конфигурация Postfix и перезапущена служба. Возможен перерыв входящей и исходящей почты. Сначала будет создан и проверен backup; Restore доступен позже.",
                            "WARNING: Existing Postfix routes and settings will be overwritten and service restarted. Mail may be interrupted. A verified backup is required; Restore remains available later.",
                            "אזהרה: תצורת Postfix הקיימת תוחלף וייתכן שיבוש בדואר.")));
                    }
                    else if (inspectedMail.Mta == "postfix")
                    {
                        allowExisting.Checked = false;
                        AddLine(page, UiTheme.Text(T(
                            "Force Replace недоступен: SHA-256 файлов main.cf и master.cf нельзя проверить. Проверьте доступ к ним у SSH-пользователя.",
                            "Force Replace disabled: SHA-256 of main.cf and master.cf is unavailable. Verify SSH user's read permissions.",
                            "לא ניתן לאמת קבצי Postfix. החלפה כפויה חסומה.")));
                    }
                }
                else
                {
                    allowExisting.Checked = false;
                    AddLine(page, UiTheme.Text(T(
                        "Для разблокировки Force Replace сначала выполните проверку существующего MTA.",
                        "Run the read-only MTA inspection before Force Replace can be offered.",
                        "יש לבדוק תחילה את שרת הדואר.")));
                }
                AddLine(page, UiTheme.Text(T(
                    "Для существующего Postfix режим Preserve Existing Mail создаёт отдельный экземпляр Postfix на выбранном SMTP-порту с отдельной очередью. При Exim/Sendmail доступен только режим Direct Send/Connector с уже установленным Postfix, FQDN и дополнительной проверкой сохранности основной MTA; SELinux Enforcing пока блокируется.",
                    "Preserve Existing Mail uses an independent Postfix and queue. With existing Exim/Sendmail, guarded Direct Send/Connector needs already-installed Postfix binaries, explicit FQDN and approval; enforcing SELinux is not live-verified.",
                    "עבור Postfix קיים נוצר מופע נפרד ביציאת SMTP שנבחרה ללא שינוי בתצורה הקיימת.")));
                AddLine(page, UiTheme.Text(T(
                    "Connector и политики сохранения/маскарада отправителя можно применить только к отдельному Postfix через Advanced SMTP с предварительной проверкой, подтверждением и Restore. Основной MTA, MX, SPF, DKIM и DMARC автоматически не меняются.",
                    "Verified Connector and sender policies can be activated only on an isolated sidecar through explicit Advanced SMTP actions. Domain, MX, SPF, DKIM, DMARC and primary MTA are not automatically altered.",
                    "ניתן להפעיל Connector ושימור או שינוי דומיין שולח רק בשרת Postfix המבודד, לאחר בדיקה ואישור. הגדרות השרת הראשי אינן משתנות.")));
                if (existingSmtpAudit is not null && existingSmtpAuditIdentity == TryCurrentIdentity())
                    AddLine(page, UiTheme.Text(existingSmtpAudit.Summary(language.SelectedIndex)));
                else
                    AddLine(page, UiTheme.Text(T(
                        "Публичный SMTP и безопасность пересылки пока не проверены. Проверка не отправляет письма и ничего не меняет.",
                        "Public SMTP and relay safety not audited yet. The check sends no mail and changes nothing.",
                        "טרם נבדקו שירותי SMTP ציבוריים והגבלות relay. הבדיקה אינה משנה דבר.")));
                AddAction(page, T("Анализ существующего публичного SMTP и правил Relay",
                                  "Audit existing public SMTP and relay policy",
                                  "בדיקת SMTP ציבורי והרשאות relay"),
                    InspectExistingPublicSmtpAsync, false, "shield", "smtp-audit");
                AddAction(page, T("Проверить почтовый сервер и маршруты (только чтение)",
                                  "Inspect existing MTA and routing (read-only)",
                                  "בדיקת שרת הדואר והניתוב"),
                    InspectMailRoutingAsync, false, "check", "preflight");
                AddAction(page, T("Проверка перед установкой", "Preflight read-only check", "בדיקה לפני התקנה"), PreflightAsync, false, "check", "preflight");
                if (mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 0)
                    AddAction(page, T("Установить и настроить XOAUTH2 Postfix",
                                      "Install and configure XOAUTH2 Postfix",
                                      "התקנת Postfix עם XOAUTH2"), ApplyAsync, true, "download", "postfix");
                else
                    AddLine(page, UiTheme.Text(T(
                        "Для Connector/Direct Send используйте выше кнопки проверки и установки отдельного Relay. Общая установка XOAUTH2 здесь не предлагается; существующий Relay изменяется только через расширенный EOP Preview/Apply.",
                        "Connector/Direct Send uses the dedicated NEW isolated gateway Preview/Install actions above. The XOAUTH2 installer is not offered; changes to an existing sidecar require advanced EOP Preview/Apply.",
                        "עבור Connector/Direct Send יש להשתמש בבדיקות ובהתקנה הייעודיות של הממסר.")));
                bool verifiedPrimary = inspectedServerIdentity == TryCurrentIdentity();
                if (verifiedPrimary && inspectedMail?.Mta == "postfix")
                {
                    AddLine(page, UiTheme.Text(T(
                        "Резервная копия только основного Postfix",
                        "Backup for primary Postfix ONLY",
                        "גיבוי לשרת Postfix ראשי בלבד"), true));
                    AddAction(page, T("Создать проверенный архив основного Postfix",
                        "Create verified primary Postfix backup", "צור גיבוי Postfix מאומת"),
                        BackupNowAsync, false, "shield", "backup");
                    AddAction(page, T("Показать проверенные архивы Postfix",
                        "List verified Postfix backups", "הצג גיבויי Postfix"),
                        ListBackupsAsync, false, "refresh", "backup");
                    if (backupSelector.Items.Count > 0)
                    {
                        AddLine(page, UiTheme.Text(T("Выберите резервную копию Postfix",
                            "Select a verified Postfix backup", "בחר גיבוי Postfix")));
                        AddLine(page, backupSelector);
                    }
                    AddAction(page, T("Восстановить выбранный Postfix...",
                        "Restore selected Postfix configuration...",
                        "שחזור תצורת Postfix"),
                        RestoreBackupAsync, false, "back", "restore");
                }
                else if (verifiedPrimary && (inspectedMail?.Mta is "exim" or "sendmail"))
                {
                    AddLine(page, UiTheme.Text(T(
                        "Архив конфигурации основного Exim/Sendmail",
                        "Primary Exim/Sendmail configuration archive",
                        "גיבוי תצורת Exim או Sendmail"), true));
                    AddLine(page, UiTheme.Text(T(
                        "Закрытый архив остаётся на Linux: /var/backups/linuxmailrelay365-foreign-mta. Может содержать пароли; не включает очереди, внешние сертификаты и состояние службы. Восстановление автоматически запрещено.",
                        "Root-only archive stays on Linux under /var/backups/linuxmailrelay365-foreign-mta. May contain passwords. Excludes mail queues, external certs and service state. Automatic Restore is DISABLED.",
                        "הגיבוי נשמר בלינוקס בלבד, ללא תור דואר או מצב שירות. השחזור האוטומטי מושבת.")));
                    AddAction(page, T(
                        "Проверить синтаксис Exim/Sendmail (без изменений)",
                        "Validate Exim/Sendmail native configuration (read-only)",
                        "בדיקת תקינות תצורת Exim/Sendmail ללא שינוי"),
                        CheckForeignMtaNativeSyntaxAsync, false, "check", "foreign-static-check");
                    AddLine(page, UiTheme.Text(T(
                        "Только статическая проверка конфигурации, без отправки почты и перезапуска MTA. Результат не подтверждает TLS, SMTP AUTH, очереди или доставку.",
                        "Static syntax check only. No mail sent or MTA restarted. This is NOT proof of TLS, SMTP AUTH, queues or delivery.",
                        "בדיקת תחביר בלבד, ללא שליחת דואר או הפעלה מחדש. זו אינה הוכחה למסירה.")));
                    AddAction(page, T("Создать и проверить архив Exim/Sendmail",
                        "Create and verify Exim/Sendmail archive",
                        "צור ואמת גיבוי Exim/Sendmail"),
                        BackupForeignMtaAsync, false, "shield", "foreign-backup");
                    AddAction(page, T("Показать проверенные архивы Exim/Sendmail",
                        "List verified Exim/Sendmail archives",
                        "הצג גיבויי Exim/Sendmail"),
                        ListForeignMtaBackupsAsync, false, "refresh", "foreign-backup-list");
                    if (foreignBackupSelector.Items.Count > 0)
                    {
                        AddLine(page, UiTheme.Text(T("Выберите архив для повторной проверки",
                            "Select archive to verify", "בחר גיבוי לאימות")));
                        AddLine(page, foreignBackupSelector);
                        AddAction(page, T("Проверить SHA-256 и содержимое архива",
                            "Verify archive SHA-256 and contents",
                            "אמת SHA-256 ותוכן הגיבוי"),
                            VerifyForeignMtaBackupAsync, false, "check", "foreign-backup-verify");
                        AddAction(page, T("Сравнить текущую конфигурацию с архивом (без изменений)",
                            "Compare active configuration with snapshot (read-only)",
                            "השווה תצורה נוכחית לגיבוי ללא שינוי"),
                            PreviewForeignMtaRecoveryAsync, false, "check", "foreign-recovery-preview");
                        AddAction(page, T(
                            "Проверить готовность восстановления Exim/Sendmail (только аудит)",
                            "Audit Exim/Sendmail offline recovery readiness (read-only)",
                            "בדיקת מוכנות לשחזור Exim/Sendmail ללא שינוי"),
                            PreflightForeignMtaRecoveryAsync, false, "check",
                            "foreign-recovery-preflight");
                        AddLine(page, UiTheme.Text(T(
                            "Проверяются служба, процессы, очереди и неизменность архива. Даже успешный аудит НЕ разрешает автоматический Restore или перезапуск MTA.",
                            "Checks service, processes, queues and archive SHA. Even a clean audit NEVER authorizes automatic Restore or service restart.",
                            "הבדיקה אינה מאשרת שחזור אוטומטי או הפעלת שירות.")));
                        AddAction(page, T("Извлечь архив в отдельный защищённый каталог на Linux...",
                            "Extract verified files to separate protected Linux directory...",
                            "חלץ גיבוי לתיקייה מוגנת ונפרדת בלינוקס"),
                            ExportForeignMtaOfflineAsync, false, "shield", "foreign-recovery-export");
                    }
                }
                else
                    AddLine(page, UiTheme.Text(T(
                        "Сначала выполните анализ MTA. Архив Postfix НЕ сохраняет конфигурацию Exim/Sendmail.",
                        "Inspect the active MTA first. A Postfix backup DOES NOT cover Exim or Sendmail.",
                        "יש לבדוק תחילה את שרת הדואר. גיבוי Postfix אינו כולל Exim או Sendmail.")));
                if (advancedSmtpTools.Checked && (preserveExistingMail.Checked || mailTransport.SelectedIndex != 0))
                {
                    AddLine(page, UiTheme.Text(T(
                        "Отдельный SMTP Relay: резервирование только его конфигурации (не основного Postfix/Exim/Sendmail). Очереди и внешние сертификаты в архив НЕ входят. Restore только при остановленных службах Relay и пустой очереди.",
                        "Isolated SMTP Relay: CONFIG-only backup (not primary Postfix/Exim/Sendmail). Queue, external certificates and tenant settings are NOT included. Restore requires all isolated services stopped and queue empty.",
                        "גיבוי תצורת ממסר SMTP מבודד בלבד; ללא תור דואר או מפתחות חיצוניים.")));
                    AddAction(page, T("Создать резервную копию отдельного Relay",
                                      "Back up isolated Relay configuration",
                                      "גיבוי תצורת ממסר מבודד"),
                        BackupSidecarConfigAsync, false, "shield", "sidecar-config-backup");
                    AddAction(page, T("Показать архивы отдельного Relay",
                                      "List isolated Relay backups",
                                      "רשימת גיבויי ממסר"),
                        ListSidecarConfigBackupsAsync, false, "refresh", "sidecar-config-list");
                    if (sidecarBackupSelector.Items.Count > 0)
                    {
                        AddLine(page, UiTheme.Text(T(
                            "Архив отдельного Relay (не основной MTA)",
                            "Isolated Relay backup (not primary MTA)",
                            "גיבוי ממסר מבודד")));
                        AddLine(page, sidecarBackupSelector);
                    }
                    AddAction(page, T("Проверить восстановление отдельного Relay",
                                      "Preview isolated Relay offline restore",
                                      "בדיקת שחזור ממסר מבודד"),
                        PreviewSidecarConfigRestoreAsync, false, "check", "sidecar-config-restore-preview");
                    AddAction(page, T("Восстановить конфигурацию отдельного Relay...",
                                      "Restore isolated Relay config (offline)...",
                                      "שחזור תצורת ממסר מבודד"),
                        RestoreSidecarConfigAsync, false, "shield", "sidecar-config-restore");
                }
                AddLine(page, UiTheme.Text(T(
                    "Postfix будет принимать локальную почту и отправлять её через XOAUTH2. Не используйте этот профиль без проверки, если сервер уже принимает почту извне.",
                    "Postfix will use a local-only listener and XOAUTH2 transport. Review existing inbound-mail setups before applying.",
                    "Postfix ישלח דואר מקומי דרך XOAUTH2. יש לבדוק תצורה קיימת.")));
                break;
            case 4:
                EnsureRoutingLoaded();
                if (mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 0)
                {
                    AddLine(page, UiTheme.Text(T(
                        "XOAUTH2: проверка токена не подтверждает доставку письма получателю. После теста проверьте Exchange Online и почтовый ящик.",
                        "XOAUTH2: a valid token does NOT prove message delivery. Independently verify Exchange Online and the recipient mailbox.",
                        "אימות OAuth אינו הוכחה למסירת דואר לנמען.")));
                    AddField(page, T("Кому отправить тестовое письмо", "Test recipient", "נמען בדיקה"), testRecipient);
                    AddAction(page, T("Проверить OAuth-токен и очередь",
                                      "Check OAuth token and mail queue",
                                      "בדיקת אסימון OAuth ותור הדואר"),
                        DiagnosticsAsync, true, "check", "token");
                    AddAction(page, T("Отправить тестовое письмо (XOAUTH2)",
                                      "Send test email (XOAUTH2)",
                                      "שליחת הודעת בדיקה (XOAUTH2)"),
                        SendTestAsync, false, "send", "smtp-test");
                }
                else if (mailTransport.SelectedIndex == 0)
                {
                    AddLine(page, UiTheme.Text(T(
                        "Несколько XOAUTH2 mailbox: это только план. Проверка токена и тестовая отправка скрыты, чтобы не отправить письмо от чужого фиксированного ящика. Применение запрещено.",
                        "Multi-mailbox XOAUTH2 is PLAN ONLY for live delivery. Token/test-mail actions remain hidden; experimental OFFLINE configuration never starts sending.",
                        "ריבוי תיבות XOAUTH2 הוא תכנון בלבד; לא תישלח הודעה.")));
                    AddAction(page, T("Проверить состояние локального SMTP и очереди (без отправки)",
                                      "Inspect local SMTP and queue (no mail sent)",
                                      "בדיקת SMTP ותור ללא שליחה"),
                        InspectRelayHealthAsync, true, "check", "smtp-health");
                    AddAction(page, T(
                        "Обновить подтверждение SMTP AUTH/From Guard на 120 секунд...",
                        "Refresh 120-second SMTP AUTH/From Guard proof (supervised test)...",
                        "עדכון אישור אבטחה זמני לבדיקת SMTP"),
                        RefreshMultiMailboxIngressProofAsync, false, "shield",
                        "multi-mailbox-ingress-proof");
                    AddLine(page, UiTheme.Text(T(
                        "Для реальной отправки нужна ручная проверка Microsoft 365. Это подтверждение истекает через 120 секунд. Автообновление пока НЕ настроено; включение SMTP НЕ выполняется.",
                        "For real delivery, Microsoft 365 must be tested separately. Proof expires after 120 seconds. Auto-renewal is NOT installed and SMTP is NOT started.",
                        "האישור פג לאחר 120 שניות. אין חידוש אוטומטי או הפעלת SMTP.")));
                }
                else
                {
                    AddLine(page, UiTheme.Text(mailTransport.SelectedIndex == 2
                        ? T("Direct Send: проверьте MX, принятый домен, доступность TCP 25 и очередь. Внешние адресаты не поддерживаются. Проверка не отправляет письма.",
                            "Direct Send: review MX, accepted domain, outbound TCP 25 and queue. External recipients are blocked. This check sends no mail.",
                            "Direct Send: בדיקת MX, תחום ופורט 25; שליחה רק לנמענים פנימיים.")
                        : T("Connector: проверьте MX и TCP 25, действующий Inbound Connector и очередь. Права реального Connector проверяются отдельно. Проверка не отправляет письма.",
                            "Connector: review MX, TCP 25, authorized tenant Inbound Connector and queue. This does not verify tenant rights or send mail.",
                            "Connector: בדיקת MX, פורט 25 ומצב המחבר; ללא שליחה.")));
                    AddAction(page, T("Проверить EOP/MX и соединение TCP 25 (без отправки)",
                                      "Inspect EOP/MX and outbound TCP 25 (no mail)",
                                      "בדיקת EOP ופורט 25 ללא שליחה"),
                        CheckOutboundModeAsync, false, "check", "outbound-mode");
                    AddAction(page, T("Проверить отдельный SMTP и очередь (без отправки)",
                                      "Inspect isolated SMTP and queue (no mail)",
                                      "בדיקת SMTP נפרד ותור ללא שליחה"),
                        InspectRelayHealthAsync, true, "check", "smtp-health");
                    AddLine(page, UiTheme.Text(T(
                        "Для реальной проверки отправьте согласованное тестовое письмо из настроенного SMTP-клиента и подтвердите получение. Мастер не будет подменять этот тест XOAUTH2-письмом.",
                        "For real delivery acceptance, send an approved test from a configured SMTP client and confirm receipt. The Wizard never substitutes a misleading XOAUTH2 test.",
                        "יש לשלוח בדיקה מלקוח SMTP מאושר ולאמת קבלה.")));
                }
                AddAction(page, T("Сохранить проверочное состояние перед перезагрузкой Linux",
                                  "Record server continuity baseline before Linux reboot",
                                  "שמירת מצב לפני הפעלה מחדש של Linux"),
                                  RecordRebootBaselineAsync, false, "shield", "reboot-baseline");
                AddAction(page, T("Проверить Postfix после ПОЛНОЙ перезагрузки Linux",
                                  "Verify services and config after a real Linux reboot",
                                  "בדיקת Postfix אחרי אתחול Linux"),
                                  VerifyRebootContinuityAsync, false, "check", "reboot-verify");
                AddAction(page, T("Резервные копии и Restore", "Backup & Restore", "גיבוי ושחזור"),
                    OpenBackupStepAsync, false, "shield", "backup");
                AddUpdateAccess(page);
                AddAction(page, T("Центр защиты: проверить / настроить позже", "Security Center: inspect / configure later", "מרכז אבטחה"), OpenSecurityCenterAsync, false, "shield");
                AddAction(page, T("Копировать безопасный диагностический отчёт", "Copy privacy-safe diagnostic report", "העתק דוח אבחון בטוח"),
                    CopySafeReportAsync, false, "copy", "diagnostics");
                AddAction(page, T("Сохранить безопасный отчёт JSON", "Save privacy-safe JSON report", "שמור דוח JSON"),
                    SaveSafeReportAsync, false, "download", "diagnostics");
                break;
        }
        pageHost.ResumeLayout();

        navigation.Controls.Clear();
        if (step == 0)
        {
            var connect = UiTheme.Action(T(
                "Проверить подключение и продолжить", "Check connection and continue",
                "בדיקת חיבור והמשך"), primary: true, glyph: "ssh");
            connect.Enabled = !busy;
            connect.Click += async (_, _) => await RunBusyAsync("ssh", CheckSshAndContinueAsync);
            navigation.Controls.Add(connect);
            if (!busy) AcceptButton = connect;
            var skip = UiTheme.Action(T(
                "Пропустить проверку", "Skip connection check",
                "דלג על בדיקת החיבור"), glyph: "next");
            skip.Enabled = !busy;
            skip.Click += (_, _) =>
            {
                try { EnsureSecurityLoaded(); }
                catch (Exception ex) { WriteLine("ERROR: " + ex.Message); return; }
                step = 1;
                RenderPage();
            };
            navigation.Controls.Add(skip);
        }
        else
        {
            var back = UiTheme.Action(T("Назад", "Back", "חזרה"), glyph: "back");
            back.Enabled = !busy;
            back.Click += (_, _) => { step--; RenderPage(); };
            var next = UiTheme.Action(T("Далее", "Next", "הבא"),
                primary: step < 4, glyph: "next");
            next.Enabled = step < 4 && !busy;
            next.Click += (_, _) => { step++; RenderPage(); };
            navigation.Controls.Add(next);
            navigation.Controls.Add(back);
        }
        activityToggle.Text = activityPanel.Visible
            ? T("Скрыть журнал", "Hide activity", "הסתר יומן")
            : T("Показать журнал", "Show activity", "הצג יומן");
        status.Text = lastStatus ?? T("Готов к работе · Пароли M365 не сохраняются",
            "Ready · M365 mailbox passwords are never stored", "מוכן · סיסמאות M365 אינן נשמרות");
        status.ForeColor = lastFailed ? Color.FromArgb(174, 40, 43) : UiTheme.Muted;
        FitFooterHeight();
    }

    /// <summary>
    /// Disposable Windows CI visual QA only. No SSH, Entra or SMTP operations.
    /// Screens capture the *actual* WinForms controls with factory defaults,
    /// not an inferred or designed mockup. Production never invokes this.
    /// </summary>
    internal int CaptureWizardScreens(string directory)
    {
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("RUNNER_TEMP")))
            throw new InvalidOperationException("Wizard capture requires a disposable GitHub Actions runner.");
        if (!Visible || InvokeRequired)
            throw new InvalidOperationException("Wizard capture must run on its visible UI thread.");
        string root = Path.GetFullPath(directory);
        Directory.CreateDirectory(root);
        Size = new Size(1050, 830);
        WindowState = FormWindowState.Normal;
        int captured = 0;

        void Screenshot(string filename, bool scrollToBottom = false)
        {
            // Capture the real top OR bottom of the scrollable step using
            // actual WinForms widgets. Never synthesize labels or status.
            pageHost.AutoScrollPosition = Point.Empty;
            pageHost.PerformLayout();
            PerformLayout();
            if (scrollToBottom && pageHost.VerticalScroll.Visible)
                pageHost.AutoScrollPosition = new Point(0, pageHost.VerticalScroll.Maximum);
            Refresh();
            Application.DoEvents();
            foreach (Control footerControl in new Control[] { status, activityToggle })
            {
                if (!footerControl.Visible) continue;
                var location = PointToClient(footerControl.PointToScreen(Point.Empty));
                if (location.Y < 0 ||
                    location.Y + footerControl.Height > ClientSize.Height - 2)
                    throw new InvalidOperationException("Wizard footer text extends beyond client area.");
            }
            // Form.DrawToBitmap captures the non-client Windows title bar as
            // well as the client area. A ClientSize bitmap silently crops the
            // entire bottom footer by the title-bar/border thickness even when
            // logical control bounds are correct. Capture the full WINDOW.
            Size capture = Size;
            using var bitmap = new Bitmap(capture.Width, capture.Height);
            DrawToBitmap(bitmap, new Rectangle(Point.Empty, capture));
            // Drawing can trigger an additional WinForms measure pass.
            // Validate AFTER painting as well, so a clipped status is a
            // failing CI test rather than a superficially valid PNG.
            if (footerLayout is null || wizardFrame is null ||
                footerLayout.Bottom > wizardFrame.ClientSize.Height ||
                footerLayout.Height < 60 || footerLayout.Top <= 0)
                throw new InvalidOperationException("Fixed footer is not inside the window.");
            foreach (Control footerControl in new Control[] { status, activityToggle })
            {
                if (!footerControl.Visible) continue;
                var bottom = PointToClient(footerControl.PointToScreen(Point.Empty)).Y +
                    footerControl.Height;
                if (bottom > ClientSize.Height - 9)
                    throw new InvalidOperationException("Wizard footer overflow after layout.");
            }
            bitmap.Save(Path.Combine(root, filename),
                        System.Drawing.Imaging.ImageFormat.Png);
            captured++;
        }

        string[] names =
        [
            "01-linux-connection.png",
            "02-optional-security.png",
            "03-microsoft-365.png",
            "04-postfix-xoauth2.png",
            "05-diagnostics.png"
        ];
        for (int index = 0; index < 5; index++)
        {
            step = index;
            RenderPage();
            Screenshot(names[index]);
            Screenshot("0" + (index + 1) + "-wizard-bottom.png", scrollToBottom: true);
            if (index == 2)
            {
                // The operator can choose Connector/Direct Send BEFORE
                // Entra. Capture the real skip-configuration screens as well.
                foreach (var (choice, picture) in new[] {
                    (1, "03-connector-no-entra.png"),
                    (2, "03-direct-send-no-entra.png")
                })
                {
                    routingLoading = true;
                    try { mailTransport.SelectedIndex = choice; }
                    finally { routingLoading = false; }
                    RenderPage();
                    Screenshot(picture);
                }
                routingLoading = true;
                try { mailTransport.SelectedIndex = 0; }
                finally { routingLoading = false; }
            }
            if (index == 3)
            {
                // Capture actual GUI of the deliberately blocked multi-mailbox
                // XOAUTH2 plan without connecting or inspecting host files.
                routingLoading = true;
                try { oauthSenderMode.SelectedIndex = 1; }
                finally { routingLoading = false; }
                RenderPage();
                Screenshot("04-postfix-xoauth2-multi-plan.png");
                Screenshot("04-postfix-xoauth2-multi-bottom.png", scrollToBottom: true);
                routingLoading = true;
                try { oauthSenderMode.SelectedIndex = 0; }
                finally { routingLoading = false; }
                try
                {
                    routingLoading = true;
                    mailTransport.SelectedIndex = 1;
                }
                finally { routingLoading = false; }
                RenderPage();
                Screenshot("04-postfix-connector.png");
                try
                {
                    routingLoading = true;
                    mailTransport.SelectedIndex = 2;
                }
                finally { routingLoading = false; }
                RenderPage();
                Screenshot("04-postfix-direct-send.png");
                try
                {
                    routingLoading = true;
                    mailTransport.SelectedIndex = 0;
                }
                finally { routingLoading = false; }
            }
        }
        // Additional compact-window QA across ALL five pages. These are
        // captured on actual WinForms controls, not assistant mockups.
        // A compact viewport exposes text wrapping and footer regressions.
        Size = new Size(900, 700);
        for (int index = 0; index < 5; index++)
        {
            step = index;
            RenderPage();
            Screenshot("compact-0" + (index + 1) + "-wizard.png");
        }
        step = 0;
        foreach (var (lang, name) in new[]
        {
            (0, "compact-ru-ssh.png"),
            (1, "compact-en-ssh.png"),
            (2, "compact-he-ssh.png")
        })
        {
            language.SelectedIndex = lang;
            RenderPage();
            Screenshot(name);
        }
        language.SelectedIndex = 0;
        Size = new Size(1050, 830);

        // Visual QA: the final step must offer only valid diagnostics for
        // each route. These screenshots neither connect nor send mail.
        step = 4;
        routingLoading = true;
        try { mailTransport.SelectedIndex = 1; }
        finally { routingLoading = false; }
        RenderPage();
        Screenshot("05-connector-diagnostics.png");
        routingLoading = true;
        try { mailTransport.SelectedIndex = 2; }
        finally { routingLoading = false; }
        RenderPage();
        Screenshot("05-direct-send-diagnostics.png");
        routingLoading = true;
        try
        {
            mailTransport.SelectedIndex = 0;
            oauthSenderMode.SelectedIndex = 1;
        }
        finally { routingLoading = false; }
        RenderPage();
        Screenshot("05-xoauth2-multi-plan-only.png");
        routingLoading = true;
        try { oauthSenderMode.SelectedIndex = 0; }
        finally { routingLoading = false; }
        // Verify the same connection form reflows at the compact window size.
        Size = new Size(760, 700);
        step = 0;
        RenderPage();
        Screenshot("01-linux-connection-compact.png");
        // Password mode is the operator's deployment path: capture both
        // responsive widths with the optional host-key checkbox visible.
        Size = new Size(1050, 830);
        sshAuthMode.SelectedIndex = 1;
        RenderPage();
        Screenshot("01-linux-password.png");
        Size = new Size(760, 700);
        RenderPage();
        Screenshot("01-linux-password-compact.png");
        Size = new Size(1050, 830);
        sshAuthMode.SelectedIndex = 0;
        RenderPage();
        File.WriteAllText(Path.Combine(root, "README.txt"),
            "Actual WinForms Preview wizard screenshots from a disposable CI runner.\n" +
            "Factory defaults only; no real SSH, Microsoft 365 tenant, TPM or SMTP delivery.\n" +
            "Captures top and bottom of all five scrollable pages and Multi-mailbox; no real 200% DPI monitor is emulated.\n");
        step = 0;
        RenderPage();
        return captured;
    }

    private void WriteLine(string message)
    {
        if (InvokeRequired) { BeginInvoke(() => WriteLine(message)); return; }
        var time = DateTime.Now.ToString("HH:mm:ss");
        activity.AppendText($"{time}  {DiagnosticJournal.SanitizeLocalActivity(message).TrimEnd()}\r\n");
        if (activity.TextLength > 150000)
            activity.Text = activity.Text[^90000..];
    }

    private async Task RunBusyAsync(string category, Func<Task> work)
    {
        if (busy) return;
        busy = true;
        lastFailed = false;
        lastStatus = T("Выполняется...", "Working...", "מתבצע...");
        journal.Record(category, "started");
        RenderPage();
        try
        {
            await work();
            journal.Record(category, "ok");
            lastStatus = T("Операция завершена", "Operation finished", "הפעולה הסתיימה");
        }
        catch (OperationCanceledException)
        {
            journal.Record(category, "cancelled");
            lastStatus = T("Операция отменена", "Operation cancelled", "הפעולה בוטלה");
            WriteLine("Operation cancelled.");
        }
        catch (Exception ex)
        {
            journal.Record(category, "failed");
            WriteLine("ERROR: " + ex.Message);
            lastFailed = true;
            activityPanel.Visible = true;
            if (footerLayout is not null)
                footerLayout.RowStyles[2].Height =
                    (int)Math.Round(145 * Math.Max(1f, DeviceDpi / 96f));
            lastStatus = T("Ошибка — проверь журнал", "Error — review activity", "שגיאה — בדוק יומן");
        }
        finally
        {
            busy = false;
            if (!IsDisposed && !Disposing && !updateShuttingDown)
                RenderPage();
        }
    }

    private Task CopySafeReportAsync()
    {
        Clipboard.SetText(journal.ExportJson());
        WriteLine("Privacy-safe diagnostic JSON copied. Contains operation category and status only.");
        return Task.CompletedTask;
    }

    private Task SaveSafeReportAsync()
    {
        using var dialog = new SaveFileDialog
        {
            Title = "LinuxMailRelay365 diagnostic report",
            Filter = "JSON report (*.json)|*.json",
            FileName = "LinuxMailRelay365-diagnostics-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + ".json",
            AddExtension = true,
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            File.WriteAllText(dialog.FileName, journal.ExportJson(), new UTF8Encoding(false));
            WriteLine("Privacy-safe diagnostic JSON saved. No credentials or machine identifiers included.");
        }
        return Task.CompletedTask;
    }

    private void ClearAutomaticSshHostKeyOnIdentityChange()
    {
        var oldIdentity = approvedSshIdentity;
        if (oldIdentity is null) return;
        if (string.Equals(oldIdentity.Value.Host, host.Text.Trim(),
                StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(sshPort.Text, out int port) && port == oldIdentity.Value.Port &&
            string.Equals(oldIdentity.Value.User, sshUser.Text.Trim(), StringComparison.Ordinal))
            return;
        // Operator-entered fingerprints remain untouched.
        if (string.Equals(sshFingerprint.Text, automaticallyPinnedSshFingerprint,
                StringComparison.Ordinal))
            sshFingerprint.Clear();
        approvedSshIdentity = null;
        automaticallyPinnedSshFingerprint = null;
    }

    private bool ConfirmFirstUseSshHostKey(SshEndpoint endpoint, string sha256)
    {
        // HostKeyReceived is raised on the SSH worker thread before AUTH.
        // Marshal the decision to the visible GUI; no password is sent first.
        if (IsDisposed || Disposing) return false;
        if (InvokeRequired)
        {
            try
            {
                return (bool)Invoke(new Func<SshEndpoint, string, bool>(
                    ConfirmFirstUseSshHostKey), endpoint, sha256);
            }
            catch (InvalidOperationException) { return false; }
        }
        if (!string.Equals(host.Text.Trim(), endpoint.Host, StringComparison.OrdinalIgnoreCase) ||
            !int.TryParse(sshPort.Text, out int port) || port != endpoint.Port ||
            !string.Equals(sshUser.Text.Trim(), endpoint.Username, StringComparison.Ordinal))
            return false;
        var choice = MessageBox.Show(this,
            T("Это первый SSH-контакт с " + endpoint.Host + ":" + endpoint.Port +
              ". Получен отпечаток ключа сервера:\n\nSHA256:" + sha256 +
              "\n\nЭтот ключ ещё НЕ проверен независимым способом. Для защиты от перехвата по возможности сверьте его на Linux-сервере через консоль.\n\nДоверять этому ключу только для текущего запуска программы и продолжить?",
              "First SSH connection to " + endpoint.Host + ":" + endpoint.Port +
              ". Server host key fingerprint:\n\nSHA256:" + sha256 +
              "\n\nThis key has NOT been independently verified. For MITM protection, compare it using your Linux server console if available.\n\nTrust this key for the current application session and continue?",
              "מפתח SSH חדש לשרת " + endpoint.Host + ".\nSHA256:" + sha256 +
              "\nיש לאמת את המפתח ממקור אמין לפני אישור. להמשיך?"),
            T("Подтверждение SSH host key", "Verify first-use SSH host key", "אימות מפתח SSH"),
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);
        if (choice != DialogResult.Yes) return false;
        // Session-only pin. Never persist an unverified key to disk.
        sshFingerprint.Text = "SHA256:" + sha256;
        approvedSshIdentity = (endpoint.Host, endpoint.Port, endpoint.Username);
        automaticallyPinnedSshFingerprint = sshFingerprint.Text;
        WriteLine("SSH first-use host key approved and pinned in memory for this session.");
        return true;
    }

    private SshEndpoint Endpoint()
    {
        if (!int.TryParse(sshPort.Text, out int port)) throw new ArgumentException("Invalid SSH port.");
        bool passwordMode = sshAuthMode.SelectedIndex == 1;
        if (passwordMode && string.IsNullOrEmpty(sshPassword.Text))
            throw new ArgumentException("Enter an SSH password or select SSH key mode.");
        var endpoint = new SshEndpoint(host.Text.Trim(), port, sshUser.Text.Trim(),
            passwordMode ? "" : sshKey.Text.Trim(),
            passwordMode ? sshPassword.Text : "",
            passwordMode ? sshFingerprint.Text.Trim() : "",
            sudoPassword.Text)
        {
            ConfirmFirstUseHostKey = passwordMode ? ConfirmFirstUseSshHostKey : null
        };
        endpoint.Validate();
        return endpoint;
    }

    private (Guid Tenant, string Mailbox) CloudInputs()
    {
        if (discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption)
            throw new ArgumentException("Choose the correct Microsoft 365 tenant from the list before continuing.");
        if (discoveredTenants.Count > 0 && tenantSelector.SelectedItem is TenantOption chosen &&
            !string.Equals(tenant.Text.Trim(), chosen.Id.ToString(), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Tenant ID does not match the selected Microsoft Entra organization.");
        if (!Guid.TryParse(tenant.Text.Trim(), out var guid) || guid == Guid.Empty)
            throw new ArgumentException("Enter an exact non-empty Microsoft 365 Tenant GUID.");
        if (!SshRemote.IsEmail(mailbox.Text.Trim()))
            throw new ArgumentException("Enter a valid Microsoft 365 sender mailbox.");
        return (guid, mailbox.Text.Trim().ToLowerInvariant());
    }

    private string PublicCertPath(SshEndpoint endpoint) => Path.Combine(dataDirectory,
        "certificate-" + SecurityOptionsStore.Identity(endpoint) + ".pem");

    private string StatePath(Guid tenantId) => Path.Combine(dataDirectory,
        "state-" + tenantId.ToString("N") + "-" + SecurityOptionsStore.Identity(Endpoint()) + ".json");

    private void EnsureRoutingLoaded()
    {
        string identity;
        try { identity = MailRoutingPlanStore.Identity(host.Text, sshPort.Text, sshUser.Text); }
        catch (ArgumentException) { return; }
        if (routingIdentity == identity) return;
        routingLoading = true;
        try
        {
            routingPlan = MailRoutingPlanStore.Load(dataDirectory, identity);
            mailTransport.SelectedIndex = routingPlan.Transport switch
             {
                 "connector" => 1, "direct-send" => 2, _ => 0
             };
            senderPolicy.SelectedIndex = routingPlan.SenderPolicy switch
            {
                "preserve-domain" => 1, "masquerade" => 2, _ => 0
            };
            oauthSenderMode.SelectedIndex = routingPlan.OAuthSenderMode == "authorized-multiple-mailboxes" ? 1 : 0;
            oauthSenderMapPath.Text = routingPlan.OAuthSenderMapPath;
            oauthSenderAuditSummary = "";
            oauthIngressAuditSummary = "";            oauthSignerAuditSummary = "";

            recipientScope.SelectedIndex = routingPlan.RecipientScope switch
            {
                "internal-only" => 1, "external-needed" => 2, _ => 0
            };
            preserveExistingMail.Checked = routingPlan.PreserveExistingMail;
            acceptedDomain.Text = routingPlan.VerifiedDomain;
            outboundMxHost.Text = routingPlan.EopMxHost;
            outboundFixedSender.Text = routingPlan.EopFixedSender;
            outboundSenderOwnerFile.Text = routingPlan.EopSenderOwnerFile;
            outboundPublicIp.Text = routingPlan.EopPublicIp;
            outboundConnectorName.Text = routingPlan.EopConnectorName;
            previewedTenantConnectorSha = null;
            previewedTenantConnectorContext = null;
            outboundCertPath.Text = routingPlan.EopCertificatePath;
            outboundCertKeyPath.Text = routingPlan.EopKeyPath;
            connectorApproved.Checked = false;
            acceptedDomainApproved.Checked = false;
            smtpListenIp.Text = routingPlan.ListenIpv4;
            privateAuthDns.Text = routingPlan.PrivateSmtpServerName;
            smtpTrustedCidrs.Text = routingPlan.TrustedCidrs;
            isolatedSmtpPort.Text = routingPlan.SidecarPort.ToString();
            postfixBasicsHostname.Text = routingPlan.PostfixBasicsHostname;
            postfixBasicsDomain.Text = routingPlan.PostfixBasicsDomain;
            postfixBasicsInterfaces.SelectedIndex =
                routingPlan.PostfixBasicsInterfaces == "all" ? 1 : 0;
            publicInternetRequested.Checked = routingPlan.PublicInternetRequested;
            advancedSmtpTools.Checked = routingPlan.ShowAdvancedSmtpTools;
            allowExisting.Checked = false;
            inspectedMail = null;
            inspectedServerIdentity = null;
            backupSelector.Items.Clear();
            sidecarBackupSelector.Items.Clear();
            reviewedSidecarRestoreSha = null;
            reviewedSidecarRestoreId = null;
            reviewedSidecarRestoreIdentity = null;
            existingSmtpAudit = null;
            existingSmtpAuditIdentity = null;
            discoveredIsolatedRelay = null;
            discoveredMailIdentity = null;
            inspectedHost = null;
            inspectedHostIdentity = null;
            previewedCleanBootstrapSha = null;
            previewedCleanBootstrapIdentity = null;
            cleanBootstrapSummary = "";
            previewedPostfixBasicsSha = null;
            previewedPostfixBasicsContext = null;
            postfixBasicsSummary = "";
            routingIdentity = identity;
        }
        finally { routingLoading = false; }
    }

    private void SaveRoutingChoices()
    {
        if (routingLoading || routingIdentity is null) return;
        routingPlan.Transport = mailTransport.SelectedIndex switch
        {
            1 => "connector", 2 => "direct-send", _ => "oauth2"
        };
        routingPlan.SenderPolicy = senderPolicy.SelectedIndex switch
        {
            1 => "preserve-domain", 2 => "masquerade", _ => "fixed-mailbox"
        };
        routingPlan.OAuthSenderMode = oauthSenderMode.SelectedIndex == 1
            ? "authorized-multiple-mailboxes" : "fixed-mailbox";
        routingPlan.OAuthSenderMapPath = oauthSenderMapPath.Text.Trim();
        routingPlan.RecipientScope = recipientScope.SelectedIndex switch
        {
            1 => "internal-only", 2 => "external-needed", _ => "unknown"
        };
        routingPlan.PreserveExistingMail = preserveExistingMail.Checked;
        routingPlan.VerifiedDomain = acceptedDomain.Text.Trim().ToLowerInvariant();
        routingPlan.EopMxHost = outboundMxHost.Text.Trim().ToLowerInvariant();
        routingPlan.EopFixedSender = outboundFixedSender.Text.Trim().ToLowerInvariant();
        routingPlan.EopSenderOwnerFile = outboundSenderOwnerFile.Text.Trim();
        routingPlan.EopPublicIp = outboundPublicIp.Text.Trim();
        routingPlan.EopConnectorName = outboundConnectorName.Text.Trim();
        routingPlan.EopCertificatePath = outboundCertPath.Text.Trim();
        routingPlan.EopKeyPath = outboundCertKeyPath.Text.Trim();
        routingPlan.ListenIpv4 = smtpListenIp.Text.Trim();
        routingPlan.PrivateSmtpServerName = privateAuthDns.Text.Trim();
        routingPlan.TrustedCidrs = smtpTrustedCidrs.Text.Trim();
        if (int.TryParse(isolatedSmtpPort.Text.Trim(), out int port))
            routingPlan.SidecarPort = port;
        routingPlan.PublicInternetRequested = publicInternetRequested.Checked;
        routingPlan.ShowAdvancedSmtpTools = advancedSmtpTools.Checked;
        routingPlan.PostfixBasicsHostname = postfixBasicsHostname.Text.Trim().ToLowerInvariant();
        routingPlan.PostfixBasicsDomain = postfixBasicsDomain.Text.Trim().ToLowerInvariant();
        routingPlan.PostfixBasicsInterfaces = postfixBasicsInterfaces.SelectedIndex == 1
            ? "all" : "loopback-only";
        // Operators can edit domain while typing. Save only valid completed values.
        try { MailRoutingPlanStore.Save(dataDirectory, routingIdentity, routingPlan); }
        catch (InvalidDataException) { }
    }

    private PreserveFlowSnapshot CurrentPreserveFlowSnapshot()
    {
        string selectedHost = host.Text.Trim();
        if (string.Equals(selectedHost, "linux.example.net", StringComparison.OrdinalIgnoreCase))
            selectedHost = "";
        return new PreserveFlowSnapshot(
            selectedHost, smtpListenIp.Text.Trim(), isolatedSmtpPort.Text.Trim(),
            mailbox.Text.Trim(), tenant.Text.Trim(), smtpTrustedCidrs.Text.Trim(),
            inspectedServerIdentity == TryCurrentIdentity() ? inspectedMail?.Mta : null,
            publicInternetRequested.Checked,
            mailTransport.SelectedIndex != 0,
            senderPolicy.SelectedIndex != 0,
            acceptedDomain.Text.Trim(),
            mailTransport.SelectedIndex switch { 1 => "connector", 2 => "direct-send", _ => "oauth2" },
            oauthSenderMode.SelectedIndex == 1 ? "authorized-multiple-mailboxes" : "fixed-mailbox",
            outboundMxHost.Text.Trim(), outboundFixedSender.Text.Trim(),
            preserveExistingMail.Checked,
            senderPolicy.SelectedIndex switch { 1 => "preserve-domain", 2 => "masquerade", _ => "fixed-mailbox" });
    }

    private void ResizePreserveFlowHelp()
    {
        if (IsDisposed) return;
        int width = Math.Clamp(pageHost.ClientSize.Width - 54, 280,
            (int)Math.Round(1000 * Math.Max(1f, DeviceDpi / 96f)));
        preserveFlowPreview.MinimumSize = new Size(280, 240);
        preserveFlowPreview.Width = width;
        preserveFlowPreview.Height = width < 790 ? 650 : 286;
        preserveMailInstructions.Width = width;
        deliveryModeExplanation.Width = width;
    }

    private void UpdatePreserveFlowPreview()
    {
        if (IsDisposed) return;
        var snapshot = CurrentPreserveFlowSnapshot();
        preserveFlowPreview.UpdateData(snapshot, language.SelectedIndex);
        preserveMailInstructions.Text = snapshot.ClientInstructions(language.SelectedIndex);
        deliveryModeExplanation.Text = MailRoutingGuidance.Explain(
            snapshot.TransportMode, snapshot.SenderPolicy, snapshot.OAuthSenderMode,
            snapshot.Mailbox, snapshot.OutboundMx, snapshot.EopFixedSender,
            snapshot.VerifiedDomain, snapshot.SmtpPort, snapshot.KeepExisting,
            language.SelectedIndex);
    }

    private void CopyPreserveInstructions()
    {
        // Do not trigger navigation/re-render and lose the current scroll position.
        try
        {
            UpdatePreserveFlowPreview();
            Clipboard.SetText(preserveMailInstructions.Text);
            WriteLine("Copied Preserve Existing Mail client setup instructions.");
        }
        catch (System.Runtime.InteropServices.ExternalException error)
        {
            WriteLine("Clipboard unavailable: " + error.Message);
        }
    }

    private string[] NetworkFirewallArguments(string action, bool includePublic)
    {
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int smtpPort))
            throw new InvalidDataException("Isolated SMTP port must be a number from 1024 to 65535.");
        routingPlan.SidecarPort = smtpPort;
        routingPlan.ListenIpv4 = smtpListenIp.Text.Trim();
        routingPlan.TrustedCidrs = smtpTrustedCidrs.Text.Trim();
        MailRoutingPlanStore.Validate(routingPlan);
        var args = new List<string> { action, "--smtp-port", smtpPort.ToString() };
        if (routingPlan.ListenIpv4.Length > 0)
        {
            args.Add("--listen-ip");
            args.Add(routingPlan.ListenIpv4);
            foreach (string cidr in routingPlan.TrustedCidrs.Split(',',
                         StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                args.Add("--trusted-network");
                args.Add(cidr);
            }
        }
        if (includePublic && publicInternetRequested.Checked) args.Add("--public-internet");
        return [.. args];
    }

    private string[] PrivateAuthTlsArguments(bool apply)
    {
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int selectedPort)
            || selectedPort is < 1024 or > 65535)
            throw new InvalidDataException("Custom isolated SMTP port must be 1024-65535.");
        var settings = new[]
        {
            "--smtp-port", selectedPort.ToString(),
            "--server-name", privateAuthDns.Text.Trim(),
            "--tls-cert", privateAuthCertPath.Text.Trim(),
            "--tls-key", privateAuthKeyPath.Text.Trim(),
            "--password-file", privateAuthHashPath.Text.Trim()
        };
        if (settings.Any(x => string.IsNullOrWhiteSpace(x)))
            throw new InvalidDataException("Enter the SMTP DNS name and three Linux file paths before checking.");
        return apply
            ? ["--apply", .. settings, "--confirm", "ENABLE_PRIVATE_AUTH_TLS"]
            : ["--check-only", .. settings];
    }

    private async Task CheckAuthTlsAsync()
    {
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("Install an isolated Postfix with Preserve Existing Mail first.");
        var existing = await SshRemote.IsSidecarAuthTlsEnabledAsync(endpoint, CancellationToken.None);
        if (existing == true)
        {
            int port = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
            WriteLine("Isolated Postfix already requires STARTTLS and SMTP AUTH on TCP " + port + ".");
            await VerifyInstalledTlsIdentityAsync(endpoint, port);
            return;
        }
        if (existing is null)
            throw new InvalidOperationException("Existing SMTP AUTH/TLS settings are partially configured or unrecognized. Review manually before running setup.");
        var args = PrivateAuthTlsArguments(apply: false);
        WriteLine("SMTP AUTH/TLS read-only preflight on custom TCP port " + isolatedSmtpPort.Text.Trim() +
                  ". No passwords or private keys are transferred.");
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildAuthTlsBundle(args), TimeSpan.FromSeconds(90));
        result.EnsureSuccess();
        WriteLine(result.StdOut);
        WriteLine("This only verifies prerequisites. Actual TLS certificate trust, client AUTH and Microsoft 365 delivery still require independent verification.");
    }

    private async Task EnableAuthTlsAsync()
    {
        var endpoint = Endpoint();
        var args = PrivateAuthTlsArguments(apply: true);
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("Preserve Existing Mail isolated Postfix must already be installed.");
        var current = await SshRemote.IsSidecarAuthTlsEnabledAsync(endpoint, CancellationToken.None);
        if (current == true)
            throw new InvalidOperationException("SMTP AUTH/STARTTLS is already configured; existing isolated configuration is never silently overwritten.");
        if (current is null)
            throw new InvalidOperationException("SMTP AUTH/STARTTLS settings are ambiguous. No changes made. Inspect the isolated Postfix configuration.");
        // Guard preflight is independent of operator confirmation.
        var preview = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildAuthTlsBundle(PrivateAuthTlsArguments(apply: false)),
            TimeSpan.FromSeconds(90));
        preview.EnsureSuccess();
        if (!preview.StdOut.Contains("AUTH_TLS_PREFLIGHT=ready", StringComparison.Ordinal))
            throw new InvalidOperationException("SMTP AUTH/TLS preflight did not establish readiness.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Enable Private SMTP AUTH + STARTTLS",
            T("Это изменит ТОЛЬКО конфигурацию отдельного Postfix на TCP ",
              "This will change ONLY the isolated Postfix on TCP ",
              "הפעולה תשנה רק את שרת Postfix הנפרד ביציאה ") + isolatedSmtpPort.Text.Trim() +
            "\n" + T("После включения ВСЕ клиенты на этом порту обязаны использовать STARTTLS, имя пользователя и пароль. Старые приложения на этом порту перестанут работать без новых настроек. Сервер Postfix на порту 25 не изменяется. Доступ из интернета запрещён.",
                "ALL clients on this port must switch to STARTTLS and SMTP username/password. Existing unauthenticated applications on this port will stop working until updated. Primary port 25 remains unchanged. Public Internet access remains blocked.",
                "כל הלקוחות ביציאה זו יחויבו ב-STARTTLS ובאימות. SMTP ראשי לא ישתנה."),
            "ENABLE PRIVATE SMTP AUTH")) return;
        WriteLine("Enabling isolated Postfix SMTP AUTH and mandatory STARTTLS on TCP " + isolatedSmtpPort.Text.Trim() +
                  "; no public firewall opening.");
        var installed = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildAuthTlsBundle(args), TimeSpan.FromMinutes(3));
        installed.EnsureSuccess();
        WriteLine(installed.StdOut);
        WriteLine("Update clients: configured DNS name " + privateAuthDns.Text.Trim() +
                  ", custom port " + isolatedSmtpPort.Text.Trim() +
                  ", STARTTLS REQUIRED, SMTP AUTH REQUIRED, verify server DNS and CA trust. Authentication details are not stored by this wizard.");
    }

    private async Task VerifyInstalledTlsIdentityAsync(SshEndpoint endpoint, int installedPort)
    {
        string dns = privateAuthDns.Text.Trim();
        if (string.IsNullOrEmpty(dns))
        {
            WriteLine("TLS chain and DNS verification skipped: enter the SMTP DNS name from the certificate SAN to verify it.");
            return;
        }
        var script = EmbeddedAssets.BuildTlsIdentityProbeBundle(installedPort, dns,
            privateTlsCaPath.Text.Trim());
        WriteLine("Checking SMTP certificate chain and DNS/SNI against the installed custom TCP port " +
                  installedPort + " on Linux loopback. No SMTP credentials or mail data are transmitted.");
        var report = await SshRemote.RunRootScriptAsync(endpoint, script, TimeSpan.FromSeconds(60));
        WriteLine(report.StdOut);
        if (report.ExitCode != 0 ||
            !report.StdOut.Contains("SMTP_TLS_PROBE_RESULT=verified_local_chain_dns_and_starttls",
                StringComparison.Ordinal))
        {
            WriteLine("TLS identity NOT VERIFIED. Review certificate SAN, expiry, trust chain and Linux CA trust. " +
                      "Do not configure clients to bypass certificate verification.");
        }
        else
        {
            WriteLine("Linux loopback validated the SMTP certificate chain and DNS name. " +
                      "This does NOT prove trust on actual client devices, external reachability or Microsoft 365 delivery.");
        }
    }

    private async Task RestoreAuthTlsAsync()
    {
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("No installed isolated Postfix was detected.");
        int installedPort = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int selectedPort) ||
            selectedPort != installedPort)
            throw new InvalidOperationException("The Wizard custom SMTP port must match the actual installed isolated TCP port (" + installedPort + ") before restoration.");
        if (await SshRemote.IsSidecarAuthTlsEnabledAsync(endpoint, CancellationToken.None) != true)
            throw new InvalidOperationException("SMTP AUTH/STARTTLS is not verified as active. Restoration blocked until the installed mode is inspected.");
        var preview = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildAuthTlsRestoreBundle(installedPort),
            TimeSpan.FromSeconds(90));
        preview.EnsureSuccess();
        var hashMatch = System.Text.RegularExpressions.Regex.Match(preview.StdOut,
            @"(?m)^AUTH_TLS_RESTORE_CURRENT_MAIN_SHA256=([a-f0-9]{64})\r?$");
        if (!preview.StdOut.Contains("AUTH_TLS_RESTORE_PREFLIGHT=ready", StringComparison.Ordinal) ||
            !hashMatch.Success)
            throw new InvalidDataException("The isolated SMTP AUTH restore preflight did not return a verified SHA-256.");
        string fingerprint = hashMatch.Groups[1].Value;
        WriteLine("Restore preflight ready for installed isolated TCP " + installedPort +
                  "; SMTP AUTH and mandatory STARTTLS will be DISABLED. Current configuration SHA-256: " + fingerprint +
                  ". No changes made so far.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Restore previous private SMTP",
            T("ОПАСНО: будет выключена обязательная TLS-защита и SMTP AUTH на порту ",
              "SECURITY DOWNGRADE: mandatory TLS and per-client SMTP AUTH will be disabled on TCP ",
              "אזהרה: הצפנה ואימות SMTP יוסרו ביציאה ") + installedPort +
            "\n" + T("Приложения смогут отправлять почту без пароля из доверенных подсетей. Перед операцией создаётся закрытый backup действующих настроек, ключа и хешей. Основной Postfix не меняется. НЕ открывайте порт в интернет.",
                "Applications in the trusted private CIDRs will be able to submit mail WITHOUT passwords. An offline root-only archive of the active TLS key and password hashes is retained for recovery. Primary Postfix is unchanged. NEVER expose this port to the Internet.",
                "השחזור מאפשר שליחה מרשתות מהימנות ללא סיסמה. ארכיון פרטי יישמר. אין לפתוח את הפורט לאינטרנט."),
            "RESTORE TRUSTED SMTP")) return;
        // The root-side restore script rechecks the complete SHA-256, private
        // listeners, stored manifests and policy under an exclusive lock.
        var applied = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildAuthTlsRestoreBundle(installedPort, fingerprint),
            TimeSpan.FromMinutes(3));
        applied.EnsureSuccess();
        if (!applied.StdOut.Contains("AUTH_TLS_RESTORED=yes", StringComparison.Ordinal))
            throw new InvalidOperationException("The isolated SMTP restoration did not confirm success. Inspect recovery diagnostics.");
        WriteLine(applied.StdOut);
        await InspectAuthArchivesAsync(endpoint);
        WriteLine("Restored private trusted-CIDR SMTP on TCP " + installedPort +
                  ". Update every affected application's settings: STARTTLS and SMTP AUTH are NO LONGER required. " +
                  "The recovery archive holds sensitive TLS key/password hash material and must remain root-only. " +
                  "Do not open the port to public internet.");
    }

    private async Task InspectAuthArchivesAsync(SshEndpoint endpoint)
    {
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildAuthArchiveAuditBundle(), TimeSpan.FromSeconds(60));
        result.EnsureSuccess();
        WriteLine("Read-only SMTP AUTH recovery archive audit (metadata and SHA-256 only; no credential contents):");
        WriteLine(result.StdOut);
        if (result.StdOut.Contains("AUTH_TLS_ARCHIVE_STATUS=incomplete_or_tampered", StringComparison.Ordinal) ||
            result.StdOut.Contains("AUTH_TLS_ARCHIVE_STATUS=unsafe_root_directory", StringComparison.Ordinal) ||
            result.StdOut.Contains("AUTH_TLS_ARCHIVE_STATUS=unexpected_entry_manual_review", StringComparison.Ordinal))
            WriteLine("WARNING: SMTP AUTH recovery archive must be inspected by an administrator before it is relied on for restoration.");
        else if (result.StdOut.Contains("AUTH_TLS_ARCHIVE_STATUS=verified_root_only", StringComparison.Ordinal))
            WriteLine("Recovery archives have root-only directory access and matching Postfix configuration SHA-256. This does not verify a full server disaster recovery restore.");
    }

    private async Task AuditInstalledPrivateSmtpAsync()
    {
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int selectedPort) ||
            selectedPort is < 1024 or > 65535)
            throw new InvalidDataException("Choose a custom isolated SMTP port from 1024 to 65535.");
        var endpoint = Endpoint();
        int checkPort = selectedPort;
        if (await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
        {
            checkPort = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
            if (checkPort != selectedPort)
                WriteLine("Installed sidecar actually listens on TCP " + checkPort +
                          ", not the unsaved Wizard selection " + selectedPort +
                          ". Auditing the installed port.");
        }
        WriteLine("Read-only installed SMTP security audit (selected TCP " + checkPort +
                  "): isolated listener, Postfix relay policy, Dovecot AUTH, STARTTLS and SELinux. " +
                  "No mail sent, no credentials read, no settings changed.");
        var report = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildInstalledSidecarAuditBundle(checkPort),
            TimeSpan.FromSeconds(90));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        if (report.StdOut.Contains("SMTP_SECURITY_RESULT=needs_manual_review", StringComparison.Ordinal))
            WriteLine("ATTENTION: installed SMTP security requires manual review. Do not open the custom port to the Internet.");
        else if (report.StdOut.Contains("SMTP_SECURITY_RESULT=local_auth_tls_verified_external_unverified", StringComparison.Ordinal))
            WriteLine("Local SMTP AUTH/STARTTLS handshake passes. Certificate trust on actual clients, firewall reachability and Microsoft 365 delivery remain unverified.");
        else if (report.StdOut.Contains("SMTP_SECURITY_RESULT=private_unauthenticated_not_public_safe", StringComparison.Ordinal))
            WriteLine("Private trusted-network relay without per-client SMTP AUTH. Do not expose it to the Internet.");
        // A backup check belongs with the existing security audit; no extra
        // wizard action or separate popup is required.
        await InspectAuthArchivesAsync(endpoint);
        if (await SshRemote.IsSidecarAuthTlsEnabledAsync(endpoint, CancellationToken.None) == true)
            await VerifyInstalledTlsIdentityAsync(endpoint, checkPort);
    }

    private (int Port, string Operation, string Username, string HashPath) GetSmtpAccountChange()
    {
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int port) || port is < 1024 or > 65535)
            throw new InvalidDataException("Choose a custom SMTP port from 1024 to 65535.");
        string operation = smtpAccountOperation.SelectedIndex switch
        {
            0 => "add",
            1 => "rotate",
            2 => "revoke",
            _ => throw new InvalidDataException("Choose Add, Rotate or Revoke.")
        };
        return (port, operation, smtpAccountName.Text.Trim(), smtpAccountHashPath.Text.Trim());
    }

    private async Task GenerateSmtpCredentialAsync()
    {
        string username = smtpAccountName.Text.Trim();
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("Install an independent SMTP sidecar before creating client account credentials.");
        var check = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildSmtpCredentialGeneratorBundle(username, false),
            TimeSpan.FromSeconds(50));
        if (check.ExitCode != 0 ||
            !check.StdOut.Contains("SMTP_SECRET_PREFLIGHT=valid_username_only", StringComparison.Ordinal))
            throw new InvalidOperationException("SMTP credential preview refused the account name.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Generate per-client SMTP secret",
            "Generate a cryptographically random SMTP client password on Linux. " +
            "Only two new root-only salted SHA512-CRYPT hash files will remain on disk. " +
            "The plaintext password is returned ONCE through your verified SSH session " +
            "and shown only in a private Windows dialog; it is never written to logs or configuration. " +
            "Existing files cannot be overwritten. This does not modify Postfix or Microsoft 365. " +
            "Save the password securely before closing the dialog; the server cannot recover it.",
            "GENERATE SMTP PASSWORD")) return;
        var generated = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildSmtpCredentialGeneratorBundle(username, true),
            TimeSpan.FromSeconds(70));
        // Never call EnsureSuccess here: it formats remote stdout into the
        // exception, which could accidentally disclose a generated secret.
        if (generated.ExitCode != 0)
            throw new InvalidOperationException("SMTP password generation failed. Inspect root-only Linux files without logging stdout.");
        var secret = System.Text.RegularExpressions.Regex.Match(generated.StdOut,
            @"(?m)^SMTP_GENERATED_SECRET=([A-Za-z0-9_-]{38,100})\r?$");
        var hash = System.Text.RegularExpressions.Regex.Match(generated.StdOut,
            @"(?m)^SMTP_GENERATED_HASH_PATH=(/etc/linuxmailrelay365/generated-accounts/[A-Za-z0-9._@-]+[.]hash)\r?$");
        var passwd = System.Text.RegularExpressions.Regex.Match(generated.StdOut,
            @"(?m)^SMTP_GENERATED_PASSWD_PATH=(/etc/linuxmailrelay365/generated-accounts/[A-Za-z0-9._@-]+[.]passwd)\r?$");
        if (!secret.Success || !hash.Success || !passwd.Success ||
            !generated.StdOut.Contains("SMTP_GENERATED_STATUS=created", StringComparison.Ordinal))
            throw new InvalidDataException("Secret response incomplete. Inspect Linux hash files before retrying; plaintext cannot be recovered.");
        smtpAccountHashPath.Text = hash.Groups[1].Value;
        if (string.IsNullOrWhiteSpace(privateAuthHashPath.Text))
            privateAuthHashPath.Text = passwd.Groups[1].Value;
        WriteLine("Generated a private SMTP password and two root-only salted hash files. No plaintext entered logs.");
        using var dialog = new Form
        {
            Text = "LinuxMailRelay365 | One-time SMTP password",
            StartPosition = FormStartPosition.CenterParent,
            ClientSize = new Size(655, 215),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MinimizeBox = false, MaximizeBox = false
        };
        var note = new Label
        {
            Left = 16, Top = 15, Width = 625, Height = 55,
            Text = "This SMTP application password is shown only once. " +
                   "Copy it securely into the client before closing this dialog."
        };
        var passwordField = new TextBox
        {
            Left = 16, Top = 77, Width = 625, ReadOnly = true,
            Text = secret.Groups[1].Value, UseSystemPasswordChar = true
        };
        var show = new CheckBox { Left = 16, Top = 114, Width = 155,
                                  Text = "Show password" };
        show.CheckedChanged += (_, _) =>
            passwordField.UseSystemPasswordChar = !show.Checked;
        var copy = new Button { Left = 265, Top = 157, Width = 175,
                                Text = "Copy to clipboard" };
        copy.Click += (_, _) => Clipboard.SetText(passwordField.Text);
        var close = new Button { Left = 453, Top = 157, Width = 188,
                                 Text = "I saved the password", DialogResult = DialogResult.OK };
        dialog.AcceptButton = close;
        dialog.Controls.AddRange([note, passwordField, show, copy, close]);
        try { dialog.ShowDialog(this); }
        finally { passwordField.Clear(); }
    }

    private async Task PreviewSmtpAccountChangeAsync()
    {
        var entry = GetSmtpAccountChange();
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("The isolated Postfix is not installed.");
        int installed = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
        if (installed != entry.Port)
            throw new InvalidDataException("Selected SMTP port does not match installed TCP " + installed + ".");
        var report = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildSmtpAccountManagerBundle(entry.Port, entry.Operation,
                entry.Username, entry.HashPath), TimeSpan.FromSeconds(60));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        WriteLine("Preview only: SMTP account change NOT applied. Microsoft 365 sender identity is unchanged.");
    }

    private async Task RotateTlsCertificateAsync()
    {
        var endpoint = Endpoint();
        if (await SshRemote.IsSidecarAuthTlsEnabledAsync(endpoint, CancellationToken.None) != true)
            throw new InvalidOperationException("The isolated Postfix does not have verified mandatory STARTTLS and SMTP AUTH.");
        int installedPort = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int desiredPort) || installedPort != desiredPort)
            throw new InvalidDataException("Chosen custom SMTP port must match installed TCP " + installedPort + ".");
        string dns = privateAuthDns.Text.Trim(), cert = privateAuthCertPath.Text.Trim(),
               key = privateAuthKeyPath.Text.Trim(), ca = privateTlsCaPath.Text.Trim();
        var preview = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildTlsRotationBundle(installedPort, dns, cert, key, ca),
            TimeSpan.FromSeconds(90));
        preview.EnsureSuccess();
        var expected = System.Text.RegularExpressions.Regex.Match(preview.StdOut,
            @"(?m)^TLS_ROTATE_OLD_CERT_SHA256=([a-f0-9]{64})\r?$");
        if (!expected.Success || !preview.StdOut.Contains("TLS_ROTATE_PREFLIGHT=ready",
                StringComparison.Ordinal))
            throw new InvalidDataException("The new certificate preflight did not confirm readiness.");
        WriteLine("TLS rotation preflight OK: custom TCP " + installedPort + "; old certificate SHA-256 " +
                  expected.Groups[1].Value + ". No changes made.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Rotate private SMTP TLS",
            T("Будет заменён сертификат только отдельного Postfix на TCP ",
              "Replace ONLY the isolated Postfix STARTTLS certificate on TCP ",
              "החלפת אישור SMTP בפורט ") + installedPort +
            "\n" + T("При ошибке новая конфигурация будет откачена. Резервная копия с закрытым ключом останется только на Linux. Сертификат должен быть доверенным для всех приложений. Основной Postfix не меняется.",
                       "Failure will attempt rollback. The root-only recovery archive contains the previous private key. Client trust must be checked separately; the primary Postfix is unchanged.",
                       "בכשל יתבצע ניסיון שחזור. המפתח נשאר בלינוקס."),
            "ROTATE PRIVATE SMTP TLS")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildTlsRotationBundle(installedPort, dns, cert, key, ca,
                expected.Groups[1].Value), TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("TLS_ROTATE_APPLIED=yes", StringComparison.Ordinal))
            throw new InvalidOperationException("SMTP TLS rotation did not confirm success; inspect recovery archive.");
        WriteLine(result.StdOut);
        await VerifyInstalledTlsIdentityAsync(endpoint, installedPort);
    }

    private async Task ApplySmtpAccountChangeAsync()
    {
        var entry = GetSmtpAccountChange();
        var endpoint = Endpoint();
        if (await SshRemote.IsSidecarAuthTlsEnabledAsync(endpoint, CancellationToken.None) != true)
            throw new InvalidOperationException("Private SMTP AUTH and mandatory STARTTLS must already be active.");
        if (await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None) != entry.Port)
            throw new InvalidOperationException("Custom SMTP port mismatch with installed isolated Postfix.");
        var preview = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildSmtpAccountManagerBundle(entry.Port, entry.Operation,
                entry.Username, entry.HashPath), TimeSpan.FromSeconds(60));
        preview.EnsureSuccess();
        var match = System.Text.RegularExpressions.Regex.Match(preview.StdOut,
            @"(?m)^SMTP_ACCOUNT_CURRENT_STATE_SHA256=([a-f0-9]{64})\r?$");
        if (!match.Success || !preview.StdOut.Contains("SMTP_ACCOUNT_RESULT=preview_ready",
              StringComparison.Ordinal))
            throw new InvalidDataException("SMTP account preflight not ready. No changes applied.");
        string currentSha = match.Groups[1].Value;
        if (!ConfirmDestructive("LinuxMailRelay365 | Private SMTP account change",
            T("Изменение доступа SMTP на отдельном Postfix. Убедитесь, что приложения готовы к изменению логина или пароля. Порт: ",
              "Change one application's access to the private SMTP sidecar. Update affected app credentials after this operation. TCP port: ",
              "שינוי חשבון SMTP של יישום נפרד. יציאה: ") + entry.Port +
            "\n" + T("Действующий Postfix и M365-отправитель не меняются. На Linux будет создан закрытый backup. Операция: ",
                       "Primary Postfix and M365 sender are unchanged; a root-only backup is retained. Operation: ",
                       "שרת SMTP ראשי אינו משתנה. פעולה: ") + entry.Operation,
            "CHANGE PRIVATE SMTP ACCOUNT")) return;
        var applied = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildSmtpAccountManagerBundle(entry.Port, entry.Operation,
                entry.Username, entry.HashPath, currentSha), TimeSpan.FromMinutes(3));
        applied.EnsureSuccess();
        if (!applied.StdOut.Contains("SMTP_ACCOUNT_RESULT=applied", StringComparison.Ordinal))
            throw new InvalidDataException("SMTP account update did not confirm success; inspect private service logs.");
        WriteLine(applied.StdOut);
        WriteLine("Update/revoke the affected application's SMTP credentials. No Microsoft 365 mailbox or primary Postfix changes were requested.");
    }

    private async Task RecordRebootBaselineAsync()
    {
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("The isolated SMTP gateway is not installed.");
        int port = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
        if (!ConfirmDestructive("LinuxMailRelay365 | Pre-reboot baseline",
            T("Записать закрытый контрольный снимок для TCP ",
              "Store a root-only continuity baseline for TCP ",
              "שמירת מצב לפורט ") + port +
            "\n" + T("Сервер не будет перезагружен. Повторная запись поверх существующего состояния запрещена. После самостоятельной перезагрузки запустите вторую проверку.",
                       "The server will NOT reboot automatically. Existing baseline is never overwritten. After manually rebooting the server, run Verify after reboot.",
                       "השרת לא יופעל מחדש באופן אוטומטי."),
            "RECORD REBOOT BASELINE")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildRebootContinuityBundle(port, true),
            TimeSpan.FromSeconds(75));
        result.EnsureSuccess();
        WriteLine(result.StdOut);
        WriteLine("Root-only reboot baseline recorded. Perform a controlled reboot manually when ready; then reconnect and verify.");
    }

    private async Task VerifyRebootContinuityAsync()
    {
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("No isolated SMTP detected after reboot.");
        int port = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildRebootContinuityBundle(port, false),
            TimeSpan.FromSeconds(75));
        WriteLine(result.StdOut);
        result.EnsureSuccess();
        if (!result.StdOut.Contains("REBOOT_CONTINUITY_RESULT=local_services_continuity_verified",
                StringComparison.Ordinal))
            throw new InvalidOperationException("A full-reboot continuity test is not verified.");
        WriteLine("Local service continuity passed after a different kernel boot ID. " +
                  "Validate actual client CA trust, Microsoft 365 token and recipient delivery separately.");
    }

    private async Task InstallHealthMonitorAsync()
    {
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("Install isolated Postfix before enabling its health monitor.");
        int installedPort = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int selectedPort) || selectedPort != installedPort)
            throw new InvalidDataException("The selected custom port must match installed SMTP TCP " + installedPort + ".");
        var preview = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHealthMonitorBundle(installedPort, false), TimeSpan.FromSeconds(60));
        preview.EnsureSuccess();
        if (!preview.StdOut.Contains("HEALTH_TIMER_PREFLIGHT=ready", StringComparison.Ordinal))
            throw new InvalidOperationException("Local journaled SMTP monitor preflight did not confirm readiness.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Local Health Monitoring",
            T("Будет добавлен только отдельный systemd timer для SMTP на TCP ",
              "Install only a dedicated 15-minute systemd health timer for TCP ",
              "התקנת ניטור SMTP בפורט ") + installedPort +
            "\n" + T("Результаты сохраняются в локальном journald, внешние уведомления пока не настроены. Основной Postfix и firewall не меняются.",
                       "Reports are written to local journald only; external notifications are NOT configured. No primary Postfix or firewall changes.",
                       "דוחות יישמרו ביומן Linux בלבד."),
            "ENABLE SMTP MONITOR")) return;
        var applied = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHealthMonitorBundle(installedPort, true), TimeSpan.FromSeconds(90));
        applied.EnsureSuccess();
        if (!applied.StdOut.Contains("HEALTH_TIMER_INSTALLED=yes", StringComparison.Ordinal))
            throw new InvalidOperationException("Monitoring timer installation did not confirm success.");
        WriteLine(applied.StdOut);
        WriteLine("Local systemd timer installed. Use journalctl -u linuxmailrelay365-health.service; " +
                  "integrate your monitoring platform separately for external alerts.");
    }

    private async Task EnableHealthAlertsAsync()
    {
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("Install isolated SMTP and its 15-minute local health timer first.");
        int port = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int selected) || selected != port)
            throw new InvalidDataException("The selected SMTP port must match installed TCP " + port + ".");
        var check = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHealthAlertsBundle(port, "check"), TimeSpan.FromSeconds(70));
        check.EnsureSuccess();
        var sha = System.Text.RegularExpressions.Regex.Match(check.StdOut,
            @"(?m)^HEALTH_WEBHOOK_CONFIG_SHA256=([a-f0-9]{64})\r?$");
        if (!check.StdOut.Contains("HEALTH_WEBHOOK_PREFLIGHT=ready", StringComparison.Ordinal) ||
            !sha.Success)
            throw new InvalidOperationException("HTTPS webhook did not pass local preflight.");
        WriteLine(check.StdOut);
        if (!ConfirmDestructive("LinuxMailRelay365 | Enable HTTPS health alerts",
            "Adds only the LinuxMailRelay365-owned systemd drop-in for the existing 15-minute SMTP health timer. " +
            "It may transmit aggregate alarm codes and queue metrics to the EXTERNAL HTTPS endpoint. " +
            "The private webhook URL/token remains ONLY on the Linux server as root:root 0600, never on Windows. " +
            "DNS/TLS and receipt are checked on the first actual alert; no alert is transmitted by this preview. " +
            "The primary Postfix, its queue, and firewall are not changed.",
            "ENABLE SMTP HEALTH ALERTS")) return;
        var applied = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHealthAlertsBundle(port, "enable", sha.Groups[1].Value),
            TimeSpan.FromSeconds(90));
        applied.EnsureSuccess();
        if (!applied.StdOut.Contains("HEALTH_WEBHOOK_ENABLED=yes", StringComparison.Ordinal))
            throw new InvalidOperationException("External alert integration did not confirm success.");
        WriteLine(applied.StdOut);
        WriteLine("Opt-in HTTPS alerting now follows the existing timer. Test with a genuine alert/recovery event and verify the receiver.");
    }

    private async Task DisableHealthAlertsAsync()
    {
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("No isolated SMTP installed.");
        int port = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
        var status = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHealthAlertsBundle(port, "status"),
            TimeSpan.FromSeconds(50));
        status.EnsureSuccess();
        if (!status.StdOut.Contains("HEALTH_WEBHOOK_STATUS=enabled", StringComparison.Ordinal))
        {
            WriteLine("External HTTPS alerts are not enabled on this isolated SMTP instance.");
            return;
        }
        if (!ConfirmDestructive("LinuxMailRelay365 | Disable external alerts",
            "Remove only the owned systemd health-alert drop-in. The local 15-minute health timer continues. " +
            "The root-only Linux webhook config and delivery-state file are retained for operator review. " +
            "Postfix, existing mail and firewall are untouched.",
            "DISABLE SMTP HEALTH ALERTS")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHealthAlertsBundle(port, "disable"), TimeSpan.FromSeconds(85));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("HEALTH_WEBHOOK_DISABLED=yes", StringComparison.Ordinal))
            throw new InvalidOperationException("External alerts disable could not be verified.");
        WriteLine(result.StdOut);
    }

    private (Guid Tenant, string Domain, string Name, string Ip, string Certificate) TenantConnectorOptions()
    {
        if (!Guid.TryParse(tenant.Text.Trim(), out Guid id) || id == Guid.Empty)
            throw new InvalidDataException("Choose exact Entra tenant ID before managing an Exchange Connector.");
        if (discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption)
            throw new InvalidDataException("Choose the intended Entra tenant from discovery first.");
        if (discoveredTenants.Count > 0 && tenantSelector.SelectedItem is TenantOption selected &&
            selected.Id != id)
            throw new InvalidDataException("Exchange Connector tenant differs from selected Entra tenant.");
        if (mailTransport.SelectedIndex != 1)
            throw new InvalidOperationException("Choose Microsoft 365 Connector transport first.");
        string domain = acceptedDomain.Text.Trim().ToLowerInvariant();
        string name = outboundConnectorName.Text.Trim();
        string ip = outboundPublicIp.Text.Trim();
        string cert = outboundCertPath.Text.Trim();
        if (string.IsNullOrEmpty(ip) == string.IsNullOrEmpty(cert))
            throw new InvalidOperationException("For Connector creation choose EXACTLY ONE identity: static public IPv4 OR client certificate. Clear the unused value.");
        return (id, domain, name, ip, ip.Length > 0 ? "" : domain);
    }

    private async Task<string> RunTenantConnectorManagerAsync(
        (Guid Tenant, string Domain, string Name, string Ip, string Certificate) options,
        string action, string? sha = null)
    {
        if (action is not ("Preview" or "Apply"))
            throw new ArgumentException("Unsupported tenant Connector action.");
        var scriptPath = Path.Combine(dataDirectory, "Manage-LinuxMailRelay365Connector.ps1");
        var reportPath = Path.Combine(dataDirectory, "connector-result-" +
            Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(scriptPath, EmbeddedAssets.TenantConnectorManager, new UTF8Encoding(false));
        var psi = new ProcessStartInfo("pwsh.exe")
        {
            UseShellExecute = true,
            WorkingDirectory = dataDirectory
        };
        foreach (var arg in new[]
        {
            "-NoLogo", "-NoProfile", "-File", scriptPath,
            "-Action", action, "-TenantId", options.Tenant.ToString("D"),
            "-AcceptedDomain", options.Domain, "-ConnectorName", options.Name,
            "-ResultPath", reportPath
        })
            psi.ArgumentList.Add(arg);
        if (options.Ip.Length > 0)
        {
            psi.ArgumentList.Add("-PublicIpv4");
            psi.ArgumentList.Add(options.Ip);
        }
        else
        {
            psi.ArgumentList.Add("-CertificateName");
            psi.ArgumentList.Add(options.Certificate);
        }
        if (action == "Apply")
        {
            if (sha is null)
                throw new InvalidOperationException("A reviewed tenant Connector SHA-256 is required.");
            psi.ArgumentList.Add("-ExpectedSha256");
            psi.ArgumentList.Add(sha);
            psi.ArgumentList.Add("-TypedConfirmation");
            psi.ArgumentList.Add("CREATE_REVIEWED_M365_CONNECTOR");
        }
        try
        {
            using var process = Process.Start(psi) ??
                throw new InvalidOperationException("PowerShell 7 did not start.");
            await process.WaitForExitAsync();
            if (process.ExitCode != 0)
                throw new InvalidOperationException("Exchange Online Connector command failed. Review the PowerShell 7 console; no success claimed.");
            string status = await File.ReadAllTextAsync(reportPath);
            if (status.Length > 4096 || status.Contains('\0') || !status.Contains(
                "EXO_CONNECTOR_TENANT=exact_match", StringComparison.Ordinal))
                throw new InvalidDataException("Tenant Connector status is incomplete.");
            return status;
        }
        finally
        {
            if (File.Exists(reportPath))
                File.Delete(reportPath);
        }
    }

    private async Task PreviewTenantConnectorAsync()
    {
        var options = TenantConnectorOptions();
        string report = await RunTenantConnectorManagerAsync(options, "Preview");
        var sha = System.Text.RegularExpressions.Regex.Match(report,
            @"(?m)^EXO_CONNECTOR_REVIEW_SHA256=([a-f0-9]{64})\r?$");
        if (!sha.Success || !report.Contains("EXO_CONNECTOR_PLAN=ready", StringComparison.Ordinal) ||
            !report.Contains("CHANGES_APPLIED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Tenant Connector Preview did not return a verified read-only plan.");
        previewedTenantConnectorSha = sha.Groups[1].Value;
        previewedTenantConnectorContext = string.Join("|", options.Tenant, options.Domain,
            options.Name, options.Ip, options.Certificate);
        WriteLine("Read-only Exchange Online Connector creation preview completed. No tenant changes.");
        WriteLine(report);
        WriteLine("The preview does not prove ownership of the public egress IP/certificate, sender DNS or final recipient delivery.");
    }

    private async Task CreateTenantConnectorAsync()
    {
        var options = TenantConnectorOptions();
        string context = string.Join("|", options.Tenant, options.Domain,
            options.Name, options.Ip, options.Certificate);
        if (previewedTenantConnectorSha is null || previewedTenantConnectorContext != context)
            throw new InvalidOperationException("Run NEW tenant Connector Preview with exactly these inputs first.");
        if (!acceptedDomainApproved.Checked)
            throw new InvalidOperationException("Confirm the accepted domain in the intended tenant before creating a Connector.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Create Microsoft 365 Inbound Connector",
            "CLOUD TENANT CHANGE: Create a new ENABLED OnPremises Inbound Connector named " +
            options.Name + " in the explicitly selected Microsoft 365 tenant. The sending server MUST own " +
            (options.Ip.Length > 0 ? "the selected exclusive public IPv4." :
                "a CA-validated TLS client certificate whose DNS name matches the accepted domain.") +
            " A duplicate or changed tenant inventory is refused. The action does NOT alter existing " +
            "Connectors, DNS records, mailboxes, primary Postfix or Security Defaults. " +
            "It may grant Internet relay privileges to the specified sending source; review service and anti-abuse controls. " +
            "Actual recipient delivery, Exchange protection and emergency revoke still need separate tests.",
            "CREATE M365 CONNECTOR")) return;
        string sha = previewedTenantConnectorSha;
        previewedTenantConnectorSha = null;
        previewedTenantConnectorContext = null;
        string result = await RunTenantConnectorManagerAsync(options, "Apply", sha);
        if (!result.Contains("EXO_CONNECTOR_CREATED=yes", StringComparison.Ordinal) ||
            !result.Contains("CHANGES_APPLIED=tenant_new_connector_only", StringComparison.Ordinal))
            throw new InvalidOperationException("Tenant Connector creation could not be verified.");
        WriteLine(result);
        WriteLine("Microsoft 365 Inbound Connector created and observed in the selected tenant. " +
                  "Actual server identity, certificate, test message and recipient delivery remain unverified.");
        connectorApproved.Checked = false;
    }

    // An explicit FQDN is needed when Postfix is not the primary mail MTA.
    // Do not silently derive an identity from an SSH IP address.
    private (string Mta, string Hostname) ForeignMtaOptions()
    {
        if (inspectedMail?.Mta is "exim" or "sendmail")
        {
            if (inspectedServerIdentity != SecurityOptionsStore.Identity(Endpoint()))
                throw new InvalidOperationException("Reinspect the selected Exim/Sendmail server before using preservation mode.");
            string sidecarHostname = foreignSidecarHostname.Text.Trim().TrimEnd('.');
            if (inspectedHostIdentity != TryCurrentIdentity() ||
                inspectedHost?.HasFqdn != true ||
                string.Equals(sidecarHostname, inspectedHost.Fqdn, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "Review active Exim/Sendmail hostname and set a distinct sidecar FQDN before applying any changes.");
            return (inspectedMail.Mta, sidecarHostname);
        }
        return ("", "");
    }

    private async Task InspectOAuthSenderMapAsync()
    {
        EnsureRoutingLoaded();
        if (mailTransport.SelectedIndex != 0 || oauthSenderMode.SelectedIndex != 1)
            throw new InvalidOperationException(
                "Select the XOAUTH2 multi-mailbox PLAN before inspecting its sender map.");
        var endpoint = Endpoint();
        string auditedPath = oauthSenderMapPath.Text.Trim();
        string auditedEndpointIdentity = SecurityOptionsStore.Identity(endpoint);
        oauthSenderAuditSummary = "";
        var script = EmbeddedAssets.BuildOAuthSenderMapAuditBundle(auditedPath);
        var report = await SshRemote.RunRootScriptAsync(endpoint, script,
            TimeSpan.FromSeconds(90));
        report.EnsureSuccess();
        // Do not print arbitrary remote stdout; expose ONLY fixed, nonsecret
        // result keys and bounded numeric/hash values.
        var allowed = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["OAUTH_SENDER_MAP_RESULT"] = @"\Astructural_review_only\z",
            ["OAUTH_SENDER_MAP_MAP_SHA256"] = @"\A[a-f0-9]{64}\z",
            ["OAUTH_SENDER_MAP_ENTRIES"] = @"\A[1-9][0-9]{0,3}\z",
            ["OAUTH_SENDER_MAP_LOCAL_LOGINS"] = @"\A[1-9][0-9]{0,3}\z",
            ["OAUTH_SENDER_MAP_MAILBOXES"] = @"\A[1-9][0-9]{0,3}\z",
            ["OAUTH_SENDER_MAP_IDENTITIES"] = @"\A[1-9][0-9]{0,3}\z",
            ["OAUTH_SENDER_MAP_TENANTS"] = @"\A[1-9][0-9]{0,3}\z",
            ["OAUTH_SENDER_MAP_SENDAS_DIFFERENT_FROM"] = @"\A[0-9]{1,4}\z",
            ["OAUTH_SENDER_MAP_POLICY_SIMULATION"] = @"\Apassed_offline_only\z",
            ["OAUTH_SENDER_MAP_POLICY_SIMULATION_TEST_CASES"] = @"\A[1-9][0-9]{0,4}\z",
            ["OAUTH_SENDER_MAP_EXISTING_FROM_GUARD_CAPACITY_COMPATIBLE"] = @"\A(?:yes|no)\z",
            ["OAUTH_SENDER_MAP_LOCAL_SMTP_LOGIN_VERIFIED"] = @"\Ano\z",
            ["OAUTH_SENDER_MAP_ENVELOPE_AUTHORIZATION_ACTIVE"] = @"\Ano\z",
            ["OAUTH_SENDER_MAP_HEADER_FROM_GUARD_ACTIVE"] = @"\Ano\z",
            ["OAUTH_SENDER_MAP_EXCHANGE_SENDAS_VERIFIED"] = @"\Ano\z",
            ["OAUTH_SENDER_MAP_CERTIFICATE_AND_SIGNER_VERIFIED"] = @"\Ano\z",
            ["OAUTH_SENDER_MAP_POSTFIX_CHANGED"] = @"\Ano\z",
            ["OAUTH_SENDER_MAP_MESSAGES_SENT"] = @"\Ano\z"
        };
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in report.StdOut.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            int equal = line.IndexOf('=');
            if (equal <= 0) continue;
            string key = line[..equal];
            string value = line[(equal + 1)..];
            if (allowed.TryGetValue(key, out string? pattern))
            {
                if (!System.Text.RegularExpressions.Regex.IsMatch(value, pattern,
                    System.Text.RegularExpressions.RegexOptions.CultureInvariant) ||
                    !values.TryAdd(key, value))
                    throw new InvalidDataException("Malformed multi-mailbox audit report.");
            }
        }
        if (values.Count != allowed.Count)
            throw new InvalidDataException("Incomplete multi-mailbox audit report.");
        if (oauthSenderMapPath.Text.Trim() != auditedPath ||
            auditedEndpointIdentity != TryCurrentIdentity() ||
            mailTransport.SelectedIndex != 0 || oauthSenderMode.SelectedIndex != 1)
            throw new InvalidOperationException("The Linux endpoint, sender map, or delivery mode changed during audit. Run it again.");
        foreach (string key in allowed.Keys)
            WriteLine(key + "=" + values[key]);
        oauthSenderAuditSummary = T(
            "Проверка карты завершена: " + values["OAUTH_SENDER_MAP_ENTRIES"] + " отправителей; " +
                values["OAUTH_SENDER_MAP_POLICY_SIMULATION_TEST_CASES"] + " синтетических проверок. ТОЛЬКО ПРОВЕРКА ПЛАНА. SMTP AUTH, Exchange Send As и отправка НЕ подтверждены.",
            "Map reviewed: " + values["OAUTH_SENDER_MAP_ENTRIES"] + " senders; " +
                values["OAUTH_SENDER_MAP_POLICY_SIMULATION_TEST_CASES"] + " synthetic policy cases. PLAN ONLY. Live SMTP AUTH, Exchange Send As and mail delivery NOT verified.",
            "מיפוי נבדק; בדיקה בלבד. SMTP AUTH, Send As ושליחת דואר לא אומתו.");
        RenderPage();
        WriteLine("Offline policy simulation passed: login, envelope sender, configured mailbox and From matching / negative spoofing tests. It is NOT real SMTP AUTH, installed Milter, Exchange Send As or delivery. No route was enabled.");
        WriteLine("Structural map review passed; sender authentication, header From ownership, Entra Exchange permissions and SMTP delivery remain NOT VERIFIED. No route was enabled.");
    }

    private async Task InspectOAuthIdentitySigningAsync()
    {
        EnsureRoutingLoaded();
        if (mailTransport.SelectedIndex != 0 || oauthSenderMode.SelectedIndex != 1)
            throw new InvalidOperationException(
                "Select the planned XOAUTH2 multi-mailbox policy before verifying local signers.");
        var endpoint = Endpoint();
        string auditedPath = oauthSenderMapPath.Text.Trim();
        string currentIdentity = SecurityOptionsStore.Identity(endpoint);
        oauthSignerAuditSummary = "";
        var report = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildOAuthIdentitySigningAuditBundle(auditedPath),
            TimeSpan.FromMinutes(15));
        report.EnsureSuccess();
        var allowed = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["OAUTH_SIGNING_REVIEW"] = @"\Aread_only_offline_only\z",
            ["OAUTH_SIGNING_MAP_SHA256"] = @"\A[a-f0-9]{64}\z",
            ["OAUTH_SIGNING_IDENTITIES"] = @"\A[1-9][0-9]{0,2}\z",
            ["OAUTH_SIGNING_VERIFIED"] = @"\A[0-9]{1,2}\z",
            ["OAUTH_SIGNING_UNVERIFIED"] = @"\A[0-9]{1,2}\z",
            ["OAUTH_SIGNING_ALL_SIGNERS_VALID"] = @"\A(?:yes|no)\z",
            ["OAUTH_SIGNING_HARDWARE_PROVENANCE"] = @"\Anot_verified\z",
            ["OAUTH_SIGNING_EXCHANGE_SENDAS"] = @"\Anot_verified\z",
            ["OAUTH_SIGNING_POSTFIX_CHANGED"] = @"\Ano\z",
            ["OAUTH_SIGNING_ENROLLED_OR_ACTIVATED"] = @"\Ano\z",
            ["OAUTH_SIGNING_MAIL_SENT"] = @"\Ano\z"
        };
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in report.StdOut.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            int equal = line.IndexOf('=');
            if (equal <= 0) continue;
            string key = line[..equal];
            if (!allowed.TryGetValue(key, out string? pattern)) continue;
            string value = line[(equal + 1)..];
            if (!System.Text.RegularExpressions.Regex.IsMatch(value, pattern,
                    System.Text.RegularExpressions.RegexOptions.CultureInvariant) ||
                !values.TryAdd(key, value))
                throw new InvalidDataException("Invalid or duplicated offline OAuth signing evidence.");
        }
        if (values.Count != allowed.Count ||
            !int.TryParse(values["OAUTH_SIGNING_IDENTITIES"], out int total) ||
            !int.TryParse(values["OAUTH_SIGNING_VERIFIED"], out int valid) ||
            !int.TryParse(values["OAUTH_SIGNING_UNVERIFIED"], out int invalid) ||
            total is < 1 or > 64 || valid + invalid != total ||
            ((invalid == 0) != (values["OAUTH_SIGNING_ALL_SIGNERS_VALID"] == "yes")))
            throw new InvalidDataException("Incomplete or inconsistent offline OAuth signer evidence.");
        if (auditedPath != oauthSenderMapPath.Text.Trim() ||
            currentIdentity != TryCurrentIdentity() ||
            mailTransport.SelectedIndex != 0 || oauthSenderMode.SelectedIndex != 1)
            throw new InvalidOperationException("SSH endpoint or sender map changed during the offline check.");
        foreach (string key in allowed.Keys)
            WriteLine(key + "=" + values[key]);
        oauthSignerAuditSummary = T(
            $"Офлайн-подпись PS256: {valid} из {total}. Не проверено: {invalid}. Microsoft 365 Send As и доставка НЕ подтверждены.",
            $"Offline PS256 signer proof: {valid} of {total}. Unverified: {invalid}. Microsoft 365 Send As and delivery are NOT verified.",
            $"בדיקת חתימת PS256 לא מקוונת: {valid} מתוך {total}. לא אומתו: {invalid}. הרשאות Send As ושליחה לא אומתו.");
        RenderPage();
        WriteLine("Offline mailbox signing was reviewed as m365mailer. No Entra token, SMTP message, Postfix change or sender authorization was performed.");
    }

    private async Task InspectOAuthIngressAsync()
    {
        EnsureRoutingLoaded();
        if (mailTransport.SelectedIndex != 0 || oauthSenderMode.SelectedIndex != 1)
            throw new InvalidOperationException("Choose the planned multi-mailbox XOAUTH2 sender mode before inspection.");
        var endpoint = Endpoint();
        string auditedPath = oauthSenderMapPath.Text.Trim();
        string auditedIdentity = SecurityOptionsStore.Identity(endpoint);
        oauthIngressAuditSummary = "";        oauthSignerAuditSummary = "";

        var report = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildOAuthIngressAuditBundle(auditedPath), TimeSpan.FromSeconds(110));
        report.EnsureSuccess();
        // Untrusted Linux stdout must never reach user-visible logs unfiltered.
        var allowed = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["OAUTH_INGRESS_REVIEW"] = @"\Aread_only\z",
            ["OAUTH_INGRESS_MAP_SHA256"] = @"\A[a-f0-9]{64}\z",
            ["OAUTH_INGRESS_AUTH_ACCOUNTS"] = @"\A(?:unavailable_or_unsafe|exact_match|different|over_64_account_limit)\z",
            ["OAUTH_INGRESS_FROM_GUARD_POLICY"] = @"\A(?:unavailable_or_unsafe|exact_match|different|over_64_account_limit)\z",
            ["OAUTH_INGRESS_POSTFIX_OWNER_RULES"] = @"\A(?:unavailable_or_unsafe|exact_match|different|over_64_account_limit)\z",
            ["OAUTH_INGRESS_FROM_GUARD_SHA_PIN"] = @"\A(?:not_verified|configured_pinned_only)\z",
            ["OAUTH_INGRESS_SASL_TLS_CONFIG"] = @"\A(?:not_verified|configured_only)\z",
            ["OAUTH_INGRESS_SENDER_LOGIN_CONFIG"] = @"\A(?:not_verified|configured_only)\z",
            ["OAUTH_INGRESS_FROM_GUARD_MILTER_CONFIG"] = @"\A(?:not_verified|configured_fail_closed_only)\z",
            ["OAUTH_INGRESS_SERVICES"] = @"\A(?:not_all_active|all_report_active)\z",
            ["OAUTH_INGRESS_MILTER_SOCKET"] = @"\A(?:not_verified|metadata_matches_only)\z",
            ["OAUTH_INGRESS_MASTER_CF_SERVICE"] = @"\A(?:unavailable_or_unsafe|single_private_smtpd_no_overrides|unexpected_inet_service|per_service_overrides_present)\z",
            ["OAUTH_INGRESS_TRACE_HEADER_GUARD"] = @"\A(?:not_verified|exact_static_reject|different_rule|unavailable_or_unsafe|different_configuration)\z",
            ["OAUTH_INGRESS_TRANSPORT"] = @"\A(?:not_multi_mailbox_xoauth2|eop_smtp_not_xoauth2_multi)\z",
            ["OAUTH_INGRESS_OVERALL"] = @"\A(?:not_ready|ingress_config_consistent_not_live_verified)\z",
            ["OAUTH_INGRESS_REAL_SMTP_LOGIN_VERIFIED"] = @"\Ano\z",
            ["OAUTH_INGRESS_REAL_FROM_GUARD_MESSAGE_VERIFIED"] = @"\Ano\z",
            ["OAUTH_INGRESS_M365_SENDAS_VERIFIED"] = @"\Ano\z",
            ["OAUTH_INGRESS_MASTER_CF_OVERRIDES_VERIFIED"] = @"\Ano\z",
            ["OAUTH_INGRESS_MULTI_MAILBOX_ENABLED"] = @"\Ano\z",
            ["OAUTH_INGRESS_POSTFIX_CHANGED"] = @"\Ano\z",
            ["OAUTH_INGRESS_MESSAGES_SENT"] = @"\Ano\z"
        };
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in report.StdOut.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            int equal = line.IndexOf('=');
            if (equal <= 0) continue;
            string key = line[..equal];
            string value = line[(equal + 1)..];
            if (allowed.TryGetValue(key, out string? pattern))
            {
                if (!System.Text.RegularExpressions.Regex.IsMatch(value, pattern,
                        System.Text.RegularExpressions.RegexOptions.CultureInvariant) ||
                    !values.TryAdd(key, value))
                    throw new InvalidDataException("Invalid or duplicate SMTP ingress audit status.");
            }
        }
        if (values.Count != allowed.Count)
            throw new InvalidDataException("Incomplete read-only SMTP ingress audit report.");
        if (oauthSenderMapPath.Text.Trim() != auditedPath ||
            auditedIdentity != TryCurrentIdentity() ||
            mailTransport.SelectedIndex != 0 || oauthSenderMode.SelectedIndex != 1)
            throw new InvalidOperationException("SMTP host, sender policy or map changed while inspecting; rerun the audit.");
        foreach (string key in allowed.Keys)
            WriteLine(key + "=" + values[key]);
        bool consistent = values["OAUTH_INGRESS_OVERALL"] ==
            "ingress_config_consistent_not_live_verified";
        oauthIngressAuditSummary = consistent
            ? T("SMTP AUTH, Dovecot и From Guard структурно согласованы с картой. Это НЕ реальный SMTP-тест и НЕ готовый XOAUTH2: почтовый поток остаётся заблокированным.",
                "SMTP AUTH, Dovecot, From Guard and Postfix master.cf readback are structurally consistent. NOT a live SMTP test or multi-mailbox XOAUTH2 readiness; sending remains disabled.",
                "התצורה תואמת למפה בלבד. שליחת XOAUTH2 עדיין חסומה.")
            : T("Обнаружены отсутствующие или несовместимые настройки SMTP AUTH / From Guard. Проверьте диагностические статусы. Применение запрещено.",
                "SMTP AUTH, From Guard or Return-Path trace-header protection is missing or differs from the planned map. See sanitized status report. Deployment remains blocked.",
                "זוהתה תצורה לא תואמת. שליחה חסומה.");
        RenderPage();
        WriteLine("Ingress comparison is read-only: no real authenticated client, no Milter message inspection, no Exchange permissions, no SMTP delivery.");
    }


    private async Task<RemoteResult> CleanBootstrapScriptAsync(
        SshEndpoint endpoint, string action, int port, string? sha = null)
    {
        string script = EmbeddedAssets.BuildCleanPostfixBundle(port, action, sha);
        // Root SSH accounts need no sudo binary on a fresh minimal Linux.
        return endpoint.Username == "root"
            ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script,
                timeout: TimeSpan.FromMinutes(action == "apply" ? 17 : 2))
            : await SshRemote.RunRootScriptAsync(endpoint, script,
                TimeSpan.FromMinutes(action == "apply" ? 17 : 2));
    }

    private async Task PreviewCleanPostfixAsync()
    {
        EnsureRoutingLoaded();
        if (mailTransport.SelectedIndex is not (1 or 2))
            throw new InvalidOperationException("Clean Postfix package preparation is for Connector or Direct Send.");
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int port) || port is < 1024 or > 65535)
            throw new ArgumentException("Choose a private SMTP port 1024..65535.");
        var endpoint = Endpoint();
        if (inspectedMail?.Mta != "none" ||
            inspectedServerIdentity != SecurityOptionsStore.Identity(endpoint) ||
            existingSmtpAuditIdentity != SecurityOptionsStore.Identity(endpoint) ||
            existingSmtpAudit is null ||
            MailServerDiscoveryDecision.InstallationSafetyStatus(inspectedMail, existingSmtpAudit) != "ready")
            throw new InvalidOperationException(
                "Fresh clean-package preparation requires a prior verified read-only inspection " +
                "with no recognized MTA or unexplained SMTP listeners. Run Reinspect MTA first.");
        previewedCleanBootstrapSha = null;
        previewedCleanBootstrapIdentity = null;
        cleanBootstrapSummary = "";
        var report = await SshRemote.ExecuteAsync(endpoint, "bash -s",
            EmbeddedAssets.BuildCleanPostfixBundle(port, "check"),
            timeout: TimeSpan.FromSeconds(120));
        report.EnsureSuccess();
        var ready = System.Text.RegularExpressions.Regex.Match(report.StdOut,
            @"(?m)^CLEAN_POSTFIX_BOOTSTRAP_READY=(yes|no)\r?$");
        var sha = System.Text.RegularExpressions.Regex.Match(report.StdOut,
            @"(?m)^CLEAN_POSTFIX_PLAN_SHA256=([a-f0-9]{64})\r?$");
        var blockers = System.Text.RegularExpressions.Regex.Match(report.StdOut,
            @"(?m)^CLEAN_POSTFIX_BLOCKERS=([a-z0-9_,]{1,500})\r?$");
        if (!report.StdOut.Contains("CLEAN_POSTFIX_BOOTSTRAP_VERSION=1", StringComparison.Ordinal) ||
            !report.StdOut.Contains("CHANGES_APPLIED=no", StringComparison.Ordinal) ||
            !ready.Success || !blockers.Success)
            throw new InvalidDataException("Incomplete read-only clean Linux package preflight.");
        if (ready.Groups[1].Value != "yes")
        {
            cleanBootstrapSummary = T(
                "Установка пока запрещена. Причины: ", "Package preparation blocked. Reasons: ",
                "הכנת החבילות חסומה. סיבות: ") + blockers.Groups[1].Value;
            WriteLine("Clean Linux preflight blocked: " + blockers.Groups[1].Value +
                      ". No changes made.");
            return;
        }
        if (!sha.Success || blockers.Groups[1].Value != "none")
            throw new InvalidDataException("Clean-package preflight did not return a consistent SHA256.");
        previewedCleanBootstrapSha = sha.Groups[1].Value;
        previewedCleanBootstrapIdentity = SecurityOptionsStore.Identity(endpoint);
        previewedCleanBootstrapPort = port;
        cleanBootstrapSummary = T(
            "Чистый Linux подтверждён по проверке. Postfix ещё не установлен. Следующая кнопка установит пакет Postfix с отключённым основным сервисом; затем потребуется отдельно установить Relay.",
            "Clean host preflight passed. Next action installs Postfix packages with primary service disabled; the isolated SMTP Relay still requires separate installation.",
            "נמצא שרת נקי. התקנת החבילות מחייבת אישור; הממסר יותקן בנפרד.");
        WriteLine("Clean Postfix package plan checked (SHA256 " + sha.Groups[1].Value +
                  "). This is a preview only. No packages, services or ports changed.");
    }

    private async Task ApplyCleanPostfixAsync()
    {
        if (previewedCleanBootstrapSha is null)
            throw new InvalidOperationException("Run clean-host package Preview first.");
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int port) ||
            port != previewedCleanBootstrapPort ||
            previewedCleanBootstrapIdentity != TryCurrentIdentity() ||
            mailTransport.SelectedIndex is not (1 or 2))
            throw new InvalidOperationException(
                "Linux host, route or custom SMTP port changed after package Preview. Reinspect and preview again.");
        string expected = previewedCleanBootstrapSha;
        if (!ConfirmDestructive("LinuxMailRelay365 | Prepare CLEAN Linux Postfix packages",
            "PACKAGE INSTALLATION on a verified clean Linux server. Install the distro Postfix " +
            "package and its package dependencies. A temporary startup block is used and removed " +
            "afterward; the PRIMARY postfix.service will remain disabled. " +
            "No isolated SMTP listener, firewall change, DNS change, M365 Connector or message " +
            "will be created. Package-manager postinstall scripts may modify system files. " +
            "If installation fails, packages are NOT automatically purged; manual review or " +
            "recovery may be required. Proceed only if the target VM has a tested backup.",
            "INSTALL CLEAN POSTFIX")) return;
        previewedCleanBootstrapSha = null;
        previewedCleanBootstrapIdentity = null;
        var endpoint = Endpoint();
        var response = await CleanBootstrapScriptAsync(endpoint, "apply", port, expected);
        response.EnsureSuccess();
        if (!response.StdOut.Contains("CLEAN_POSTFIX_PACKAGES_PREPARED=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("PRIMARY_POSTFIX_SERVICE=disabled", StringComparison.Ordinal) ||
            !response.StdOut.Contains("ISOLATED_RELAY_INSTALLED=no", StringComparison.Ordinal))
            throw new InvalidDataException(
                "Postfix package installation outcome is uncertain. Inspect the host manually before continuing.");
        cleanBootstrapSummary = T(
            "Postfix-пакеты подготовлены, основной Postfix выключен. Выполните повторный анализ и затем отдельную установку Connector/Direct Send.",
            "Postfix packages are prepared; the primary service is disabled. Reinspect the MTA and install the isolated Connector/Direct Send separately.",
            "החבילות הותקנו. השירות הראשי כבוי; יש לבדוק שוב לפני התקנת הממסר.");
        WriteLine("Clean Linux Postfix package preparation succeeded; no isolated SMTP Relay was installed.");
        await InspectMailRoutingAsync();
    }

    private async Task PreviewFreshConnectorAsync()
    {
        var cfg = EopOptions();
        if (cfg.Mode != "connector" || cfg.SenderPolicy != "fixed-mailbox")
            throw new InvalidOperationException("Fresh private Connector requires a fixed sender; use EOP route Apply for advanced policies.");
        var trusted = smtpTrustedCidrs.Text.Split(',', StringSplitOptions.RemoveEmptyEntries |
            StringSplitOptions.TrimEntries);
        var foreign = ForeignMtaOptions();
        var report = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildFreshConnectorBundle(cfg.Port, cfg.Mx, cfg.Domain,
                cfg.Sender, smtpListenIp.Text.Trim(), trusted, cfg.PublicIp,
                cfg.Cert, cfg.Key, false, foreign.Mta, foreign.Hostname), TimeSpan.FromSeconds(65));
        report.EnsureSuccess();
        if (!report.StdOut.Contains("CONNECTOR_PREFLIGHT=inputs_valid_only", StringComparison.Ordinal))
            throw new InvalidOperationException("New Connector input preflight did not succeed.");
        WriteLine(report.StdOut);
        WriteLine("Inputs only: existing Microsoft 365 inbound Connector, fixed sender authorization, accepted domain and actual external recipients are NOT verified. No Linux changes.");
    }

    private async Task InstallFreshConnectorAsync()
    {
        var cfg = EopOptions();
        if (cfg.Mode != "connector" || cfg.SenderPolicy != "fixed-mailbox")
            throw new InvalidOperationException("Fresh Connector supports a fixed sender only; use EOP route manager for non-fixed senders.");
        if (!acceptedDomainApproved.Checked || !connectorApproved.Checked)
            throw new InvalidOperationException("Manually verify both the accepted domain and the existing Inbound Connector in the exact M365 tenant.");
        var endpoint = Endpoint();
        if (await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("Sidecar already installed. Do not overwrite; use its EOP routing manager.");
        var observation = await SshRemote.ProbeSecurityAsync(endpoint,
            EmbeddedAssets.SecurityProbe, CancellationToken.None);
        observation.EnsureSuccess();
        var inventory = MailRoutingInventory.Parse(observation.StdOut);
        if (inspectedMail is null || inspectedServerIdentity != SecurityOptionsStore.Identity(endpoint) ||
            inspectedMail != inventory)
            throw new InvalidOperationException("Reinspect existing Linux mail configuration before installing a new Connector.");
        if (inventory.Mta is not ("postfix" or "exim" or "sendmail") ||
            !preserveExistingMail.Checked || allowExisting.Checked)
            throw new InvalidOperationException("Fresh Connector requires Preserve Existing Mail and a known existing primary MTA.");
        await ConfirmCurrentActiveMtaForInstallationAsync(endpoint, inventory);
        var foreign = ForeignMtaOptions();
        if (inventory.Mta != "postfix" && foreign.Mta != inventory.Mta)
            throw new InvalidOperationException("The selected foreign MTA is not the inspected primary service.");
        var trusted = smtpTrustedCidrs.Text.Split(',', StringSplitOptions.RemoveEmptyEntries |
            StringSplitOptions.TrimEntries);
        var preview = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildFreshConnectorBundle(cfg.Port, cfg.Mx, cfg.Domain,
                cfg.Sender, smtpListenIp.Text.Trim(), trusted, cfg.PublicIp,
                cfg.Cert, cfg.Key, false, foreign.Mta, foreign.Hostname), TimeSpan.FromSeconds(70));
        preview.EnsureSuccess();
        if (!preview.StdOut.Contains("CONNECTOR_PREFLIGHT=inputs_valid_only", StringComparison.Ordinal))
            throw new InvalidOperationException("New Connector preflight did not succeed.");
        var tls = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildOutboundModePreflightBundle("connector", cfg.Port,
                cfg.Mx, cfg.Domain, cfg.PublicIp, cfg.Cert, true),
            TimeSpan.FromSeconds(90));
        tls.EnsureSuccess();
        if (!tls.StdOut.Contains("EOP_TLS_CONNECTIVITY=tls_12_plus_hostname_verified",
                StringComparison.Ordinal))
            throw new InvalidOperationException("Exchange Online EOP port 25 and certificate trust preflight failed.");
        if (!ConfirmDestructive("LinuxMailRelay365 | New isolated Microsoft 365 Connector",
            "Create only a private independent Postfix listener on custom TCP " + cfg.Port +
            " with a fixed sender under tenant-accepted domain " + cfg.Domain +
            ". Outbound to Microsoft 365 EOP will use TCP 25. The existing tenant Connector MUST " +
            "authorize the selected public egress IP or TLS certificate and must be verified independently. " +
            "EXTERNAL recipients can be accepted for relay. Unauthenticated incoming clients are restricted " +
            "to the specified trusted private networks; public inbound access is not enabled. " +
            "Existing primary " + inventory.Mta + " service, config, queue and port 25 must stay unchanged. " +
            (foreign.Mta.Length > 0 ? "This uses already-installed Postfix binaries and an explicit guard against foreign MTA changes; package installation is forbidden. " : "") +
            "This action does not create or change Entra/Exchange Connectors or DNS records.",
            foreign.Mta.Length == 0 ? "INSTALL PRIVATE CONNECTOR" :
                "PRESERVE EXISTING " + foreign.Mta.ToUpperInvariant() + " + INSTALL CONNECTOR")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildFreshConnectorBundle(cfg.Port, cfg.Mx, cfg.Domain,
                cfg.Sender, smtpListenIp.Text.Trim(), trusted, cfg.PublicIp,
                cfg.Cert, cfg.Key, true, foreign.Mta, foreign.Hostname), TimeSpan.FromMinutes(4));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("CONNECTOR_SIDECAR_INSTALLED=yes", StringComparison.Ordinal))
            throw new InvalidOperationException("New Connector sidecar installation was not confirmed.");
        WriteLine(result.StdOut);
        WriteLine("Installed isolated fixed-sender Connector SMTP gateway. Actual tenant authorization and external recipient delivery remain UNVERIFIED.");
        inspectedMail = null;
        inspectedServerIdentity = null;
        acceptedDomainApproved.Checked = false;
        connectorApproved.Checked = false;
    }

    private async Task PreviewFreshDirectSendAsync()
    {
        var cfg = EopOptions();
        if (cfg.Mode != "direct-send")
            throw new InvalidOperationException("Select Direct Send, not Connector.");
        var trusted = smtpTrustedCidrs.Text.Split(',', StringSplitOptions.RemoveEmptyEntries |
            StringSplitOptions.TrimEntries);
        var foreign = ForeignMtaOptions();
        var report = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildDirectSendSidecarBundle(cfg.Port, cfg.Mx, cfg.Domain,
                cfg.Sender, smtpListenIp.Text.Trim(), trusted, false, foreign.Mta, foreign.Hostname),
            TimeSpan.FromSeconds(55));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        WriteLine("Input validation only. No Entra app, no Connector, no Postfix changes. " +
                  "Accepted-domain ownership and recipient delivery are NOT verified.");
    }

    private async Task InstallFreshDirectSendAsync()
    {
        var cfg = EopOptions();
        if (cfg.Mode != "direct-send")
            throw new InvalidOperationException("Choose Direct Send in the outbound transport selector.");
        if (!acceptedDomainApproved.Checked)
            throw new InvalidOperationException("You must verify and approve the accepted domain in your Microsoft 365 tenant.");
        var endpoint = Endpoint();
        if (await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("An isolated SMTP sidecar already exists. Use the EOP route manager, never overwrite.");
        var observed = await SshRemote.ProbeSecurityAsync(endpoint,
            EmbeddedAssets.SecurityProbe, CancellationToken.None);
        observed.EnsureSuccess();
        var inventory = MailRoutingInventory.Parse(observed.StdOut);
        if (inspectedMail is null || inspectedServerIdentity != SecurityOptionsStore.Identity(endpoint) ||
            inspectedMail != inventory)
            throw new InvalidOperationException("Inspect the existing Linux mail configuration again before installation.");
        if (inventory.Mta is not ("postfix" or "exim" or "sendmail") ||
            !preserveExistingMail.Checked || allowExisting.Checked)
            throw new InvalidOperationException("Fresh Direct Send requires Preserve Existing Mail with a known primary MTA.");
        await ConfirmCurrentActiveMtaForInstallationAsync(endpoint, inventory);
        var foreign = ForeignMtaOptions();
        if (inventory.Mta != "postfix" && foreign.Mta != inventory.Mta)
            throw new InvalidOperationException("The existing Exim/Sendmail inventory has changed.");
        var trusted = smtpTrustedCidrs.Text.Split(',', StringSplitOptions.RemoveEmptyEntries |
            StringSplitOptions.TrimEntries);
        var preflight = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildDirectSendSidecarBundle(cfg.Port, cfg.Mx, cfg.Domain,
                cfg.Sender, smtpListenIp.Text.Trim(), trusted, false, foreign.Mta, foreign.Hostname),
            TimeSpan.FromSeconds(60));
        preflight.EnsureSuccess();
        if (!preflight.StdOut.Contains("DIRECT_SEND_PREFLIGHT=inputs_valid_only", StringComparison.Ordinal))
            throw new InvalidOperationException("Direct Send installer preflight failed. Nothing was changed.");
        var outbound = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildOutboundModePreflightBundle("direct-send", cfg.Port,
                cfg.Mx, cfg.Domain, "", "", true), TimeSpan.FromSeconds(85));
        outbound.EnsureSuccess();
        if (!outbound.StdOut.Contains("EOP_TLS_CONNECTIVITY=tls_12_plus_hostname_verified",
             StringComparison.Ordinal))
            throw new InvalidOperationException("EOP MX TLS / DNS check failed. No Direct Send installed.");
        if (!ConfirmDestructive("LinuxMailRelay365 | New private Direct Send gateway",
            "Create only an isolated Postfix listener on custom TCP " + cfg.Port + ". " +
            "Primary " + inventory.Mta + " service, queue, config and port 25 stay untouched. " +
            (foreign.Mta.Length > 0 ? "Postfix binaries MUST already exist; no package/service replacement is performed. " : "") +
            "Only the declared internal tenant domain " +
            "is eligible for RCPT TO, and the sender is rewritten to one declared address. " +
            "Public inbound SMTP uses a separate opt-in manager and is never opened by outbound routing. The Microsoft 365 domain must really be accepted in " +
            "the chosen tenant. Client devices must be changed only AFTER testing.",
            foreign.Mta.Length == 0 ? "INSTALL PRIVATE DIRECT SEND" :
                "PRESERVE EXISTING " + foreign.Mta.ToUpperInvariant() + " + INSTALL DIRECT SEND")) return;
        var applied = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildDirectSendSidecarBundle(cfg.Port, cfg.Mx, cfg.Domain,
                cfg.Sender, smtpListenIp.Text.Trim(), trusted, true, foreign.Mta, foreign.Hostname), TimeSpan.FromMinutes(4));
        applied.EnsureSuccess();
        if (!applied.StdOut.Contains("DIRECT_SEND_SIDECAR_INSTALLED=yes", StringComparison.Ordinal))
            throw new InvalidOperationException("Standalone Direct Send gateway did not confirm successful installation.");
        WriteLine(applied.StdOut);
        inspectedMail = null;
        inspectedServerIdentity = null;
        acceptedDomainApproved.Checked = false;
        WriteLine("New private Direct Send installed. This does NOT prove tenant mail delivery. " +
                  "Verify client RCPT restrictions, TLS trust and actual internal delivery before switching apps.");
    }

    private (int Port, string Mode, string Mx, string Sender, string Domain,
             string PublicIp, string Cert, string Key, string SenderPolicy, string SenderOwnerFile) EopOptions()
    {
        if (mailTransport.SelectedIndex is not (1 or 2))
            throw new InvalidOperationException("Select Direct Send or Microsoft 365 Connector.");
        if (MailDeliveryAdvisor.ConflictsWithRecipients(
            recipientScope.SelectedIndex == 2 ? "external-needed" : "unknown",
            mailTransport.SelectedIndex))
            throw new InvalidOperationException("Direct Send cannot deliver to external recipients. Choose Connector/XOAUTH2 or change the recipient requirement.");
        if (mailTransport.SelectedIndex == 2 && senderPolicy.SelectedIndex != 0)
            throw new NotSupportedException("Direct Send requires a fixed sender. Original sender preservation and masquerading require a verified M365 Connector.");
        if (!preserveExistingMail.Checked)
            throw new InvalidOperationException("Private EOP transport changes require Preserve Existing Mail.");
        if (publicInternetRequested.Checked)
            throw new InvalidOperationException("Public SMTP inbound requires a separate authenticated TLS workflow; outbound EOP setup never opens public SMTP.");
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int port) ||
            port is < 1024 or > 65535)
            throw new InvalidDataException("Select an inbound custom SMTP port 1024–65535.");
        return (port, mailTransport.SelectedIndex == 1 ? "connector" : "direct-send",
            outboundMxHost.Text.Trim(), outboundFixedSender.Text.Trim(),
            acceptedDomain.Text.Trim(), outboundPublicIp.Text.Trim(),
            outboundCertPath.Text.Trim(), outboundCertKeyPath.Text.Trim(),
            senderPolicy.SelectedIndex switch { 1 => "preserve-domain", 2 => "masquerade", _ => "fixed-mailbox" },
            senderPolicy.SelectedIndex == 0 ? "" : outboundSenderOwnerFile.Text.Trim());
    }

    private async Task<(SshEndpoint Endpoint, int Port)> EopInstalledEndpointAsync(int chosenPort)
    {
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("Install a private, isolated Postfix before changing its outbound route.");
        int installedPort = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
        if (installedPort != chosenPort)
            throw new InvalidDataException("Installed sidecar TCP " + installedPort +
                " differs from unsaved Wizard TCP " + chosenPort + ".");
        return (endpoint, installedPort);
    }

    private async Task PreviewFromOwnerGuardAsync()
    {
        var opt = EopOptions();
        if (opt.Mode != "connector" || opt.SenderPolicy == "fixed-mailbox")
            throw new InvalidOperationException(
                "Private From Guard is only for Connector preserve-domain or masquerade.");
        var (endpoint, port) = await EopInstalledEndpointAsync(opt.Port);
        var report = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildFromOwnerGuardBundle(port, opt.SenderOwnerFile),
            TimeSpan.FromMinutes(2));
        report.EnsureSuccess();
        if (!report.StdOut.Contains("FROM_GUARD_PREFLIGHT=ready", StringComparison.Ordinal) ||
            !report.StdOut.Contains("CHANGES_APPLIED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Independent From Guard did not pass read-only preflight.");
        WriteLine(report.StdOut);
        WriteLine("The guard is not connected to SMTP routing by Preview. " +
                  "The primary MTA, mail queues, messages and Microsoft 365 tenant are unchanged.");
    }

    private async Task EnableFromOwnerGuardAsync()
    {
        var opt = EopOptions();
        if (opt.Mode != "connector" || opt.SenderPolicy == "fixed-mailbox")
            throw new InvalidOperationException(
                "Private From Guard applies only to a multi-sender Connector.");
        var (endpoint, port) = await EopInstalledEndpointAsync(opt.Port);
        var preview = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildFromOwnerGuardBundle(port, opt.SenderOwnerFile),
            TimeSpan.FromMinutes(2));
        preview.EnsureSuccess();
        if (!preview.StdOut.Contains("FROM_GUARD_PREFLIGHT=ready", StringComparison.Ordinal))
            throw new InvalidDataException("From Guard preview failed before any changes.");
        var owner = System.Text.RegularExpressions.Regex.Match(preview.StdOut,
            @"(?m)^FROM_GUARD_OWNER_SHA256=([a-f0-9]{64})\r?$");
        var engine = System.Text.RegularExpressions.Regex.Match(preview.StdOut,
            @"(?m)^FROM_GUARD_ENGINE_SHA256=([a-f0-9]{64})\r?$");
        if (!owner.Success || !engine.Success)
            throw new InvalidDataException("Missing reviewed From Guard policy or binary SHA-256.");
        string warning = T(
            "Будет создан отдельный непривилегированный сервис Linux для проверки заголовка RFC5322 From и его сокет. Источник владельцев отправителей должен быть root 0600. Основной MTA, очередь и маршрут Connector пока НЕ меняются. Для включения фильтра в маршрут нужен отдельный Preview и Apply Connector. RHEL SELinux Enforcing не проверен и заблокирован.",
            "A separate unprivileged Linux service and socket will be installed to validate RFC5322 From against the approved root-only 0600 owner file. The primary MTA, queues and Connector route are NOT changed here. Connector Preview/Apply must be run separately to attach the filter. RHEL SELinux Enforcing is unverified and blocked.",
            "יותקן שירות עצמאי לבדיקת From. לא ישתנו שרת הדואר הראשי, התור או נתיב Connector.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Independent RFC5322 From Guard",
            warning, "ENABLE FROM GUARD")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildFromOwnerGuardBundle(port, opt.SenderOwnerFile,
                owner.Groups[1].Value, engine.Groups[1].Value),
            TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("FROM_GUARD_SERVICE=active", StringComparison.Ordinal) ||
            !result.StdOut.Contains("FROM_GUARD_POSTFIX_ROUTING_CHANGED=no",
                StringComparison.Ordinal))
            throw new InvalidDataException("From Guard staging did not confirm success.");
        WriteLine(result.StdOut);
        WriteLine("Guard staged. Next Preview/Apply the private Connector route separately. " +
                  "A live mail header/tenant delivery acceptance test is still required.");
    }

    private async Task PreviewEopRouteAsync()
    {
        var opt = EopOptions();
        var (endpoint, port) = await EopInstalledEndpointAsync(opt.Port);
        var report = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildEopRouteBundle(port, opt.Mode, opt.Mx,
                opt.Sender, opt.Domain, opt.PublicIp, opt.Cert, opt.Key,
                senderPolicy: opt.SenderPolicy, senderOwnerFile: opt.SenderOwnerFile),
            TimeSpan.FromSeconds(75));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        WriteLine("EOP route preview only. No tenant Connector, mailbox, primary Postfix or sender policy was changed. " +
                  "Direct Send allows only declared internal recipient domains; the tenant must be verified independently.");
    }

    private async Task ApplyEopRouteAsync()
    {
        var opt = EopOptions();
        if (!acceptedDomainApproved.Checked)
            throw new InvalidOperationException("Confirm the accepted domain in the intended Microsoft 365 tenant.");
        if (opt.Mode == "connector" && !connectorApproved.Checked)
            throw new InvalidOperationException("Verify the existing Inbound Connector in the intended tenant first.");
        var (endpoint, port) = await EopInstalledEndpointAsync(opt.Port);
        var preview = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildEopRouteBundle(port, opt.Mode, opt.Mx,
                opt.Sender, opt.Domain, opt.PublicIp, opt.Cert, opt.Key,
                senderPolicy: opt.SenderPolicy, senderOwnerFile: opt.SenderOwnerFile),
            TimeSpan.FromSeconds(75));
        preview.EnsureSuccess();
        var match = System.Text.RegularExpressions.Regex.Match(preview.StdOut,
            @"(?m)^EOP_ROUTE_MAIN_SHA256=([a-f0-9]{64})\r?$");
        if (!preview.StdOut.Contains("EOP_ROUTE_PREFLIGHT=ready", StringComparison.Ordinal) ||
            !match.Success)
            throw new InvalidOperationException("EOP route preflight not ready. No changes were made.");
        string? senderOwnerSha = null;
        if (opt.Mode == "connector" && opt.SenderPolicy != "fixed-mailbox")
        {
            var owner = System.Text.RegularExpressions.Regex.Match(preview.StdOut,
                @"(?m)^EOP_ROUTE_OWNER_FILE_SHA256=([a-f0-9]{64})\r?$");
            if (!owner.Success)
                throw new InvalidDataException("Sender ownership map was not verified at preview; no route changed.");
            senderOwnerSha = owner.Groups[1].Value;
        }
        // Verify real EOP MX TLS before any route is switched. The preflight
        // neither authenticates nor sends a message.
        var network = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildOutboundModePreflightBundle(
                opt.Mode, port, opt.Mx, opt.Domain, opt.PublicIp, opt.Cert, true),
            TimeSpan.FromSeconds(85));
        network.EnsureSuccess();
        if (!network.StdOut.Contains("EOP_TLS_CONNECTIVITY=tls_12_plus_hostname_verified",
            StringComparison.Ordinal))
            throw new InvalidOperationException(
                "External EOP MX port 25 STARTTLS, certificate trust or DNS verification failed. Route was not changed.");
        WriteLine("EOP MX STARTTLS and Linux CA trust passed; tenant Connector and real delivery are NOT verified.");
        string warning = opt.Mode == "direct-send"
            ? "Direct Send: ONLY the declared tenant-internal recipient domain is allowed at RCPT TO. External recipients are rejected locally."
            : "Connector: external recipients may be routed ONLY if your existing inbound Connector explicitly authorizes this server's public IP or certificate. Tenant-side identity cannot be verified by this Linux tool.";
        if (!ConfirmDestructive("LinuxMailRelay365 | Apply private EOP outbound route",
            warning + "\n\n" +
            "Linux inbound custom TCP " + port + " is preserved. Sender policy: " + opt.SenderPolicy +
            ". The Linux sender owner file limits envelope MAIL FROM to authenticated logins when preserving senders. " +
            "It does not prove RFC5322 From header ownership or Exchange Send As permission. " +
            "Only the isolated Postfix config and its dedicated queue are affected, and a root-only recovery archive is created. " +
            "Drain the isolated queue and pause submitting clients first. The route manager refuses a nonempty sidecar queue. The primary Postfix is unchanged.",
            "DEPLOY PRIVATE EOP ROUTE")) return;
        var applied = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildEopRouteBundle(port, opt.Mode, opt.Mx,
                opt.Sender, opt.Domain, opt.PublicIp, opt.Cert, opt.Key,
                expectedMainSha: match.Groups[1].Value, connectorApproved:
                    opt.Mode == "connector" && connectorApproved.Checked,
                senderPolicy: opt.SenderPolicy, senderOwnerFile: opt.SenderOwnerFile,
                expectedOwnerSha: senderOwnerSha),
            TimeSpan.FromMinutes(3));
        applied.EnsureSuccess();
        if (!applied.StdOut.Contains("EOP_ROUTE_APPLIED=yes", StringComparison.Ordinal))
            throw new InvalidOperationException("Private EOP transport change did not confirm success.");
        WriteLine(applied.StdOut);
        WriteLine("Local EOP route applied. Tenant delivery, accepted domains and client applications require independent tests.");
        acceptedDomainApproved.Checked = false;
        connectorApproved.Checked = false;
    }

    private async Task RestoreEopRouteAsync()
    {
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int selected) ||
            selected is < 1024 or > 65535)
            throw new InvalidDataException("Choose the installed private SMTP port.");
        var (endpoint, port) = await EopInstalledEndpointAsync(selected);
        var status = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildEopRouteBundle(port, "", "", "", "", "", "", "",
                status: true), TimeSpan.FromSeconds(60));
        status.EnsureSuccess();
        var match = System.Text.RegularExpressions.Regex.Match(status.StdOut,
            @"(?m)^EOP_ROUTE_CURRENT_MAIN_SHA256=([a-f0-9]{64})\r?$");
        if (!status.StdOut.Contains("EOP_ROUTE_STATUS=active", StringComparison.Ordinal) ||
            !match.Success)
            throw new InvalidOperationException("No verified active EOP route exists to restore.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Restore original private XOAUTH2 route",
            "Restore the original isolated Postfix XOAUTH2 outbound configuration on custom TCP " +
            port + ". The previously archived configuration must match exactly. " +
            "The primary Postfix and its mail queue will not be touched. " +
            "Pause applications and drain the isolated queue before restoring; queued messages block automatic route changes.",
            "RESTORE PRIVATE EOP ROUTE")) return;
        var restore = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildEopRouteBundle(port, "", "", "", "", "", "", "",
                expectedMainSha: match.Groups[1].Value, restore: true),
            TimeSpan.FromMinutes(3));
        restore.EnsureSuccess();
        if (!restore.StdOut.Contains("EOP_ROUTE_RESTORED=yes", StringComparison.Ordinal))
            throw new InvalidOperationException("EOP restore did not verify success; inspect root-only archive.");
        WriteLine(restore.StdOut);
        WriteLine("Original isolated XOAUTH2 transport restored, with root-only route recovery retained.");
    }

    private async Task InspectM365DnsAsync()
    {
        string domain = acceptedDomain.Text.Trim().ToLowerInvariant();
        if (domain.Length == 0 && mailbox.Text.Contains('@'))
            domain = mailbox.Text.Trim().Split('@').Last().ToLowerInvariant();
        if (domain.Length == 0)
            throw new InvalidDataException("Enter an accepted mail domain before requesting the DNS audit.");
        string mx = mailTransport.SelectedIndex is 1 or 2
            ? outboundMxHost.Text.Trim().ToLowerInvariant() : "";
        var report = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildM365DnsAuditBundle(domain, mx), TimeSpan.FromSeconds(90));
        report.EnsureSuccess();
        WriteLine("Read-only public DNS hints: no DNS modifications, raw TXT records, message addresses or secrets.");
        WriteLine(report.StdOut);
        WriteLine("Public DNS does not verify tenant accepted-domain ownership, Connector authorization, DKIM signing or final recipient delivery.");
    }

    private async Task CheckOutboundModeAsync()
    {
        if (mailTransport.SelectedIndex is not (1 or 2))
            throw new InvalidOperationException("Select Connector or Direct Send first.");
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int customPort) ||
            customPort is < 1024 or > 65535)
            throw new InvalidDataException("Choose private Linux SMTP port 1024-65535.");
        var report = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildOutboundModePreflightBundle(
                mailTransport.SelectedIndex == 1 ? "connector" : "direct-send",
                customPort, outboundMxHost.Text.Trim(), acceptedDomain.Text.Trim(),
                outboundPublicIp.Text.Trim(), outboundCertPath.Text.Trim(), true),
            TimeSpan.FromSeconds(85));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        WriteLine("Read-only plan. Private Linux custom TCP " + customPort +
                  " differs from Microsoft 365 outbound TCP 25. Tenant Connector and delivery remain unverified.");
    }

    private async Task InspectRelayHealthAsync()
    {
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int selectedPort) ||
            selectedPort is < 1024 or > 65535)
            throw new InvalidDataException("Custom SMTP port must be 1024-65535.");
        var endpoint = Endpoint();
        int installedPort = await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None)
            ? await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None)
            : selectedPort;
        var report = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildRelayHealthBundle(installedPort), TimeSpan.FromSeconds(70));
        report.EnsureSuccess();
        WriteLine("Read-only local SMTP operational health, custom TCP " + installedPort +
                  ". Queue addresses and SMTP credentials are never returned.");
        WriteLine(report.StdOut);
        if (report.StdOut.Contains("HEALTH_STATUS=attention", StringComparison.Ordinal))
            WriteLine("ATTENTION: review queue backlog, service status, free space and expiring certificates. " +
                      "This does not prove Microsoft 365 delivery.");
        if (report.StdOut.Contains("HEALTH_STATUS=local_preflight_only", StringComparison.Ordinal))
            WriteLine("Local readiness checks passed. Actual Microsoft 365 and recipient delivery remain unverified.");
    }

    private async Task InspectRhelSelinuxAsync()
    {
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int selectedPort) ||
            selectedPort is < 1024 or > 65535)
            throw new InvalidDataException("Custom SMTP port must be 1024-65535.");
        var endpoint = Endpoint();
        int actualPort = await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None)
            ? await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None)
            : selectedPort;
        if (actualPort != selectedPort)
            WriteLine("Auditing installed custom TCP " + actualPort + " rather than unsaved " + selectedPort + ".");
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildRhelSelinuxDoctorBundle(actualPort), TimeSpan.FromSeconds(75));
        result.EnsureSuccess();
        WriteLine(result.StdOut);
        WriteLine("SELinux labels and a known port type are only preflight hints. " +
                  "A real SELinux Enforcing acceptance test must confirm mail-queue and SASL socket access, " +
                  "audit AVC denials, power-cycle restart and Microsoft 365 delivery. " +
                  "This inspection never installs policies or changes SELinux.");
    }

    private async Task ProbeEnforcingSmtpAsync()
    {
        var endpoint = Endpoint();
        if (!await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None))
            throw new InvalidOperationException("Install and review the isolated SMTP sidecar before live RHEL Enforcing checks.");
        int port = await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None);
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int selected) || selected != port)
            throw new InvalidDataException("Selected SMTP port differs from installed custom TCP " + port + ".");
        string hostname = privateAuthDns.Text.Trim();
        if (string.IsNullOrEmpty(hostname))
            throw new InvalidDataException("Enter the private SMTP STARTTLS certificate DNS name first.");
        var report = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildRhelEnforcingLiveSmokeBundle(port, hostname,
                privateTlsCaPath.Text.Trim()), TimeSpan.FromSeconds(90));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        if (!report.StdOut.Contains("RHEL_ENFORCING_LIVE_SMTP=tls_auth_handshake_passed",
                                   StringComparison.Ordinal))
            throw new InvalidOperationException("RHEL Enforcing SMTP/TLS local handshake was not verified.");
        WriteLine("Only loopback STARTTLS certificate and AUTH advertisement were checked in SELinux Enforcing. " +
                  "No SMTP login, MAIL FROM, RCPT, DATA or mail delivery was attempted. " +
                  "Production still requires approved policy audit, AVC check, SASL login, queue I/O, OS reboot and M365 receipt.");
    }

    private int RhelCustomPort()
    {
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int port) ||
            port is < 1024 or > 65535)
            throw new InvalidDataException("Choose a custom SMTP port 1024-65535.");
        return port;
    }

    private async Task PrepareRhelSelinuxPortAsync()
    {
        int port = RhelCustomPort();
        var endpoint = Endpoint();
        var preview = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildRhelSelinuxPortBundle(port), TimeSpan.FromSeconds(90));
        preview.EnsureSuccess();
        WriteLine(preview.StdOut);
        if (preview.StdOut.Contains("RHEL_PORT_PREFLIGHT=already_allowed", StringComparison.Ordinal))
        {
            WriteLine("SELinux already maps this port to smtp_port_t. No changes made.");
            return;
        }
        var match = System.Text.RegularExpressions.Regex.Match(preview.StdOut,
            @"(?m)^RHEL_PORT_POLICY_SHA256=([a-f0-9]{64})\r?$");
        if (!preview.StdOut.Contains("RHEL_PORT_PREFLIGHT=ready", StringComparison.Ordinal) ||
            !match.Success)
            throw new InvalidOperationException("RHEL policy preflight did not authorize this change.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Review RHEL SELinux port label",
            "Add an SELinux smtp_port_t mapping for TCP " + port +
            " only after confirming it is unassigned. An explicit rollback record is created. " +
            "NO SELinux mode, booleans, Dovecot socket labels, Postfix service or firewall rules will be changed. " +
            "This is preparation only and does NOT prove an Enforcing mail relay works.",
            "ADD RHEL SMTP PORT LABEL")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildRhelSelinuxPortBundle(port, "apply", match.Groups[1].Value),
            TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("RHEL_PORT_APPLIED=smtp_port_t", StringComparison.Ordinal))
            throw new InvalidOperationException("SELinux custom port mapping was not confirmed.");
        WriteLine(result.StdOut);
        WriteLine("SELinux port label prepared. Run the separate SELinux Enforcing diagnostics and live acceptance before production.");
    }

    private async Task RestoreRhelSelinuxPortAsync()
    {
        int port = RhelCustomPort();
        var endpoint = Endpoint();
        var status = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildRhelSelinuxPortBundle(port, "status"), TimeSpan.FromSeconds(85));
        status.EnsureSuccess();
        var match = System.Text.RegularExpressions.Regex.Match(status.StdOut,
            @"(?m)^RHEL_PORT_CURRENT_POLICY_SHA256=([a-f0-9]{64})\r?$");
        if (!status.StdOut.Contains("RHEL_PORT_STATUS=active", StringComparison.Ordinal) ||
            !match.Success)
            throw new InvalidOperationException("There is no verified managed SELinux port mapping to remove.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Restore SELinux port mapping",
            "Remove only the LinuxMailRelay365-added smtp_port_t record for TCP " + port +
            " after the SMTP listener has stopped and its port is free. The operation refuses policy changes " +
            "after the baseline. Existing third-party SELinux labels are never removed.",
            "RESTORE RHEL SMTP PORT LABEL")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildRhelSelinuxPortBundle(port, "restore", match.Groups[1].Value),
            TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("RHEL_PORT_RESTORED=yes", StringComparison.Ordinal))
            throw new InvalidOperationException("SELinux policy restore was not confirmed.");
        WriteLine(result.StdOut);
    }

    private async Task InspectMtaCoexistenceAsync()
    {
        int port = RhelCustomPort();
        var report = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildMtaCoexistenceBundle(port), TimeSpan.FromSeconds(70));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        WriteLine("Read-only MTA coexistence inventory: no package replacement, service restart, MX changes, or configuration updates. " +
                  "Exim/Sendmail fixed-sender sidecars require already-installed Postfix binaries, an explicit FQDN, typed approval and a live root-only service/config fingerprint before and after startup. " +
                  "Multiple active MTAs, unknown unit state, SELinux Enforcing or package conflicts must block installation.");
    }

    private async Task InspectPlatformAsync()
    {
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int port) ||
            port is < 1024 or > 65535)
            throw new InvalidDataException("Custom SMTP port must be 1024-65535.");
        WriteLine("Read-only platform preflight for the selected TCP port " + port +
                  ": RHEL/Oracle/Rocky/Alma/CentOS Stream, Ubuntu/Debian, Dovecot, Postfix and SELinux.");
        var report = await SshRemote.ExecuteAsync(Endpoint(), "bash -s",
            EmbeddedAssets.BuildPlatformCompatBundle(port), timeout: TimeSpan.FromSeconds(60));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        if (report.StdOut.Contains("SELINUX_SMTP_PORT=conflict", StringComparison.Ordinal) ||
            report.StdOut.Contains("SELINUX_SMTP_PORT=unmapped", StringComparison.Ordinal))
            WriteLine("SELinux may block the selected custom SMTP port. Review its current label; do NOT relabel an existing service port automatically.");
        if (report.StdOut.Contains("PLATFORM_READINESS=unsupported_distro_manual_review", StringComparison.Ordinal))
            WriteLine("Unsupported Linux release for the current automated plan. No system changes made.");
        WriteLine("Platform inspection is informational only. Queue labels, OAuth delivery and firewall reachability remain unverified.");
    }

    private (int Port, string Listener, string Dns) PublicSmtpOptions()
    {
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int port) ||
            port is < 1024 or > 65535)
            throw new InvalidDataException("Choose the installed SMTP port 1024-65535.");
        string listen = smtpListenIp.Text.Trim();
        string dns = privateAuthDns.Text.Trim();
        if (string.IsNullOrEmpty(listen) || string.IsNullOrEmpty(dns))
            throw new InvalidDataException("Enter the private local listener IPv4 and exact SMTP TLS DNS name.");
        return (port, listen, dns);
    }

    private async Task PreviewPublicSmtpAsync()
    {
        var options = PublicSmtpOptions();
        var (endpoint, port) = await EopInstalledEndpointAsync(options.Port);
        var report = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildPublicSmtpBundle(port, options.Listener, options.Dns),
            TimeSpan.FromSeconds(110));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        WriteLine("Read-only public SMTP review: Dovecot AUTH, TLS 1.2+, system CA/DNS, local health timer, " +
                  "Fail2ban jails and single active firewall are checked. Jail effectiveness, real Internet NAT, " +
                  "hosted clients, Microsoft 365 delivery and abuse resistance STILL REQUIRE live independent tests.");
    }

    private async Task ApplyPublicSmtpAsync()
    {
        if (!publicInternetRequested.Checked)
            throw new InvalidOperationException("Select the optional public SMTP plan first.");
        if (!preserveExistingMail.Checked || mailTransport.SelectedIndex != 0 ||
            senderPolicy.SelectedIndex != 0)
            throw new InvalidOperationException("Public SMTP requires Preserve Existing Mail, fixed XOAUTH2 sender and a separate authenticated Postfix.");
        var options = PublicSmtpOptions();
        var (endpoint, port) = await EopInstalledEndpointAsync(options.Port);
        var check = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildPublicSmtpBundle(port, options.Listener, options.Dns),
            TimeSpan.FromSeconds(110));
        check.EnsureSuccess();
        var sha = System.Text.RegularExpressions.Regex.Match(check.StdOut,
            @"(?m)^PUBLIC_SMTP_CURRENT_MAIN_SHA256=([a-f0-9]{64})\r?$");
        if (!sha.Success || !check.StdOut.Contains(
                "PUBLIC_SMTP_PREFLIGHT=ready_with_operator_acceptance_required", StringComparison.Ordinal))
            throw new InvalidOperationException("Public SMTP prerequisites failed. Firewall was not opened.");
        WriteLine(check.StdOut);
        if (!ConfirmDestructive("LinuxMailRelay365 | PUBLIC INTERNET SMTP",
            "HIGH RISK: permits SMTP connections from ANY Internet IPv4 source to local " +
            options.Listener + " TCP " + port + ", potentially through existing NAT. This is NOT port 25 and " +
            "does NOT enable anonymous relaying. YOU MUST have actually tested: 1) certificate trust and SNI, " +
            "2) required STARTTLS and account authentication, 3) external unauthorized RCPT refusal, " +
            "4) Fail2ban postfix/dovecot bans against this dedicated instance, 5) monitoring and abuse alerts, " +
            "6) host firewall/NAT exposure, and 7) tenant-approved sender/mailbox.\n\n" +
            "Do not proceed on production without a test VM and reviewed rollback. The existing primary Postfix " +
            "is not changed; a root-only SHA-checked backup is created. The separate firewall change is logged. " +
            "Postfix and firewall rollback is attempted if deployment fails.",
            "ENABLE PUBLIC AUTH SMTP")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildPublicSmtpBundle(port, options.Listener, options.Dns,
                "apply", sha.Groups[1].Value, approved: true), TimeSpan.FromMinutes(4));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("PUBLIC_SMTP_APPLIED=authenticated_starttls_only", StringComparison.Ordinal))
            throw new InvalidOperationException("Public SMTP activation was not verified; inspect firewall and recovery.");
        WriteLine(result.StdOut);
        WriteLine("Only local Postfix and firewall activation was verified. NAT reachability, a real Fail2ban ban drill and Microsoft 365 delivery are NOT verified by this operation.");
    }

    private async Task RestorePublicSmtpAsync()
    {
        var options = PublicSmtpOptions();
        var (endpoint, port) = await EopInstalledEndpointAsync(options.Port);
        var status = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildPublicSmtpBundle(port, options.Listener, options.Dns, "status"),
            TimeSpan.FromSeconds(85));
        status.EnsureSuccess();
        var sha = System.Text.RegularExpressions.Regex.Match(status.StdOut,
            @"(?m)^PUBLIC_SMTP_CURRENT_MAIN_SHA256=([a-f0-9]{64})\r?$");
        if (!sha.Success || !(status.StdOut.Contains("PUBLIC_SMTP_STATUS=active", StringComparison.Ordinal) ||
                              status.StdOut.Contains("PUBLIC_SMTP_STATUS=incomplete", StringComparison.Ordinal)))
            throw new InvalidOperationException("No verified public SMTP configuration or interrupted activation exists to restore.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Close public SMTP",
            "Close the ALL-SOURCES firewall rule for local " + options.Listener + " TCP " + port +
            " and restore the original isolated Postfix client restrictions. Applications submitting from " +
            "the Internet will lose access. The primary Postfix, custom port and independent backup archive remain intact.",
            "CLOSE PUBLIC SMTP")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildPublicSmtpBundle(port, options.Listener, options.Dns,
                "restore", sha.Groups[1].Value), TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("PUBLIC_SMTP_RESTORED=private_client_restrictions", StringComparison.Ordinal))
            throw new InvalidOperationException("Public firewall/config restore not fully verified. Inspect active firewall rules manually.");
        WriteLine(result.StdOut);
        WriteLine("Public firewall rule closed and isolated Postfix private client restrictions restored.");
    }

    private async Task CheckNetworkFirewallAsync()
    {
        var args = NetworkFirewallArguments("--check", includePublic: true);
        WriteLine("Read-only Linux network and firewall checks: Entra HTTPS 443, Exchange SMTP 587, selected SMTP listener and active firewall.");
        var report = await SshRemote.ExecuteAsync(Endpoint(), "bash -s",
            EmbeddedAssets.BuildNetworkFirewallBundle(args), timeout: TimeSpan.FromSeconds(55));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        if (publicInternetRequested.Checked)
            WriteLine("SECURITY: Public Internet SMTP planning is NOT an activation. Use Advanced SMTP > Preview / Apply / Restore only after AUTH/TLS, monitoring and Fail2ban acceptance.");
        WriteLine("Local checks cannot prove reachability from another network or guarantee mail delivery.");
    }

    private async Task OpenTrustedFirewallAsync()
    {
        if (publicInternetRequested.Checked)
            throw new NotSupportedException("Public SMTP requested: no firewall changes allowed. Uncheck the public option; authenticated TLS public submission is not yet supported.");
        var args = NetworkFirewallArguments("--apply", includePublic: false);
        if (routingPlan.ListenIpv4.Length == 0 || routingPlan.TrustedCidrs.Length == 0)
            throw new InvalidOperationException("A specific local private IPv4 and trusted client CIDRs are required; never open a wildcard SMTP rule.");
        // Display the exact scope before changing an already-active UFW/firewalld.
        string preview = "TCP " + routingPlan.SidecarPort + " -> " + routingPlan.ListenIpv4 +
            " from [" + routingPlan.TrustedCidrs + "]";
        if (!ConfirmDestructive("LinuxMailRelay365 | Trusted SMTP firewall",
            T("Открыть доступ ТОЛЬКО из доверенных подсетей: ",
              "Allow ONLY the following trusted SMTP network sources: ",
              "פתיחה לרשתות מהימנות בלבד: ") + preview +
            "\nExisting UFW/firewalld must be active. The app will NOT enable a disabled firewall. No internet-wide port opening.",
            "OPEN TRUSTED SMTP")) return;
        args = [.. args, "--confirm", "OPEN_TRUSTED_SMTP_PORT"];
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildNetworkFirewallBundle(args), TimeSpan.FromSeconds(90));
        result.EnsureSuccess();
        WriteLine(result.StdOut);
        WriteLine("Firewall rules applied for explicitly trusted source networks. Check reachability from an actual client.");
    }

    private async Task InspectExistingPublicSmtpAsync()
    {
        var endpoint = Endpoint();
        WriteLine("Read-only public SMTP audit: active listener bindings, Postfix relay restrictions, SASL and TLS. No external mail or messages sent.");
        var report = await SshRemote.ExecuteAsync(endpoint, "bash -s",
            EmbeddedAssets.BuildExistingSmtpAuditBundle(),
            timeout: TimeSpan.FromSeconds(120));
        report.EnsureSuccess();
        existingSmtpAudit = ExistingSmtpAudit.Parse(report.StdOut);
        existingSmtpAuditIdentity = SecurityOptionsStore.Identity(endpoint);
        WriteLine(existingSmtpAudit.Summary(language.SelectedIndex));
        if (existingSmtpAudit.SuspectedUnsafeRelay)
            WriteLine("WARNING: configuration suggests unsafe relay rules. This is not a proven open relay. Review immediately; avoid Force Replace until existing mail flow is understood.");
        else if (existingSmtpAudit.PotentiallyPublic)
            WriteLine("Potentially public SMTP bind detected; this is not proof of Internet access or an open relay.");
    }

    private async Task InspectMailRoutingAsync()
    {
        EnsureRoutingLoaded();
        var endpoint = Endpoint();
        // A failed or partial read must never leave stale successful evidence.
        inspectedMail = null;
        inspectedServerIdentity = null;
        existingSmtpAudit = null;
        existingSmtpAuditIdentity = null;
        discoveredIsolatedRelay = null;
        discoveredMailIdentity = null;
        inspectedHost = null;
        inspectedHostIdentity = null;
        var report = await SshRemote.ProbeSecurityAsync(
            endpoint, EmbeddedAssets.SecurityProbe, CancellationToken.None);
        report.EnsureSuccess();
        var inventory = MailRoutingInventory.Parse(report.StdOut);
        inspectedMail = inventory;
        inspectedServerIdentity = SecurityOptionsStore.Identity(endpoint);
        allowExisting.Checked = false;
        WriteLine("Existing MTA: " + inventory.Mta + "; relayhost: " + inventory.CurrentRelay +
                  "; transport: " + inventory.CurrentTransport);
        WriteLine("Postfix configuration fingerprint: " + inventory.ConfigSha256);
        if (inventory.Mta != "none")
            WriteLine("Existing mail flows detected. Preserve mode will NOT change them.");
        UpdatePreserveFlowPreview();
        try
        {
            await InspectExistingPublicSmtpAsync();
        }
        catch (Exception error)
        {
            // Never report "safe" when Python, a service probe, or access rights
            // are unavailable. Preserve the earlier valid MTA inventory.
            existingSmtpAudit = null;
            existingSmtpAuditIdentity = null;
            WriteLine("Public SMTP audit could not complete; status UNKNOWN and requires manual review. " + error.GetType().Name);
        }
        try
        {
            discoveredIsolatedRelay = await SshRemote.HasIsolatedSidecarAsync(
                endpoint, CancellationToken.None);
        }
        catch (Exception error)
        {
            discoveredIsolatedRelay = null;
            WriteLine("Isolated Relay presence unverified (" + error.GetType().Name +
                      "); do not assume absence.");
        }
        try
        {
            var detected = await SshRemote.ExecuteAsync(endpoint, "bash -s",
                EmbeddedAssets.BuildMailHostInspectionBundle(
                    int.TryParse(isolatedSmtpPort.Text.Trim(), out int checkPort) &&
                        checkPort is >= 1024 and <= 65535 ? checkPort : 2525,
                    inventory.Mta), timeout: TimeSpan.FromSeconds(90));
            detected.EnsureSuccess();
            inspectedHost = MailHostInspection.Parse(detected.StdOut);
            inspectedHostIdentity = SecurityOptionsStore.Identity(endpoint);
            WriteLine("Read-only Linux hostname and Postfix/Exim/Sendmail settings inspected. " +
                "Use the wizard buttons to fill fields explicitly; M365 domain ownership is unverified.");
        }
        catch (Exception ex)
        {
            inspectedHost = null;
            inspectedHostIdentity = null;
            WriteLine("Linux hostname/MTA settings could not be read (" +
                ex.GetType().Name + "); no fields were filled automatically.");
        }
        discoveredMailIdentity = SecurityOptionsStore.Identity(endpoint);
        var recommendation = MailServerDiscoveryDecision.Assess(
            inspectedMail, existingSmtpAudit, discoveredIsolatedRelay);
        WriteLine("Read-only MTA discovery: " + recommendation.Code +
                  "; no Microsoft 365 delivery mode selected automatically; no changes made.");
    }


    private string? TryCurrentIdentity()
    {
        try { return SecurityOptionsStore.Identity(Endpoint()); }
        catch (Exception ex) when (ex is ArgumentException or FileNotFoundException) { return null; }
    }

    private bool ConfirmDestructive(string dialogTitle, string explanation, string phrase)
    {
        var workArea = Screen.FromControl(this).WorkingArea.Size;
        using var dialog = new Form
        {
            Text = dialogTitle, StartPosition = FormStartPosition.CenterParent,
            ClientSize = PreferredDialogSize(workArea, DeviceDpi, 880, 580),
            MinimumSize = PreferredDialogSize(workArea, DeviceDpi, 630, 450),
            BackColor = UiTheme.Canvas, ForeColor = UiTheme.Navy,
            Font = new Font("Segoe UI", 10f),
            AutoScaleMode = AutoScaleMode.Dpi, FormBorderStyle = FormBorderStyle.Sizable,
            MaximizeBox = true, MinimizeBox = false
        };
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2,
            Padding = new Padding(14, 12, 14, 12)
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true,
            BackColor = UiTheme.Canvas };
        var body = new TableLayoutPanel
        {
            Dock = DockStyle.Top, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 1, RowCount = 0,
            Padding = new Padding(10, 8, 10, 12)
        };
        body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var warning = UiTheme.Text(explanation);
        warning.MaximumSize = new Size(Math.Max(250, dialog.ClientSize.Width - 80), 0);
        warning.ForeColor = Color.FromArgb(156, 38, 42);
        AddLine(body, warning);
        var prompt = UiTheme.Text(
            T("Для подтверждения введите: ", "Type to confirm: ", "הקלד לאישור: ") + phrase);
        AddLine(body, prompt);
        var input = Field("");
        input.Width = Math.Max(200, dialog.ClientSize.Width - 80);
        input.AccessibleName = "Explicit destructive operation confirmation";
        AddLine(body, input);
        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = true,
            FlowDirection = FlowDirection.RightToLeft,
            Padding = new Padding(4, 6, 4, 4)
        };
        var approve = UiTheme.Action(
            T("Подтвердить действие", "Confirm operation", "אישור"), true, "check");
        approve.Enabled = false;
        approve.BackColor = Color.FromArgb(160, 42, 47);
        approve.ForeColor = Color.White;
        input.TextChanged += (_, _) =>
            approve.Enabled = string.Equals(input.Text.Trim(), phrase, StringComparison.Ordinal);
        approve.Click += (_, _) => { dialog.DialogResult = DialogResult.OK; dialog.Close(); };
        var cancel = UiTheme.Action(T("Отмена", "Cancel", "ביטול"), false, "back");
        cancel.Click += (_, _) => { dialog.DialogResult = DialogResult.Cancel; dialog.Close(); };
        actions.Controls.Add(approve);
        actions.Controls.Add(cancel);
        scroll.Controls.Add(body);
        root.Controls.Add(scroll, 0, 0);
        root.Controls.Add(actions, 0, 1);
        dialog.Controls.Add(root);
        void Fit()
        {
            int width = Math.Max(255, scroll.ClientSize.Width - 6);
            body.Width = width;
            warning.MaximumSize = new Size(Math.Max(240, width - 24), 0);
            prompt.MaximumSize = new Size(Math.Max(240, width - 24), 0);
            input.Width = Math.Max(200, width - body.Padding.Horizontal - 12);
        }
        dialog.ClientSizeChanged += (_, _) => Fit();
        dialog.Shown += (_, _) => { Fit(); input.Focus(); };
        dialog.AcceptButton = approve;
        dialog.CancelButton = cancel;
        return dialog.ShowDialog(this) == DialogResult.OK;
    }

    private async Task BackupSidecarConfigAsync()
    {
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildSidecarConfigRecoveryBundle("--backup"),
            TimeSpan.FromMinutes(5));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("SIDECAR_BACKUP_STATUS=verified_config_only_no_queue",
                StringComparison.Ordinal))
            throw new InvalidDataException("Independent Relay backup was not verified.");
        reviewedSidecarRestoreSha = null;
        reviewedSidecarRestoreId = null;
        WriteLine(result.StdOut);
        WriteLine("Archive remains root-only on the Linux host. It contains local secrets; NEVER attach it to reports.");
    }

    private async Task ListSidecarConfigBackupsAsync()
    {
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildSidecarConfigRecoveryBundle("--list"),
            TimeSpan.FromMinutes(5));
        result.EnsureSuccess();
        sidecarBackupSelector.Items.Clear();
        foreach (string line in result.StdOut.Split('\n'))
        {
            var match = System.Text.RegularExpressions.Regex.Match(line.Trim(),
                @"\ASIDECAR_BACKUP_ID=([0-9]{8}T[0-9]{6}Z-[a-f0-9]{12})\z");
            if (match.Success)
                sidecarBackupSelector.Items.Add(match.Groups[1].Value);
        }
        sidecarBackupSelector.SelectedIndex = -1;
        reviewedSidecarRestoreSha = null;
        reviewedSidecarRestoreId = null;
        WriteLine("Verified independent Relay configuration archives: " +
                  sidecarBackupSelector.Items.Count + ". Queue and external dependencies are excluded.");
        RenderPage();
    }

    private async Task PreviewSidecarConfigRestoreAsync()
    {
        if (sidecarBackupSelector.SelectedItem is not string backupId)
            throw new InvalidOperationException("List and select a verified isolated Relay backup first.");
        var endpoint = Endpoint();
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildSidecarConfigRecoveryBundle("--preview-restore", backupId),
            TimeSpan.FromMinutes(5));
        result.EnsureSuccess();
        var sha = System.Text.RegularExpressions.Regex.Match(result.StdOut,
            @"(?m)^SIDECAR_CURRENT_SHA256=([a-f0-9]{64})\r?$");
        if (!sha.Success ||
            !result.StdOut.Contains("SIDECAR_RESTORE_PREVIEW=", StringComparison.Ordinal) ||
            !result.StdOut.Contains("CHANGES_APPLIED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Isolated Restore Preview did not provide a verified current SHA-256.");
        reviewedSidecarRestoreSha = sha.Groups[1].Value;
        reviewedSidecarRestoreId = backupId;
        reviewedSidecarRestoreIdentity = SecurityOptionsStore.Identity(endpoint);
        WriteLine(result.StdOut);
        WriteLine("The preview DOES NOT stop the Relay or prove an empty queue. Before restoring, stop ONLY " +
            "linuxmailrelay365-sidecar.service, linuxmailrelay365-smtp-auth.service, " +
            "linuxmailrelay365-health.service and linuxmailrelay365-health.timer, " +
            "then ensure the independent queue is EMPTY. The restore tool never changes primary MTA services.");
    }

    private async Task RestoreSidecarConfigAsync()
    {
        if (sidecarBackupSelector.SelectedItem is not string backupId ||
            reviewedSidecarRestoreId != backupId ||
            reviewedSidecarRestoreSha is null ||
            reviewedSidecarRestoreIdentity != SecurityOptionsStore.Identity(Endpoint()))
            throw new InvalidOperationException("Run an isolated Relay Restore Preview for this exact server and backup first.");
        if (!ConfirmDestructive("LinuxMailRelay365 | OFFLINE isolated SMTP Relay restore",
            T("Опасное действие: восстановить отдельную конфигурацию Relay из архива " + backupId +
              ". Все службы Relay и мониторинга должны быть ОСТАНОВЛЕНЫ, очередь должна быть ПУСТОЙ. " +
              "Письма из очереди, внешние сертификаты, пакеты и Microsoft 365 НЕ восстанавливаются. " +
              "Создаётся аварийная копия. Службы после Restore НЕ запускаются автоматически. Основной MTA не изменяется.",
              "Restore ONLY the independent SMTP Relay configuration from " + backupId +
              ". Isolated SMTP/Auth/monitoring units MUST be stopped, queue EMPTY. " +
              "External TLS keys, queued mail, packages and Microsoft 365 are NOT restored. " +
              "An emergency snapshot is created. No services restart automatically. The primary MTA is untouched.",
              "שחזור תצורת הממסר המבודד בלבד כשהשירותים עצורים והתור ריק."),
            "RESTORE ISOLATED RELAY")) return;
        string expected = reviewedSidecarRestoreSha;
        reviewedSidecarRestoreSha = null;
        reviewedSidecarRestoreId = null;
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildSidecarConfigRecoveryBundle("--restore", backupId, expected),
            TimeSpan.FromMinutes(8));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("SIDECAR_RESTORED_BACKUP_ID=" + backupId, StringComparison.Ordinal) ||
            !result.StdOut.Contains("SIDECAR_SERVICES_STARTED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Independent Relay configuration restoration was not confirmed.");
        WriteLine(result.StdOut);
        inspectedMail = null;
        inspectedServerIdentity = null;
        sidecarBackupSelector.Items.Clear();
        WriteLine("Restored files ONLY. Recheck certificates, DNS, M365 delivery and Relay configuration BEFORE manually starting isolated services.");
    }

    private void RequirePostfixBackup()
    {
        if (inspectedServerIdentity != TryCurrentIdentity() || inspectedMail?.Mta != "postfix")
            throw new InvalidOperationException(
                "Reinspect the active Postfix before using Postfix backup or Restore. This archive does not cover Exim/Sendmail.");
    }

    private string ConfirmedForeignBackupMta(bool allowStopped = false)
    {
        string? current = TryCurrentIdentity();
        if (current is null || inspectedServerIdentity != current ||
            inspectedHostIdentity != current || inspectedHost is null ||
            (inspectedHost.MtaState != "active" &&
             !(allowStopped && inspectedHost.MtaState == "installed_inactive")) ||
            inspectedMail?.Mta is not ("exim" or "sendmail") ||
            inspectedHost.Mta != inspectedMail.Mta)
            throw new InvalidOperationException(
                allowStopped
                    ? "Reinspect the exact installed Exim/Sendmail and hostname before archive verification or read-only preflight."
                    : "Reinspect active Exim/Sendmail and hostname before creating a primary MTA backup.");
        return inspectedMail.Mta;
    }

    private static bool ForeignBackupReportOk(string output, string mta, string status)
    {
        if (output.Length > 8192 || output.Contains('\0')) return false;
        string normalized = output.Replace("\r\n", "\n");
        return normalized.Contains("FOREIGN_BACKUP_STATUS=" + status + "\n",
                StringComparison.Ordinal) &&
            normalized.Contains("FOREIGN_BACKUP_MTA=" + mta + "\n",
                StringComparison.Ordinal) &&
            normalized.Contains("FOREIGN_BACKUP_PRIMARY_CONFIG_CHANGED=no\n",
                StringComparison.Ordinal) &&
            normalized.Contains("FOREIGN_BACKUP_MAIL_QUEUE_CHANGED=no\n",
                StringComparison.Ordinal) &&
            normalized.Contains("FOREIGN_BACKUP_SERVICE_CHANGED=no\n",
                StringComparison.Ordinal) &&
            normalized.Contains("FOREIGN_BACKUP_RESTORE_ENABLED=no\n",
                StringComparison.Ordinal);
    }

    private static string ParseForeignBackupFormat(string output, string mta)
    {
        var matches = System.Text.RegularExpressions.Regex.Matches(output,
            @"(?m)^FOREIGN_BACKUP_FORMAT=(v1_regular_files|v2_package_metadata)\r?$");
        if (matches.Count != 1)
            throw new InvalidDataException("Missing or duplicate verified MTA snapshot format.");
        string format = matches[0].Groups[1].Value;
        if (format == "v2_package_metadata" && mta != "sendmail")
            throw new InvalidDataException("Unexpected package metadata archive for this MTA.");
        return format;
    }

    private async Task CheckForeignMtaNativeSyntaxAsync()
    {
        var endpoint = Endpoint();
        string mta = ConfirmedForeignBackupMta(allowStopped: true);
        string identity = SecurityOptionsStore.Identity(endpoint);
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildForeignMtaNativeCheckBundle(mta),
            TimeSpan.FromSeconds(90));
        response.EnsureSuccess();
        string normalized = response.StdOut.Replace("\r\n", "\n");
        string[] required = {
            "FOREIGN_STATIC_VERSION=1\n",
            "FOREIGN_STATIC_MTA=" + mta + "\n",
            "FOREIGN_STATIC_CHECK=passed_partial_parse_only\n",
            "FOREIGN_STATIC_CONFIG_CHANGED=no\n",
            "FOREIGN_STATIC_QUEUE_CHANGED=no\n",
            "FOREIGN_STATIC_SERVICE_CHANGED=no\n",
            "FOREIGN_STATIC_DELIVERY_VERIFIED=no\n"
        };
        if (normalized.Length > 2048 || normalized.Contains('\0') ||
            required.Any(x => normalized.Split(x).Length != 2) ||
            identity != TryCurrentIdentity() ||
            mta != ConfirmedForeignBackupMta(allowStopped: true))
            throw new InvalidDataException(
                "Native MTA static validation report is incomplete or SSH identity changed.");
        WriteLine("Read-only " + mta +
            " native syntax check passed. No services, queues or configuration changed. " +
            "This is NOT evidence of SMTP AUTH, TLS, live mail delivery or backup recoverability.");
    }

    private async Task BackupForeignMtaAsync()
    {
        var endpoint = Endpoint();
        string mta = ConfirmedForeignBackupMta();
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildForeignMtaBackupBundle(mta, "backup"),
            TimeSpan.FromMinutes(4));
        response.EnsureSuccess();
        if (!ForeignBackupReportOk(response.StdOut, mta, "verified"))
            throw new InvalidDataException("Existing MTA configuration backup was not verified.");
        var id = System.Text.RegularExpressions.Regex.Match(response.StdOut,
            @"(?m)^FOREIGN_BACKUP_ID=([0-9]{8}T[0-9]{6}Z-[a-f0-9]{12})\r?$");
        var sha = System.Text.RegularExpressions.Regex.Match(response.StdOut,
            @"(?m)^FOREIGN_BACKUP_ARCHIVE_SHA256=([a-f0-9]{64})\r?$");
        if (!id.Success || !sha.Success ||
            inspectedServerIdentity != TryCurrentIdentity())
            throw new InvalidDataException("Missing verified MTA archive ID or SSH host changed.");
        string format = ParseForeignBackupFormat(response.StdOut, mta);
        foreignBackupListContext = null;
        foreignBackupSelector.Items.Clear();
        WriteLine("Verified " + mta + " root-only config snapshot: " +
            id.Groups[1].Value + " SHA256=" + sha.Groups[1].Value +
            ", format=" + format +
            ". No mail queue, external certificate or service-state backup. Restore disabled." +
            (format == "v2_package_metadata"
                ? " Sendmail package directory/link metadata captured without following symlinks. Offline Export is unavailable for this snapshot."
                : ""));
    }

    private async Task ListForeignMtaBackupsAsync()
    {
        var endpoint = Endpoint();
        string mta = ConfirmedForeignBackupMta(allowStopped: true);
        foreignBackupListContext = null;
        foreignBackupSelector.Items.Clear();
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildForeignMtaBackupBundle(mta, "list"),
            TimeSpan.FromMinutes(2));
        response.EnsureSuccess();
        if (!ForeignBackupReportOk(response.StdOut, mta, "verified_list"))
            throw new InvalidDataException("Foreign MTA archive inventory could not be verified.");
        var count = System.Text.RegularExpressions.Regex.Match(response.StdOut,
            @"(?m)^FOREIGN_BACKUP_COUNT=([0-9]{1,3})\r?$");
        var matches = System.Text.RegularExpressions.Regex.Matches(response.StdOut,
            @"(?m)^FOREIGN_BACKUP_ID=([0-9]{8}T[0-9]{6}Z-[a-f0-9]{12})\r?$");
        if (!count.Success || !int.TryParse(count.Groups[1].Value, out int expected) ||
            expected != matches.Count || expected > 128 ||
            inspectedServerIdentity != TryCurrentIdentity())
            throw new InvalidDataException("Foreign MTA backup listing has inconsistent count or host.");
        var unique = new SortedSet<string>(StringComparer.Ordinal);
        foreach (System.Text.RegularExpressions.Match item in matches)
            if (!unique.Add(item.Groups[1].Value))
                throw new InvalidDataException("Duplicate foreign MTA backup ID.");
        foreach (string id in unique)
            foreignBackupSelector.Items.Add(id);
        if (foreignBackupSelector.Items.Count > 0)
            foreignBackupSelector.SelectedIndex = 0;
        foreignBackupListContext = SecurityOptionsStore.Identity(endpoint) + "|" + mta;
        WriteLine("Verified primary " + mta + " config archives: " + matches.Count +
            ". Contents stay on Linux and Restore is not available.");
        RenderPage();
    }

    private async Task VerifyForeignMtaBackupAsync()
    {
        var endpoint = Endpoint();
        string mta = ConfirmedForeignBackupMta(allowStopped: true);
        if (foreignBackupListContext != SecurityOptionsStore.Identity(endpoint) + "|" + mta ||
            foreignBackupSelector.SelectedItem is not string id)
            throw new InvalidOperationException("List and choose the verified archive for this MTA.");
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildForeignMtaBackupBundle(mta, "verify", id),
            TimeSpan.FromMinutes(3));
        response.EnsureSuccess();
        if (!ForeignBackupReportOk(response.StdOut, mta, "verified"))
            throw new InvalidDataException("Selected MTA archive failed checksum verification.");
        var sha = System.Text.RegularExpressions.Regex.Match(response.StdOut,
            @"(?m)^FOREIGN_BACKUP_ARCHIVE_SHA256=([a-f0-9]{64})\r?$");
        if (!sha.Success || foreignBackupListContext !=
            SecurityOptionsStore.Identity(endpoint) + "|" + mta)
            throw new InvalidDataException("Archive digest missing or selected MTA changed.");
        string format = ParseForeignBackupFormat(response.StdOut, mta);
        WriteLine("Primary " + mta + " archive " + id + " SHA256=" + sha.Groups[1].Value +
            ", format=" + format + " verified on Linux. Nothing restored." +
            (format == "v2_package_metadata"
                ? " Package-owned database and symlink metadata included; Offline Export and automatic Restore are blocked."
                : ""));
    }

    private async Task PreviewForeignMtaRecoveryAsync()
    {
        var endpoint = Endpoint();
        string mta = ConfirmedForeignBackupMta(allowStopped: true);
        if (foreignBackupListContext != SecurityOptionsStore.Identity(endpoint) + "|" + mta ||
            foreignBackupSelector.SelectedItem is not string id)
            throw new InvalidOperationException("Re-list verified snapshots and select one for this MTA.");
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildForeignMtaBackupBundle(mta, "preview-recovery", id),
            TimeSpan.FromMinutes(3));
        response.EnsureSuccess();
        if (!ForeignBackupReportOk(response.StdOut, mta, "recovery_preview_only"))
            throw new InvalidDataException("Read-only recovery comparison report was incomplete.");
        var state = System.Text.RegularExpressions.Regex.Match(response.StdOut,
            @"(?m)^FOREIGN_BACKUP_CURRENT_CONFIG_MATCH=(identical|different|unverified)\r?$");
        var sha = System.Text.RegularExpressions.Regex.Match(response.StdOut,
            @"(?m)^FOREIGN_BACKUP_ARCHIVE_SHA256=([a-f0-9]{64})\r?$");
        if (!state.Success || !sha.Success ||
            foreignBackupListContext != SecurityOptionsStore.Identity(endpoint) + "|" + mta)
            throw new InvalidDataException("Recovery preview was not bound to this host and archive.");
        string format = ParseForeignBackupFormat(response.StdOut, mta);
        WriteLine("Read-only " + mta + " configuration comparison with backup " + id +
            ": current=" + state.Groups[1].Value + ", archive SHA256=" +
            sha.Groups[1].Value + ", format=" + format +
            ". No SMTP changes or Restore performed." +
            (format == "v2_package_metadata"
                ? " Package metadata are compared, but automatic recovery remains blocked."
                : ""));
    }

    private async Task PreflightForeignMtaRecoveryAsync()
    {
        var endpoint = Endpoint();
        string mta = ConfirmedForeignBackupMta(allowStopped: true);
        string identity = SecurityOptionsStore.Identity(endpoint) + "|" + mta;
        if (foreignBackupListContext != identity ||
            foreignBackupSelector.SelectedItem is not string id)
            throw new InvalidOperationException(
                "List and select the verified Exim/Sendmail backup before read-only preflight.");
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildForeignMtaBackupBundle(mta, "offline-preflight", id),
            TimeSpan.FromMinutes(3));
        response.EnsureSuccess();
        if (!ForeignBackupReportOk(response.StdOut, mta, "read_only_no_restore"))
            throw new InvalidDataException("Foreign MTA preflight did not prove no configuration changes.");
        string Value(string field, string allowed)
        {
            var matches = System.Text.RegularExpressions.Regex.Matches(response.StdOut,
                @"(?m)^" + System.Text.RegularExpressions.Regex.Escape(field) +
                @"=(" + allowed + @")\r?$");
            if (matches.Count != 1)
                throw new InvalidDataException("Missing or duplicate field in foreign MTA preflight.");
            return matches[0].Groups[1].Value;
        }
        string service = Value("FOREIGN_PREFLIGHT_SERVICE",
            "running|stopped_declared|unverified");
        string processes = Value("FOREIGN_PREFLIGHT_PROCESSES",
            "running|none_observed|unverified");
        string queue = Value("FOREIGN_PREFLIGHT_QUEUE",
            "empty_reported|nonempty_reported|unverified");
        string listener = Value("FOREIGN_PREFLIGHT_LISTENER",
            "running|none_observed|unverified");
        string config = Value("FOREIGN_PREFLIGHT_CONFIG_MATCH",
            "identical|different|unverified");
        string archiveSha = Value("FOREIGN_PREFLIGHT_ARCHIVE_SHA256", "[a-f0-9]{64}");
        string planSha = Value("FOREIGN_PREFLIGHT_PLAN_SHA256", "[a-f0-9]{64}");
        string gate = Value("FOREIGN_PREFLIGHT_GATE",
            "blocked_running|blocked_nonempty_queue|blocked_unverified|offline_candidate_manual_recovery_only");
        string current = SecurityOptionsStore.Identity(Endpoint()) + "|" +
                         ConfirmedForeignBackupMta();
        if (foreignBackupListContext != current || current != identity ||
            foreignBackupSelector.SelectedItem is not string selected || selected != id)
            throw new InvalidOperationException("SSH server, MTA or selected backup changed during preflight.");
        WriteLine("Read-only " + mta + " recovery preflight: service=" + service +
            ", processes=" + processes + ", queue=" + queue +
            ", listener=" + listener + ", config=" + config + ", gate=" + gate +
            ", snapshot SHA256=" + archiveSha + ", evidence SHA256=" + planSha +
            ". No Restore, service action, SMTP send or queue change. Manual recovery only.");
    }

    private async Task ExportForeignMtaOfflineAsync()
    {
        var endpoint = Endpoint();
        string mta = ConfirmedForeignBackupMta(allowStopped: true);
        if (foreignBackupListContext != SecurityOptionsStore.Identity(endpoint) + "|" + mta ||
            foreignBackupSelector.SelectedItem is not string id)
            throw new InvalidOperationException("Re-list verified snapshots and select one for this MTA.");
        // Re-verify the exact selected archive and format before asking for
        // confirmation. V2 includes package-owned DBs and symlink metadata;
        // a regular-file-only export would silently omit essential objects.
        var verified = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildForeignMtaBackupBundle(mta, "verify", id),
            TimeSpan.FromMinutes(3));
        verified.EnsureSuccess();
        if (!ForeignBackupReportOk(verified.StdOut, mta, "verified"))
            throw new InvalidDataException("Selected MTA archive verification failed before Export.");
        string format = ParseForeignBackupFormat(verified.StdOut, mta);
        if (foreignBackupListContext != SecurityOptionsStore.Identity(Endpoint()) + "|" + mta ||
            foreignBackupSelector.SelectedItem is not string currentId || currentId != id)
            throw new InvalidOperationException("SSH host or selected archive changed during verification.");
        bool packageV2 = format == "v2_package_metadata";
        string warning = packageV2
            ? T("Sendmail Snapshot v2: файлы будут скопированы ТОЛЬКО в приватный каталог на Linux. Символические ссылки останутся данными JSON и НЕ будут созданы. Права и владельцы оригинальных файлов НЕ применяются. Это НЕ восстановление /etc/mail. Пароли и ключи остаются в архиве. Продолжить?",
                "Sendmail Snapshot v2: files are copied ONLY into a private Linux review directory. Symlinks are inert JSON metadata, never created. Original owners/modes are NOT applied. This is NOT an /etc/mail restore. Secrets stay in the archive. Proceed?",
                "גיבוי Sendmail v2 ייוצא לתיקייה פרטית בלבד. קישורים סמליים יישמרו כנתונים בלבד. אין שחזור של /etc/mail.")
            : T("Будут извлечены файлы архива " + id +
                  " в НОВЫЙ каталог root-only внутри /var/backups. Текущий /etc, почтовая очередь, службы и маршруты не меняются. Файлы могут содержать пароли! Самостоятельно проверьте восстановление на отдельной VM. Продолжить?",
                "A NEW private, root-only folder under /var/backups will receive extracted files from snapshot " +
                  id + ". Active /etc, MTA services, queues and routes are NOT changed. Extracted files may contain passwords. Validate recovery separately on a disposable VM. Proceed?",
                "הגיבוי ייחלץ לתיקייה חדשה ומוגנת. אין שינוי בתצורה הפעילה או בשירותי הדואר.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Offline " + mta + " recovery export",
            warning, packageV2 ? "EXPORT INERT SENDMAIL SNAPSHOT" : "EXTRACT VERIFIED MTA ARCHIVE")) return;
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildForeignMtaBackupBundle(mta, "export-offline", id),
            TimeSpan.FromMinutes(5));
        response.EnsureSuccess();
        if (!ForeignBackupReportOk(response.StdOut, mta, "exported_offline_only"))
            throw new InvalidDataException("Offline export did not return verified non-mutating status.");
        var path = System.Text.RegularExpressions.Regex.Match(response.StdOut,
            @"(?m)^FOREIGN_BACKUP_OFFLINE_DIRECTORY=(/var/backups/linuxmailrelay365-foreign-mta/" +
            mta + @"/\.offline-recovery-[a-zA-Z0-9_-]{8,20})\r?$");
        var sha = System.Text.RegularExpressions.Regex.Match(response.StdOut,
            @"(?m)^FOREIGN_BACKUP_ARCHIVE_SHA256=([a-f0-9]{64})\r?$");
        string reportedFormat = ParseForeignBackupFormat(response.StdOut, mta);
        if (!path.Success || !sha.Success || reportedFormat != format ||
            foreignBackupListContext != SecurityOptionsStore.Identity(Endpoint()) + "|" + mta ||
            foreignBackupSelector.SelectedItem is not string stillSelected || stillSelected != id)
            throw new InvalidDataException("Offline export format, directory, archive or SSH host changed.");
        if (packageV2 && !System.Text.RegularExpressions.Regex.IsMatch(response.StdOut,
            @"(?m)^FOREIGN_BACKUP_OFFLINE_LINKS_MATERIALIZED=no\r?$"))
            throw new InvalidDataException("Sendmail v2 export did not confirm inert package symlinks.");
        WriteLine("Verified offline " + mta + " snapshot exported privately on Linux: " +
            path.Groups[1].Value + "; archive SHA256=" + sha.Groups[1].Value +
            (packageV2
                ? ". Package links are JSON metadata ONLY; original owners and modes are NOT applied. This is NOT a live /etc/mail restore. Do NOT copy secrets to Windows or start MTA with this tree."
                : ". Active server unchanged. DO NOT copy secrets to Windows or start MTA with these files."));
    }

    private async Task BackupNowAsync()
    {
        RequirePostfixBackup();
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildRecoveryBundle("--backup"), TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        WriteLine(result.StdOut);
        WriteLine("Backup stored under /var/backups/linuxmailrelay365 on Linux. Archives never leave the server.");
    }

    private async Task ListBackupsAsync()
    {
        RequirePostfixBackup();
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildRecoveryBundle("--list"), TimeSpan.FromMinutes(2));
        result.EnsureSuccess();
        backupSelector.Items.Clear();
        foreach (var line in result.StdOut.Split('\n'))
        {
            var match = System.Text.RegularExpressions.Regex.Match(line.Trim(),
                @"^BACKUP_ID=([0-9]{8}T[0-9]{6}Z-[a-f0-9]{12})$");
            if (match.Success) backupSelector.Items.Add(match.Groups[1].Value);
        }
        backupSelector.SelectedIndex = -1;
        WriteLine("Verified Linux backups: " + backupSelector.Items.Count +
            ". Select a backup explicitly before Restore.");
        RenderPage();
    }

    private async Task RestoreBackupAsync()
    {
        RequirePostfixBackup();
        if (backupSelector.SelectedItem is not string backupId)
            throw new InvalidOperationException("List backups and select one verified backup before restoring.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Restore Postfix",
            T("Существующая конфигурация /etc/postfix будет заменена резервной копией " + backupId +
              ". Postfix будет перезапущен. Доставка почты может прерваться. Перед восстановлением создаётся ещё одна резервная копия. Пакеты не откатываются.",
              "This restores the full Postfix configuration from backup " + backupId +
              ", restarts Postfix and may interrupt mail. A safety backup is made first. Installed packages are NOT reverted.",
              "השחזור יחליף את הגדרות Postfix ועשוי לשבש דואר."),
            "RESTORE POSTFIX")) return;
        WriteLine("Restoring verified Postfix backup: " + backupId);
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildRecoveryBundle("--restore", backupId), TimeSpan.FromMinutes(6));
        result.EnsureSuccess();
        WriteLine(result.StdOut);
        inspectedMail = null;
        inspectedServerIdentity = null;
        allowExisting.Checked = false;
        backupSelector.Items.Clear();
        WriteLine("Restore complete. Re-run the MTA inspection before any further modifications.");
    }

    private Task OpenBackupStepAsync()
    {
        step = 3;
        RenderPage();
        return Task.CompletedTask;
    }

    private void EnsureSecurityLoaded()
    {
        var endpoint = Endpoint();
        string identity = SecurityOptionsStore.Identity(endpoint);
        if (securityServerIdentity == identity) return;
        securityLoading = true;
        try
        {
            securityOptions = SecurityOptionsStore.Load(dataDirectory, endpoint);
            hardwareRequest.Checked = securityOptions.RequestHardwareBackedKey;
            ipRequest.Checked = securityOptions.RequestIpConditionalAccess;
            monitoringRequest.Checked = securityOptions.RequestEntraSignInMonitoring;
            securityServerIdentity = identity;
            linuxSecurity = null;
            reviewedTpmPlanSha = null;
            reviewedTpmPlanContext = null;
            tpmPlanSummary = "";
            hardwareOAuthSummary = "";
            reviewedEntraPublicCertificates = null;
            reviewedEntraCertPlanSha = null;
            reviewedEntraCertContext = null;
            reviewedEntraCertObjectId = null;
            entraCertificateSummary = "";
            reviewedTpmKeyPlanSha = null;
            reviewedTpmKeyPlanContext = null;
            tpmKeySummary = "";
            hardwareStageSummary = "";
            reviewedHardwareStageSha = null;
            reviewedHardwareStageContext = null;
            hardwareStageKeyRef.Text = "";
            hardwareCutoverSummary = "";
            verifiedHardwarePreflightSha = null;
            verifiedHardwarePreflightContext = null;
            verifiedHardwareSmtpAuthSha = null;
            verifiedHardwareSmtpAuthContext = null;
            reviewedHardwareCutoverSha = null;
            reviewedHardwareCutoverContext = null;
            listedHardwareBackupsContext = null;
            hardwareCutoverBackup.Items.Clear();
            cloudSecuritySummary = "Microsoft 365: не проверено. Проверка выполняется только по запросу.";
        }
        finally { securityLoading = false; }
    }

    private void SaveSecurityChoices()
    {
        if (securityLoading || securityServerIdentity is null) return;
        securityOptions.RequestHardwareBackedKey = hardwareRequest.Checked;
        securityOptions.RequestIpConditionalAccess = ipRequest.Checked;
        securityOptions.RequestEntraSignInMonitoring = monitoringRequest.Checked;
        SecurityOptionsStore.Save(dataDirectory, Endpoint(), securityOptions);
        WriteLine("Optional security preferences saved for this Linux host. NO controls were enabled.");
    }

    private async Task CheckLinuxSecurityAsync()
    {
        EnsureSecurityLoaded();
        WriteLine("READ-ONLY Linux security probe (no sudo, installs or configuration changes)...");
        var result = await SshRemote.ProbeSecurityAsync(Endpoint(), EmbeddedAssets.SecurityProbe);
        result.EnsureSuccess();
        linuxSecurity = LinuxSecurityInventory.Parse(result.StdOut);
        WriteLine(linuxSecurity.SummaryRu());
        WriteLine("Presence of TPM/HSM is NOT proof that the key is nonexportable or supported by OAuth transport.");
        RenderPage();
    }

    private async Task InspectHardwareOAuthAsync()
    {
        if (linuxSecurity is null)
            throw new InvalidOperationException("Run Linux security discovery first.");
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildHardwareOAuthDiagnosticBundle(false), TimeSpan.FromSeconds(90));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("HARDWARE_OAUTH_INSPECTION_VERSION=1", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_OAUTH_MODE=inventory_only", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_OAUTH_ENTRA_CONTACTED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_OAUTH_MAIL_CONFIG_CHANGED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Hardware identity inventory returned an incomplete report.");
        hardwareOAuthSummary = result.StdOut.Trim();
        WriteLine(hardwareOAuthSummary);
        RenderPage();
    }

    private async Task VerifyOfflineHardwareOAuthAsync()
    {
        if (linuxSecurity is null)
            throw new InvalidOperationException("Run Linux security discovery first.");
        if (MessageBox.Show(this, T(
            "Проверка использует уже подготовленный ключ TPM/HSM для локальной PS256-подписи. Может потребоваться доступ к аппаратному устройству или PIN, но существующий ключ, почта, Postfix и Entra не изменяются. Выполнить?",
            "This test uses an existing TPM/HSM key for offline PS256 signing. Device/PIN access may be required, but no new key is created and no mail, Postfix or Entra change is made. Continue?",
            "הבדיקה משתמשת במפתח קיים לחתימה מקומית, ללא שינוי בדואר או ב-Entra. להמשיך?"),
            "LinuxMailRelay365 | Offline TPM/HSM signing",
            MessageBoxButtons.YesNo, MessageBoxIcon.Information) != DialogResult.Yes) return;
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildHardwareOAuthDiagnosticBundle(true), TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("HARDWARE_OAUTH_INSPECTION_VERSION=1", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_OAUTH_MODE=offline_signing", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_OAUTH_ENTRA_CONTACTED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_OAUTH_MAIL_CONFIG_CHANGED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Hardware OAuth signing probe returned an incomplete report.");
        hardwareOAuthSummary = result.StdOut.Trim();
        WriteLine(hardwareOAuthSummary);
        WriteLine("Provider PS256 signature check is local only. TPM provenance, restart continuity and Microsoft 365 acceptance require independent evidence.");
        RenderPage();
    }

    private void VerifySelectedEntraApplication(EntraCertificateReview source)
    {
        if (discoveredTenants.Count > 1 && tenantSelector.SelectedItem is not TenantOption)
            throw new InvalidOperationException("Select the exact Microsoft Entra tenant first.");
        if (!Guid.TryParse(tenant.Text.Trim(), out var selectedTenant) ||
            selectedTenant != source.TenantId ||
            (tenantSelector.SelectedItem is TenantOption chosen && chosen.Id != selectedTenant))
            throw new InvalidOperationException("Wizard tenant does not match the installed Linux OAuth identity.");
        if (!Guid.TryParse(existingAppId.Text.Trim(), out var selectedClient) ||
            selectedClient != source.ClientId)
            throw new InvalidOperationException("Enter the exact existing Entra application Client ID installed on Linux.");
    }

    private async Task<EntraCertificateReview> ReadEntraPublicCertificateAsync(SshEndpoint endpoint, string target)
    {
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildEntraPublicCertificateBundle(target), TimeSpan.FromSeconds(90));
        result.EnsureSuccess();
        return EntraCertificateReview.Parse(result.StdOut);
    }

    private static void WriteRestrictedGraphPayload(string path, string payload)
    {
        var sid = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException("An identifiable Windows account is required for temporary Graph proof.");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                                                        AccessControlType.Allow));
        // Set a private Windows DACL BEFORE writing the short-lived PoP JWT.
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        System.IO.FileSystemAclExtensions.SetAccessControl(file, security);
        byte[] bytes = Encoding.UTF8.GetBytes(payload);
        file.Write(bytes);
        file.Flush(flushToDisk: true);
        CryptographicOperations.ZeroMemory(bytes);
    }

    private async Task<string> RunGraphEntraCertificateManagerAsync(
        EntraCertificateReview source, string action, string? reviewedSha = null,
        string? ephemeralProof = null)
    {
        if (action is not ("Preview" or "Apply") ||
            (action == "Apply" && (reviewedSha is null || ephemeralProof is null)) ||
            (action == "Preview" && (reviewedSha is not null || ephemeralProof is not null)))
            throw new ArgumentException("Unsupported Entra certificate action or approval.");
        Directory.CreateDirectory(dataDirectory);
        var script = Path.Combine(dataDirectory, "Manage-LinuxMailRelay365EntraCertificate.ps1");
        var input = Path.Combine(dataDirectory, "entra-public-input-" + Guid.NewGuid().ToString("N") + ".json");
        var report = Path.Combine(dataDirectory, "entra-public-report-" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(script, EmbeddedAssets.EntraCertificateManager, new UTF8Encoding(false));
        try
        {
            WriteRestrictedGraphPayload(input, source.PayloadJson(ephemeralProof));
            var psi = new ProcessStartInfo("pwsh.exe")
            {
                UseShellExecute = true,
                WorkingDirectory = dataDirectory
            };
            foreach (string arg in new[]
            {
                "-NoLogo", "-NoProfile", "-File", script,
                "-Action", action, "-InputPath", input, "-ResultPath", report
            }) psi.ArgumentList.Add(arg);
            if (action == "Apply")
            {
                psi.ArgumentList.Add("-ExpectedSha256");
                psi.ArgumentList.Add(reviewedSha!);
                psi.ArgumentList.Add("-TypedConfirmation");
                psi.ArgumentList.Add("ADD_REVIEWED_ENTRA_OAUTH_CERT");
            }
            using var process = Process.Start(psi) ??
                throw new InvalidOperationException("PowerShell 7 Graph process did not start.");
            await process.WaitForExitAsync();
            if (process.ExitCode != 0)
                throw new InvalidOperationException(
                    "Entra certificate operation refused or failed. Inspect the PowerShell 7 console. " +
                    "If Graph may have accepted addKey, inspect existing app certificates before retrying.");
            var statusText = await File.ReadAllTextAsync(report);
            if (statusText.Length > 4096 || statusText.Contains('\0') ||
                !statusText.Contains("ENTRA_CERT_TENANT=exact_match", StringComparison.Ordinal) ||
                !statusText.Contains("ENTRA_CERT_APP=exact_client_id", StringComparison.Ordinal) ||
                !statusText.Contains("ENTRA_CERT_PRIVATE_KEY_EXPORTED=no", StringComparison.Ordinal))
                throw new InvalidDataException("Graph certificate result was incomplete.");
            return statusText.Trim();
        }
        finally
        {
            if (File.Exists(input)) File.Delete(input);
            if (File.Exists(report)) File.Delete(report);
        }
    }

    private Task PreviewEntraCertificateAsync() =>
        PreviewEntraCertificateForTargetAsync(SelectedHardwareCutoverTarget());

    private async Task PreviewEntraCertificateForTargetAsync(string target)
    {
        if (linuxSecurity is null && target != "primary-rotation")
            throw new InvalidOperationException("Run Linux security discovery first.");
        var endpoint = Endpoint();
        reviewedEntraPublicCertificates = null;
        reviewedEntraCertPlanSha = null;
        reviewedEntraCertContext = null;
        reviewedEntraCertObjectId = null;
        reviewedEntraCertTarget = null;
        var source = await ReadEntraPublicCertificateAsync(endpoint, target);
        VerifySelectedEntraApplication(source);
        string output = await RunGraphEntraCertificateManagerAsync(source, "Preview");
        var sha = System.Text.RegularExpressions.Regex.Match(output,
            @"(?m)^ENTRA_CERT_PLAN_SHA256=([a-f0-9]{64})\r?$");
        var obj = System.Text.RegularExpressions.Regex.Match(output,
            @"(?m)^ENTRA_CERT_OBJECT_ID=([a-f0-9-]{36})\r?$");
        if (!sha.Success || !obj.Success || !Guid.TryParse(obj.Groups[1].Value, out var graphId) ||
            graphId == Guid.Empty ||
            !output.Contains("ENTRA_CERT_ACTIVE_KEY=valid", StringComparison.Ordinal) ||
            !output.Contains("ENTRA_CERT_CANDIDATE=not_registered", StringComparison.Ordinal) ||
            !output.Contains("CHANGES_APPLIED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Graph certificate Preview is incomplete or not read-only.");
        reviewedEntraPublicCertificates = source;
        reviewedEntraCertPlanSha = sha.Groups[1].Value;
        reviewedEntraCertObjectId = graphId.ToString("D");
        reviewedEntraCertTarget = target;
        reviewedEntraCertContext = source.Context(SecurityOptionsStore.Identity(endpoint), target);
        entraCertificateSummary = output;
        WriteLine(output);
        WriteLine("Entra certificate review: no tenant mutation. Existing app certificates are preserved.");
        RenderPage();
    }

    private Task AddEntraCertificateAsync() =>
        AddEntraCertificateForTargetAsync(SelectedHardwareCutoverTarget());

    private async Task AddEntraCertificateForTargetAsync(string target)
    {
        if ((linuxSecurity is null && target != "primary-rotation") ||
            reviewedEntraCertTarget != target ||
            reviewedEntraPublicCertificates is null ||
            reviewedEntraCertPlanSha is null || reviewedEntraCertObjectId is null ||
            reviewedEntraCertContext is null)
            throw new InvalidOperationException("Review the exact target application and public certificate first.");
        var endpoint = Endpoint();
        var source = await ReadEntraPublicCertificateAsync(endpoint, target);
        VerifySelectedEntraApplication(source);
        if (reviewedEntraCertContext != source.Context(SecurityOptionsStore.Identity(endpoint), target))
        {
            reviewedEntraCertPlanSha = null;
            throw new InvalidOperationException("Linux active/staged identity or certificate changed. Run Entra Preview again.");
        }
        if (!ConfirmDestructive("LinuxMailRelay365 | Register TPM/HSM public certificate in Entra",
            T("ИЗМЕНЕНИЕ MICROSOFT ENTRA. Будет ДОБАВЛЕН только публичный сертификат существующего приложения. Другие сертификаты, права и настройки останутся прежними. Требуются Application.ReadWrite.All, подтверждение действующим ключом на Linux и соответствие SHA256-плану. Закрытый ключ не передаётся в Entra. Подтвердить?",
              "MICROSOFT ENTRA CHANGE: add ONLY the new public certificate to the exact existing app. Existing keys and permissions are not replaced. Requires delegated Application.ReadWrite.All, an ephemeral proof signed by the current Linux key and an unchanged SHA256 plan. No private key is sent. Continue?",
              "שינוי ב-Entra: רק אישור ציבורי חדש מתווסף; מפתחות קיימים נשמרים. לא מועבר מפתח פרטי."),
            "ADD_REVIEWED_ENTRA_OAUTH_CERT")) return;
        var proofRun = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildEntraPublicCertificateBundle(target,
                reviewedEntraCertObjectId, source.ActiveSha, source.StagedSha,
                source.ActiveCertificateSha, source.CandidateCertificateSha),
            TimeSpan.FromSeconds(90));
        // IMPORTANT: a failed root shell cleanup can leave a signed proof in
        // stdout. Never invoke RemoteResult.EnsureSuccess here: it includes
        // stdout/stderr in its exception, which could expose an ephemeral JWT.
        if (proofRun.ExitCode != 0)
            throw new InvalidOperationException(
                "Linux Graph proof signing failed; inspect local Linux status without exporting the proof.");
        // Never write proofRun.StdOut to any report or activity journal.
        string proof = EntraCertificateReview.ParseProof(proofRun.StdOut);
        string sha = reviewedEntraCertPlanSha;
        reviewedEntraCertPlanSha = null;
        reviewedEntraCertContext = null;
        reviewedEntraCertObjectId = null;
        reviewedEntraCertTarget = null;
        reviewedEntraPublicCertificates = null;
        string output = await RunGraphEntraCertificateManagerAsync(source, "Apply", sha, proof);
        if (!output.Contains("ENTRA_CERT_ADDED=yes", StringComparison.Ordinal) ||
            !output.Contains("ENTRA_CERT_EXISTING_KEYS_PRESERVED=yes", StringComparison.Ordinal) ||
            !output.Contains("CHANGES_APPLIED=entra_addkey_only", StringComparison.Ordinal))
            throw new InvalidDataException("Microsoft Graph did not verify safe addKey completion.");
        entraCertificateSummary = output;
        WriteLine(output);
        if (target == "primary-rotation")
        {
            primaryRotationGraphCertificateSha = source.CandidateCertificateSha;
            primaryRotationGraphContext = source.Context(
                SecurityOptionsStore.Identity(endpoint), target);
            verifiedPrimaryRotationSmtpSha = null;
            verifiedPrimaryRotationSmtpContext = null;
            WriteLine("Primary PEM rotation: candidate public certificate was added; active key unchanged. Next test staged SMTP AUTH without sending mail.");
        }
        else
            WriteLine("Public TPM/HSM certificate added to existing Entra app. Next: separate Linux staged OAuth token verification and rollback-protected cutover; mail delivery is NOT proven.");
        RenderPage();
    }

    private static string PrimaryRotationCode(string raw, string code)
    {
        if (raw.Length > 4096 || raw.Contains('\0') ||
            !System.Text.RegularExpressions.Regex.IsMatch(
                code, @"\A[A-Z_]{3,45}\z"))
            throw new InvalidDataException("Invalid primary OAuth rotation status.");
        var result = System.Text.RegularExpressions.Regex.Matches(
            raw, @"(?m)^PRIMARY_OAUTH_ROTATION_" + code + @"=([A-Za-z0-9_:-]{1,128})\r?$");
        if (result.Count != 1)
            throw new InvalidDataException("Missing or duplicate primary OAuth rotation status: " + code);
        return result[0].Groups[1].Value;
    }

    private static string PrimaryRotationSha(string raw, string code)
    {
        string value = PrimaryRotationCode(raw, code);
        if (!System.Text.RegularExpressions.Regex.IsMatch(value,
                @"\A[a-f0-9]{64}\z", System.Text.RegularExpressions.RegexOptions.CultureInvariant))
            throw new InvalidDataException("Invalid primary OAuth rotation SHA256.");
        return value;
    }

    private string PrimaryRotationContext(SshEndpoint endpoint) =>
        SecurityOptionsStore.Identity(endpoint) + "|primary-rotation";

    private void ClearPrimaryRotationReview(bool preserveGraph = false)
    {
        reviewedPrimaryRotationPlanSha = null;
        reviewedPrimaryRotationPlanContext = null;
        reviewedPrimaryRotationStageSha = null;
        reviewedPrimaryRotationStageContext = null;
        verifiedPrimaryRotationSmtpSha = null;
        verifiedPrimaryRotationSmtpContext = null;
        if (!preserveGraph)
        {
            primaryRotationGraphContext = null;
            primaryRotationGraphCertificateSha = null;
        }
    }

    private async Task<string> RunPrimaryRotationAsync(
        SshEndpoint endpoint, string action, int days = 365, string? digest = null)
    {
        var r = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildPrimaryOAuthRotationBundle(action, days, digest),
            TimeSpan.FromMinutes(action is "preflight" or "activate" ? 5 : 3));
        // Failure reports contain ONLY status codes, never private PEM or OAuth tokens.
        // Do not surface arbitrary SSH stderr in diagnostic logs.
        if (r.ExitCode != 0)
            throw new InvalidOperationException(
                "Primary OAuth rotation refused or failed. Inspect the Linux identity, permissions, " +
                "existing staged candidate and registration in Entra; current route was not intentionally changed.");
        return r.StdOut;
    }

    private async Task PreviewPrimaryOAuthRotationAsync()
    {
        var endpoint = Endpoint();
        if (!int.TryParse(certificateDays.Text, out int days) || days is < 1 or > 365)
            throw new ArgumentException("Certificate validity must be 1..365 days.");
        ClearPrimaryRotationReview();
        var result = await RunPrimaryRotationAsync(endpoint, "plan", days);
        string sha = PrimaryRotationSha(result, "PLAN_SHA256");
        if (PrimaryRotationCode(result, "READY_FOR_STAGE") != "yes" ||
            PrimaryRotationCode(result, "ACTIVE_OAUTH_CHANGED") != "no")
            throw new InvalidOperationException(
                "A staged certificate already exists; inspect it before attempting another rotation.");
        reviewedPrimaryRotationPlanSha = sha;
        reviewedPrimaryRotationPlanContext = PrimaryRotationContext(endpoint) + "|" + days;
        primaryRotationSummary = "PRIMARY_OAUTH_ROTATION_PLAN_SHA256=" + sha +
            Environment.NewLine + "Staging is available. Active mail identity remains unchanged.";
        WriteLine(primaryRotationSummary);
        RenderPage();
    }

    private async Task StagePrimaryOAuthRotationAsync()
    {
        var endpoint = Endpoint();
        if (!int.TryParse(certificateDays.Text, out int days) || days is < 1 or > 365 ||
            reviewedPrimaryRotationPlanSha is null ||
            reviewedPrimaryRotationPlanContext != PrimaryRotationContext(endpoint) + "|" + days)
            throw new InvalidOperationException("Review the exact primary OAuth certificate plan first.");
        string sha = reviewedPrimaryRotationPlanSha;
        var fresh = await RunPrimaryRotationAsync(endpoint, "plan", days);
        if (PrimaryRotationSha(fresh, "PLAN_SHA256") != sha ||
            PrimaryRotationCode(fresh, "READY_FOR_STAGE") != "yes" ||
            PrimaryRotationCode(fresh, "ACTIVE_OAUTH_CHANGED") != "no")
            throw new InvalidOperationException("Primary OAuth identity or staging state changed. Review again.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Stage a new primary OAuth certificate",
            T("Будет создан НОВЫЙ локальный программный PEM-ключ и публичный сертификат на Linux. Действующий app.json, Postfix, очередь и настройки Entra НЕ меняются. Новый приватный ключ останется на Linux. Подтвердить?",
              "A NEW software PEM key and public certificate will be staged on Linux. Active app.json, Postfix, queue and Entra stay UNCHANGED. The private key never leaves Linux. Continue?",
              "יצירת מפתח ואישור חדש ב-Linux ללא הפעלה וללא שינוי ב-Entra."),
            "STAGE_PRIMARY_OAUTH_CERT")) return;
        ClearPrimaryRotationReview();
        string result = await RunPrimaryRotationAsync(endpoint, "stage", days, sha);
        if (PrimaryRotationCode(result, "STAGED") != "yes" ||
            PrimaryRotationCode(result, "ACTIVE_OAUTH_CHANGED") != "no" ||
            PrimaryRotationCode(result, "SMTP_SUBMITTED") != "no")
            throw new InvalidDataException("Linux did not prove safe staged certificate creation.");
        reviewedPrimaryRotationStageSha = PrimaryRotationSha(result, "STAGE_SHA256");
        reviewedPrimaryRotationStageContext = PrimaryRotationContext(endpoint);
        primaryRotationSummary = "New OAuth certificate staged, but NOT active. " +
            "Register its public X.509 certificate in Entra; the current mail route is unchanged.";
        WriteLine(primaryRotationSummary);
        RenderPage();
    }

    private async Task InspectPrimaryOAuthRotationAsync()
    {
        var endpoint = Endpoint();
        string context = PrimaryRotationContext(endpoint);
        string result = await RunPrimaryRotationAsync(endpoint, "status");
        if (PrimaryRotationCode(result, "READY_FOR_PREFLIGHT") != "yes" ||
            PrimaryRotationCode(result, "ACTIVE_OAUTH_CHANGED") != "no")
            throw new InvalidDataException("Staged OAuth identity was not verified.");
        string latest = PrimaryRotationSha(result, "STAGE_SHA256");
        // A refresh of the SAME immutable candidate must not lose a verified
        // Graph registration. Any digest, server or identity change invalidates
        // all previous approvals and candidate SMTP AUTH evidence.
        bool same = reviewedPrimaryRotationStageSha == latest &&
            reviewedPrimaryRotationStageContext == context;
        ClearPrimaryRotationReview(preserveGraph: same);
        reviewedPrimaryRotationStageSha = latest;
        reviewedPrimaryRotationStageContext = context;
        primaryRotationSummary = "Staged certificate fingerprint checked. SHA256=" +
            reviewedPrimaryRotationStageSha + Environment.NewLine +
            "Entra certificate registration and candidate SMTP AUTH are still required.";
        WriteLine(primaryRotationSummary);
        RenderPage();
    }

    private async Task VerifyPrimaryOAuthRotationSmtpAsync()
    {
        var endpoint = Endpoint();
        string context = PrimaryRotationContext(endpoint);
        if (reviewedPrimaryRotationStageSha is null ||
            reviewedPrimaryRotationStageContext != context ||
            primaryRotationGraphCertificateSha is null || primaryRotationGraphContext is null)
            throw new InvalidOperationException(
                "Review the staged certificate and register its PUBLIC key in Entra first.");
        var certs = await ReadEntraPublicCertificateAsync(endpoint, "primary-rotation");
        if (primaryRotationGraphCertificateSha != certs.CandidateCertificateSha ||
            primaryRotationGraphContext != certs.Context(
                SecurityOptionsStore.Identity(endpoint), "primary-rotation"))
            throw new InvalidOperationException("Linux candidate changed since Entra registration review.");
        string sha = reviewedPrimaryRotationStageSha;
        string status = await RunPrimaryRotationAsync(endpoint, "status");
        if (PrimaryRotationSha(status, "STAGE_SHA256") != sha ||
            PrimaryRotationCode(status, "ACTIVE_OAUTH_CHANGED") != "no")
            throw new InvalidOperationException("Staged certificate changed; repeat Entra review.");
        if (MessageBox.Show(this, T(
            "Будет установлен реальный STARTTLS-сеанс с Exchange Online и выполнен SMTP AUTH XOAUTH2 новым сертификатом. Письмо НЕ отправляется, Postfix не изменяется. Продолжить?",
            "This performs a real Exchange Online STARTTLS and SMTP AUTH XOAUTH2 check with the staged certificate. It sends NO MAIL/RCPT/DATA and makes NO Postfix changes. Continue?",
            "בדיקת התחברות SMTP עם האישור החדש ללא שליחת דואר."),
            Text, MessageBoxButtons.YesNo, MessageBoxIcon.Information) != DialogResult.Yes) return;
        string response = await RunPrimaryRotationAsync(endpoint, "preflight", digest: sha);
        if (PrimaryRotationSha(response, "STAGE_SHA256") != sha ||
            PrimaryRotationCode(response, "CANDIDATE_SMTP_AUTH") != "verified_no_message" ||
            PrimaryRotationCode(response, "ACTIVE_OAUTH_CHANGED") != "no")
            throw new InvalidDataException("Staged certificate SMTP AUTH was not verified.");
        verifiedPrimaryRotationSmtpSha = sha;
        verifiedPrimaryRotationSmtpContext = context;
        primaryRotationSummary = "Candidate Exchange Online SMTP AUTH VERIFIED without submitting mail. " +
            "Review and explicitly approve activation if ready.";
        WriteLine(primaryRotationSummary);
        RenderPage();
    }

    private async Task ActivatePrimaryOAuthRotationAsync()
    {
        var endpoint = Endpoint();
        string context = PrimaryRotationContext(endpoint);
        if (reviewedPrimaryRotationStageSha is null ||
            reviewedPrimaryRotationStageContext != context ||
            reviewedPrimaryRotationStageSha != verifiedPrimaryRotationSmtpSha ||
            verifiedPrimaryRotationSmtpContext != context ||
            primaryRotationGraphCertificateSha is null || primaryRotationGraphContext is null)
            throw new InvalidOperationException(
                "Review the exact candidate, add its public Entra certificate and verify SMTP AUTH first.");
        var certificates = await ReadEntraPublicCertificateAsync(endpoint, "primary-rotation");
        if (primaryRotationGraphCertificateSha != certificates.CandidateCertificateSha ||
            primaryRotationGraphContext != certificates.Context(
                SecurityOptionsStore.Identity(endpoint), "primary-rotation"))
            throw new InvalidOperationException("Primary certificate changed. Recheck Entra registration.");
        string sha = reviewedPrimaryRotationStageSha;
        string status = await RunPrimaryRotationAsync(endpoint, "status");
        if (PrimaryRotationSha(status, "STAGE_SHA256") != sha ||
            PrimaryRotationCode(status, "ACTIVE_OAUTH_CHANGED") != "no")
            throw new InvalidOperationException("Staged identity drift detected before activation.");
        if (!ConfirmDestructive("LinuxMailRelay365 | ACTIVATE primary OAuth certificate",
            T("РЕАЛЬНОЕ ИЗМЕНЕНИЕ: активный app.json будет переключён на новый ключ. До и после операции повторно проверяется XOAUTH2 SMTP AUTH, без отправки писем. Старый ключ и его резервная копия сохраняются; при ошибке выполняется автоматический откат. Продолжить?",
              "REAL CHANGE: active app.json will switch to the staged certificate. XOAUTH2 SMTP AUTH will be rechecked before AND after, with NO mail sent. Old keys and a backup are preserved; errors trigger rollback. Continue?",
              "שינוי אמיתי ב-OAuth עם בדיקת SMTP AUTH, גיבוי ושחזור אוטומטי."),
            "ACTIVATE_PRIMARY_OAUTH_CERT")) return;
        verifiedPrimaryRotationSmtpSha = null;
        verifiedPrimaryRotationSmtpContext = null;
        string output = await RunPrimaryRotationAsync(endpoint, "activate", digest: sha);
        if (PrimaryRotationCode(output, "ACTIVATED") != "yes" ||
            PrimaryRotationCode(output, "OLD_KEYS_PRESERVED") != "yes" ||
            PrimaryRotationCode(output, "POST_ACTIVATION_SMTP_AUTH") != "verified_no_message" ||
            PrimaryRotationCode(output, "ROUTING_CHANGED") != "no")
            throw new InvalidDataException(
                "Activation needs manual review: verify Linux active identity and backup before retrying.");
        ClearPrimaryRotationReview();
        primaryRotationSummary = "Primary OAuth rotation ACTIVATED; previous key retained. " +
            "Now confirm real test mail end-to-end before retiring any old Entra credential.";
        WriteLine(primaryRotationSummary);
        RenderPage();
    }

    private string CurrentTpmKeyContext(SshEndpoint endpoint, string target, string handle) =>
        SecurityOptionsStore.Identity(endpoint) + "|" + target + "|" + handle;

    private async Task PreviewTpmKeyAsync()
    {
        if (linuxSecurity?.HasTpm2 != true)
            throw new InvalidOperationException("Run Linux discovery and detect TPM 2.0 first.");
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        string handle = tpmKeyHandle.Text.Trim();
        reviewedTpmKeyPlanSha = null;
        reviewedTpmKeyPlanContext = null;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildTpmOauthProvisionBundle(target, handle),
            TimeSpan.FromSeconds(120));
        result.EnsureSuccess();
        var match = System.Text.RegularExpressions.Regex.Match(result.StdOut,
            @"(?m)^TPM_PROVISION_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!match.Success ||
            !result.StdOut.Contains("TPM_PROVISION_KEY_CREATED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("TPM_PROVISION_HANDLE_FREE=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("TPM_PROVISION_ACTIVE_OAUTH_CHANGED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("TPM_PROVISION_ENTRA_CONTACTED=no", StringComparison.Ordinal))
            throw new InvalidDataException("TPM2 provisioning did not return an intact read-only review.");
        reviewedTpmKeyPlanSha = match.Groups[1].Value;
        reviewedTpmKeyPlanContext = CurrentTpmKeyContext(endpoint, target, handle);
        tpmKeySummary = result.StdOut.Trim();
        WriteLine(tpmKeySummary);
        WriteLine("TPM2 handle availability and OpenSSL3 provider reviewed. No persistent key or certificate was created.");
        RenderPage();
    }

    private async Task ApplyTpmKeyAsync()
    {
        if (linuxSecurity?.HasTpm2 != true)
            throw new InvalidOperationException("TPM2 must be detected in Linux security discovery.");
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        string handle = tpmKeyHandle.Text.Trim();
        if (reviewedTpmKeyPlanSha is null ||
            reviewedTpmKeyPlanContext != CurrentTpmKeyContext(endpoint, target, handle))
            throw new InvalidOperationException("Review this exact TPM2 handle and SHA256 plan first.");
        string sha = reviewedTpmKeyPlanSha;
        var fresh = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildTpmOauthProvisionBundle(target, handle),
            TimeSpan.FromSeconds(120));
        fresh.EnsureSuccess();
        var actual = System.Text.RegularExpressions.Regex.Match(fresh.StdOut,
            @"(?m)^TPM_PROVISION_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!actual.Success || actual.Groups[1].Value != sha ||
            !fresh.StdOut.Contains("TPM_PROVISION_READY_FOR_APPROVED_CREATION=yes", StringComparison.Ordinal))
        {
            reviewedTpmKeyPlanSha = null;
            reviewedTpmKeyPlanContext = null;
            throw new InvalidOperationException("TPM2 handle, identity or provider changed; review a new plan.");
        }
        if (!ConfirmDestructive("LinuxMailRelay365 | Create TPM2 persistent RSA key",
            T("ЭТО РЕАЛЬНО СОЗДАСТ постоянный аппаратный RSA-ключ в TPM2 по адресу ",
              "THIS WILL CREATE a new persistent RSA key inside the TPM2 at handle ",
              "פעולה זו יוצרת מפתח חומרה קבוע ב-TPM2: ") + handle + ".\n" +
            T("Используется только свободный owner handle, но операция расходует TPM NVRAM. Автоматического удаления нет даже при неуспешной проверке сертификата. Действующие ключи, app.json и Postfix не меняются. Если создание оборвётся, потребуется ручная проверка состояния TPM. Продолжить?",
              "The free owner handle consumes TPM NVRAM; NO existing key is evicted and NO automatic TPM key deletion occurs, even on failure. Active keys, app.json and Postfix remain untouched. An interrupted operation may require manual TPM inventory. Continue?",
              "מפתח קבוע ייכתב ב-TPM ללא מחיקת מפתחות קיימים; במקרה כשל נדרשת בדיקה ידנית."),
            "CREATE_TPM2_OAUTH_KEY")) return;
        reviewedTpmKeyPlanSha = null;
        reviewedTpmKeyPlanContext = null;
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildTpmOauthProvisionBundle(target, handle, sha),
            TimeSpan.FromMinutes(7));
        response.EnsureSuccess();
        if (!response.StdOut.Contains("TPM_PROVISION_PERSISTENT_KEY_CREATED=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("TPM_PROVISION_CERTIFICATE_CREATED=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("TPM_PROVISION_SERVICE_ACCOUNT_PS256_VERIFIED=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("TPM_PROVISION_ACTIVE_OAUTH_CHANGED=no", StringComparison.Ordinal))
            throw new InvalidDataException("TPM2 creation did not pass key/certificate acceptance; inspect the selected TPM handle.");
        tpmKeySummary = response.StdOut.Trim();
        WriteLine(tpmKeySummary);
        hardwareStageProvider.SelectedIndex = 0;
        hardwareStageKeyRef.Text = "handle:" + handle;
        WriteLine("TPM2 hardware key and public certificate created. Next: review and stage the candidate identity; Entra certificate upload remains separate.");
        RenderPage();
    }

    private string SelectedHardwareStageProvider() => hardwareStageProvider.SelectedIndex switch
    {
        0 => "tpm2",
        1 => "pkcs11",
        _ => throw new InvalidOperationException("Select TPM2 or PKCS#11 provider.")
    };

    private string CurrentHardwareStageContext(SshEndpoint endpoint, string target,
                                               string provider, string keyRef) =>
        SecurityOptionsStore.Identity(endpoint) + "|" + target + "|" + provider + "|" + keyRef;

    private async Task PreviewHardwareStageAsync()
    {
        if (linuxSecurity is null)
            throw new InvalidOperationException("Run Linux security discovery first.");
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        string provider = SelectedHardwareStageProvider();
        string keyRef = hardwareStageKeyRef.Text.Trim();
        reviewedHardwareStageSha = null;
        reviewedHardwareStageContext = null;
        var bundle = EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
            target, "stage-plan", stageProvider: provider, stageKeyRef: keyRef);
        var result = await SshRemote.RunRootScriptAsync(endpoint, bundle,
            TimeSpan.FromSeconds(90));
        result.EnsureSuccess();
        var hash = System.Text.RegularExpressions.Regex.Match(result.StdOut,
            @"(?m)^HARDWARE_STAGE_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!hash.Success ||
            !result.StdOut.Contains("HARDWARE_STAGE_STAGED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_STAGE_ROUTING_IDENTITY_UNCHANGED=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_STAGE_ENTRA_CONTACTED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Hardware OAuth candidate review report was incomplete.");
        reviewedHardwareStageSha = hash.Groups[1].Value;
        reviewedHardwareStageContext = CurrentHardwareStageContext(endpoint, target, provider, keyRef);
        hardwareStageSummary = result.StdOut.Trim();
        WriteLine(hardwareStageSummary);
        WriteLine("TPM/HSM candidate preview completed; no key was created, no file or mail service changed.");
        RenderPage();
    }

    private async Task ApplyHardwareStageAsync()
    {
        if (linuxSecurity is null)
            throw new InvalidOperationException("Run Linux security discovery first.");
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        string provider = SelectedHardwareStageProvider();
        string keyRef = hardwareStageKeyRef.Text.Trim();
        if (reviewedHardwareStageSha is null ||
            reviewedHardwareStageContext != CurrentHardwareStageContext(endpoint, target, provider, keyRef))
            throw new InvalidOperationException("Review the exact hardware provider/key reference first.");
        string sha = reviewedHardwareStageSha;
        var fresh = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                target, "stage-plan", stageProvider: provider, stageKeyRef: keyRef),
            TimeSpan.FromSeconds(90));
        fresh.EnsureSuccess();
        var digest = System.Text.RegularExpressions.Regex.Match(fresh.StdOut,
            @"(?m)^HARDWARE_STAGE_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!digest.Success || digest.Groups[1].Value != sha ||
            !fresh.StdOut.Contains("HARDWARE_STAGE_STAGED=no", StringComparison.Ordinal))
        {
            reviewedHardwareStageSha = null;
            reviewedHardwareStageContext = null;
            throw new InvalidOperationException("The hardware certificate/provider or key plan changed. Review again.");
        }
        if (!ConfirmDestructive("LinuxMailRelay365 | Stage TPM/HSM OAuth candidate",
            T("Создаётся только отдельный hardware-staged.json. Сертификат и ключ уже должны существовать на Linux. Будет выполнена локальная PS256-подпись; при ошибке новый кандидат удаляется. Никаких запросов в Entra, смены app.json или отправки писем. Цель: ",
              "Only a separate hardware-staged.json is created. The certificate and key must already be present on Linux. Local PS256 signing is required; on failure the new candidate is removed. No Entra call, active app.json change or mail sent. Target: ",
              "נוצר רק קובץ זהות חומרה נפרד לאחר בדיקת חתימה מקומית, ללא שינוי בדואר או ב-Entra. יעד: ") + target,
            "STAGE_HARDWARE_OAUTH")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(
                target, "stage-apply", approvalSha: sha,
                stageProvider: provider, stageKeyRef: keyRef),
            TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("HARDWARE_STAGE_STAGED=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_STAGE_LOCAL_PS256_VERIFIED=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_STAGE_KEY_CREATED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_STAGE_ENTRA_CONTACTED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Hardware staging did not confirm a verified, non-invasive candidate.");
        reviewedHardwareStageSha = null;
        reviewedHardwareStageContext = null;
        hardwareStageSummary = result.StdOut.Trim();
        WriteLine(hardwareStageSummary);
        WriteLine("Staged hardware OAuth validated. Register the PUBLIC hardware-app.crt in Entra before a separate cutover review and approval.");
        RenderPage();
    }

    private string CurrentDeliveryAcceptanceContext(
        SshEndpoint endpoint, string target, string runId)
    {
        return SecurityOptionsStore.Identity(endpoint) + "|" + target + "|" +
               runId + "|" + acceptanceInternalRecipient.Text.Trim() + "|" +
               acceptanceExternalRecipient.Text.Trim();
    }

    private async Task PreviewDeliveryAcceptanceAsync()
    {
        if (linuxSecurity is null)
            throw new InvalidOperationException("Run Linux security discovery first.");
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        string internalAddress = acceptanceInternalRecipient.Text.Trim();
        string externalAddress = acceptanceExternalRecipient.Text.Trim();
        reviewedAcceptanceSha = null;
        reviewedAcceptanceContext = null;
        acceptanceRunId = Guid.NewGuid().ToString("N");
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildDeliveryAcceptanceBundle(
                target, acceptanceRunId, internalAddress, externalAddress),
            TimeSpan.FromSeconds(100));
        response.EnsureSuccess();
        var match = System.Text.RegularExpressions.Regex.Match(response.StdOut,
            @"(?m)^SMTP_ACCEPTANCE_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!match.Success ||
            !response.StdOut.Contains("SMTP_ACCEPTANCE_RUN_ID=" + acceptanceRunId, StringComparison.Ordinal) ||
            !response.StdOut.Contains("SMTP_ACCEPTANCE_READY_FOR_APPROVED_TEST=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("SMTP_ACCEPTANCE_ACTIVE_HARDWARE_IDENTITY=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("SMTP_ACCEPTANCE_MAIL_SENT=no", StringComparison.Ordinal) ||
            !response.StdOut.Contains("SMTP_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Delivery test Preview is not complete or was not read-only.");
        reviewedAcceptanceSha = match.Groups[1].Value;
        reviewedAcceptanceContext = CurrentDeliveryAcceptanceContext(endpoint, target, acceptanceRunId);
        acceptanceSummary = response.StdOut.Trim();
        WriteLine(acceptanceSummary);
        WriteLine("The acceptance preview did not send any email. Inbound accepted-domain membership and recipient inbox access must be verified by the operator.");
        RenderPage();
    }

    private async Task ApplyDeliveryAcceptanceAsync()
    {
        if (linuxSecurity is null || reviewedAcceptanceSha is null || acceptanceRunId is null)
            throw new InvalidOperationException("Review two exact delivery acceptance recipients first.");
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        string runId = acceptanceRunId;
        string sha = reviewedAcceptanceSha;
        string internalAddress = acceptanceInternalRecipient.Text.Trim();
        string externalAddress = acceptanceExternalRecipient.Text.Trim();
        if (reviewedAcceptanceContext != CurrentDeliveryAcceptanceContext(endpoint, target, runId))
            throw new InvalidOperationException("Test host, recipients or run identifier changed. Review again.");
        var fresh = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildDeliveryAcceptanceBundle(
                target, runId, internalAddress, externalAddress),
            TimeSpan.FromSeconds(100));
        fresh.EnsureSuccess();
        var match = System.Text.RegularExpressions.Regex.Match(fresh.StdOut,
            @"(?m)^SMTP_ACCEPTANCE_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!match.Success || match.Groups[1].Value != sha ||
            !fresh.StdOut.Contains("SMTP_ACCEPTANCE_MAIL_SENT=no", StringComparison.Ordinal))
        {
            reviewedAcceptanceSha = null;
            reviewedAcceptanceContext = null;
            throw new InvalidOperationException("Active hardware identity, test recipients or SMTP binary changed. Review again.");
        }
        if (!ConfirmDestructive("LinuxMailRelay365 | Microsoft 365 acceptance delivery",
            T("Это ОТПРАВИТ два РЕАЛЬНЫХ письма через активный TPM/HSM OAuth: ",
              "This will SEND TWO REAL short messages using the active TPM/HSM OAuth: ",
              "יישלחו שתי הודעות אמיתיות באמצעות OAuth חומרה פעיל: ") +
            "\nInternal: " + internalAddress + "\nExternal: " + externalAddress + "\n" +
            T("Повторение того же теста блокируется, даже если SSH оборвётся. Принятие SMTP не доказывает доставку в Inbox; проверьте оба ящика или Message Trace. Продолжить?",
              "The same run cannot be retried even if SSH fails. SMTP acceptance does not prove Inbox delivery; check both mailboxes or Message Trace. Continue?",
              "אין שליחה חוזרת אוטומטית. יש לאמת את קבלת הדואר בתיבות."),
            "SEND_TWO_ACCEPTANCE_TESTS")) return;
        reviewedAcceptanceSha = null;
        reviewedAcceptanceContext = null;
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildDeliveryAcceptanceBundle(
                target, runId, internalAddress, externalAddress, sha),
            TimeSpan.FromMinutes(7));
        if (response.ExitCode != 0)
            throw new InvalidOperationException(
                "One or both acceptance submissions failed or their result is unknown. " +
                "Do NOT retry the same trace ID. Inspect the Linux acceptance ledger and recipient mailboxes. " +
                "No token or mailbox address is included in this error.");
        if (!response.StdOut.Contains("SMTP_ACCEPTANCE_TWO_SMTP_SUBMISSIONS_ACCEPTED=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("SMTP_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED=no", StringComparison.Ordinal) ||
            !response.StdOut.Contains("SMTP_ACCEPTANCE_AUTOMATIC_RETRY=no", StringComparison.Ordinal) ||
            !response.StdOut.Contains("SMTP_ACCEPTANCE_PRIMARY_MTA_CHANGED=no", StringComparison.Ordinal))
            throw new InvalidDataException("SMTP acceptance evidence missing. Inspect recipient mailboxes and do not repeat this run.");
        acceptanceSummary = response.StdOut.Trim();
        WriteLine(acceptanceSummary);
        WriteLine("Exchange accepted TWO test submissions. Trace ID " + runId +
                  ". Recipients must independently confirm actual mailbox delivery; this does NOT prove local Postfix ingress/queue processing.");
        RenderPage();
    }

    private string SelectedHardwareCutoverTarget() => hardwareCutoverTarget.SelectedIndex switch
    {
        0 => "sidecar",
        1 => "primary",
        _ => throw new InvalidOperationException("Select one supported installed OAuth transport.")
    };

    private async Task PreviewHardwareCutoverAsync()
    {
        if (linuxSecurity is null)
            throw new InvalidOperationException("Run Linux security discovery first.");
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        reviewedHardwareCutoverSha = null;
        reviewedHardwareCutoverContext = null;
        verifiedHardwarePreflightSha = null;
        verifiedHardwarePreflightContext = null;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(target, "plan"), TimeSpan.FromSeconds(90));
        result.EnsureSuccess();
        var sha = System.Text.RegularExpressions.Regex.Match(result.StdOut,
            @"(?m)^HARDWARE_CUTOVER_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!sha.Success ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_APPLIED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_ROUTING_IDENTITY_UNCHANGED=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_ENTRA_TOKEN_VERIFIED=not_yet", StringComparison.Ordinal))
            throw new InvalidDataException("Hardware OAuth cutover did not provide a complete read-only review.");
        reviewedHardwareCutoverSha = sha.Groups[1].Value;
        reviewedHardwareCutoverContext = SecurityOptionsStore.Identity(endpoint) + "|" + target;
        hardwareCutoverSummary = result.StdOut.Trim();
        WriteLine(hardwareCutoverSummary);
        WriteLine("Hardware OAuth plan reviewed: NO changes yet. Hardware-staged certificate must already be registered in Entra before activation.");
        RenderPage();
    }

    private async Task VerifyStagedHardwareEntraTokenAsync()
    {
        if (linuxSecurity is null)
            throw new InvalidOperationException("Run Linux security discovery before staged OAuth verification.");
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        string context = SecurityOptionsStore.Identity(endpoint) + "|" + target;
        if (reviewedHardwareCutoverSha is null || reviewedHardwareCutoverContext != context)
            throw new InvalidOperationException("Review the matching hardware OAuth cutover plan first.");
        string sha = reviewedHardwareCutoverSha;
        var fresh = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(target, "plan"), TimeSpan.FromSeconds(90));
        fresh.EnsureSuccess();
        var match = System.Text.RegularExpressions.Regex.Match(fresh.StdOut,
            @"(?m)^HARDWARE_CUTOVER_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!match.Success || match.Groups[1].Value != sha ||
            !fresh.StdOut.Contains("HARDWARE_CUTOVER_APPLIED=no", StringComparison.Ordinal))
        {
            verifiedHardwarePreflightSha = null;
            verifiedHardwarePreflightContext = null;
            verifiedHardwareSmtpAuthSha = null;
            verifiedHardwareSmtpAuthContext = null;
            reviewedHardwareCutoverSha = null;
            reviewedHardwareCutoverContext = null;
            throw new InvalidOperationException("Staged identity, hardware key or certificate changed. Review the plan again.");
        }
        if (MessageBox.Show(this, T(
            "Операция отправит реальный запрос токена в Entra через существующий TPM/HSM-ключ. Письмо не отправляется, активный app.json и Postfix не меняются. Проверка требует разрешений существующего Entra-приложения. Продолжить?",
            "This calls the REAL Entra token endpoint with the staged TPM/HSM key. No mail is sent and the active app.json and Postfix stay unchanged. The existing Entra application must already authorize the certificate. Continue?",
            "הפעולה בודקת אסימון Entra באמצעות המפתח החומרתי ללא שינוי תצורת הדואר. להמשיך?"),
            "LinuxMailRelay365 | Staged TPM/HSM token check",
            MessageBoxButtons.YesNo, MessageBoxIcon.Information) != DialogResult.Yes) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(target, "token-preflight", approvalSha: sha),
            TimeSpan.FromMinutes(4));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("HARDWARE_CUTOVER_STAGED_ONLY=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_ENTRA_TOKEN_VERIFIED=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_LOCAL_SIGNING_VERIFIED=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_TOKEN_PRINTED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_ACTIVE_OAUTH_CHANGED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_MAIL_SENT=no", StringComparison.Ordinal))
            throw new InvalidDataException("Staged Entra token test did not verify the expected read-only mail state.");
        verifiedHardwarePreflightSha = sha;
        verifiedHardwarePreflightContext = context;
        WriteLine(result.StdOut.Trim());
        WriteLine("Staged hardware key acquired an Entra application token without activating a mail transport. Exchange SMTP authorization and recipient delivery still need a separate test.");
        RenderPage();
    }

    private async Task VerifyStagedExchangeSmtpAuthAsync()
    {
        if (linuxSecurity is null)
            throw new InvalidOperationException("Run Linux discovery before staged SMTP AUTH verification.");
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        string context = SecurityOptionsStore.Identity(endpoint) + "|" + target;
        if (reviewedHardwareCutoverSha is null || reviewedHardwareCutoverContext != context)
            throw new InvalidOperationException("Review the exact staged OAuth cutover plan first.");
        string sha = reviewedHardwareCutoverSha;
        var fresh = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(target, "plan"), TimeSpan.FromSeconds(90));
        fresh.EnsureSuccess();
        var digest = System.Text.RegularExpressions.Regex.Match(fresh.StdOut,
            @"(?m)^HARDWARE_CUTOVER_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!digest.Success || digest.Groups[1].Value != sha ||
            !fresh.StdOut.Contains("HARDWARE_CUTOVER_APPLIED=no", StringComparison.Ordinal))
        {
            reviewedHardwareCutoverSha = null;
            reviewedHardwareCutoverContext = null;
            verifiedHardwareSmtpAuthSha = null;
            verifiedHardwareSmtpAuthContext = null;
            throw new InvalidOperationException("Hardware OAuth signing, certificate or provider changed. Review the staged plan again.");
        }
        if (MessageBox.Show(this, T(
            "Будет установлен реальный STARTTLS-сеанс с smtp.office365.com:587 и выполнен AUTH XOAUTH2 через подготовленный TPM/HSM-ключ. Команды MAIL FROM, RCPT TO и DATA не отправляются. Активный app.json, Postfix и очередь не меняются. Продолжить?",
            "A real STARTTLS connection to smtp.office365.com:587 will authenticate using AUTH XOAUTH2 with the staged TPM/HSM key. No MAIL FROM, RCPT TO or DATA command is sent; active app.json, Postfix and mail queue are unchanged. Continue?",
            "תתבצע בדיקת STARTTLS ו-SMTP AUTH אמיתית ללא שליחת דואר וללא שינוי Postfix. להמשיך?"),
            "LinuxMailRelay365 | Staged Exchange SMTP AUTH",
            MessageBoxButtons.YesNo, MessageBoxIcon.Information) != DialogResult.Yes) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(target, "smtp-auth-preflight", approvalSha: sha),
            TimeSpan.FromMinutes(5));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("HARDWARE_CUTOVER_STAGED_ONLY=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_SMTP_STARTTLS_VERIFIED=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_SMTP_AUTH_XOAUTH2_VERIFIED=yes", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_MAIL_FROM_RCPT_DATA_SENT=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_ACTIVE_OAUTH_CHANGED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_TOKEN_PRINTED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("HARDWARE_CUTOVER_APPLIED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Exchange SMTP AUTH preflight did not prove the required non-delivery status.");
        verifiedHardwareSmtpAuthSha = sha;
        verifiedHardwareSmtpAuthContext = context;
        WriteLine(result.StdOut.Trim());
        WriteLine("Exchange Online STARTTLS and XOAUTH2 authentication passed with staged hardware OAuth. No message sent. Recipient delivery still requires authorized end-to-end tests.");
        RenderPage();
    }

    private async Task ApplyHardwareCutoverAsync()
    {
        if (linuxSecurity is null)
            throw new InvalidOperationException("Run Linux security discovery first.");
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        string context = SecurityOptionsStore.Identity(endpoint) + "|" + target;
        if (reviewedHardwareCutoverContext != context || reviewedHardwareCutoverSha is null)
            throw new InvalidOperationException("Review this exact hardware OAuth identity and SHA plan first.");
        string sha = reviewedHardwareCutoverSha;
        var fresh = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(target, "plan"), TimeSpan.FromSeconds(90));
        fresh.EnsureSuccess();
        var planSha = System.Text.RegularExpressions.Regex.Match(fresh.StdOut,
            @"(?m)^HARDWARE_CUTOVER_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!planSha.Success || planSha.Groups[1].Value != sha ||
            !fresh.StdOut.Contains("HARDWARE_CUTOVER_APPLIED=no", StringComparison.Ordinal))
        {
            reviewedHardwareCutoverSha = null;
            reviewedHardwareCutoverContext = null;
            throw new InvalidOperationException("Hardware OAuth plan, key reference or certificate changed. Review again before activation.");
        }
        if (!ConfirmDestructive("LinuxMailRelay365 | Activate hardware OAuth",
            T("Перед изменением app.json и после него будут выполнены РЕАЛЬНЫЕ проверки подписи, токена Entra и SMTP AUTH XOAUTH2 через STARTTLS. Письма не отправляются. Сертификат аппаратного ключа должен уже быть зарегистрирован в Entra. При неудачной проверке после переключения прежняя конфигурация восстанавливается. Исходный ключ не удаляется. Цель: ",
              "REAL signing, Entra token and Exchange Online STARTTLS/XOAUTH2 AUTH checks will run both before and after the atomic app.json switch, without sending mail. The hardware public certificate must already be registered in Entra. Failed postcheck restores the old identity, without deleting the old key. Target: ",
              "מתבצעת בדיקת אסימון אמיתית מול Entra לפני ואחרי ההחלפה, עם שחזור אוטומטי במקרה כשל. יעד: ") + target + "\n" +
            T("ВНИМАНИЕ: сервер может временно использовать новый ключ для параллельной отправки. Для production необходимо отдельное окно обслуживания.",
              "CAUTION: concurrent mail delivery may briefly see the new identity. Production requires a separately approved maintenance window.",
              "זהירות: דואר מקביל עלול להשתמש בזהות החדשה לזמן קצר."),
            "ACTIVATE_HARDWARE_OAUTH")) return;
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(target, "apply", approvalSha: sha),
            TimeSpan.FromMinutes(12));
        response.EnsureSuccess();
        if (!response.StdOut.Contains("HARDWARE_CUTOVER_APPLIED=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("HARDWARE_CUTOVER_ENTRA_TOKEN_VERIFIED=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("HARDWARE_CUTOVER_LOCAL_SIGNING_VERIFIED=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("HARDWARE_CUTOVER_SMTP_STARTTLS_VERIFIED=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("HARDWARE_CUTOVER_SMTP_AUTH_XOAUTH2_VERIFIED=yes", StringComparison.Ordinal) ||
            !response.StdOut.Contains("HARDWARE_CUTOVER_MAIL_FROM_RCPT_DATA_SENT=no", StringComparison.Ordinal) ||
            !response.StdOut.Contains("HARDWARE_CUTOVER_TOKEN_PRINTED=no", StringComparison.Ordinal))
            throw new InvalidDataException("Hardware identity cutover did not confirm signed Entra and Exchange SMTP AUTH acceptance. Inspect the Linux backup state.");
        reviewedHardwareCutoverSha = null;
        reviewedHardwareCutoverContext = null;
        verifiedHardwarePreflightSha = null;
        verifiedHardwarePreflightContext = null;
        verifiedHardwareSmtpAuthSha = null;
        verifiedHardwareSmtpAuthContext = null;
        hardwareCutoverSummary = response.StdOut.Trim();
        WriteLine(hardwareCutoverSummary);
        WriteLine("Hardware OAuth activated after pre/post signing, Entra token and Exchange SMTP AUTH checks. No message was sent or key removed. Real recipient delivery remains unverified.");
        await ListHardwareCutoverBackupsAsync();
    }

    private async Task ListHardwareCutoverBackupsAsync()
    {
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        hardwareCutoverBackup.Items.Clear();
        listedHardwareBackupsContext = null;
        var response = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(target, "list"), TimeSpan.FromSeconds(90));
        response.EnsureSuccess();
        if (!response.StdOut.Contains("HARDWARE_CUTOVER_BACKUP_COUNT=", StringComparison.Ordinal))
            throw new InvalidDataException("Missing hardware OAuth backup inventory.");
        var matches = System.Text.RegularExpressions.Regex.Matches(response.StdOut,
            @"(?m)^HARDWARE_CUTOVER_BACKUP_ID=([0-9]{8}T[0-9]{6}Z-[a-f0-9]{12})\r?$");
        foreach (System.Text.RegularExpressions.Match match in matches)
            hardwareCutoverBackup.Items.Add(match.Groups[1].Value);
        if (hardwareCutoverBackup.Items.Count > 0) hardwareCutoverBackup.SelectedIndex = 0;
        listedHardwareBackupsContext = SecurityOptionsStore.Identity(endpoint) + "|" + target;
        WriteLine("Hardware OAuth rollback inventory: " + hardwareCutoverBackup.Items.Count + " verified snapshots.");
        RenderPage();
    }

    private async Task RollbackHardwareCutoverAsync()
    {
        var endpoint = Endpoint();
        string target = SelectedHardwareCutoverTarget();
        if (listedHardwareBackupsContext != SecurityOptionsStore.Identity(endpoint) + "|" + target ||
            hardwareCutoverBackup.SelectedItem is not string backupId)
            throw new InvalidOperationException("List and select a verified hardware OAuth recovery snapshot first.");
        var current = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(target, "list"), TimeSpan.FromSeconds(90));
        current.EnsureSuccess();
        if (!System.Text.RegularExpressions.Regex.IsMatch(current.StdOut,
            @"(?m)^HARDWARE_CUTOVER_BACKUP_ID=" + backupId + @"\r?$"))
            throw new InvalidOperationException("OAuth snapshot changed or is no longer valid. List the snapshots again.");
        if (!ConfirmDestructive("LinuxMailRelay365 | Restore hardware OAuth",
            T("Откат изменит только активный app.json, если его SHA совпадает с сохранённой аппаратной конфигурацией. Изменения Entra/сертификатов не откатываются. Снимок: ",
              "Rollback will replace only active app.json if its SHA matches the deployed hardware identity. Entra changes and certificates are NOT rolled back. Snapshot: ",
              "השחזור מחליף רק את קובץ הזהות הפעיל אם טביעת האצבע תואמת. הגיבוי: ") + backupId,
            "ROLLBACK_HARDWARE_OAUTH")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildHardwareOAuthCutoverBundle(target, "rollback", backupId: backupId),
            TimeSpan.FromMinutes(2));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("HARDWARE_CUTOVER_RESTORED_PREVIOUS_IDENTITY=yes", StringComparison.Ordinal))
            throw new InvalidDataException("OAuth rollback did not confirm the previous identity.");
        hardwareCutoverSummary = result.StdOut.Trim();
        WriteLine(hardwareCutoverSummary);
        reviewedHardwareCutoverSha = null;
        reviewedHardwareCutoverContext = null;
        listedHardwareBackupsContext = null;
        hardwareCutoverBackup.Items.Clear();
        RenderPage();
    }

    private string SelectedTpmDependencyProfile() => tpmDependencyProfile.SelectedIndex switch
    {
        0 => "auto",
        1 => "runtime",
        2 => "build-prereqs",
        3 => "pkcs11",
        4 => "native-provider",
        _ => throw new InvalidOperationException("Select a supported TPM dependency profile.")
    };

    private async Task PreviewTpmDependenciesAsync()
    {
        var endpoint = Endpoint();
        if (linuxSecurity?.HasTpm2 != true)
            throw new InvalidOperationException("A Linux TPM 2.0 inventory must first detect the hardware.");
        if (linuxSecurity.Get("OS_ID") is not ("rhel" or "ol" or "rocky" or "almalinux"))
            throw new InvalidOperationException("RPM dependency preparation is only available for RHEL/Oracle/Rocky/Alma 8-10.");
        string profile = SelectedTpmDependencyProfile();
        reviewedTpmPlanSha = null;
        reviewedTpmPlanContext = null;
        var report = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildTpmDependenciesBundle(profile), TimeSpan.FromSeconds(75));
        report.EnsureSuccess();
        var digest = System.Text.RegularExpressions.Regex.Match(report.StdOut,
            @"(?m)^TPM_DEPS_PLAN_SHA256=([a-f0-9]{64})\r?$");
        if (!digest.Success || !report.StdOut.Contains("TPM_DEPS_APPLIED=no", StringComparison.Ordinal))
            throw new InvalidDataException("TPM package inventory did not return a safe read-only SHA-reviewed plan.");
        reviewedTpmPlanSha = digest.Groups[1].Value;
        reviewedTpmPlanContext = SecurityOptionsStore.Identity(endpoint) + "|" + profile;
        tpmPlanSummary = report.StdOut.Trim();
        WriteLine(tpmPlanSummary);
        WriteLine("Read-only TPM RPM plan saved for review; no packages, firmware, services or keys changed.");
        RenderPage();
    }

    private async Task InspectTpmProviderAsync()
    {
        var endpoint = Endpoint();
        if (linuxSecurity?.HasTpm2 != true)
            throw new InvalidOperationException("Detect a Linux TPM 2.0 device first.");
        if (linuxSecurity.Get("OS_ID") is not ("rhel" or "ol" or "rocky" or "almalinux"))
            throw new InvalidOperationException("Provider diagnosis currently supports RHEL-family 8-10.");
        string profile = SelectedTpmDependencyProfile();
        reviewedTpmPlanSha = null;
        reviewedTpmPlanContext = null;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildTpmDependenciesBundle(profile, inspectProvider: true),
            TimeSpan.FromMinutes(2));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("TPM_DEPS_PROVIDER_DIAGNOSTIC=read_only", StringComparison.Ordinal) ||
            !result.StdOut.Contains("TPM_DEPS_DIAG_PS256_SIGNATURE_VERIFIED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("TPM_DEPS_DIAG_ENTRA_CONTACTED=no", StringComparison.Ordinal) ||
            !result.StdOut.Contains("TPM_DEPS_APPLIED=no", StringComparison.Ordinal))
            throw new InvalidDataException("TPM provider diagnostic report was incomplete.");
        tpmPlanSummary = result.StdOut.Trim();
        WriteLine(tpmPlanSummary);
        WriteLine("Provider loading is not PS256 proof. Use the separate offline existing-key signature test if configured.");
        RenderPage();
    }

    private async Task InstallTpmDependenciesAsync()
    {
        var endpoint = Endpoint();
        string profile = SelectedTpmDependencyProfile();
        string identity = SecurityOptionsStore.Identity(endpoint) + "|" + profile;
        if (reviewedTpmPlanContext != identity || reviewedTpmPlanSha is null)
            throw new InvalidOperationException("Preview and review the exact TPM RPM plan on this Linux host first.");
        string sha = reviewedTpmPlanSha;
        var fresh = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildTpmDependenciesBundle(profile), TimeSpan.FromSeconds(75));
        fresh.EnsureSuccess();
        if (!fresh.StdOut.Contains("TPM_DEPS_PLAN_SHA256=" + sha, StringComparison.Ordinal) ||
            !fresh.StdOut.Contains("TPM_DEPS_READY_FOR_INSTALL=yes", StringComparison.Ordinal) ||
            !fresh.StdOut.Contains("TPM_DEPS_APPLIED=no", StringComparison.Ordinal))
        {
            reviewedTpmPlanSha = null;
            reviewedTpmPlanContext = null;
            throw new InvalidOperationException("TPM state or package plan changed; review a new plan before installing.");
        }
        var missing = System.Text.RegularExpressions.Regex.Match(fresh.StdOut,
            @"(?m)^TPM_DEPS_MISSING=([A-Za-z0-9,._+\-]*)\r?$");
        if (!missing.Success)
            throw new InvalidDataException("TPM package inventory does not include a valid missing-package list.");
        string packages = missing.Groups[1].Value.Length == 0 ? "(none)" : missing.Groups[1].Value;
        if (!ConfirmDestructive("LinuxMailRelay365 | Install TPM2 RPM dependencies",
            T("Установка DNF будет выполнена только после подтверждения. Пакеты: ",
              "DNF will install packages only after your approval. Packages: ",
              "חבילות RPM יותקנו רק לאחר אישור: ") + packages + "\n" +
            T("Приложение не включает TPM-подпись, не меняет ключи, firewall, SELinux и Postfix. Установка RPM может запускать сценарии пакетов и изменять зависимости; проверьте транзакцию DNF и состояние служб. Используются только уже настроенные доверенные репозитории.",
              "The application does not activate hardware signing or directly modify TPM keys, firewall, SELinux or Postfix. RPM scriptlets/dependencies may affect services; review the DNF transaction and service state. Only existing trusted repositories are used.",
              "התוכנה אינה מפעילה חתימה או משנה מפתחות TPM, חומת אש, SELinux או Postfix. התקנת RPM עשויה להשפיע על שירותים."),
            "INSTALL_TPM2_DEPENDENCIES")) return;
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildTpmDependenciesBundle(profile, sha), TimeSpan.FromMinutes(18));
        result.EnsureSuccess();
        if (!result.StdOut.Contains("TPM_DEPS_INSTALL_RESULT=verified_rpms", StringComparison.Ordinal) &&
            !result.StdOut.Contains("TPM_DEPS_INSTALL_RESULT=already_installed", StringComparison.Ordinal))
            throw new InvalidDataException("DNF completed without verified TPM RPM status.");
        WriteLine(result.StdOut);
        reviewedTpmPlanSha = null;
        reviewedTpmPlanContext = null;
        tpmPlanSummary = "";
        var rescanned = await SshRemote.ProbeSecurityAsync(endpoint, EmbeddedAssets.SecurityProbe);
        rescanned.EnsureSuccess();
        linuxSecurity = LinuxSecurityInventory.Parse(rescanned.StdOut);
        WriteLine(linuxSecurity.SummaryRu());
        try
        {
            var providerCheck = await SshRemote.RunRootScriptAsync(endpoint,
                EmbeddedAssets.BuildTpmDependenciesBundle(profile, inspectProvider: true),
                TimeSpan.FromMinutes(2));
            providerCheck.EnsureSuccess();
            if (!providerCheck.StdOut.Contains("TPM_DEPS_PROVIDER_DIAGNOSTIC=read_only", StringComparison.Ordinal) ||
                !providerCheck.StdOut.Contains("TPM_DEPS_DIAG_PS256_SIGNATURE_VERIFIED=no", StringComparison.Ordinal) ||
                !providerCheck.StdOut.Contains("TPM_DEPS_APPLIED=no", StringComparison.Ordinal))
                throw new InvalidDataException("Provider diagnostic report was incomplete.");
            tpmPlanSummary = providerCheck.StdOut.Trim();
            WriteLine(tpmPlanSummary);
        }
        catch (Exception)
        {
            WriteLine("TPM packages were installed, but follow-up provider diagnostics did not complete; use the separate read-only check.");
        }
        WriteLine("TPM2 RPM installation verified; provider load and a hardware PS256 signature require independent acceptance.");
        RenderPage();
    }

    private async Task DiscoverTenantsAsync()
    {
        string scriptPath = Path.Combine(dataDirectory, "Discover-LinuxMailRelay365Tenants.ps1");
        string resultPath = Path.Combine(dataDirectory, "tenants-discovery.json");
        File.WriteAllText(scriptPath, EmbeddedAssets.TenantDiscoveryScript, new UTF8Encoding(false));
        if (File.Exists(resultPath)) File.Delete(resultPath); // Prevent reuse of stale tenant lists.
        var psi = new ProcessStartInfo("pwsh.exe")
        {
            UseShellExecute = true,
            WorkingDirectory = dataDirectory
        };
        foreach (string argument in new[] { "-NoLogo", "-NoProfile", "-File", scriptPath, "-ResultPath", resultPath })
            psi.ArgumentList.Add(argument);
        WriteLine("Tenant discovery: interactive Microsoft sign-in. Az.Accounts may be installed for CurrentUser if absent.");
        using var process = Process.Start(psi) ?? throw new IOException("PowerShell 7 could not be started.");
        await process.WaitForExitAsync();
        if (process.ExitCode != 0 || !File.Exists(resultPath))
            throw new IOException("Tenant discovery failed. No settings were modified; manual Tenant ID remains available.");
        var choices = TenantDiscovery.Parse(await File.ReadAllTextAsync(resultPath));
        discoveredTenants = choices;
        tenantSelectionLoading = true;
        try
        {
            tenantSelector.Items.Clear();
            foreach (TenantOption choice in choices) tenantSelector.Items.Add(choice);
            tenantSelector.SelectedIndex = choices.Count == 1 ? 0 : -1;
            tenant.ReadOnly = choices.Count > 0;
            tenant.Text = choices.Count == 1 ? choices[0].Id.ToString() : "";
        }
        finally { tenantSelectionLoading = false; }
        if (choices.Count == 0)
            WriteLine("No accessible tenants were enumerated. Enter a Tenant GUID manually or retry sign-in.");
        else if (choices.Count == 1)
            WriteLine("Single Microsoft Entra tenant selected automatically: " + choices[0].Id);
        else
            WriteLine("Multiple Microsoft Entra tenants detected: " + choices.Count + ". User selection required.");
        RenderPage();
    }

    private Task UseManualTenantAsync()
    {
        discoveredTenants = Array.Empty<TenantOption>();
        tenantSelectionLoading = true;
        try
        {
            tenantSelector.Items.Clear();
            tenantSelector.SelectedIndex = -1;
            tenant.ReadOnly = false;
            tenant.Clear();
        }
        finally { tenantSelectionLoading = false; }
        WriteLine("Manual Tenant ID entry enabled. Microsoft 365 provisioning still verifies the exact tenant.");
        RenderPage();
        return Task.CompletedTask;
    }

    private async Task CheckCloudSecurityAsync()
    {
        if (!Guid.TryParse(tenant.Text.Trim(), out var tenantId) || tenantId == Guid.Empty)
            throw new ArgumentException("Enter the exact Tenant GUID to check Entra APIs.");
        string path = Path.Combine(dataDirectory, "cloud-security-" + tenantId.ToString("N") + ".json");
        string script = Path.Combine(dataDirectory, "Test-LinuxMailRelay365Security.ps1");
        File.WriteAllText(script, EmbeddedAssets.CloudSecurityProbe, new UTF8Encoding(false));
        var psi = new ProcessStartInfo("pwsh.exe") { UseShellExecute = true, WorkingDirectory = dataDirectory };
        foreach (var arg in new[] { "-NoLogo", "-NoProfile", "-File", script,
                                    "-TenantId", tenantId.ToString(), "-ResultPath", path })
            psi.ArgumentList.Add(arg);
        WriteLine("Read-only Entra readiness check requires interactive admin Device Code. Optional scopes are requested only now.");
        using var process = Process.Start(psi) ?? throw new IOException("Could not start PowerShell 7.");
        await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new IOException("Entra security preflight did not complete; nothing was changed.");
        using var state = JsonDocument.Parse(await File.ReadAllTextAsync(path));
        var root = state.RootElement;
        if (root.GetProperty("changesApplied").GetBoolean())
            throw new InvalidDataException("Unexpected security probe response.");
        cloudSecuritySummary = "Entra CA policy read: " + root.GetProperty("conditionalAccessPolicyRead").GetString() +
            "; sign-in log read: " + root.GetProperty("signInLogRead").GetString() +
            "; Workload ID Premium: " + root.GetProperty("workloadIdPremium").GetString() +
            ". No IP policy was created or enabled.";
        WriteLine(cloudSecuritySummary);
        RenderPage();
    }

    private Task ShowSecurityHelpAsync()
    {
        var sb = new StringBuilder();
        sb.AppendLine(T(
            "ДОПОЛНИТЕЛЬНАЯ ЗАЩИТА — ПО УМОЛЧАНИЮ НИЧЕГО НЕ ВКЛЮЧЕНО",
            "OPTIONAL SECURITY — NOTHING ENABLED BY DEFAULT",
            "אבטחה נוספת — שום אפשרות לא מופעלת כברירת מחדל"));
        sb.AppendLine();
        sb.AppendLine(T(
            "1) TPM 2.0 / HSM: сначала выполните безопасную диагностику Linux. Для аппаратного ключа используйте поддерживаемый TPM2 или PKCS#11 provider и проверьте подпись. Обнаружение TPM не активирует аппаратную авторизацию. Не удаляйте работающий ключ, пока не проверены новый токен и SMTP.",
            "1) TPM 2.0 / HSM: run the Linux read-only probe, check TPM2/PKCS#11 signing support and configure a nonexportable key with supported vendor tools. Discovery never activates hardware signing. Do not delete the working key until token and SMTP tests pass.",
            "1) TPM 2.0 / HSM: בדקו את תמיכת Linux בקריאה בלבד. נדרש מפתח חומרה מאומת ובדיקת חתימה, אסימון וחיבור SMTP. אין למחוק את המפתח הפעיל לפני אימות מלא."));
        sb.AppendLine();
        sb.AppendLine(T(
            "2) Ограничение Entra по IP: требуется соответствующая лицензия Workload ID Premium и Conditional Access для workload identities. Сначала задайте разрешённые исходящие IP, включите Report-only, проверьте входы приложения, а затем отдельно активируйте политику. Если одно приложение используется несколькими Linux, их IP должны входить в общую политику.",
            "2) Entra IP restriction: requires appropriate Workload ID Premium licensing and Conditional Access for workload identities. Start with approved public egress IPs and Report-only, validate sign-in results, then enable explicitly. Shared applications require a compatible IP allowlist.",
            "2) הגבלת IP ב-Entra: דרושים רישוי והרשאות מתאימים. התחילו במדיניות Report-only, בדקו כניסות וכתובות יציאה ציבוריות מאושרות, ורק לאחר מכן הפעילו את המדיניות."));
        sb.AppendLine();
        sb.AppendLine(T(
            "3) Мониторинг Entra: для чтения журналов входа и оповещений требуются роли администратора и разрешения Graph. Отпечаток сертификата и IP — диагностические признаки, но не гарантия привязки к конкретному устройству.",
            "3) Entra monitoring: reading sign-in logs and alerts needs appropriate administrative roles and Graph consent. Certificate thumbprints and source IPs are audit signals, not enforcement of a unique device identity.",
            "3) ניטור Entra: קריאת יומני כניסה והתראות מחייבת הרשאות מנהל ו-Graph. טביעת אישור וכתובת IP הן אינדיקציות ביקורת בלבד."));
        sb.AppendLine();
        sb.AppendLine(T(
            "Все переключатели сохраняют только план. Они не меняют автоматически ключи, лицензии, Conditional Access, Linux, SMTP или почтовую доставку.",
            "All security choices are plans only. No keys, licenses, Conditional Access policies, Linux SMTP routes or message delivery change automatically.",
            "בחירת האפשרויות שומרת תכנון בלבד; אין שינוי אוטומטי במפתחות, ברישיונות, במדיניות או במסירת הדואר."));
        var workArea = Screen.FromControl(this).WorkingArea.Size;
        using var dialog = new Form
        {
            Text = T("LinuxMailRelay365 | Защита", "LinuxMailRelay365 | Optional security",
                     "LinuxMailRelay365 | אבטחה"),
            StartPosition = FormStartPosition.CenterParent,
            ClientSize = PreferredDialogSize(workArea, DeviceDpi, 930, 690),
            MinimumSize = PreferredDialogSize(workArea, DeviceDpi, 600, 430),
            BackColor = UiTheme.Canvas, AutoScaleMode = AutoScaleMode.Dpi,
            FormBorderStyle = FormBorderStyle.Sizable, MaximizeBox = true
        };
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2,
            Padding = new Padding(14, 12, 14, 12)
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var text = new TextBox
        {
            Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
            Font = new Font("Segoe UI", 10), Dock = DockStyle.Fill,
            Text = sb.ToString(), BackColor = Color.White,
            RightToLeft = language.SelectedIndex == 2 ? RightToLeft.Yes : RightToLeft.No
        };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), true);
        close.Click += (_, _) => dialog.Close();
        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = true,
            FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(6)
        };
        actions.Controls.Add(close);
        layout.Controls.Add(text, 0, 0);
        layout.Controls.Add(actions, 0, 1);
        dialog.Controls.Add(layout);
        dialog.AcceptButton = close;
        dialog.ShowDialog(this);
        return Task.CompletedTask;
    }

    private Task OpenSecurityUrlAsync(string url)
    {
        // Only fixed first-party destinations are allowed for external navigation.
        if (url != "https://entra.microsoft.com/")
            throw new ArgumentException("Unapproved security help destination.");
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        return Task.CompletedTask;
    }

    private Task OpenSecurityCenterAsync()
    {
        EnsureSecurityLoaded();
        step = 1;
        RenderPage();
        return Task.CompletedTask;
    }

    private async Task CheckSshAsync()
    {
        WriteLine("Checking Linux connection and OpenSSH host-key trust...");
        var result = await SshRemote.CheckAsync(Endpoint());
        result.EnsureSuccess();
        WriteLine(result.StdOut);
    }

    private async Task PrepareAsync()
    {
        var endpoint = Endpoint();
        WriteLine("Preparing Linux identity certificate (public certificate only will be copied)...");
        EnsureSecurityLoaded();
        if (!int.TryParse(certificateDays.Text, out int validity) || validity is < 1 or > 365)
            throw new ArgumentException("Certificate validity must be from 1 to 365 days.");
        if (securityOptions.RequestHardwareBackedKey)
        {
            var answer = MessageBox.Show(this,
                T("Аппаратная защита только запланирована и НЕ подключена к транспорту. Сейчас будет создан программный ключ PEM. Продолжить без аппаратной защиты?",
                  "Hardware signing is PLANNED but NOT active. The wizard will create a software PEM key. Continue without hardware protection?",
                  "הגנת חומרה אינה פעילה. להמשיך עם מפתח תוכנה?"),
                Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (answer != DialogResult.Yes) return;
            WriteLine("SECURITY: explicit software-key fallback approved; hardware protection remains NOT ACTIVE.");
        }
        var r = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildLinuxBundle(["--prepare-only", "--certificate-days", validity.ToString()]), TimeSpan.FromMinutes(3));
        r.EnsureSuccess();
        WriteLine(r.StdOut);
        string pem = await SshRemote.ReadPublicCertificateAsync(endpoint, CancellationToken.None);
        using var cert = X509Certificate2.CreateFromPem(pem);
        var path = PublicCertPath(endpoint);
        File.WriteAllText(path, pem);
        publicCertificatePath = path;
        WriteLine($"Public certificate saved: {path}");
        WriteLine($"SHA256 certificate expires {cert.NotAfter:u}; private key stayed on Linux.");
    }

    private async Task SetupM365Async()
    {
        var cloud = CloudInputs();
        string certFile = publicCertificatePath ?? PublicCertPath(Endpoint());
        if (!File.Exists(certFile)) throw new InvalidOperationException("First prepare the Linux certificate.");
        string scriptPath = Path.Combine(dataDirectory, "Initialize-LinuxMailRelay365.ps1");
        File.WriteAllText(scriptPath, EmbeddedAssets.Provisioner, new UTF8Encoding(false));
        var psi = new ProcessStartInfo("pwsh.exe")
        {
            UseShellExecute = true,
            WorkingDirectory = dataDirectory
        };
        psi.ArgumentList.Add("-NoLogo");
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(scriptPath);
        psi.ArgumentList.Add("-TenantId");
        psi.ArgumentList.Add(cloud.Tenant.ToString());
        psi.ArgumentList.Add("-Mailbox");
        psi.ArgumentList.Add(cloud.Mailbox);
        psi.ArgumentList.Add("-CertificatePath");
        psi.ArgumentList.Add(certFile);
        psi.ArgumentList.Add("-ResultPath");
        psi.ArgumentList.Add(StatePath(cloud.Tenant));
        string displayName = applicationName.Text.Trim();
        if (displayName.Length is < 3 or > 90) throw new ArgumentException("App name must be 3..90 characters.");
        psi.ArgumentList.Add("-ApplicationName");
        psi.ArgumentList.Add(displayName);
        psi.ArgumentList.Add("-CertificateLabel");
        string label = "LinuxMailRelay365 " + Endpoint().Host;
        psi.ArgumentList.Add(label[..Math.Min(90, label.Length)]);
        if (!string.IsNullOrWhiteSpace(existingAppId.Text))
        {
            if (!Guid.TryParse(existingAppId.Text.Trim(), out var existing) || existing == Guid.Empty)
                throw new ArgumentException("Existing Client ID must be a GUID.");
            psi.ArgumentList.Add("-ExistingAppId");
            psi.ArgumentList.Add(existing.ToString());
        }
        WriteLine("Connecting to Microsoft Entra and Exchange Online in PowerShell 7. Complete admin Device Code prompts in the console.");
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start PowerShell 7 (pwsh.exe).");
        await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new InvalidOperationException("Microsoft 365 provisioning failed; check the PowerShell output.");
        await VerifyM365Async();
    }

    private async Task VerifyM365Async()
    {
        var cloud = CloudInputs();
        string path = StatePath(cloud.Tenant);
        if (!File.Exists(path)) throw new FileNotFoundException("No completed Microsoft 365 state. Run the Entra/Exchange setup first.");
        using var state = JsonDocument.Parse(await File.ReadAllTextAsync(path));
        var root = state.RootElement;
        if (!root.GetProperty("rbacReady").GetBoolean() ||
            !string.Equals(root.GetProperty("mailbox").GetString(), cloud.Mailbox, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(root.GetProperty("tenantId").GetString(), cloud.Tenant.ToString(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Microsoft 365 application is not marked ready for this tenant and mailbox.");
        WriteLine("Verified scoped Exchange application role (from local result). Client ID: " + root.GetProperty("clientId").GetString());
        WriteLine("This is a configuration checkpoint, not a live Exchange Online authorization recheck.");
    }

    private async Task<(Guid Tenant, string Mailbox, string Client)> ReadyStateAsync()
    {
        await VerifyM365Async();
        var cloud = CloudInputs();
        using var state = JsonDocument.Parse(await File.ReadAllTextAsync(StatePath(cloud.Tenant)));
        string client = state.RootElement.GetProperty("clientId").GetString() ?? "";
        if (!Guid.TryParse(client, out var app) || app == Guid.Empty)
            throw new InvalidDataException("Entra application ID is invalid.");
        // A new Linux host needs a new Entra certificate credential. Fail rather than silently reuse another host's identity.
        string pem = await SshRemote.ReadPublicCertificateAsync(Endpoint(), CancellationToken.None);
        using var cert = X509Certificate2.CreateFromPem(pem);
        var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cert.RawData));
        if (!sha.Equals(state.RootElement.GetProperty("certificateSha256").GetString(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The Linux certificate does not match the certificate registered with Entra.");
        return (cloud.Tenant, cloud.Mailbox, app.ToString());
    }

    private async Task PreflightAsync()
    {
        EnsureRoutingLoaded();
        if (mailTransport.SelectedIndex is 1 or 2)
        {
            await CheckOutboundModeAsync();
            return;
        }
        var result = await SshRemote.ExecuteAsync(Endpoint(),
            "echo '=== identity ==='; id; echo '=== OS ==='; cat /etc/os-release; " +
            "echo '=== Postfix ==='; command -v postconf && postconf -h relayhost && postconf -h default_transport || true; " +
            "echo '=== SMTP 587 connectivity ==='; timeout 8 bash -c 'echo >/dev/tcp/smtp.office365.com/587' && echo reachable || echo blocked; " +
            "echo '=== HTTPS 443 connectivity ==='; timeout 8 bash -c 'echo >/dev/tcp/login.microsoftonline.com/443' && echo reachable || echo blocked", timeout: TimeSpan.FromSeconds(45));
        result.EnsureSuccess();
        WriteLine(result.StdOut);
    }


    private async Task ConfirmCurrentActiveMtaForInstallationAsync(
        SshEndpoint endpoint, MailRoutingInventory installed)
    {
        // Postconf binary presence is NOT evidence that Postfix is running.
        // Re-read services and standard SMTP sockets immediately before any
        // package install, Postfix restart or route modification.
        var probe = await SshRemote.ExecuteAsync(endpoint, "bash -s",
            EmbeddedAssets.BuildExistingSmtpAuditBundle(),
            timeout: TimeSpan.FromSeconds(100));
        probe.EnsureSuccess();
        var liveAudit = ExistingSmtpAudit.Parse(probe.StdOut);
        string safety = MailServerDiscoveryDecision.InstallationSafetyStatus(
            installed, liveAudit);
        if (safety != "ready")
        {
            // A clean, explicitly reviewed package bootstrap may leave a
            // DISABLED primary Postfix. Require verified root-owned hashes and
            // zero SMTP listeners before the first isolated EOP installation.
            if (installed.Mta == "postfix" &&
                liveAudit.Mta == "no_active_mta_verified" &&
                mailTransport.SelectedIndex is 1 or 2)
            {
                if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int port))
                    throw new InvalidDataException("A custom SMTP port is required.");
                var prepared = await CleanBootstrapScriptAsync(
                    endpoint, "verify", port);
                prepared.EnsureSuccess();
                if (prepared.StdOut.Contains("CLEAN_POSTFIX_PREPARED_VERIFIED=yes",
                      StringComparison.Ordinal) &&
                    prepared.StdOut.Contains("CLEAN_POSTFIX_PREPARED_CUSTOM_PORT=" +
                      port, StringComparison.Ordinal) &&
                    prepared.StdOut.Contains("POSTFIX_PRIMARY_STARTED=no",
                      StringComparison.Ordinal))
                {
                    WriteLine("Inactive primary Postfix is verified against the one-time " +
                        "root-owned clean-bootstrap marker; first isolated EOP setup permitted.");
                    return;
                }
            }
            throw new InvalidOperationException(
                "Current active MTA does not safely match the inspected Linux configuration: " +
                safety + ". No installation performed. Run read-only MTA discovery again.");
        }
        WriteLine("Active MTA rechecked immediately before Apply; type matches installed MTA. " +
                  "This is not proof of an Internet-safe relay or Microsoft 365 delivery.");
    }

    private async Task ApplyAsync()
    {
        EnsureRoutingLoaded();
        if (mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 1)
            throw new NotSupportedException(
                "Multi-mailbox XOAUTH2 is an unimplemented planning option. The active transport rewrites all From addresses to one mailbox. Do not deploy until sender ownership and Exchange grants are verified.");
        routingPlan.ListenIpv4 = smtpListenIp.Text.Trim();
        routingPlan.TrustedCidrs = smtpTrustedCidrs.Text.Trim();
        if (!int.TryParse(isolatedSmtpPort.Text.Trim(), out int selectedPort))
            throw new InvalidDataException("Enter an isolated SMTP port from 1024 to 65535.");
        routingPlan.SidecarPort = selectedPort;
        MailRoutingPlanStore.Validate(routingPlan);
        if (publicInternetRequested.Checked)
            throw new NotSupportedException("The ordinary installer never opens public SMTP. Clear the public plan to install private SMTP, then use Advanced SMTP > reviewed public AUTH/TLS activation.");
        var chosenTransport = mailTransport.SelectedIndex switch
        {
            1 => "connector", 2 => "direct-send", _ => "oauth2"
        };
        var chosenSender = senderPolicy.SelectedIndex;
        if (chosenTransport != "oauth2" || chosenSender != 0)
            throw new NotSupportedException("Main Install applies XOAUTH2 only. For Direct Send or Connector, install the isolated Postfix first and use Advanced SMTP → EOP route Preview / Apply. Connector sender handling is available under the isolated EOP route. No Postfix changes were applied.");
        var endpoint = Endpoint();
        var observed = await SshRemote.ProbeSecurityAsync(endpoint,
            EmbeddedAssets.SecurityProbe, CancellationToken.None);
        observed.EnsureSuccess();
        var inventory = MailRoutingInventory.Parse(observed.StdOut);
        if (inspectedMail is null || inspectedServerIdentity != SecurityOptionsStore.Identity(endpoint))
            throw new InvalidOperationException("First inspect the existing Linux mail server. No changes made.");
        if (inspectedMail != inventory)
            throw new InvalidOperationException("Postfix configuration changed since inspection, including main.cf/master.cf fingerprint. Inspect again.");
        await ConfirmCurrentActiveMtaForInstallationAsync(endpoint, inventory);
        if (inventory.Mta is "sendmail" or "exim")
            throw new NotSupportedException("Sendmail/Exim are protected. Isolated gateway for these MTAs is planned but not implemented.");
        if (inventory.Mta == "postfix" && preserveExistingMail.Checked)
        {
            if (allowExisting.Checked)
                throw new InvalidOperationException("Choose Preserve Existing Mail OR Force Replace, never both.");
            // This path does not modify the primary Postfix configuration,
            // restart its service, or write to its existing mail queue.
            var sidecarState = await ReadyStateAsync();
            var confirmation = MessageBox.Show(this, T(
                "Установить отдельный экземпляр Postfix на TCP " + routingPlan.SidecarPort + "? Существующий Postfix (порт 25) и его очередь останутся без изменений. Сетевой SMTP допускается только из доверенных подсетей.",
                "Install isolated Postfix on TCP " + routingPlan.SidecarPort + "? Existing port 25, mail routing and queue stay untouched. Remote clients require trusted subnets.",
                "להתקין מופע Postfix נפרד בפורט " + routingPlan.SidecarPort + "?"),
                Text, MessageBoxButtons.YesNo, MessageBoxIcon.Information);
            if (confirmation != DialogResult.Yes) return;
            var isolatedArgs = new List<string> {
                "--tenant-id", sidecarState.Tenant.ToString(), "--client-id", sidecarState.Client,
                "--mailbox", sidecarState.Mailbox, "--smtp-port", routingPlan.SidecarPort.ToString()
            };
            if (routingPlan.ListenIpv4.Length > 0)
            {
                isolatedArgs.Add("--listen-ip");
                isolatedArgs.Add(routingPlan.ListenIpv4);
                foreach (var cidr in routingPlan.TrustedCidrs.Split(',',
                             StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    isolatedArgs.Add("--trusted-network");
                    isolatedArgs.Add(cidr);
                }
            }
            WriteLine("Installing isolated SMTP gateway (Postfix TCP " + routingPlan.SidecarPort + ", independent queue); primary MTA unchanged.");
            var installed = await SshRemote.RunRootScriptAsync(endpoint,
                EmbeddedAssets.BuildSidecarBundle([.. isolatedArgs]), TimeSpan.FromMinutes(5));
            installed.EnsureSuccess();
            WriteLine(installed.StdOut);
            WriteLine("Sidecar installed. Test SMTP port " + routingPlan.SidecarPort + " and independently verify Microsoft 365 delivery.");
            inspectedMail = null;
            inspectedServerIdentity = null;
            allowExisting.Checked = false;
            return;
        }
        if (inventory.Mta == "postfix" &&
            !System.Text.RegularExpressions.Regex.IsMatch(inventory.ConfigSha256, @"^[a-f0-9]{64}$"))
            throw new InvalidOperationException("Cannot verify Postfix configuration SHA-256. Force Replace disabled.");
        if (inventory.Mta == "postfix" && !allowExisting.Checked)
            throw new InvalidOperationException("Force Replace requires explicit selection after MTA inspection.");
        bool force = inventory.Mta == "postfix";
        string publicExposureWarning = existingSmtpAuditIdentity == SecurityOptionsStore.Identity(endpoint) &&
            existingSmtpAudit?.PotentiallyPublic == true
            ? T("\nОБНАРУЖЕН ПОТЕНЦИАЛЬНО ПУБЛИЧНЫЙ SMTP: замена может прервать входящую почту из интернета и старые маршруты.",
                "\nPOTENTIALLY PUBLIC SMTP DETECTED: replacing may disrupt inbound internet mail and legacy routes.",
                "\nזוהתה האזנת SMTP ציבורית אפשרית. החלפת ההגדרות עלולה לשבש דואר נכנס.")
            : T("\nПубличный SMTP не подтверждён: проверка требует внешней проверки NAT/firewall и клиентской доставки.",
                "\nPublic SMTP exposure is not confirmed. NAT/firewall and actual external delivery require separate verification.",
                "\nמצב הגישה מהאינטרנט אינו מאומת.");
        if (force && !ConfirmDestructive("LinuxMailRelay365 | Force Replace Postfix",
            T("ОПАСНО: будут перезаписаны настройки Postfix, включая маршруты, входящую почту и параметры SMTP. Будет создан и проверен полный backup /etc/postfix. Возможен перерыв почтового обслуживания.",
              "DANGER: Postfix settings and routes will be overwritten; inbound and outbound mail may be interrupted. A verified /etc/postfix backup is mandatory; automatic rollback is attempted on failure.",
              "אזהרה: הגדרות Postfix יוחלפו. ייווצר גיבוי מאומת.") + publicExposureWarning,
            "REPLACE POSTFIX")) return;
        var state = await ReadyStateAsync();
        var approval = MessageBox.Show(this,
            T("Применить настройку Postfix на Linux? Конфигурация будет сохранена в резервных копиях.\nНе продолжайте, если сервер обслуживает другую почту без предварительной проверки.",
              "Apply Postfix configuration on Linux? Backups will be saved. Review existing mail workloads first.",
              "להחיל הגדרות Postfix בלינוקס? תיווצר תצורת גיבוי."),
            Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (approval != DialogResult.Yes) return;
        var arguments = new List<string> { "--tenant-id", state.Tenant.ToString(), "--client-id", state.Client,
                                           "--mailbox", state.Mailbox };
        if (force)
        {
            arguments.Add("--force-replace");
            arguments.Add("--confirm-force-replace");
            arguments.Add("REPLACE_POSTFIX_CONFIG");
            arguments.Add("--expect-postfix-sha256");
            arguments.Add(inventory.ConfigSha256);
        }
        if (routingPlan.ListenIpv4.Length > 0)
        {
            arguments.Add("--listen-ip");
            arguments.Add(routingPlan.ListenIpv4);
            foreach (var cidr in routingPlan.TrustedCidrs.Split(',',
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                arguments.Add("--trusted-network");
                arguments.Add(cidr);
            }
        }
        WriteLine("Installing Postfix XOAUTH2 transport (no mailbox passwords, no refresh token, no client secret)...");
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildLinuxBundle([.. arguments]), TimeSpan.FromMinutes(15));
        result.EnsureSuccess();
        WriteLine(result.StdOut);
        WriteLine("Postfix installation finished; Microsoft 365 delivery must be verified with a test message.");
        inspectedMail = null;
        inspectedServerIdentity = null;
        allowExisting.Checked = false;
    }

    private async Task DiagnosticsAsync()
    {
        EnsureRoutingLoaded();
        if (mailTransport.SelectedIndex != 0 || oauthSenderMode.SelectedIndex != 0)
            throw new NotSupportedException(
                "OAuth token diagnostics require the active single-mailbox XOAUTH2 route. " +
                "For EOP or planned multi-mailbox routes, use read-only SMTP health and route checks.");
        var endpoint = Endpoint();
        bool isolated = await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None);
        var result = isolated
            ? await SshRemote.SidecarDiagnosticsAsync(endpoint, CancellationToken.None)
            : await SshRemote.DiagnosticsAsync(endpoint, CancellationToken.None);
        result.EnsureSuccess();
        WriteLine(isolated ? "Isolated SMTP port " + await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None) + " with separate Postfix queue." : "Primary Postfix mode.");
        WriteLine(result.StdOut);
        WriteLine("Token-check verifies Entra authorization, not delivery; check Exchange and recipient logs.");
    }

    private async Task SendTestAsync()
    {
        EnsureRoutingLoaded();
        if (mailTransport.SelectedIndex is 1 or 2)
            throw new NotSupportedException(
                "The standard test email button is XOAUTH2-only. For Connector or Direct Send first verify the active EOP route and use the separately approved private SMTP acceptance workflow. This button will not send with unrelated XOAUTH2 credentials.");
        if (mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 1)
            throw new NotSupportedException(
                "Multi-mailbox XOAUTH2 has not been installed or verified. The current transport uses one fixed mailbox; no test email was sent.");
        var cloud = CloudInputs();
        string dest = testRecipient.Text.Trim();
        if (!SshRemote.IsEmail(dest)) throw new ArgumentException("Invalid test recipient.");
        var endpoint = Endpoint();
        bool isolated = await SshRemote.HasIsolatedSidecarAsync(endpoint, CancellationToken.None);
        int installedPort = isolated
            ? await SshRemote.GetIsolatedSidecarPortAsync(endpoint, CancellationToken.None)
            : 0;
        if (isolated)
        {
            var authState = await SshRemote.IsSidecarAuthTlsEnabledAsync(endpoint, CancellationToken.None);
            if (authState != false)
            {
                WriteLine(authState == true
                    ? "SMTP AUTH/STARTTLS is enabled on isolated TCP " + installedPort +
                      ". The wizard intentionally does not store client credentials and cannot submit an anonymous test. " +
                      "Send a test from an authenticated application; use Diagnostics to check the OAuth token and queue."
                    : "Isolated SMTP security settings are ambiguous. Test submission blocked pending manual inspection.");
                return;
            }
        }
        var result = isolated
            ? await SshRemote.SendIsolatedSidecarTestAsync(endpoint, cloud.Mailbox, dest, installedPort, CancellationToken.None)
            : await SshRemote.SendTestAsync(endpoint, cloud.Mailbox, dest, CancellationToken.None);
        result.EnsureSuccess();
        WriteLine(isolated ? "Test message accepted by isolated SMTP :" + installedPort + ". " + result.StdOut
                           : "Test submitted to primary Postfix. " + result.StdOut);
        WriteLine("Verify Exchange delivery; acceptance by a local queue is not final delivery.");
    }

    private async Task StageUpdateWithProgressAsync(
        SignedUpdateOffer offer, string publisher, bool unsignedPreview = false)
    {
        using var cancellation = new CancellationTokenSource();
        var working = Screen.FromControl(this).WorkingArea.Size;
        using var dialog = new Form
        {
            Text = unsignedPreview
                ? T("Установка тестовой Preview", "Install test Preview", "התקנת גרסת ניסיון")
                : T("Установка подписанного обновления", "Install signed update",
                    "התקנת עדכון חתום"),
            StartPosition = FormStartPosition.CenterParent,
            ClientSize = PreferredDialogSize(working, DeviceDpi, 700, 300),
            MinimumSize = PreferredDialogSize(working, DeviceDpi, 520, 260),
            AutoScaleMode = AutoScaleMode.Dpi,
            BackColor = UiTheme.Canvas,
            ForeColor = UiTheme.Navy,
            FormBorderStyle = FormBorderStyle.Sizable,
            MaximizeBox = false, MinimizeBox = false
        };
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4,
            Padding = new Padding(20, 16, 20, 16)
        };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var description = UiTheme.Text(unsignedPreview
            ? T("Тестовая неподписанная версия: SHA-256 GitHub, архитектура, версия и self-test, резервная копия и откат.",
                "Unsigned TEST Preview: verify GitHub SHA-256, architecture, version and self-test, then back up and roll back on failure.",
                "גרסת ניסיון לא חתומה: אימות SHA-256, ארכיטקטורה, גרסה ובדיקת תקינות.")
            : T("Скачивание. Проверяем SHA-256, Authenticode, сертификат издателя и self-test. Неподписанный EXE не будет запущен.",
                "Downloading. Checking SHA-256, Authenticode, publisher certificate and self-test. Unsigned EXEs will not execute.",
                "מוריד ומוודא חתימה, SHA-256 ובדיקת תקינות."));
        description.Dock = DockStyle.Fill;
        var progressText = UiTheme.Text(T(
            "Подготовка загрузки...", "Preparing download...", "מכין הורדה..."));
        progressText.Dock = DockStyle.Fill;
        var bar = new ProgressBar
        {
            Dock = DockStyle.Top, Minimum = 0, Maximum = 100,
            Value = 0, Height = Math.Max(22, (int)Math.Round(25 * Math.Max(1f, DeviceDpi / 96f))),
            Style = ProgressBarStyle.Continuous
        };
        var cancel = UiTheme.Action(T("Отмена", "Cancel", "ביטול"), false, "back");
        cancel.Click += (_, _) =>
        {
            if (cancellation.IsCancellationRequested) return;
            cancellation.Cancel();
            cancel.Enabled = false;
            progressText.Text = T("Отмена загрузки...", "Cancelling download...", "מבטל הורדה...");
        };
        dialog.FormClosing += (_, args) =>
        {
            if (cancellation.IsCancellationRequested) return;
            if (updateShuttingDown) return;
            cancellation.Cancel();
            args.Cancel = true;
        };
        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft, WrapContents = true
        };
        actions.Controls.Add(cancel);
        panel.Controls.Add(description, 0, 0);
        panel.Controls.Add(progressText, 0, 1);
        panel.Controls.Add(bar, 0, 2);
        panel.Controls.Add(actions, 0, 3);
        dialog.Controls.Add(panel);
        dialog.CancelButton = cancel;
        dialog.Show(this);
        try
        {
            var progress = new Progress<(long, long)>(data =>
            {
                if (dialog.IsDisposed) return;
                int percent = data.Item2 <= 0 ? 0 :
                    (int)Math.Min(100, data.Item1 * 100 / data.Item2);
                bar.Value = Math.Clamp(percent, 0, 100);
                double received = data.Item1 / 1048576.0;
                double total = data.Item2 / 1048576.0;
                progressText.Text = T("Загружено: ", "Downloaded: ", "הורדו: ") +
                    received.ToString("F1") + " / " + total.ToString("F1") + " MiB (" +
                    percent + "%)";
            });
            await SignedPortableUpdater.StageAndLaunchAsync(
                offer, publisher, cancellation.Token, progress, unsignedPreview);
        }
        finally
        {
            // The signed helper is either launched or the download failed.
            // Do not leave a window on screen during parent EXE shutdown.
            updateShuttingDown = true;
            dialog.Close();
            updateShuttingDown = false;
        }
    }

    private void AddUpdateAccess(TableLayoutPanel page)
    {
        string last = SignedPortableUpdater.LastUpdateStatus();
        if (last.Length > 0)
        {
            string summary = last switch
            {
                "INSTALLED" => T("Последнее обновление: установлено успешно.",
                    "Last update: installed successfully.", "העדכון האחרון הותקן בהצלחה."),
                "ROLLED_BACK" => T("Последнее обновление: выполнен откат.",
                    "Last update: rolled back.", "העדכון האחרון בוטל."),
                "MANUAL_REVIEW_REQUIRED" => T(
                    "Updater заблокирован после ошибки. Проверьте резервную копию.",
                    "Updater blocked after an error. Review the backup before retrying.",
                    "העדכון חסום בעקבות תקלה. נדרשת בדיקה ידנית."),
                "UNAVAILABLE" => T("Статус предыдущего обновления недоступен.",
                    "Previous update status is unavailable.", "סטטוס העדכון הקודם אינו זמין."),
                _ => T("Статус предыдущего обновления не распознан.",
                    "Previous update status was not recognized.", "מצב העדכון הקודם אינו מזוהה.")
            };
            AddLine(page, UiTheme.Text(summary));
        }
        previewUpdates.Text = T("Включая Preview/RC", "Include Preview/RC",
            "כולל גרסאות ניסיון");
        AddLine(page, previewUpdates);
        AddAction(page, T("Проверить обновление GitHub",
            "Check GitHub updates", "בדיקת עדכוני GitHub"),
            CheckUpdatesAsync, false, "refresh", "update");
    }

    private async Task CheckUpdatesAsync()
    {
        WriteLine("Checking published GitHub Releases. CI preview artifacts are not releases.");
        bool withPreview = previewUpdates.Checked;
        var (url, message) = await UpdateCheck.QueryAsync(withPreview, CancellationToken.None);
        releaseUrl = url;
        WriteLine(message);
        if (url is null)
        {
            WriteLine(T(
                "Подходящих релизов нет. Неподписанные Preview EXE нельзя устанавливать автоматически.",
                "No eligible published release. Unsigned CI preview EXEs cannot be installed automatically.",
                "אין גרסה שפורסמה. קובצי CI לא חתומים אינם מותקנים אוטומטית."));
            return;
        }

        var offer = await SignedPortableUpdater.FindAsync(withPreview, CancellationToken.None);
        if (offer is null || !string.Equals(offer.PageUrl, url, StringComparison.Ordinal))
            throw new InvalidDataException("Release metadata changed; repeat the update check.");

        // Only a non-elevated unsigned Preview can install another test Preview.
        // Stable and already-signed installations never use this weaker path.
        if (withPreview && SignedPortableUpdater.IsPreviewRelease(offer) &&
            SignedPortableUpdater.CanInstallPreview(out _))
        {
            var previewAction = MessageBox.Show(this, T(
                "ВНИМАНИЕ: это НЕПОДПИСАННЫЙ тестовый Preview, НЕ Stable. GitHub SHA-256 проверяет скачанный файл, но НЕ является цифровой подписью издателя. Только тестовый ПК. Сохраните важную работу. После согласия EXE заменится с .bak и откатом при сбое.\n\nДа — установить, Нет — открыть релиз, Отмена — ничего.",
                "WARNING: this is an UNSIGNED TEST Preview, NOT Stable. GitHub SHA-256 checks downloaded bytes but is NOT a trusted publisher signature. Test PCs only; save important work. With consent the EXE is replaced with .bak and rollback on failure.\n\nYes: install, No: open release, Cancel: do nothing.",
                "אזהרה: גרסת ניסיון לא חתומה, לא Stable. SHA-256 אינו תחליף לחתימת מפרסם. לבדיקה בלבד."),
                Text, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button3);
            if (previewAction == DialogResult.No)
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                return;
            }
            if (previewAction != DialogResult.Yes) return;
            WriteLine("Installing approved UNSIGNED TEST Preview; validating release SHA-256, architecture and self-test.");
            await StageUpdateWithProgressAsync(offer, "", unsignedPreview: true);
            WriteLine("Preview update verified; closing EXE for backup and replacement.");
            updateShuttingDown = true;
            Close();
            return;
        }
        if (withPreview && SignedPortableUpdater.IsPreviewRelease(offer) &&
            !SignedPortableUpdater.CanInstallPreview(out var previewReason))
            WriteLine("Unsigned Preview update unavailable: " + previewReason);

        if (!SignedPortableUpdater.CanInstall(out string publisher, out string reason))
        {
            WriteLine("Signed automatic update is blocked: " + reason);
            var open = MessageBox.Show(this, T(
                "Текущий EXE не подписан доверенным издателем. Автоустановка запрещена. Открыть страницу релиза?",
                "The installed EXE is not signed by a Windows-trusted publisher. Auto-install is blocked. Open release page?",
                "קובץ ההפעלה הנוכחי אינו חתום באופן מהימן. התקנה אוטומטית חסומה. לפתוח דף גרסה?"),
                Text, MessageBoxButtons.YesNo, MessageBoxIcon.Information,
                MessageBoxDefaultButton.Button2);
            if (open == DialogResult.Yes)
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            return;
        }

        var action = MessageBox.Show(this, T(
            "Доступен релиз. Установка будет разрешена только после проверки URL GitHub, SHA-256, архитектуры, Windows Authenticode и ТОГО ЖЕ сертификата издателя. Приложение закроется, проверенный помощник создаст .bak, выполнит self-test и откатит ошибочную замену.\n\nДа — установить, Нет — открыть страницу, Отмена — ничего не делать.",
            "A published release is available. Before installation, the updater verifies exact GitHub origin, SHA-256, architecture, Windows Authenticode and the SAME publisher certificate. The app will close; a signed helper creates .bak, runs self-test, and rolls back a failed update.\n\nYes: install, No: open page, Cancel: nothing.",
            "קיים עדכון. לפני ההתקנה ייבדקו מקור GitHub, חתימה, SHA-256 וארכיטקטורה. התוכנה תיסגר והמערכת תגבה ותבדוק את הגרסה."),
            Text, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button3);
        if (action == DialogResult.No)
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            return;
        }
        if (action != DialogResult.Yes) return;
        WriteLine("Downloading published signed update; validating SHA-256, publisher, PE machine and self-test.");
        await StageUpdateWithProgressAsync(offer, publisher);
        WriteLine("Publisher-pinned update verified; closing original EXE for external replacement.");
        updateShuttingDown = true;
        Close();
    }
}
