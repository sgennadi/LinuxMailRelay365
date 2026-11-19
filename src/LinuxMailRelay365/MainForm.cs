using System.Diagnostics;
using System.Drawing;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed class MainForm : Form
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
    private readonly TextBox mailbox = Field("");
    private readonly TextBox testRecipient = Field("");
    private readonly CheckBox allowExisting = new() { AutoSize = true };
    private readonly ComboBox backupSelector = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private readonly ComboBox sidecarBackupSelector = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private string? reviewedSidecarRestoreSha;
    private string? reviewedSidecarRestoreId;
    private string? reviewedSidecarRestoreIdentity;
    private MailRoutingInventory? inspectedMail;
    private string? inspectedServerIdentity;
    private ExistingSmtpAudit? existingSmtpAudit;
    private string? existingSmtpAuditIdentity;
    private readonly ComboBox mailTransport = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private readonly ComboBox senderPolicy = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
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
    private string cloudSecuritySummary = "Не проверено";
    private readonly CheckBox previewUpdates = new() { AutoSize = true, Checked = true };
    private readonly ComboBox language = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
    private readonly Label headline = UiTheme.Text("", true);
    private readonly Label subheading = UiTheme.Text("");
    private readonly Panel pageHost = new() { Dock = DockStyle.Fill, AutoScroll = true, BackColor = UiTheme.Canvas };
    private readonly FlowLayoutPanel navigation = new() { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
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
        MinimumSize = new Size(720, 630);
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;

        var work = Screen.FromPoint(Cursor.Position).WorkingArea;
        Size = new Size(Math.Min(1050, work.Width - 25), Math.Min(850, work.Height - 25));

        Directory.CreateDirectory(dataDirectory);
        sshPassword.UseSystemPasswordChar = true;
        sudoPassword.UseSystemPasswordChar = true;
        sshAuthMode.Items.AddRange(["SSH key / ssh-agent", "SSH username + password"]);
        mailTransport.Items.AddRange([
            "XOAUTH2 · sender mailbox (available)",
            "M365 SMTP Connector · existing tenant Connector (Advanced apply)",
            "Direct Send · internal recipients only (Advanced apply)"
        ]);
        senderPolicy.Items.AddRange([
            "Fixed Microsoft 365 sender mailbox (available)",
            "Preserve sender within verified domain (Connector only)",
            "Masquerade subdomain sender into accepted domain (Connector only)"
        ]);
        tpmDependencyProfile.Items.AddRange([
            "TPM2 utilities (RHEL/Oracle/Rocky/Alma 8-10)",
            "TPM2 development/build prerequisites (RHEL 8-10)",
            "TPM2 PKCS#11 OpenSSL 3 path (RHEL 9/10)",
            "Native TPM2 OpenSSL provider (RHEL 10 only)"
        ]);
        tpmDependencyProfile.SelectedIndex = 0;
        tpmDependencyProfile.SelectedIndexChanged += (_, _) =>
        {
            reviewedTpmPlanSha = null;
            reviewedTpmPlanContext = null;
            tpmPlanSummary = "";
            if (step == 1 && !busy) RenderPage();
        };
        smtpAccountOperation.Items.AddRange(["Add", "Rotate", "Revoke"]);
        smtpAccountOperation.SelectedIndex = 0;
        mailTransport.SelectedIndex = 0;
        senderPolicy.SelectedIndex = 0;
        mailTransport.SelectedIndexChanged += (_, _) => {
            if (!routingLoading) {
                acceptedDomainApproved.Checked = false;
                connectorApproved.Checked = false;
            }
            SaveRoutingChoices(); UpdatePreserveFlowPreview();
            if (step == 3 && !routingLoading && !busy)
            {
                int previousScroll = -pageHost.AutoScrollPosition.Y;
                RenderPage();
                pageHost.AutoScrollPosition = new Point(0, previousScroll);
            }
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
                                         isolatedSmtpPort, smtpTrustedCidrs, acceptedDomain })
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
        sshAuthMode.SelectedIndexChanged += (_, _) => { if (!busy && step == 0) RenderPage(); };
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
        top.Controls.Add(UiTheme.Text("LINUX MAIL RELAY 365  ·  " + UpdateCheck.Version, true), 1, 0);
        top.Controls.Add(language, 2, 0);

        var header = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Padding = new Padding(18, 0, 18, 6) };
        header.Controls.Add(headline);
        header.Controls.Add(subheading);

        var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, ColumnCount = 1, Padding = new Padding(18, 2, 18, 12) };
        bottom.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        bottom.RowStyles.Add(new RowStyle(SizeType.Absolute, 145));
        bottom.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        bottom.Controls.Add(navigation, 0, 0);
        bottom.Controls.Add(activity, 0, 1);
        bottom.Controls.Add(status, 0, 2);

        var shell = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 4, ColumnCount = 1 };
        shell.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        shell.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        shell.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        shell.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        shell.Controls.Add(top, 0, 0);
        shell.Controls.Add(header, 0, 1);
        shell.Controls.Add(pageHost, 0, 2);
        shell.Controls.Add(bottom, 0, 3);
        Controls.Add(shell);
        pageHost.SizeChanged += (_, _) => ResizePreserveFlowHelp();
        RenderPage();
        WriteLine("Ready. No user passwords, app secrets, or OAuth tokens are stored by this manager.");
    }

    private string T(string russian, string english, string hebrew) =>
        language.SelectedIndex switch { 1 => english, 2 => hebrew, _ => russian };

    private static void AddLine(TableLayoutPanel table, Control control)
    {
        int row = table.RowCount++;
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        table.Controls.Add(control, 0, row);
    }

    private TableLayoutPanel NewPage()
    {
        return new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1, RowCount = 0,
            Padding = new Padding(20, 4, 20, 15),
            BackColor = UiTheme.Canvas,
            MaximumSize = new Size(1020, 0)
        };
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

    private void RenderPage()
    {
        if (IsDisposed) return;
        var titles = new[]
        {
            T("1 · Подключение к Linux", "1 · Linux connection", "1 · חיבור ל-Linux"),
            T("2 · Проверка защиты (необязательно)", "2 · Optional security checks", "2 · בדיקות אבטחה אופציונליות"),
            T("3 · Microsoft 365", "3 · Microsoft 365", "3 · Microsoft 365"),
            T("4 · Настройка Postfix", "4 · Configure Postfix", "4 · הגדרת Postfix"),
            T("5 · Проверка и обслуживание", "5 · Diagnostics and updates", "5 · אבחון ועדכונים")
        };
        headline.Text = titles[step];
        subheading.Text = step switch
        {
            0 => T("Любой Linux с SSH и правами sudo. Пароль Microsoft 365 не нужен.",
                   "Any Linux with SSH and sudo access. No Microsoft 365 mailbox password.",
                   "כל שרת Linux עם SSH ו-sudo. ללא סיסמת Microsoft 365."),
            1 => T("Ничего не включаем автоматически. Проверки только читают текущую конфигурацию.",
                   "Nothing is enabled automatically. Checks are read-only.",
                   "לא מפעילים דבר אוטומטית. הבדיקות לקריאה בלבד."),
            2 => T("Сертификат создаётся на Linux. В Windows передаётся только открытая часть.",
                   "The certificate is generated on Linux; only the public part is copied to Windows.",
                   "האישור נוצר בלינוקס ורק החלק הציבורי מועבר ל-Windows."),
            3 => T("Перед изменением Postfix создаются резервные копии конфигурации.",
                   "Backups are created before Postfix configuration is changed.",
                   "גיבוי תצורת Postfix נוצר לפני כל שינוי."),
            _ => T("Тест токена, SMTP, очереди и проверка GitHub Stable/Preview.",
                   "Token, SMTP, queue, and GitHub Stable/Preview checks.",
                   "בדיקת אסימון, SMTP, תור ועדכוני GitHub.")
        };
        pageHost.SuspendLayout();
        pageHost.Controls.Clear();
        var page = NewPage();
        pageHost.Controls.Add(page);
        pageHost.AutoScrollPosition = Point.Empty;
        ResizePreserveFlowHelp();
        switch (step)
        {
            case 0:
                AddField(page, T("Linux: DNS-имя или IPv4", "Linux host (DNS or IPv4)", "כתובת שרת Linux"), host);
                AddField(page, T("SSH-порт", "SSH port", "פורט SSH"), sshPort);
                AddField(page, T("SSH-пользователь", "SSH username", "משתמש SSH"), sshUser);
                AddLine(page, UiTheme.Text(T("Способ входа по SSH", "SSH authentication", "שיטת SSH")));
                AddLine(page, sshAuthMode);
                if (sshAuthMode.SelectedIndex == 1)
                {
                    AddField(page, T("Пароль SSH (не сохраняется)", "SSH password (not saved)", "סיסמת SSH"), sshPassword);
                    AddField(page, T("Проверенный SSH host key SHA256 (обязательно, вне SSH-соединения)",
                                     "Verified SSH host key SHA256 (required, obtain out-of-band)",
                                     "טביעת SHA256 מאומתת של השרת"), sshFingerprint);
                }
                else
                {
                    AddField(page, T("Путь к SSH-ключу (или ssh-agent)", "SSH key path (or ssh-agent)", "מפתח SSH"), sshKey);
                }
                AddField(page, T("Пароль sudo (необязательно, не сохраняется)",
                                 "sudo password (optional, not saved)", "סיסמת sudo"), sudoPassword);
                AddAction(page, T("Проверить SSH и sudo", "Check SSH and sudo", "בדיקת SSH ו-sudo"), CheckSshAsync, true, "ssh", "ssh");
                AddLine(page, UiTheme.Text(T(
                    "SSH host key проверяется обязательно: ключевой режим — через known_hosts, парольный — по подтверждённому SHA256. Пароли не сохраняются на диск и не передаются в аргументах процесса.",
                    "Host-key verification is mandatory: known_hosts for key mode, verified SHA256 for password mode. Passwords are never persisted or placed in command arguments.",
                    "אימות מפתח השרת חובה. סיסמאות אינן נשמרות.")));
                break;
            case 1:
                EnsureSecurityLoaded();
                AddLine(page, UiTheme.Text(T(
                    "Все опции выключены. Выбор сохраняется как ПЛАН — он не меняет Entra, Postfix, сертификат или Linux. Для включения потребуются отдельные подтверждённые действия.",
                    "All options are off. Your selection is saved as a PLAN only: it does not modify Entra, Postfix, certificates or Linux. Activation requires separate approved steps.",
                    "כל האפשרויות כבויות. הבחירה נשמרת כתוכנית בלבד.")));
                AddAction(page, T("Проверить TPM, HSM и PKCS#11 (только чтение)",
                                  "Inspect TPM, HSM and PKCS#11 (read-only)",
                                  "בדוק TPM/HSM לקריאה בלבד"), CheckLinuxSecurityAsync, true, "shield", "linux-security");
                AddLine(page, UiTheme.Text(linuxSecurity?.SummaryRu() ??
                    T("Linux: проверка ещё не запускалась.", "Linux: not inspected yet.", "Linux: טרם נבדק.")));
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
                    AddLine(page, UiTheme.Text(tpmPlanSummary));
                    if (reviewedTpmPlanSha is not null)
                        AddAction(page, T("Установить недостающие TPM2 пакеты...",
                                          "Install reviewed missing TPM2 packages...",
                                          "התקנת חבילות TPM2 לאחר אישור"),
                                          InstallTpmDependenciesAsync, false, "shield", "tpm-deps-apply");
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
                AddAction(page, "Connect to Microsoft 365 and discover tenants", DiscoverTenantsAsync, true, "cloud", "tenant-discovery");
                if (discoveredTenants.Count > 0)
                {
                    AddLine(page, UiTheme.Text(discoveredTenants.Count == 1
                        ? "One Entra tenant discovered and selected automatically."
                        : "Multiple Entra tenants detected. Select the correct organization before configuring anything."));
                    AddLine(page, tenantSelector);
                    AddAction(page, "Use manual Tenant ID instead", UseManualTenantAsync, false, "gear");
                }
                AddField(page, "Selected Tenant ID (auto-filled or manual GUID)", tenant);
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
                AddLine(page, UiTheme.Text(T("Отправка через Microsoft 365", "Microsoft 365 delivery method", "שיטת שליחה דרך Microsoft 365")));
                AddLine(page, mailTransport);
                AddLine(page, UiTheme.Text(T("Обработка адреса отправителя", "Sender address handling", "טיפול בכתובת השולח")));
                AddLine(page, senderPolicy);
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
                    if (advancedSmtpTools.Checked)
                    {
                        AddLine(page, UiTheme.Text(T(
                            "Продвинутый маршрут применяется только к установленному отдельному Postfix. Direct Send блокирует внешних получателей. Используется один фиксированный отправитель; Connector в Tenant должен существовать до применения. Все изменения обратимы через отдельный Restore.",
                            "Advanced EOP routing applies only to isolated Postfix. NEW fixed-sender Connector and Direct Send can be installed without a prior XOAUTH2 sidecar, but an authorized tenant Connector must already exist for Connector delivery. Domain-preserving Connector policies require a reviewed existing sidecar.",
                            "ניתוב מתקדם למופע Postfix נפרד בלבד; Direct Send מוגבל לנמענים פנימיים.")));
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
                    AddField(page, T("FQDN отдельного SMTP для Exim/Sendmail (обязательно)",
                                     "Independent Postfix hostname FQDN for Exim/Sendmail (required)",
                                     "שם שרת Postfix עצמאי עבור Exim/Sendmail"), foreignSidecarHostname);
                AddField(page, T("Порт отдельного SMTP (Preserve Existing Mail; по умолчанию 2525)",
                                 "Isolated SMTP port (Preserve Existing Mail; default 2525)",
                                 "פורט SMTP נפרד (ברירת מחדל 2525)"), isolatedSmtpPort);
                AddField(page, T("Локальный IPv4 для SMTP (пусто = только loopback)",
                                 "Local IPv4 SMTP listener (blank = loopback only)",
                                 "כתובת IPv4 מקומית לקבלת SMTP"), smtpListenIp);
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
                if (preserveExistingMail.Checked)
                {
                    AddLine(page, UiTheme.Text(T(
                        "Как это работает: старые приложения остаются на текущем SMTP. Для новых указывайте отдельный адрес и порт из схемы. Письма уйдут через Microsoft 365 от выбранного mailbox; адреса получателей не меняются.",
                        "How it works: existing apps keep their current SMTP. Configure NEW apps with the separate server/port shown below. Microsoft 365 sends using the chosen mailbox; recipients are unchanged.",
                        "יישומים קיימים נשארים בשרת הקודם. ליישומים חדשים מגדירים שרת ויציאת SMTP נפרדים.")));
                    UpdatePreserveFlowPreview();
                    ResizePreserveFlowHelp();
                    AddLine(page, preserveFlowPreview);
                    AddLine(page, UiTheme.Text(T(
                        "Готовые настройки для конечного пользователя (из заполненных полей)",
                        "Ready-to-copy client setup (actual entered field values)",
                        "הגדרות ליישומי לקוח לפי הערכים שהוזנו")));
                    AddLine(page, preserveMailInstructions);
                    var copyInstructions = UiTheme.Action(
                        T("Копировать инструкции для приложений",
                          "Copy SMTP client setup instructions",
                          "העתקת הוראות הגדרת SMTP"), false, "copy");
                    copyInstructions.Enabled = !busy;
                    copyInstructions.Click += (_, _) => CopyPreserveInstructions();
                    AddLine(page, copyInstructions);
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
                AddAction(page, T("Установить и настроить Linux", "Install and configure Linux", "התקנה והגדרה ב-Linux"), ApplyAsync, true, "download", "postfix");
                AddAction(page, T("Создать проверенную резервную копию сейчас", "Create verified backup now", "יצירת גיבוי מאומת"),
                    BackupNowAsync, false, "shield", "backup");
                AddAction(page, T("Показать доступные резервные копии", "List verified backups", "רשימת גיבויים"),
                    ListBackupsAsync, false, "refresh", "backup");
                if (backupSelector.Items.Count > 0)
                {
                    AddLine(page, UiTheme.Text(T("Выберите backup для восстановления", "Select backup to restore", "בחר גיבוי לשחזור")));
                    AddLine(page, backupSelector);
                }
                AddAction(page, T("Восстановить выбранную конфигурацию...", "Restore selected configuration...", "שחזור תצורה קודמת"),
                    RestoreBackupAsync, false, "back", "restore");
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
                AddField(page, T("Кому отправить тестовое письмо", "Test recipient", "נמען בדיקה"), testRecipient);
                AddAction(page, T("Проверить токен и очередь", "Check OAuth token and mail queue", "בדיקת אסימון ותור"), DiagnosticsAsync, true, "check", "token");
                AddAction(page, T("Сохранить проверочное состояние перед перезагрузкой Linux",
                                  "Record server continuity baseline before Linux reboot",
                                  "שמירת מצב לפני הפעלה מחדש של Linux"),
                                  RecordRebootBaselineAsync, false, "shield", "reboot-baseline");
                AddAction(page, T("Проверить Postfix после ПОЛНОЙ перезагрузки Linux",
                                  "Verify services and config after a real Linux reboot",
                                  "בדיקת Postfix אחרי אתחול Linux"),
                                  VerifyRebootContinuityAsync, false, "check", "reboot-verify");
                AddAction(page, T("Отправить тестовое письмо", "Send test email", "שלח הודעת בדיקה"), SendTestAsync, false, "send", "smtp-test");
                AddAction(page, T("Резервные копии и Restore", "Backup & Restore", "גיבוי ושחזור"),
                    OpenBackupStepAsync, false, "shield", "backup");
                previewUpdates.Text = T("Включая Preview/RC", "Include Preview/RC", "כולל גרסאות ניסיון");
                AddLine(page, previewUpdates);
                AddAction(page, T("Проверить обновление GitHub", "Check GitHub updates", "בדיקת עדכוני GitHub"), CheckUpdatesAsync, false, "refresh", "update");
                AddAction(page, T("Центр защиты: проверить / настроить позже", "Security Center: inspect / configure later", "מרכז אבטחה"), OpenSecurityCenterAsync, false, "shield");
                AddAction(page, T("Копировать безопасный диагностический отчёт", "Copy privacy-safe diagnostic report", "העתק דוח אבחון בטוח"),
                    CopySafeReportAsync, false, "copy", "diagnostics");
                AddAction(page, T("Сохранить безопасный отчёт JSON", "Save privacy-safe JSON report", "שמור דוח JSON"),
                    SaveSafeReportAsync, false, "download", "diagnostics");
                break;
        }
        pageHost.ResumeLayout();

        navigation.Controls.Clear();
        var back = UiTheme.Action(T("Назад", "Back", "חזרה"), glyph: "back");
        back.Enabled = step > 0 && !busy;
        back.Click += (_, _) => { step--; RenderPage(); };
        navigation.Controls.Add(back);
        var next = UiTheme.Action(T("Далее", "Next", "הבא"), primary: true, glyph: "next");
        next.Enabled = step < 4 && !busy;
        next.Click += (_, _) =>
        {
            if (step == 0)
            {
                try { EnsureSecurityLoaded(); }
                catch (Exception ex) { WriteLine("ERROR: " + ex.Message); return; }
            }
            step++;
            RenderPage();
        };
        navigation.Controls.Add(next);
        status.Text = lastStatus ?? T("Готов к работе · Пароли M365 не сохраняются",
            "Ready · M365 mailbox passwords are never stored", "מוכן · סיסמאות M365 אינן נשמרות");
        status.ForeColor = lastFailed ? Color.FromArgb(174, 40, 43) : UiTheme.Muted;
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
            lastStatus = T("Ошибка — проверь журнал", "Error — review activity", "שגיאה — בדוק יומן");
        }
        finally { busy = false; RenderPage(); }
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
            sudoPassword.Text);
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
            acceptedDomain.Text.Trim());
    }

    private void ResizePreserveFlowHelp()
    {
        if (IsDisposed) return;
        int width = Math.Clamp(pageHost.ClientSize.Width - 54, 640, 890);
        preserveFlowPreview.Width = width;
        preserveMailInstructions.Width = width;
    }

    private void UpdatePreserveFlowPreview()
    {
        if (IsDisposed) return;
        var snapshot = CurrentPreserveFlowSnapshot();
        preserveFlowPreview.UpdateData(snapshot, language.SelectedIndex);
        preserveMailInstructions.Text = snapshot.ClientInstructions(language.SelectedIndex);
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
            return (inspectedMail.Mta, foreignSidecarHostname.Text.Trim());
        }
        return ("", "");
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
        var endpoint = Endpoint();
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
            WriteLine("Public SMTP audit could not complete; status UNKNOWN and requires manual review. " + error.Message);
        }
    }


    private string? TryCurrentIdentity()
    {
        try { return SecurityOptionsStore.Identity(Endpoint()); }
        catch (Exception ex) when (ex is ArgumentException or FileNotFoundException) { return null; }
    }

    private bool ConfirmDestructive(string dialogTitle, string explanation, string phrase)
    {
        using var dialog = new Form
        {
            Text = dialogTitle, StartPosition = FormStartPosition.CenterParent,
            ClientSize = new Size(675, 270), MinimumSize = new Size(560, 270),
            BackColor = UiTheme.Canvas, ForeColor = UiTheme.Navy,
            AutoScaleMode = AutoScaleMode.Dpi, MaximizeBox = false,
            MinimizeBox = false
        };
        var body = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 1, RowCount = 4,
            Padding = new Padding(20, 18, 20, 16)
        };
        var warning = UiTheme.Text(explanation);
        warning.MaximumSize = new Size(615, 0);
        warning.ForeColor = Color.FromArgb(156, 38, 42);
        AddLine(body, warning);
        AddLine(body, UiTheme.Text(T("Для подтверждения введите: ", "Type to confirm: ", "הקלד לאישור: ") + phrase));
        var input = Field("");
        input.Width = 610;
        input.AccessibleName = "Explicit destructive operation confirmation";
        AddLine(body, input);
        var actions = new FlowLayoutPanel
        {
            AutoSize = true, WrapContents = false, FlowDirection = FlowDirection.RightToLeft
        };
        var approve = UiTheme.Action(T("Подтвердить действие", "Confirm operation", "אישור"), true, "check");
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
        AddLine(body, actions);
        dialog.AcceptButton = approve;
        dialog.CancelButton = cancel;
        dialog.Controls.Add(body);
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

    private async Task BackupNowAsync()
    {
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildRecoveryBundle("--backup"), TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        WriteLine(result.StdOut);
        WriteLine("Backup stored under /var/backups/linuxmailrelay365 on Linux. Archives never leave the server.");
    }

    private async Task ListBackupsAsync()
    {
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

    private string SelectedTpmDependencyProfile() => tpmDependencyProfile.SelectedIndex switch
    {
        0 => "runtime",
        1 => "build-prereqs",
        2 => "pkcs11",
        3 => "native-provider",
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
        WriteLine("TPM2 RPM installation verified; non-exportable OAuth signing is NOT automatically configured.");
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
        sb.AppendLine("OPTIONAL SECURITY — NOTHING ENABLED BY DEFAULT");
        sb.AppendLine();
        sb.AppendLine("1) TPM 2.0 / HSM: run the Linux read-only probe, check TPM2/P11 signing support, and configure a nonexportable private key using supported vendor tools. The current mail transport signs with a PEM key; hardware discovery alone does not activate hardware signing. Configure and test a hardware signer before switching. Do not delete the working key until a new token and SMTP test succeeds.");
        sb.AppendLine();
        sb.AppendLine("2) Entra IP restriction: requires Entra Workload ID Premium and a Conditional Access policy for workload identities. Restrict only the selected application to approved public egress IPs. Configure Report-only, verify service-principal sign-in results, then enable explicitly in Entra Admin Center. One shared app = a common IP allowlist across Linux servers.");
        sb.AppendLine();
        sb.AppendLine("3) Entra sign-in monitoring: configure sign-in log permissions and alerts explicitly. Log access requires appropriate admin roles/consent. Thumbprint and source IP are audit signals, not a device fingerprint enforcement mechanism.");
        sb.AppendLine();
        sb.AppendLine("Security choices in this wizard are plans only. They can be selected/cleared later per SSH endpoint. No keys, CA policies, licenses or alert rules are changed by these controls.");
        var dialog = new Form {
            Text = "LinuxMailRelay365 | Optional security", StartPosition = FormStartPosition.CenterParent,
            Size = new Size(820, 560), MinimumSize = new Size(520, 380),
            BackColor = UiTheme.Canvas, AutoScaleMode = AutoScaleMode.Dpi
        };
        var text = new TextBox {
            Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
            Font = new Font("Segoe UI", 10), Dock = DockStyle.Fill,
            Text = sb.ToString(), BackColor = Color.White
        };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), true);
        close.Click += (_, _) => dialog.Close();
        var actions = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 65, Padding = new Padding(10) };
        actions.Controls.Add(close);
        dialog.Controls.Add(text);
        dialog.Controls.Add(actions);
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
        var result = await SshRemote.ExecuteAsync(Endpoint(),
            "echo '=== identity ==='; id; echo '=== OS ==='; cat /etc/os-release; " +
            "echo '=== Postfix ==='; command -v postconf && postconf -h relayhost && postconf -h default_transport || true; " +
            "echo '=== SMTP 587 connectivity ==='; timeout 8 bash -c 'echo >/dev/tcp/smtp.office365.com/587' && echo reachable || echo blocked; " +
            "echo '=== HTTPS 443 connectivity ==='; timeout 8 bash -c 'echo >/dev/tcp/login.microsoftonline.com/443' && echo reachable || echo blocked", timeout: TimeSpan.FromSeconds(45));
        result.EnsureSuccess();
        WriteLine(result.StdOut);
    }

    private async Task ApplyAsync()
    {
        EnsureRoutingLoaded();
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

    private async Task CheckUpdatesAsync()
    {
        WriteLine("Checking GitHub Releases using UniversalUpdater...");
        var (url, message) = await UpdateCheck.QueryAsync(previewUpdates.Checked, CancellationToken.None);
        releaseUrl = url;
        WriteLine(message);
        if (releaseUrl is not null)
        {
            var ask = MessageBox.Show(this, T("Открыть страницу релиза?", "Open the release page?", "לפתוח עמוד גרסה?"),
                Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (ask == DialogResult.Yes)
                Process.Start(new ProcessStartInfo(releaseUrl) { UseShellExecute = true });
        }
    }
}
