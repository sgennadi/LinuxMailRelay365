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
    private MailRoutingInventory? inspectedMail;
    private string? inspectedServerIdentity;
    private ExistingSmtpAudit? existingSmtpAudit;
    private string? existingSmtpAuditIdentity;
    private readonly ComboBox mailTransport = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private readonly ComboBox senderPolicy = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 690 };
    private readonly CheckBox preserveExistingMail = new() { AutoSize = true, Checked = true };
    private readonly TextBox acceptedDomain = Field("");
    private readonly TextBox smtpListenIp = Field("");
    private readonly TextBox smtpTrustedCidrs = Field("");
    private readonly TextBox isolatedSmtpPort = Field("2525");
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
            "M365 SMTP Connector · verified domain (planned, no provisioning)"
        ]);
        senderPolicy.Items.AddRange([
            "Fixed Microsoft 365 sender mailbox (available)",
            "Preserve verified domain sender (connector only, planned)",
            "Masquerade subdomains (connector only, planned)"
        ]);
        smtpAccountOperation.Items.AddRange(["Add", "Rotate", "Revoke"]);
        smtpAccountOperation.SelectedIndex = 0;
        mailTransport.SelectedIndex = 0;
        senderPolicy.SelectedIndex = 0;
        mailTransport.SelectedIndexChanged += (_, _) => { SaveRoutingChoices(); UpdatePreserveFlowPreview(); };
        senderPolicy.SelectedIndexChanged += (_, _) => { SaveRoutingChoices(); UpdatePreserveFlowPreview(); };
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
        smtpListenIp.Leave += (_, _) => SaveRoutingChoices();
        smtpTrustedCidrs.Leave += (_, _) => SaveRoutingChoices();
        isolatedSmtpPort.Leave += (_, _) => SaveRoutingChoices();
        foreach (TextBox item in new[] { host, mailbox, tenant, smtpListenIp,
                                         isolatedSmtpPort, smtpTrustedCidrs, acceptedDomain })
            item.TextChanged += (_, _) => UpdatePreserveFlowPreview();
        publicInternetRequested.CheckedChanged += (_, _) =>
        {
            if (routingLoading) return;
            if (publicInternetRequested.Checked)
            {
                var response = MessageBox.Show(this, T(
                    "ПУБЛИЧНЫЙ SMTP — ВЫСОКИЙ РИСК.\n\nБез SMTP AUTH и обязательного TLS доступ из интернета позволит злоумышленникам отправлять спам, подделывать адреса, перегружать очередь и привести к блокировке сервера/IP или репутации Microsoft 365.\n\nТекущий LinuxMailRelay365 НЕ умеет безопасно открывать SMTP всему интернету. Отметка сохраняет только план — firewall и Postfix не изменяются. Сохранить запрос?",
                    "PUBLIC SMTP — HIGH RISK.\n\nWithout SMTP AUTH and mandatory TLS, internet users could send spam, spoof senders, exhaust the queue and cause IP/domain/Microsoft 365 reputation blocking.\n\nThis preview DOES NOT enable public SMTP. The checkbox saves a plan only; no firewall or Postfix changes. Save the request?",
                    "SMTP ציבורי מסוכן ללא אימות והצפנת TLS. אפשרות זו שומרת תוכנית בלבד, ללא פתיחת חומת אש."),
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
                    "Открыть SMTP для всего интернета (экспертный запрос; пока ЗАБЛОКИРОВАНО)",
                    "Public Internet SMTP (advanced request only; activation BLOCKED)",
                    "SMTP לכל האינטרנט (תכנון בלבד, חסום להפעלה)");
                AddLine(page, publicInternetRequested);
                AddLine(page, UiTheme.Text(T(
                    "Риски публичного SMTP: спам, подмена отправителей, злоупотребление очередью, блокировка IP/домена и Microsoft 365. Для активации необходимы SMTP AUTH, обязательный TLS, лимиты скорости, мониторинг и контроль злоупотреблений. Здесь они ещё не реализованы.",
                    "Public SMTP risks: spam, sender spoofing, queue abuse, IP/domain/365 blocking. Safe activation requires SMTP AUTH, mandatory TLS, rate limits, abuse monitoring and verified policy. Not implemented in this preview.",
                    "פתיחת SMTP לאינטרנט ללא אימות עלולה לאפשר ספאם ולגרום לחסימת שרת הדואר.")));
                AddAction(page, T("Проверить порты 443/587, SMTP и firewall (без изменений)",
                                  "Check ports 443/587, SMTP and firewall (read-only)",
                                  "בדיקת יציאות וחומת אש (קריאה בלבד)"),
                                  CheckNetworkFirewallAsync, false, "check", "network");
                AddAction(page, T("Проверить Linux / SELinux для выбранного SMTP-порта",
                                  "Check Linux / SELinux for the selected SMTP port",
                                  "בדיקת לינוקס ו-SELinux עבור יציאת SMTP שנבחרה"),
                                  InspectPlatformAsync, false, "check", "platform");
                AddAction(page, T("Диагностика SELinux Enforcing для RHEL (только чтение)",
                                  "RHEL SELinux Enforcing acceptance report (read-only)",
                                  "דוח SELinux Enforcing ל-RHEL ללא שינויים"),
                                  InspectRhelSelinuxAsync, false, "shield", "selinux-doctor");
                AddAction(page, T("Проверить установленный SMTP: AUTH/TLS, порт, SELinux (без изменений)",
                                  "Audit installed SMTP: AUTH/TLS, port, SELinux (read-only)",
                                  "בדיקת SMTP מותקן: AUTH/TLS, יציאה ו-SELinux"),
                                  AuditInstalledPrivateSmtpAsync, false, "shield", "smtp-live-audit");
                AddAction(page, T("Открыть порт только доверенным сетям...",
                                  "Open SMTP port for trusted networks only...",
                                  "פתיחת יציאה לרשתות מהימנות בלבד"),
                                  OpenTrustedFirewallAsync, false, "shield", "firewall");
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
                    AddLine(page, UiTheme.Text(T(
                        "Режим без аутентификации требует доверенной подсети. Дополнительное включение STARTTLS и SMTP AUTH ниже доступно только для уже установленного отдельного Postfix; публичный SMTP остаётся заблокирован.",
                        "Initial private-only SMTP uses trusted networks. Optional STARTTLS + SMTP AUTH below can harden an existing separate Postfix. Public SMTP remains blocked.",
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
                    AddLine(page, UiTheme.Text(T(
                        "SMTP-клиенты: управление отдельными логинами (без изменения Microsoft 365)",
                        "SMTP client accounts: individual access (Microsoft 365 sender unchanged)",
                        "חשבונות SMTP נפרדים לכל יישום")));
                    AddLine(page, smtpAccountOperation);
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
                    "Для существующего Postfix режим Preserve Existing Mail создаёт отдельный экземпляр Postfix на выбранном SMTP-порту с отдельной очередью. Основные порты 25, main.cf, master.cf и текущая очередь не изменяются. Sendmail/Exim пока не поддерживаются.",
                    "For an existing Postfix server, Preserve Existing Mail installs a separate Postfix instance on your selected TCP port with a separate queue. Primary port 25, main.cf, master.cf and queue are untouched. Sendmail/Exim sidecars are not yet supported.",
                    "עבור Postfix קיים נוצר מופע נפרד בפורט 2525 ללא שינוי בתצורה הקיימת.")));
                AddLine(page, UiTheme.Text(T(
                    "Маскарад и Connector пока доступны только как план. Никакие изменения домена, MX, SPF, DKIM, DMARC или маршрутов существующего MTA не выполняются автоматически. Если MTA уже установлен, режим сохранения блокирует его изменение.",
                    "Masquerade and Connector are planning-only in this preview. No domain, MX, SPF, DKIM, DMARC, or existing MTA routes change automatically. Preserve mode blocks modifications of an existing MTA.",
                    "Connector והסוואת כתובות הם לתכנון בלבד. הגדרות שרת הדואר הקיים לא משתנות.")));
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
                AddLine(page, UiTheme.Text(T(
                    "Postfix будет принимать локальную почту и отправлять её через XOAUTH2. Не используйте этот профиль без проверки, если сервер уже принимает почту извне.",
                    "Postfix will use a local-only listener and XOAUTH2 transport. Review existing inbound-mail setups before applying.",
                    "Postfix ישלח דואר מקומי דרך XOAUTH2. יש לבדוק תצורה קיימת.")));
                break;
            case 4:
                AddField(page, T("Кому отправить тестовое письмо", "Test recipient", "נמען בדיקה"), testRecipient);
                AddAction(page, T("Проверить токен и очередь", "Check OAuth token and mail queue", "בדיקת אסימון ותור"), DiagnosticsAsync, true, "check", "token");
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
            mailTransport.SelectedIndex = routingPlan.Transport == "connector" ? 1 : 0;
            senderPolicy.SelectedIndex = routingPlan.SenderPolicy switch
            {
                "preserve-domain" => 1, "masquerade" => 2, _ => 0
            };
            preserveExistingMail.Checked = routingPlan.PreserveExistingMail;
            acceptedDomain.Text = routingPlan.VerifiedDomain;
            smtpListenIp.Text = routingPlan.ListenIpv4;
            smtpTrustedCidrs.Text = routingPlan.TrustedCidrs;
            isolatedSmtpPort.Text = routingPlan.SidecarPort.ToString();
            publicInternetRequested.Checked = routingPlan.PublicInternetRequested;
            allowExisting.Checked = false;
            inspectedMail = null;
            inspectedServerIdentity = null;
            backupSelector.Items.Clear();
            existingSmtpAudit = null;
            existingSmtpAuditIdentity = null;
            routingIdentity = identity;
        }
        finally { routingLoading = false; }
    }

    private void SaveRoutingChoices()
    {
        if (routingLoading || routingIdentity is null) return;
        routingPlan.Transport = mailTransport.SelectedIndex == 1 ? "connector" : "oauth2";
        routingPlan.SenderPolicy = senderPolicy.SelectedIndex switch
        {
            1 => "preserve-domain", 2 => "masquerade", _ => "fixed-mailbox"
        };
        routingPlan.PreserveExistingMail = preserveExistingMail.Checked;
        routingPlan.VerifiedDomain = acceptedDomain.Text.Trim().ToLowerInvariant();
        routingPlan.ListenIpv4 = smtpListenIp.Text.Trim();
        routingPlan.TrustedCidrs = smtpTrustedCidrs.Text.Trim();
        if (int.TryParse(isolatedSmtpPort.Text.Trim(), out int port))
            routingPlan.SidecarPort = port;
        routingPlan.PublicInternetRequested = publicInternetRequested.Checked;
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
            mailTransport.SelectedIndex == 1,
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
        if (publicInternetRequested.Checked)
            throw new NotSupportedException("Public SMTP is blocked. Clear the public Internet plan before enabling private SMTP AUTH/TLS.");
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
        if (publicInternetRequested.Checked)
            throw new InvalidOperationException("Uncheck Public Internet SMTP planning before restoring an unauthenticated private relay.");
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
        if (publicInternetRequested.Checked)
            throw new InvalidOperationException("Public SMTP access cannot be combined with private account management.");
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

    private async Task CheckNetworkFirewallAsync()
    {
        var args = NetworkFirewallArguments("--check", includePublic: true);
        WriteLine("Read-only Linux network and firewall checks: Entra HTTPS 443, Exchange SMTP 587, selected SMTP listener and active firewall.");
        var report = await SshRemote.ExecuteAsync(Endpoint(), "bash -s",
            EmbeddedAssets.BuildNetworkFirewallBundle(args), timeout: TimeSpan.FromSeconds(55));
        report.EnsureSuccess();
        WriteLine(report.StdOut);
        if (publicInternetRequested.Checked)
            WriteLine("SECURITY: PUBLIC INTERNET SMTP IS NOT ENABLED. SMTP AUTH/TLS and abuse protections are not implemented.");
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
            throw new NotSupportedException("Public Internet SMTP is planning-only and blocked. Without mandatory TLS, SMTP AUTH and abuse controls it would risk an open relay. Clear the option to install local/trusted-only SMTP.");
        var chosenTransport = mailTransport.SelectedIndex == 1 ? "connector" : "oauth2";
        var chosenSender = senderPolicy.SelectedIndex;
        if (chosenTransport != "oauth2" || chosenSender != 0)
            throw new NotSupportedException("Connector and sender masquerade are planning-only in this preview. No Postfix changes were applied.");
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
