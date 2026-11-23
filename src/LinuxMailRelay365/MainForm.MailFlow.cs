using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private string selectedMailSource = MailFlowIntent.Unknown;
    private string selectedMailScenario = MailScenarioPlanner.Choose;
    private string selectedMailTarget = MailFlowIntent.TargetM365;
    private readonly TextBox alternateUpstreamHost = Field("");
    private readonly TextBox alternateUpstreamPort = Field("587");
    private MailSubmissionEvidence? mailSubmissionEvidence;
    private string? mailSubmissionIdentity;

    private bool HasMailDiscovery()
    {
        string? identity = TryCurrentIdentity();
        return identity is not null &&
            discoveredMailIdentity == identity &&
            inspectedServerIdentity == identity &&
            existingSmtpAuditIdentity == identity &&
            inspectedHostIdentity == identity &&
            inspectedMail is not null &&
            existingSmtpAudit is not null &&
            inspectedHost is not null;
    }

    private static string TranslateMailFlow(int language, string ru, string en, string he) =>
        language == 0 ? ru : language == 2 ? he : en;

    private Label MailFlowText(string text, int width, bool bold = false, bool warning = false)
    {
        return new Label
        {
            AutoSize = true,
            MaximumSize = new Size(Math.Max(240, width), 0),
            Padding = new Padding(10, 8, 10, 8),
            Margin = new Padding(0, 5, 0, 7),
            BackColor = Color.White,
            ForeColor = warning ? Color.FromArgb(151, 82, 23) : UiTheme.Navy,
            Font = new Font("Segoe UI", bold ? 11.5f : 10.5f,
                bold ? FontStyle.Bold : FontStyle.Regular),
            Text = text
        };
    }

    // These are actual selectable WinForms cards. There are no generated
    // pictures and no artificial Microsoft 365 "available" statuses.
    private TableLayoutPanel BuildMailFlowCards(
        IReadOnlyList<(string Code, string Title, string Description, string Status,
            bool Preferred, bool Enabled)> options,
        string selected, Action<string> choose)
    {
        int available = Math.Max(340, pageHost.ClientSize.Width - 90);
        int scale = Math.Clamp((int)Math.Round(DeviceDpi / 96.0 * 100), 100, 250);
        bool wide = available >= 940 * scale / 100;
        int columns = wide ? 2 : 1;
        int width = Math.Max(260, (available - (columns - 1) * 14 - 12) / columns);
        int height = (int)Math.Round(132 * scale / 100.0);
        var grid = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = columns, RowCount = 0,
            Width = available, Padding = new Padding(0, 6, 0, 8),
            BackColor = UiTheme.Canvas
        };
        for (int i = 0; i < columns; i++)
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / columns));

        for (int i = 0; i < options.Count; i++)
        {
            var option = options[i];
            bool picked = selected == option.Code;
            var card = new Button
            {
                Width = width, Height = height,
                MinimumSize = new Size(240, height),
                AutoSize = false, Enabled = !busy && option.Enabled,
                TextAlign = ContentAlignment.MiddleLeft,
                FlatStyle = FlatStyle.Flat,
                UseVisualStyleBackColor = false,
                Font = new Font("Segoe UI", 10.5f,
                    picked ? FontStyle.Bold : FontStyle.Regular),
                ForeColor = picked ? Color.White : UiTheme.Navy,
                BackColor = picked ? UiTheme.Accent :
                    option.Enabled ? Color.White : Color.FromArgb(234, 237, 242),
                Margin = new Padding(4, 4, 10, 10),
                Cursor = option.Enabled ? Cursors.Hand : Cursors.Default,
                AccessibleName = option.Title,
                AccessibleDescription = option.Description + ". " + option.Status,
                Text = (picked ? "●  " : option.Preferred ? "★  " : "○  ") +
                    option.Title + Environment.NewLine +
                    option.Status + Environment.NewLine +
                    option.Description
            };
            card.FlatAppearance.BorderColor = picked
                ? UiTheme.Accent : option.Preferred
                    ? Color.FromArgb(51, 140, 99) : Color.FromArgb(205, 215, 230);
            card.FlatAppearance.BorderSize = picked || option.Preferred ? 2 : 1;
            string code = option.Code;
            card.Click += (_, _) => choose(code);
            int row = i / columns;
            if (row >= grid.RowCount)
            {
                grid.RowCount++;
                grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            }
            grid.Controls.Add(card, i % columns, row);
        }
        return grid;
    }

    private Control BuildLiveMailFlowDiagram()
    {
        string mailSource = selectedMailSource;
        string configuredPorts = inspectedHost?.ConfiguredSmtpPortState ?? "";
        if (configuredPorts is "unverified" or "none_configured" or "dynamic_or_unverified")
            configuredPorts = "";
        string? isolatedPort = selectedMailScenario == MailScenarioPlanner.Isolated
            ? isolatedSmtpPort.Text.Trim() : null;
        string mode = selectedMailTarget switch
        {
            MailFlowIntent.TargetCustom => "custom",
            MailFlowIntent.TargetGmail => "google-gmail",
            MailFlowIntent.TargetWorkspace => "google-workspace",
            _ => mailTransport.SelectedIndex switch
            {
                1 => "connector", 2 => "direct-send", _ => "oauth2"
            }
        };
        string? customEndpoint = mode is "google-gmail" or "google-workspace"
            ? googleOutboundPort.Text.Trim()
            : selectedMailTarget == MailFlowIntent.TargetCustom &&
              !string.IsNullOrWhiteSpace(alternateUpstreamHost.Text)
                ? alternateUpstreamHost.Text.Trim() + ":" + alternateUpstreamPort.Text.Trim()
                : null;
        bool transportVerified = selectedMailTarget == MailFlowIntent.TargetCustom &&
            customSmtpAuditContext == CurrentCustomSmtpContext() &&
            customSmtpAudit is { Tls: "verified", Tcp: "reachable" };
        var topology = MailScenarioPlanner.Flow(selectedMailScenario,
            inspectedMail?.CurrentRelay, configuredPorts, isolatedPort, mode,
            language.SelectedIndex, mailSource, customEndpoint,
            inspectedMail?.Mta ?? "unknown", transportVerified);

        int maxWidth = Math.Max(320, pageHost.ClientSize.Width - 90);
        int scale = Math.Clamp((int)Math.Round(DeviceDpi / 96.0 * 100), 100, 250);
        bool horizontal = maxWidth > 1020 * scale / 100 && topology.Nodes.Count < 5;
        var flow = new FlowLayoutPanel
        {
            AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Width = maxWidth, WrapContents = true,
            FlowDirection = horizontal ? FlowDirection.LeftToRight : FlowDirection.TopDown,
            BackColor = Color.FromArgb(238, 246, 253),
            Padding = new Padding(10, 12, 10, 12),
            Margin = new Padding(0, 5, 0, 10)
        };
        int nodeWidth = horizontal
            ? Math.Max(135, (maxWidth - 38 - 37 * (topology.Nodes.Count - 1)) / topology.Nodes.Count)
            : Math.Max(240, maxWidth - 25);
        for (int n = 0; n < topology.Nodes.Count; n++)
        {
            if (n > 0)
            {
                flow.Controls.Add(new Label
                {
                    Text = horizontal ? "→" : "↓",
                    ForeColor = UiTheme.Accent,
                    Font = new Font("Segoe UI", 18f, FontStyle.Bold),
                    Width = horizontal ? 30 : nodeWidth,
                    Height = horizontal ? 70 : 31,
                    TextAlign = ContentAlignment.MiddleCenter,
                    Margin = new Padding(0)
                });
            }
            flow.Controls.Add(new Label
            {
                Text = topology.Nodes[n], Width = nodeWidth,
                Height = (int)Math.Round(80 * scale / 100.0),
                Font = new Font("Segoe UI", 11f, FontStyle.Bold),
                BackColor = Color.White, ForeColor = UiTheme.Navy,
                BorderStyle = BorderStyle.FixedSingle,
                TextAlign = ContentAlignment.MiddleCenter,
                Margin = new Padding(0, 2, 0, 2),
                Padding = new Padding(7),
                AccessibleName = topology.Nodes[n]
            });
        }
        return new TableLayoutPanel
        {
            ColumnCount = 1, AutoSize = true,
            Width = maxWidth,
            Controls = { flow, MailFlowText(topology.Caption, maxWidth,
                warning: selectedMailScenario is MailScenarioPlanner.Rebuild) }
        };
    }

    private void ShowMailFlowPlanner(TableLayoutPanel page)
    {
        int languageIndex = language.SelectedIndex;
        int width = Math.Max(300, pageHost.ClientSize.Width - 90);
        if (!HasMailDiscovery())
        {
            AddLine(page, MailFlowText(TranslateMailFlow(languageIndex,
                "Сначала выполните read-only проверку Linux. Пока тип MTA, сокеты и ограничения SMTP не подтверждены, варианты настройки скрыты.",
                "Inspect Linux first (read-only). Mail route choices remain hidden until the current MTA, listeners and SMTP policy have been checked.",
                "יש לבדוק תחילה את Linux; אפשרויות ההגדרה מוסתרות עד השלמת הבדיקה."),
                width, warning: true));
            return;
        }
        var inventory = inspectedMail!;
        var audit = existingSmtpAudit!;
        var host = inspectedHost!;

        AddLine(page, UiTheme.Text(TranslateMailFlow(languageIndex,
            "Для чего вам нужна исходящая почта?",
            "What will generate outgoing mail?",
            "מהו מקור הדואר היוצא?"), true));
        if (mailSubmissionIdentity == TryCurrentIdentity() && mailSubmissionEvidence is not null)
            AddLine(page, MailFlowText(mailSubmissionEvidence.Brief(languageIndex), width));
        else
            AddLine(page, MailFlowText(TranslateMailFlow(languageIndex,
                "Фактические локальные источники не установлены. Выбор ниже описывает вашу цель, а не результаты автоматического обнаружения пользователей.",
                "Actual message producers are not established. Your selection below is an intended use, not proof that users or jobs are mailing.",
                "מקורות הדואר בפועל לא אומתו; הבחירה היא כוונה בלבד."),
                width));

        var sources = new[]
        {
            MailFlowIntent.Local, MailFlowIntent.Jobs,
            MailFlowIntent.Smtp, MailFlowIntent.Mixed
        }.Select(code => (
            Code: code,
            Title: MailFlowIntent.SourceLabel(code, languageIndex),
            Description: TranslateMailFlow(languageIndex,
                "Сначала только выбор задачи — ничего не изменяется.",
                "Select the intended workload; nothing changes yet.",
                "בחרו את סוג העבודה; לא יבוצעו שינויים."),
            Status: selectedMailSource == code
                ? TranslateMailFlow(languageIndex, "Выбрано", "Selected", "נבחר")
                : TranslateMailFlow(languageIndex, "Выберите", "Choose", "בחר"),
            Preferred: false,
            Enabled: true
        )).ToArray();
        AddLine(page, BuildMailFlowCards(sources, selectedMailSource, code =>
        {
            if (code == selectedMailSource) return;
            selectedMailSource = code;
            selectedMailScenario = MailScenarioPlanner.Choose;
            SaveRoutingChoices();
            RenderPage();
        }));
        if (selectedMailSource == MailFlowIntent.Unknown)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(languageIndex,
                "Выберите источник почты. Затем мастер предложит варианты на основе обнаруженного MTA и ваших требований.",
                "Choose a mail source. Then the wizard will propose routes based on discovered Linux facts and your requirements.",
                "בחרו מקור דואר ולאחר מכן יוצגו אפשרויות."), width));
            return;
        }

        AddLine(page, UiTheme.Text(TranslateMailFlow(languageIndex,
            "Куда должна уходить почта?",
            "Where should outbound mail go?",
            "לאן לשלוח דואר יוצא?"), true));
        var targetChoices = new[]
        {
            (Code: MailFlowIntent.TargetM365,
             Title: "Microsoft 365",
             Description: TranslateMailFlow(languageIndex,
                 "XOAUTH2, SMTP Connector или Direct Send — после проверки tenant.",
                 "XOAUTH2, SMTP Connector or Direct Send — after tenant verification.",
                 "XOAUTH2, Connector או Direct Send לאחר אימות."),
             Status: TranslateMailFlow(languageIndex,
                 "Требуется проверка M365", "Requires M365 verification", "נדרשת בדיקת M365"),
             Preferred: false, Enabled: true),
            (Code: MailFlowIntent.TargetGmail,
             Title: "Gmail SMTP · smtp.gmail.com",
             Description: TranslateMailFlow(languageIndex,
                 "Отправка через Google-аккаунт: 587 STARTTLS или 465 TLS, сейчас App Password; OAuth2 ещё не реализован.",
                 "Google account submission: 587 STARTTLS or 465 TLS, App Password currently supported; OAuth2 not yet implemented.",
                 "שליחה דרך חשבון Google עם TLS."),
             Status: TranslateMailFlow(languageIndex,
                 "Проверить порты и учётные данные", "Check TLS and credentials", "בדיקת TLS והרשאות"),
             Preferred: false, Enabled: true),
            (Code: MailFlowIntent.TargetWorkspace,
             Title: "Google Workspace SMTP Relay",
             Description: TranslateMailFlow(languageIndex,
                 "smtp-relay.gmail.com · 25/465/587. Авторизация по IP или SMTP AUTH после проверки Admin Console.",
                 "smtp-relay.gmail.com · 25/465/587. Authorized IP or SMTP AUTH per Workspace Admin Console.",
                 "ממסר Google Workspace בכפוף למדיניות הארגון."),
             Status: TranslateMailFlow(languageIndex,
                 "Проверить IP/TLS и правила Google", "Check IP/TLS and Google policy", "בדיקת IP/TLS"),
             Preferred: false, Enabled: true),
            (Code: MailFlowIntent.TargetCustom,
             Title: TranslateMailFlow(languageIndex,
                 "Другой SMTP-сервер", "Another SMTP server / smarthost", "שרת SMTP אחר"),
             Description: TranslateMailFlow(languageIndex,
                 "Укажите сервер и исходящий порт. DNS, TLS и необязательную SMTP AUTH можно проверить без отправки письма.",
                 "Specify an outbound server and port. Read-only DNS/TLS and optional SMTP AUTH checks do not send mail.",
                 "בחרו שרת ויציאה. תכנון בלבד."),
             Status: TranslateMailFlow(languageIndex,
                 "Нет автоматической установки", "No automatic deployment", "ללא התקנה אוטומטית"),
             Preferred: false, Enabled: true)
        };
        AddLine(page, BuildMailFlowCards(targetChoices, selectedMailTarget, code =>
        {
            selectedMailTarget = code;
            googleAppPassword.Clear(); // Never carry Google credentials between destinations.
            customSmtpPassword.Clear(); // Never retain a custom SMTP secret after a target change.
            customSmtpAudit = null;
            customSmtpAuditContext = null;
            customRoutePreview = null;
            customRoutePreviewContext = null;
            if (code == MailFlowIntent.TargetGmail && googleOutboundPort.Text.Trim() == "25")
                googleOutboundPort.Text = "587";
            googleSmtpAudit = null;
            googleSmtpAuditIdentity = null;
            selectedMailScenario = MailScenarioPlanner.Choose;
            SaveRoutingChoices();
            RenderPage();
        }));
        if (IsGoogleTarget)
            ShowGoogleSmtpChecks(page);
        if (selectedMailTarget == MailFlowIntent.TargetCustom)
        {
            AddField(page, TranslateMailFlow(languageIndex,
                "Исходящий SMTP-сервер (FQDN / IPv4)",
                "Outbound SMTP server (FQDN / IPv4)", "שרת SMTP יוצא"),
                alternateUpstreamHost);
            AddField(page, TranslateMailFlow(languageIndex,
                "Исходящий TCP-порт (это НЕ входящий порт Linux)",
                "Outbound TCP port (NOT a Linux inbound port)", "יציאה יוצאת TCP"),
                alternateUpstreamPort);
            ShowCustomSmtpChecks(page, width, languageIndex);
            AddLine(page, MailFlowText(TranslateMailFlow(languageIndex,
                "Для активного основного Postfix доступен защищённый Custom SMTP Preview/Apply. Exim/Sendmail и сложные маршруты не меняются автоматически.",
                "Guarded Custom SMTP Preview/Apply is available for an active primary Postfix. Exim/Sendmail and advanced routing remain read-only.",
                "בדיקות זמינות, אך שינוי אוטומטי של Postfix אינו נתמך עדיין."),
                width, warning: true));
        }
        AddLine(page, UiTheme.Text(TranslateMailFlow(languageIndex,
            "Как поступить с текущей конфигурацией?",
            "What should happen to the current mail configuration?",
            "מה לעשות עם תצורת הדואר הקיימת?"), true));
        string recipients = recipientScope.SelectedIndex switch
        {
            1 => "internal-only", 2 => "external-needed", _ => "unknown"
        };
        var suggestions = MailFlowIntent.Suggestions(inventory, audit, host,
            discoveredIsolatedRelay, selectedMailSource, recipients, languageIndex,
            selectedMailTarget);
        var choices = suggestions.Select(x => (
            x.Code, x.Name, x.Detail, x.Status, x.Preferred, x.Enabled)).ToArray();
        AddLine(page, BuildMailFlowCards(choices, selectedMailScenario, code =>
        {
            selectedMailScenario = code;
            SaveRoutingChoices();
            RenderPage();
        }));
        if (selectedMailScenario == MailScenarioPlanner.Choose)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(languageIndex,
                "Выберите сценарий, чтобы увидеть схему с вашими реальными параметрами. Ни один сценарий не запускает установку автоматически.",
                "Select a scenario to see a diagram containing real detected values. Choosing a card never installs or changes mail.",
                "בחרו מסלול לצפייה בתרשים לפי הנתונים שהתגלו."), width));
            return;
        }

        var chosen = suggestions.FirstOrDefault(x => x.Code == selectedMailScenario);
        if (chosen is null || !chosen.Enabled)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(languageIndex,
                "Выбранный сценарий больше не подтверждается текущей проверкой. Выполните повторный анализ и выберите другой.",
                "The previously selected scenario is no longer supported by current evidence. Reinspect and select another.",
                "האפשרות שנבחרה אינה נתמכת עוד. יש לבדוק מחדש."), width, warning: true));
            return;
        }
        AddLine(page, UiTheme.Text(TranslateMailFlow(languageIndex,
            "Предпросмотр маршрута (это не установка)",
            "Selected mail flow (preview only)",
            "תצוגה מקדימה של ניתוב הדואר"), true));
        AddLine(page, BuildLiveMailFlowDiagram());
        if (chosen.RequiresSeparatePort)
            AddLine(page, MailFlowText(TranslateMailFlow(languageIndex,
                "Только для отдельного SMTP экземпляра понадобится собственный входящий порт. Он выбирается позже после проверки свободных портов.",
                "Only an independent SMTP instance needs a new inbound port. Choose it after a live port conflict check.",
                "רק ממסר עצמאי דורש יציאה נכנסת חדשה."), width));
        if (selectedMailScenario is MailScenarioPlanner.ReplaceRelay or MailScenarioPlanner.Rebuild)
            AddLine(page, MailFlowText(TranslateMailFlow(languageIndex,
                "Важно: замена upstream и полная переустановка — разные операции. Для замены upstream не нужен новый входящий SMTP-порт. Этот выбор пока фиксирует план; запуск изменения требует отдельного проверенного действия.",
                "Changing an upstream route and rebuilding the MTA are different operations. Upstream migration requires NO new inbound port. This is an intent preview; execution needs a separately verified operation.",
                "שינוי ניתוב יוצא אינו דורש יציאה חדשה, ושונה מהתקנה מחדש."), width, warning: true));
    }

    private void AddUnverifiedM365Capabilities(TableLayoutPanel page)
    {
        if (IsGoogleTarget)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(language.SelectedIndex,
                "Google SMTP: проверка портов и App Password не подтверждает право отправлять письма с любого адреса и не меняет Postfix. Сначала подтвердите настройки Google и активный исходящий маршрут.",
                "Google SMTP port and credential checks do not prove permitted sender addresses or modify Postfix. Confirm Google service policy and the active route before applying.",
                "בדיקת יציאות וסיסמה אינה משנה Postfix או מאמתת משלוח."),
                Math.Max(300, pageHost.ClientSize.Width - 90), warning: true));
            return;
        }
        if (selectedMailTarget == MailFlowIntent.TargetCustom)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(language.SelectedIndex,
                "Проверка Custom SMTP не подтверждает права отправителя или реальную доставку. Изменение основного Postfix требует отдельного Preview, backup и подтверждения.",
                "Custom SMTP checks do not prove sender authorization or delivery. Primary Postfix migration requires separate Preview, backup and explicit approval.",
                "ממסר SMTP אחר טרם אומת; יש לבדוק TLS והרשאות."),
                Math.Max(300, pageHost.ClientSize.Width - 90), warning: true));
            return;
        }
        if (!HasMailDiscovery() || selectedMailScenario is MailScenarioPlanner.Choose or MailScenarioPlanner.Keep)
            return;
        int l = language.SelectedIndex;
        int width = Math.Max(300, pageHost.ClientSize.Width - 90);
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Microsoft 365 — что реально подтверждено?",
            "Microsoft 365 — what has actually been verified?",
            "Microsoft 365 — מה אומת בפועל?"), true));
        if (lastReadOnlyCloudInventory is { } cloud &&
            lastReadOnlyCloudLinuxIdentity == TryCurrentIdentity() &&
            Guid.TryParse(tenant.Text.Trim(), out var selectedTenant) &&
            cloud.Tenant == selectedTenant)
        {
            int enabledConnectors = cloud.Connectors.Count(x => x.Enabled);
            int validCertificates = cloud.Certificates.Count(x =>
                x.ValidFrom <= DateTimeOffset.UtcNow && x.ValidUntil > DateTimeOffset.UtcNow);
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Аудит tenant завершён (только чтение): ",
                "Tenant inventory read (no changes): ",
                "בדיקת tenant הושלמה: ") +
                "Entra app: " + cloud.ApplicationStatus +
                " · cert(s): " + validCertificates +
                " · enabled Connector(s): " + enabledConnectors +
                Environment.NewLine + TranslateMailFlow(l,
                    "Обнаруженные объекты — это ещё не доказательство SMTP.SendAsApp, SMTP AUTH, совпадения исходящего IP или доставки.",
                    "Detected objects do not prove SMTP.SendAsApp, SMTP AUTH policy, egress IP matching or message delivery.",
                    "עצמים שנמצאו אינם הוכחה להרשאות או למסירת דואר."),
                width));
        }
        else
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Проверка Microsoft 365 в этом tenant ещё не выполнена.",
                "No read-only inventory has been completed for this tenant.",
                "טרם בוצעה בדיקה של tenant זה."), width));

        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "XOAUTH2: проверить разрешения приложения и mailbox, SMTP AUTH и TCP 587. Connector: проверить действующий Inbound Connector и IP/TLS, TCP 25. Direct Send: проверить accepted domain, MX и исходящий TCP 25; только внутренние получатели. Ни один режим не считается доступным по одному обнаружению объектов.",
            "XOAUTH2: verify app/mailbox grants, SMTP AUTH and outbound 587. Connector: verify enabled inbound connector, public IP/TLS identity and outbound 25. Direct Send: check accepted domain, MX and outbound 25; internal recipients only. Inventory alone cannot prove route readiness.",
            "יש לאמת הרשאות XOAUTH2, Connector או Direct Send בנפרד מבדיקת Linux."),
            width, warning: true));
        AddAction(page, TranslateMailFlow(l,
            "Проверить объекты Microsoft 365 (вход администратора)",
            "Inspect Microsoft 365 objects (admin sign-in)",
            "בדיקת Microsoft 365 עם כניסת מנהל"),
            InspectCloudObjectsAsync, false, "cloud", "mail-flow-cloud-check");
    }
}
