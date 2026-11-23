using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

// All conditional rules in RC11 are LOCAL, UNSAVED, READ-ONLY "what if" data.
// This UI never installs maps, runs postmap, changes MTA services or submits
// a message. It also never claims that Postfix, Exim or Sendmail would route
// a real message according to the simulated match list.
internal sealed partial class MainForm
{
    private readonly CheckBox advancedRoutingToggle = new()
    {
        AutoSize = true,
        Margin = new Padding(0, 8, 0, 12),
        Font = new Font("Segoe UI", 10f, FontStyle.Bold),
        AccessibleName = "Expand conditional outbound mail routing planner"
    };
    private bool advancedRoutingEventsWired;
    private bool advancedRoutingToggleUpdating;
    private string? advancedRoutingIdentity;
    private readonly List<AdvancedRouteRule> advancedRoutingRules = [];
    private readonly ComboBox advancedRoutingMatchKind = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList,
        Font = new Font("Segoe UI", 10f),
        Margin = new Padding(0, 3, 0, 12),
        AccessibleName = "Match mail envelope sender or recipient domain"
    };
    private readonly ComboBox advancedRoutingTls = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList,
        Font = new Font("Segoe UI", 10f),
        Margin = new Padding(0, 3, 0, 12),
        AccessibleName = "Proposed outbound SMTP security"
    };
    private readonly ComboBox advancedRoutingAuth = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList,
        Font = new Font("Segoe UI", 10f),
        Margin = new Padding(0, 3, 0, 12),
        AccessibleName = "Proposed outbound SMTP AUTH requirement"
    };
    private readonly TextBox advancedRoutingCondition = Field("");
    private readonly TextBox advancedRoutingHost = Field("");
    private readonly TextBox advancedRoutingPort = Field("587");
    private readonly TextBox advancedRoutingSampleSender = Field("");
    private readonly TextBox advancedRoutingSampleRecipient = Field("");
    private AdvancedRouteSimulation? advancedRoutingSimulation;
    private int advancedRoutingEditIndex = -1;

    private void PrepareAdvancedRoutingControls(int width)
    {
        if (advancedRoutingMatchKind.Items.Count == 0)
        {
            advancedRoutingMatchKind.Items.AddRange([
                "Exact envelope sender (user@example.org)",
                "Envelope sender domain (example.org)",
                "Recipient domain (example.org)"
            ]);
            advancedRoutingMatchKind.SelectedIndex = 0;
            advancedRoutingTls.Items.AddRange([
                "STARTTLS (certificate verification required)",
                "Implicit TLS (certificate verification required)",
                "Plaintext (NO SMTP password allowed)"
            ]);
            advancedRoutingTls.SelectedIndex = 0;
            advancedRoutingAuth.Items.AddRange([
                "No SMTP AUTH / provider IP authorization",
                "SMTP AUTH required (credentials not collected here)"
            ]);
            advancedRoutingAuth.SelectedIndex = 0;
        }
        int fieldWidth = Math.Clamp(width - 45, 270, 700);
        foreach (Control field in new Control[]
        {
            advancedRoutingMatchKind, advancedRoutingTls, advancedRoutingAuth,
            advancedRoutingCondition, advancedRoutingHost, advancedRoutingPort,
            advancedRoutingSampleSender, advancedRoutingSampleRecipient
        })
        {
            field.Width = fieldWidth;
            field.MinimumSize = Size.Empty;
            field.MaximumSize = Size.Empty;
        }
        if (!advancedRoutingEventsWired)
        {
            advancedRoutingEventsWired = true;
            advancedRoutingToggle.CheckedChanged += (_, _) =>
            {
                advancedRoutingSimulation = null;
                if (!advancedRoutingToggleUpdating && !busy && !IsDisposed) RenderPage();
            };
        }
    }

    private string AdvancedRoutingTlsMode() => advancedRoutingTls.SelectedIndex switch
    {
        0 => "starttls",
        1 => "implicit",
        2 => "plain",
        _ => throw new InvalidDataException("Choose a proposed SMTP TLS mode.")
    };

    private string AdvancedRoutingAuthMode() => advancedRoutingAuth.SelectedIndex switch
    {
        0 => "none",
        1 => "password",
        _ => throw new InvalidDataException("Choose a proposed SMTP AUTH policy.")
    };

    private static string AdvancedRouteSelector(AdvancedRouteMatchKind kind, int l) =>
        kind switch
        {
            AdvancedRouteMatchKind.ExactEnvelopeSender => TranslateMailFlow(l,
                "Отправитель (полный адрес)", "Envelope sender (exact address)",
                "כתובת שולח מדויקת"),
            AdvancedRouteMatchKind.EnvelopeSenderDomain => TranslateMailFlow(l,
                "Домен отправителя", "Envelope sender domain", "דומיין שולח"),
            AdvancedRouteMatchKind.RecipientDomain => TranslateMailFlow(l,
                "Домен получателя", "Recipient domain", "דומיין נמען"),
            _ => "Unsupported selector"
        };

    private void ShowAdvancedConditionalRoutingPlanner(
        TableLayoutPanel page, int width, int l)
    {
        // Only after the existing read-only discovery has established the SSH
        // server identity, MTA and SMTP audit. Don't present proposals as facts.
        if (!HasMailDiscovery())
            return;
        string identity = TryCurrentIdentity() ?? "";
        if (!string.Equals(advancedRoutingIdentity, identity, StringComparison.Ordinal))
        {
            advancedRoutingRules.Clear();
            advancedRoutingSimulation = null;
            advancedRoutingEditIndex = -1;
            advancedRoutingIdentity = identity;
            advancedRoutingToggleUpdating = true;
            try { advancedRoutingToggle.Checked = false; }
            finally { advancedRoutingToggleUpdating = false; }
        }
        PrepareAdvancedRoutingControls(width);
        advancedRoutingToggle.Text = TranslateMailFlow(l,
            "Расширенная маршрутизация по отправителям и доменам — только план",
            "Advanced sender/domain routing — read-only what-if planner",
            "תכנון מתקדם לפי שולח ודומיין — ללא שינויים");
        AddLine(page, advancedRoutingToggle);
        if (!advancedRoutingToggle.Checked)
            return;

        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "RC11: это локальная модель, НЕ настройка SMTP и НЕ фактическая таблица Postfix. Правила действуют только в текущем окне, не сохраняются, не меняют Linux и не отправляют письма. Пересечения не получают придуманного приоритета.",
            "RC11: this is a local what-if model, NOT an active Postfix map or actual SMTP routing. Rules stay in this window, are not saved, cannot modify Linux or send mail. Overlaps have NO assumed precedence.",
            "תכנון בלבד ללא כתיבה, שמירה או משלוח דואר; אין קדימות משוערת לכללים חופפים."),
            width, warning: true));

        string mta = inspectedMail?.Mta ?? "unknown";
        if (mta == "postfix")
        {
            string senderMap = inspectedHost?.Get("MAIL_HOST_POSTFIX_ROLE_SENDER_DEPENDENT_RELAYHOST_MAPS")
                ?? "unverified";
            string transport = inspectedHost?.Get("MAIL_HOST_POSTFIX_ROLE_TRANSPORT_MAPS")
                ?? "unverified";
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Найденные объявления Postfix (без чтения адресов и паролей): ",
                "Discovered Postfix declarations (no address/password contents read): ",
                "הגדרות Postfix קיימות: ") +
                "sender_dependent_relayhost_maps=" + senderMap +
                ", transport_maps=" + transport + "." + Environment.NewLine +
                TranslateMailFlow(l,
                    "Эти механизмы имеют разную семантику и порядок обработки. Существующие карты никогда не заменяются этим мастером.",
                    "These maps have distinct semantics and precedence. Existing maps are NEVER replaced by this planner.",
                    "למפות הקיימות משמעות שונה והן אינן מוחלפות."),
                width, warning: senderMap != "not_declared" ||
                    transport != "not_declared"));
        }
        else
        {
            AddLine(page, MailFlowText("Detected MTA: " + mta + ". " +
                TranslateMailFlow(l,
                    "Для Exim/Sendmail текущие ACL/routers не анализируются как реальные маршруты. Только общая модель.",
                    "Exim/Sendmail router and ACL precedence is NOT modeled. This is a conceptual preview only.",
                    "נתיבי Exim/Sendmail אינם מאומתים; זו הדמיה בלבד."),
                width, warning: true));
        }

        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Добавить предполагаемое условие",
            "Add a proposed routing condition",
            "הוספת תנאי ניתוב מוצע"), true));
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Тип условия", "Condition type", "סוג תנאי")));
        AddLine(page, advancedRoutingMatchKind);
        AddField(page, TranslateMailFlow(l,
            "Точный адрес отправителя ИЛИ домен (без * и масок)",
            "Exact sender address OR domain (no wildcards)", "כתובת או דומיין מדויק"),
            advancedRoutingCondition);
        AddField(page, TranslateMailFlow(l,
            "Предлагаемый исходящий SMTP (FQDN / IPv4)",
            "Proposed outbound SMTP destination (FQDN / IPv4)", "יעד SMTP מוצע"),
            advancedRoutingHost);
        AddField(page, TranslateMailFlow(l,
            "Его исходящий TCP-порт (НЕ новый порт Linux)",
            "Outbound TCP port (NOT a new Linux listener)", "יציאת TCP יוצאת"),
            advancedRoutingPort);
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Предполагаемый TLS", "Proposed TLS", "TLS מוצע")));
        AddLine(page, advancedRoutingTls);
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Предполагаемый SMTP AUTH", "Proposed SMTP AUTH", "אימות SMTP מוצע")));
        AddLine(page, advancedRoutingAuth);

        bool editing = advancedRoutingEditIndex >= 0 &&
            advancedRoutingEditIndex < advancedRoutingRules.Count;
        var add = AddAction(page, editing
            ? TranslateMailFlow(l, "Сохранить изменения в модели (только локально)",
                "Save edited rule to the simulation (local only)", "שמור כלל ערוך בהדמיה")
            : TranslateMailFlow(l, "Добавить правило в модель (Linux не меняется)",
                "Add a rule to this simulation (Linux unchanged)", "הוסף כלל להדמיה בלבד"),
            AddAdvancedRoutingRuleAsync, false, editing ? "check" : "plus",
            "conditional-route-plan");
        add.Enabled = !busy && (editing ||
            advancedRoutingRules.Count < AdvancedRoutePlanner.MaximumRules);
        if (editing)
            AddAction(page, TranslateMailFlow(l, "Отменить редактирование",
                "Cancel rule edit", "בטל עריכה"),
                () =>
                {
                    advancedRoutingEditIndex = -1;
                    advancedRoutingSimulation = null;
                    RenderPage();
                    return Task.CompletedTask;
                }, false, "x", "conditional-route-plan");

        if (advancedRoutingRules.Count > 0)
        {
            // Interactive native WinForms visualization; every node opens
            // the existing local-only edit form, never an SMTP action.
            AddLine(page, BuildConditionalRoutingDiagram(width, l));
            var overlaps = AdvancedRoutePlanner.PossibleOverlaps(advancedRoutingRules);
            if (overlaps.Count > 0)
            {
                AddLine(page, MailFlowText(TranslateMailFlow(l,
                    "Возможные пересечения условий (НЕ фактический маршрут): ",
                    "Possible matching-rule overlaps (NOT actual MTA routing): ",
                    "חפיפות אפשריות בין תנאי הניתוב: ") +
                    string.Join(", ", overlaps.Take(8).Select(x =>
                        "#" + (x.FirstRule + 1) + " ↔ #" + (x.SecondRule + 1))) +
                    (overlaps.Count > 8 ? " …" : "") + Environment.NewLine +
                    TranslateMailFlow(l,
                        "Приоритет sender/recipient карт не вычисляется и должен быть проверен отдельно.",
                        "Sender/recipient map precedence is NOT inferred and requires separate inspection.",
                        "קדימות מפות השולח והנמען אינה ידועה."),
                    width, warning: true));
            }
            AddLine(page, UiTheme.Text(TranslateMailFlow(l,
                "Предлагаемые правила — порядок только для просмотра",
                "Proposed rules — display order only (NOT Postfix precedence)",
                "כללים מוצעים — הסדר לצפייה בלבד"), true));
            for (int i = 0; i < advancedRoutingRules.Count; i++)
            {
                var rule = advancedRoutingRules[i];
                int at = i;
                var line = new TableLayoutPanel
                {
                    ColumnCount = 1, RowCount = 0, AutoSize = true,
                    AutoSizeMode = AutoSizeMode.GrowAndShrink,
                    Width = Math.Max(270, width - 30),
                    Padding = new Padding(10),
                    BackColor = i % 2 == 0 ? Color.FromArgb(239, 246, 252)
                        : Color.FromArgb(248, 250, 253),
                    Margin = new Padding(0, 5, 0, 8)
                };
                line.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
                AddLine(line, MailFlowText(
                    (i + 1) + ". " + AdvancedRouteSelector(rule.Kind, l) +
                    ": " + rule.Pattern + Environment.NewLine +
                    rule.Endpoint + "  ·  TLS=" + rule.TlsMode +
                    "  ·  AUTH=" + rule.AuthMode, width - 75));
                var controls = new FlowLayoutPanel
                {
                    AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                    WrapContents = true,
                    Width = Math.Max(245, width - 65),
                    FlowDirection = FlowDirection.LeftToRight,
                    Margin = new Padding(0, 4, 0, 0)
                };
                void AddLocalAction(string name, string glyph, Action callback, bool enabled)
                {
                    var button = UiTheme.Action(name, false, glyph);
                    button.Enabled = enabled && !busy;
                    button.Click += (_, _) => { callback(); RenderPage(); };
                    controls.Controls.Add(button);
                }
                AddLocalAction(TranslateMailFlow(l, "Изменить", "Edit", "ערוך"),
                    "pencil", () => BeginAdvancedRouteEdit(at), true);
                AddLocalAction("↑", "arrow-up", () => MoveAdvancedRoute(at, -1), i > 0);
                AddLocalAction("↓", "arrow-down", () => MoveAdvancedRoute(at, 1),
                    i + 1 < advancedRoutingRules.Count);
                AddLocalAction(TranslateMailFlow(l, "Удалить", "Remove", "מחק"),
                    "trash-2", () =>
                    {
                        advancedRoutingRules.RemoveAt(at);
                        advancedRoutingEditIndex = -1;
                        advancedRoutingSimulation = null;
                    }, true);
                AddLine(line, controls);
                AddLine(page, line);
            }
            AddLine(page, MailFlowText(
                TranslateMailFlow(l, "Отпечаток только этой модели: ",
                    "This proposal's local SHA-256: ", "SHA-256 של ההצעה: ") +
                AdvancedRoutePlanner.PlanSha256(advancedRoutingRules)[..16] + "…",
                width));

            AddLine(page, UiTheme.Text(TranslateMailFlow(l,
                "Проверка предполагаемого пути — без сети и письма",
                "What-if message matching (offline, no email sent)",
                "הדמיית התאמה ללא שליחת דואר"), true));
            AddField(page, TranslateMailFlow(l,
                "Пример envelope sender", "Sample envelope sender", "שולח לדוגמה"),
                advancedRoutingSampleSender);
            AddField(page, TranslateMailFlow(l,
                "Пример envelope recipient", "Sample envelope recipient", "נמען לדוגמה"),
                advancedRoutingSampleRecipient);
            AddAction(page, TranslateMailFlow(l,
                "Показать совпавшие условия (без отправки)",
                "Simulate matching conditions (does NOT send mail)",
                "הצג התאמות ללא משלוח"),
                SimulateAdvancedRoutingAsync, false, "search", "conditional-route-plan");

            if (advancedRoutingSimulation is { } simulation &&
                simulation.PlanSha256 ==
                    AdvancedRoutePlanner.PlanSha256(advancedRoutingRules) &&
                string.Equals(simulation.SampleSender,
                    advancedRoutingSampleSender.Text, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(simulation.SampleRecipient,
                    advancedRoutingSampleRecipient.Text, StringComparison.OrdinalIgnoreCase))
            {
                AddLine(page, MailFlowText(
                    "WHAT-IF: " + simulation.Status + Environment.NewLine +
                    simulation.Explanation + Environment.NewLine +
                    "Matching rules: " + simulation.Matches.Count +
                    (simulation.Matches.Count == 0 ? "" : Environment.NewLine +
                        string.Join(Environment.NewLine,
                            simulation.Matches.Select(x =>
                                x.Selector + ": " + x.Pattern + " → " + x.Endpoint))),
                    width, warning: simulation.Status != "one-hypothetical-match"));
            }
        }
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Предпросмотр не позволяет безопасно создать реальные sender_dependent_relayhost_maps / transport_maps: сначала нужен отдельный анализ precedence, локальной доставки, DNS/TLS, сертификатов и защита от пересечений. В RC11 кнопки Apply нет.",
            "Generating real sender_dependent_relayhost_maps / transport_maps is NOT yet authorized: first verify true Postfix precedence, local delivery, DNS/TLS, certificate and overlap behavior. There is NO Apply button in RC11.",
            "אין הרשאה לשינוי מפות Postfix; נדרש אימות נוסף לפני הפעלה."),
            width, warning: true));
    }

    private Task AddAdvancedRoutingRuleAsync()
    {
        if (!HasMailDiscovery() ||
            advancedRoutingIdentity != TryCurrentIdentity())
            throw new InvalidOperationException("Reinspect this Linux server before planning routes.");
        var kind = advancedRoutingMatchKind.SelectedIndex switch
        {
            0 => AdvancedRouteMatchKind.ExactEnvelopeSender,
            1 => AdvancedRouteMatchKind.EnvelopeSenderDomain,
            2 => AdvancedRouteMatchKind.RecipientDomain,
            _ => throw new InvalidOperationException("Select an envelope route criterion.")
        };
        if (!int.TryParse(advancedRoutingPort.Text.Trim(), out int port))
            throw new InvalidDataException("Invalid outbound SMTP port.");
        var proposed = AdvancedRoutePlanner.Normalize(new(
            kind, advancedRoutingCondition.Text,
            advancedRoutingHost.Text, port,
            AdvancedRoutingTlsMode(), AdvancedRoutingAuthMode()));
        bool editing = advancedRoutingEditIndex >= 0 &&
            advancedRoutingEditIndex < advancedRoutingRules.Count;
        var candidates = advancedRoutingRules.ToList();
        if (editing)
            candidates[advancedRoutingEditIndex] = proposed;
        else
            candidates.Add(proposed);
        var reviewed = AdvancedRoutePlanner.ValidatePlan(candidates);
        advancedRoutingRules.Clear();
        advancedRoutingRules.AddRange(reviewed);
        advancedRoutingEditIndex = -1;
        advancedRoutingSimulation = null;
        WriteLine("Conditional SMTP route " + (editing ? "edited" : "added") +
            " in an UNSAVED offline model only; " +
            "no Linux settings or queued messages were changed.");
        RenderPage();
        return Task.CompletedTask;
    }

    private void BeginAdvancedRouteEdit(int at)
    {
        if (at < 0 || at >= advancedRoutingRules.Count)
            return;
        var item = advancedRoutingRules[at];
        advancedRoutingEditIndex = at;
        advancedRoutingMatchKind.SelectedIndex = (int)item.Kind;
        advancedRoutingCondition.Text = item.Pattern;
        advancedRoutingHost.Text = item.Host;
        advancedRoutingPort.Text = item.Port.ToString(
            System.Globalization.CultureInfo.InvariantCulture);
        advancedRoutingTls.SelectedIndex = item.TlsMode switch
        {
            "implicit" => 1, "plain" => 2, _ => 0
        };
        advancedRoutingAuth.SelectedIndex = item.AuthMode == "password" ? 1 : 0;
        advancedRoutingSimulation = null;
    }

    private void MoveAdvancedRoute(int at, int offset)
    {
        int target = at + offset;
        if (at < 0 || at >= advancedRoutingRules.Count ||
            target < 0 || target >= advancedRoutingRules.Count)
            return;
        (advancedRoutingRules[at], advancedRoutingRules[target]) =
            (advancedRoutingRules[target], advancedRoutingRules[at]);
        advancedRoutingEditIndex = -1;
        advancedRoutingSimulation = null;
    }

    private Task SimulateAdvancedRoutingAsync()
    {
        if (!HasMailDiscovery() || advancedRoutingIdentity != TryCurrentIdentity())
            throw new InvalidOperationException("Reinspect this Linux server first.");
        advancedRoutingSimulation = AdvancedRoutePlanner.Simulate(
            advancedRoutingRules, advancedRoutingSampleSender.Text,
            advancedRoutingSampleRecipient.Text);
        WriteLine("Conditional SMTP routing simulated offline: " +
            advancedRoutingSimulation.Status + "; matching proposals=" +
            advancedRoutingSimulation.Matches.Count +
            ". No Postfix/Exim/Sendmail configuration or email was changed.");
        RenderPage();
        return Task.CompletedTask;
    }
}
