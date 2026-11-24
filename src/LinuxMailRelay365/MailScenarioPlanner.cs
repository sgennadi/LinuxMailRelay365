namespace LinuxMailRelay365;

// UI-only topology choice. This DOES NOT grant authority to change Linux,
// Exchange or the existing mail queue. Execution remains independently gated.
internal static class MailScenarioPlanner
{
    internal const string Choose = "choose";
    internal const string Keep = "keep";
    internal const string Isolated = "isolated";
    internal const string ReplaceRelay = "replace-relay";
    internal const string Rebuild = "rebuild";

    internal static bool Supported(string? value) =>
        value is Choose or Keep or Isolated or ReplaceRelay or Rebuild;

    internal static bool RequiresSeparateInboundPort(string scenario) =>
        scenario == Isolated;

    internal sealed record ScenarioCard(
        string Code, string Title, string Subtitle, string Status, string Warning);

    internal sealed record Topology(
        IReadOnlyList<string> Nodes, string Caption, bool ShowsSeparatePort);

    private static string L(int language, string ru, string en, string he) =>
        language == 0 ? ru : language == 2 ? he : en;

    internal static IReadOnlyList<ScenarioCard> Cards(
        int language, MailRoutingInventory? mail, ExistingSmtpAudit? audit,
        bool? isolatedFound, string? requestedScenario = null)
    {
        bool postfix = mail?.Mta == "postfix";
        bool unknown = mail is null || audit is null;
        bool unsafeRelay = audit?.SuspectedUnsafeRelay == true;
        string needsReview = L(language, "Нужна проверка", "Needs review", "נדרשת בדיקה");
        return
        [
            new(Keep, L(language, "Оставить как есть", "Keep existing mail", "השאר ללא שינוי"),
                postfix
                    ? L(language, "Postfix и текущий relay", "Current Postfix and relay", "Postfix והממסר הקיים")
                    : L(language, "Не изменять сервер", "Do not change the server", "ללא שינוי בשרת"),
                L(language, "Без изменений", "No changes", "ללא שינוי"),
                L(language, "Не проверяет доставку письма конечному получателю.",
                    "Does not prove mail delivery to recipients.", "מסירה לנמענים לא אומתה.")),
            new(Isolated, L(language, "Добавить отдельный M365 Relay", "Add isolated M365 relay", "הוסף ממסר M365 נפרד"),
                L(language, "Своя очередь и новый входящий порт",
                    "Independent queue and NEW inbound port", "תור ויציאה עצמאיים"),
                isolatedFound == true
                    ? L(language, "Проверить существующий", "Inspect existing sidecar", "בדוק ממסר קיים")
                    : unknown || unsafeRelay ? needsReview
                    : L(language, "Можно планировать", "Planning candidate", "אפשר לתכנן"),
                L(language, "Только этот сценарий требует выбора отдельного SMTP-порта.",
                    "Only this scenario needs a separate SMTP listening port.",
                    "רק מסלול זה דורש יציאת SMTP נפרדת.")),
            new(ReplaceRelay,
                L(language, "Изменить исходящий Relay → M365", "Switch existing outbound relay → M365", "שנה ניתוב יוצא ל-M365"),
                L(language, "Тот же Postfix и входящий SMTP; новый исходящий маршрут",
                    "Same Postfix and inbound SMTP; NEW outbound route", "אותו Postfix, ניתוב יוצא חדש"),
                postfix && !unsafeRelay
                    ? L(language, "Миграция с backup", "Review migration with backup", "העברה עם גיבוי")
                    : needsReview,
                L(language, "Не нужен порт 2525. Для применения нужна отдельная проверенная процедура изменения маршрута и отката.",
                    "No port 2525. Applying requires a separately verified route migration and rollback.",
                    "אין צורך ביציאה 2525. נדרשים גיבוי ושחזור.")),
            new(Rebuild,
                L(language, "Заменить конфигурацию Postfix", "Rebuild Postfix configuration", "בנה מחדש Postfix"),
                L(language, "Полная замена по решению администратора",
                    "Full replacement by operator choice", "החלפה מלאה לפי בחירת מנהל"),
                L(language, "Опасно · только с backup", "High risk · backup required", "סיכון גבוה · נדרש גיבוי"),
                L(language, "Это НЕ то же самое, что заменить только relayhost. Возможен простой и потеря параметров.",
                    "Not the same as changing only relayhost. May disrupt existing mail services.",
                    "שונה מהחלפת relayhost; עלול לשבש דואר."))
        ];
    }

    internal static Topology Flow(
        string code, string? configuredExistingRelay, string? existingLocalPorts,
        string? separateInboundPort, string? upstreamMode, int language,
        string mailSource = "unknown", string? customTarget = null,
        string currentMta = "postfix", bool customTlsVerified = false)
    {
        if (!Supported(code)) code = Choose;
        string existing = string.IsNullOrWhiteSpace(configuredExistingRelay)
            ? L(language, "Текущий relay (не проверен)", "Current relay (unverified)", "ממסר קיים")
            : configuredExistingRelay;
        string localPort = !string.IsNullOrWhiteSpace(existingLocalPorts) &&
            existingLocalPorts.All(c => char.IsAsciiDigit(c) || c == ',' || c == ' ')
            ? existingLocalPorts : L(language, "входящий порт не подтверждён",
                "inbound port unverified", "יציאה נכנסת לא אומתה");
        string target = upstreamMode switch
        {
            "m365-pending" => L(language, "Microsoft 365 · способ и порт предстоит выбрать",
                "Microsoft 365 · method and port not yet selected", "Microsoft 365 · שיטה ויציאה טרם נבחרו"),
            "connector" => "Microsoft 365 EOP · TCP 25",
            "direct-send" => "Microsoft 365 MX · TCP 25",
            "google-gmail" => "Gmail · smtp.gmail.com" +
                (string.IsNullOrWhiteSpace(customTarget) ? ":587" : ":" + customTarget) +
                " (SMTP/TLS verification required)",
            "google-workspace" => "Google Workspace · smtp-relay.gmail.com" +
                (string.IsNullOrWhiteSpace(customTarget) ? ":587" : ":" + customTarget) +
                " (policy verification required)",
            "custom" => string.IsNullOrWhiteSpace(customTarget)
                ? L(language, "Другой SMTP relay (не проверен)",
                    "Custom SMTP relay (unverified)", "ממסר SMTP אחר (לא אומת)")
                : "SMTP relay " + customTarget +
                    (customTlsVerified ? " (TLS verified; delivery NOT tested)" : " (transport unverified)"),
            _ => "Microsoft 365 XOAUTH2 · TCP 587"
        };
        string incoming = MailFlowIntent.SourceLabel(mailSource, language);
        if (mailSource == MailFlowIntent.Unknown)
            incoming = L(language, "Локальные письма / SMTP-клиенты (проверьте источник)",
                "Local submissions / SMTP clients (source not established)",
                "שליחה מקומית / לקוחות SMTP (לא אומת)");
        string mtaName = currentMta switch
        {
            "postfix" => "Postfix", "exim" => "Exim", "sendmail" => "Sendmail",
            _ => L(language, "Linux MTA (не подтверждён)",
                    "Linux MTA (unverified type)", "שרת דואר Linux לא אומת")
        };
        string localSubmission = currentMta == "postfix"
            ? L(language, "локальная очередь/pickup", "local pickup / queue", "תור מקומי")
            : L(language, "локальная отправка / очередь", "local submission / queue", "הגשה מקומית");
        string primaryMta = mailSource switch
        {
            MailFlowIntent.Local or MailFlowIntent.Jobs => mtaName + " · " + localSubmission,
            MailFlowIntent.Mixed => mtaName + " · local submission + SMTP " + localPort,
            _ => mtaName + " · SMTP " + localPort
        };
        return code switch
        {
            Keep => new([incoming, primaryMta, existing],
                L(language, "Без изменения Linux и M365", "No Linux or M365 changes", "ללא שינוי"), false),
            Isolated => new([
                L(language, "Клиенты отдельного Relay", "Clients of isolated relay", "לקוחות ממסר נפרד"),
                L(language, "Новый входящий TCP ", "New inbound TCP ", "TCP חדש ") +
                    (string.IsNullOrWhiteSpace(separateInboundPort) ? "?" : separateInboundPort),
                L(language, "Отдельный Postfix + очередь", "Isolated Postfix + queue", "Postfix נפרד"),
                target],
                L(language, "Текущий почтовый сервер не меняется. Порт нового listener надо проверить.",
                    "Existing Linux MTA stays unchanged; verify the new listener port.", "שרת Linux קיים ללא שינוי."), true),
            ReplaceRelay => new([incoming, primaryMta, target],
                L(language, "Тот же входящий SMTP. Меняется только исходящий маршрут, не порт Linux.",
                    "Same inbound SMTP; only upstream routing changes, not Linux listening ports.",
                    "SMTP נכנס ללא שינוי; רק הניתוב היוצא משתנה."), false),
            Rebuild => new([incoming,
                L(language, "Основной Postfix (полная замена)", "Primary Postfix (full rebuild)", "Postfix ראשי חדש"), target],
                L(language, "Требуется backup, анализ очереди, предупреждение и подтверждение.",
                    "Requires backup, queue review, outage warning and explicit approval.",
                    "נדרשים גיבוי ואישור מפורש."), false),
            _ => new([incoming,
                L(language, "Обнаруженный Linux MTA", "Inspected Linux MTA", "שרת Linux"),
                L(language, "Выберите вариант", "Choose a scenario", "בחר מסלול")],
                L(language, "Ничего не выбрано, конфигурация не меняется.",
                    "Nothing selected; no configuration changes.", "לא נבחר מסלול."), false)
        };
    }

    internal static bool SelfTest()
    {
        var cards = Cards(1, new MailRoutingInventory("postfix", "[smtp.gmail.com]:587",
            "smtp", new string('a', 64)), null, false);
        var replace = Flow(ReplaceRelay, "[smtp.gmail.com]:587", "25", "2525", "oauth2", 1);
        var isolated = Flow(Isolated, "[smtp.gmail.com]:587", "25", "2525", "oauth2", 1);
        var keep = Flow(Keep, "[smtp.gmail.com]:587", "25", "2525", "oauth2", 1);
        var localMail = Flow(ReplaceRelay, "[relay.example.org]:465", "25", "2525",
            "oauth2", 1, MailFlowIntent.Local);
        var custom = Flow(ReplaceRelay, "[relay.example.org]:465", "25", "2525",
            "custom", 1, MailFlowIntent.Jobs, "smtp.example.net:587");
        var exim = Flow(Keep, "[old.example]:25", "25", null, "custom", 1,
            MailFlowIntent.Local, "relay.example.org:587", currentMta: "exim");
        var sendmail = Flow(Keep, "[old.example]:25", "25", null, "custom", 1,
            MailFlowIntent.Mixed, "relay.example.org:587", currentMta: "sendmail");
        var verifiedCustom = Flow(ReplaceRelay, "[old.example]:25", "25", null,
            "custom", 1, MailFlowIntent.Jobs, "relay.example.org:587",
            currentMta: "exim", customTlsVerified: true);
        return exim.Nodes[1].StartsWith("Exim · local submission", StringComparison.Ordinal) &&
            sendmail.Nodes[1].StartsWith("Sendmail · local submission", StringComparison.Ordinal) &&
            !sendmail.Nodes.Any(n => n.StartsWith("Postfix", StringComparison.Ordinal)) &&
            verifiedCustom.Nodes.Last().Contains(
                "TLS verified; delivery NOT tested", StringComparison.Ordinal) &&
            cards.Count == 4 &&
            cards.Any(c => c.Code == ReplaceRelay) &&
            replace.Nodes.SequenceEqual(new [] { "Local submissions / SMTP clients (source not established)", "Postfix · SMTP 25",
                "Microsoft 365 XOAUTH2 · TCP 587" }) &&
            !replace.ShowsSeparatePort &&
            !replace.Nodes.Any(n => n.Contains("2525", StringComparison.Ordinal)) &&
            isolated.ShowsSeparatePort &&
            isolated.Nodes.Any(n => n.Contains("2525", StringComparison.Ordinal)) &&
            keep.Nodes.Last() == "[smtp.gmail.com]:587" &&
            localMail.Nodes[1] == "Postfix · local pickup / queue" &&
            !localMail.Nodes.Any(node => node.Contains("2525", StringComparison.Ordinal)) &&
            custom.Nodes.Last().Contains("smtp.example.net:587", StringComparison.Ordinal) &&
            !RequiresSeparateInboundPort(Rebuild) &&
            !Supported("arbitrary");
    }
}
