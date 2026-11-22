namespace LinuxMailRelay365;

// Operator intention is separate from detected Linux facts. Never treat a
// selected source type as proof that any particular mail client sends mail.
internal static class MailFlowIntent
{
    internal const string Unknown = "unknown";
    internal const string Local = "local-mail";
    internal const string Jobs = "jobs-services";
    internal const string Smtp = "smtp-clients";
    internal const string Mixed = "mixed";

    internal static bool Supported(string? source) =>
        source is Unknown or Local or Jobs or Smtp or Mixed;

    private static string T(int lang, string ru, string en, string he) =>
        lang == 0 ? ru : lang == 2 ? he : en;

    internal static string SourceLabel(string source, int language) => source switch
    {
        Local => T(language, "Локальные пользователи Linux / sendmail",
            "Local Linux users / sendmail", "משתמשי Linux מקומיים / sendmail"),
        Jobs => T(language, "Системные уведомления, службы и фоновые задания",
            "System alerts, services and background jobs", "התראות מערכת, שירותים ומשימות רקע"),
        Smtp => T(language, "SMTP-приложения / сетевые клиенты",
            "SMTP applications / network clients", "יישומי SMTP / לקוחות רשת"),
        Mixed => T(language, "Смешанная почта: локальная и SMTP",
            "Mixed: local mail and SMTP clients", "דואר מקומי ולקוחות SMTP"),
        _ => T(language, "Источник отправки ещё не выбран",
            "Mail submission source not selected", "מקור הדואר טרם נבחר")
    };

    internal sealed record MailOption(
        string Code, string Name, string Detail, string Status, bool Preferred,
        bool Enabled, bool RequiresSeparatePort);

    internal static IReadOnlyList<MailOption> Suggestions(
        MailRoutingInventory inventory, ExistingSmtpAudit audit,
        MailHostInspection host, bool? existingIsolated,
        string source, string recipients, int language)
    {
        if (!Supported(source)) throw new ArgumentOutOfRangeException(nameof(source));
        bool postfix = inventory.Mta == "postfix" && audit.Mta == "postfix";
        bool unsafeRelay = audit.SuspectedUnsafeRelay;
        bool local = source is Local or Jobs;
        bool smtpClients = source is Smtp or Mixed;
        bool needsAudience = recipients == "unknown";
        string review = T(language, "Нужна проверка", "Inspection required", "נדרשת בדיקה");
        string preliminary = T(language, "Кандидат · права M365 не проверены",
            "Candidate · M365 rights not verified", "מועמד · זכויות M365 לא אומתו");
        string safe = T(language, "Без изменений", "No changes", "ללא שינוי");

        var options = new List<MailOption>();
        options.Add(new(MailScenarioPlanner.Keep,
            T(language, "Оставить существующий почтовый маршрут",
                "Keep current mail route", "השאר ניתוב דואר קיים"),
            T(language, "Никаких изменений текущего MTA, входящих портов и очереди.",
                "No changes to the MTA, inbound ports or mail queue.",
                "ללא שינוי שירות הדואר, היציאות והתור."),
            safe, Preferred: source == Unknown || unsafeRelay, Enabled: true,
            RequiresSeparatePort: false));

        options.Add(new(MailScenarioPlanner.ReplaceRelay,
            T(language, "Перенаправить существующую почту в Microsoft 365",
                "Redirect existing mail to Microsoft 365",
                "העבר דואר קיים ל-Microsoft 365"),
            postfix ? T(language,
                "Оставить локальных отправителей, Postfix и входящий SMTP. Заменить только исходящий upstream после проверки M365 и backup.",
                "Keep local senders, Postfix and inbound SMTP. Change only the outbound upstream after M365 checks and backup.",
                "שמור שולחים מקומיים ו-Postfix; שנה רק ניתוב יוצא לאחר בדיקות וגיבוי.")
                : T(language,
                "Автоматическая замена upstream на этом MTA пока не поддержана. Основной MTA не будет заменён.",
                "In-place upstream migration for this MTA is not implemented; it will not be silently replaced.",
                "העברה אוטומטית של MTA זה אינה נתמכת."),
            postfix && !unsafeRelay ? preliminary : review,
            Preferred: postfix && !unsafeRelay && local && !needsAudience,
            Enabled: postfix && !unsafeRelay,
            RequiresSeparatePort: false));

        options.Add(new(MailScenarioPlanner.Isolated,
            T(language, "Добавить отдельный Microsoft 365 Relay",
                "Add a separate Microsoft 365 relay",
                "הוסף ממסר Microsoft 365 נפרד"),
            existingIsolated == true
                ? T(language, "Отдельная конфигурация уже обнаружена: сначала проверьте её порт и очередь.",
                    "An isolated relay was already detected. Inspect its port and queue before installing another.",
                    "ממסר נפרד זוהה; בדוק יציאה ותור.")
                : smtpClients
                ? T(language, "Подходит для отдельных SMTP-клиентов. Требует собственного свободного входящего порта и отдельной очереди.",
                    "Useful for separate SMTP clients. Requires its own available inbound port and queue.",
                    "מתאים ללקוחות SMTP נפרדים; דורש יציאה ותור עצמאיים.")
                : T(language, "Для локальной почты не нужен новый порт: сначала рассмотрите замену upstream. Отдельный Relay — только по вашему выбору.",
                    "Local submissions need no extra port: consider upstream migration first. Isolated relay is optional.",
                    "דואר מקומי אינו דורש יציאה נוספת; ממסר נפרד הוא אופציונלי."),
            existingIsolated == true || unsafeRelay ? review : preliminary,
            Preferred: !unsafeRelay && smtpClients && existingIsolated != true && !needsAudience,
            Enabled: !unsafeRelay,
            RequiresSeparatePort: true));

        options.Add(new(MailScenarioPlanner.Rebuild,
            T(language, "Полностью заменить почтовую конфигурацию",
                "Rebuild mail configuration from scratch",
                "בנה מחדש תצורת דואר"),
            T(language, "Только при явном отказе от текущей конфигурации. Нужны полный backup, анализ очереди и отдельное подтверждение.",
                "Only when intentionally retiring the existing setup. Requires full backup, queue review and explicit approval.",
                "רק בהחלטה מודעת; נדרשים גיבוי, סקירת תור ואישור."),
            T(language, "Высокий риск · не рекомендуется автоматически",
                "High risk · never recommended automatically", "סיכון גבוה"),
            Preferred: false, Enabled: !unsafeRelay,
            RequiresSeparatePort: false));

        // Display relevant options ahead of less useful ones, but never
        // auto-select, auto-apply or imply that tenant rights were checked.
        return options.OrderByDescending(o => o.Preferred)
            .ThenBy(o => o.Code == MailScenarioPlanner.Rebuild ? 1 : 0)
            .ToArray();
    }

    internal static bool SelfTest()
    {
        var linux = new MailRoutingInventory("postfix", "[relay.example.org]:587",
            "smtp", new string('a', 64));
        const string smtpAudit = "SMTP_AUDIT_VERSION=1\nSMTP_AUDIT_MTA=postfix\n" +
            "SMTP_PUBLIC_BIND=loopback_only\nSMTP_RELAY_POLICY_RISK=relay_guard_present\n" +
            "SMTP_EXTERNAL_REACHABILITY=not_tested_from_internet\nSMTP_OPEN_RELAY_PROVEN=no\n";
        var audit = ExistingSmtpAudit.Parse(smtpAudit);
        // Host inspection has its own strict parser with many system fields:
        // use the existing validated fixture from its unit test pattern.
        return Supported(Unknown) && Supported(Jobs) && Supported(Smtp) &&
            !Supported("scheduled-product-name") &&
            SourceLabel(Jobs, 1).Contains("background jobs", StringComparison.Ordinal) &&
            SourceLabel(Local, 0).Contains("Linux", StringComparison.Ordinal) &&
            audit.Mta == "postfix" && linux.CurrentRelay.Contains("relay.example.org");
    }
}
