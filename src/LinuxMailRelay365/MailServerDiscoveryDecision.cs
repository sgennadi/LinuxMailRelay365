namespace LinuxMailRelay365;

// The plan advisor interprets ONLY read-only local evidence. It never selects
// an Exchange/Entra identity, deploys a route or changes an existing MTA.
internal sealed record MailServerDiscoveryDecision(
    string Code, bool PreserveRecommended, bool ManualReviewRequired)
{
    internal static MailServerDiscoveryDecision Assess(
        MailRoutingInventory? inventory, ExistingSmtpAudit? audit, bool? isolatedDetected)
    {
        if (inventory is null || audit is null)
            return new("not_verified", false, true);
        if (audit.SuspectedUnsafeRelay)
            return new("suspected_unsafe_relay", true, true);
        if (audit.Mta is "multiple_active_mta_manual_review" or
            "mta_service_state_unverified_manual_review" or
            "postfix_cli_missing_manual_review")
            return new("conflicting_or_unknown_mta", true, true);
        if (audit.Mta == "postfix" && inventory.Mta == "postfix")
        {
            if (audit.PublicBind is "unknown" or "no_matching_listeners" ||
                audit.RelayRisk is "unknown" or "needs_manual_review")
                return new("postfix_needs_review", true, true);
            return isolatedDetected == true
                ? new("existing_isolated_relay", true, audit.PotentiallyPublic)
                : new("postfix_active", true, audit.PotentiallyPublic);
        }
        if (audit.Mta is "exim_manual_review" or "sendmail_manual_review")
            return new("foreign_mta_active", true, true);
        if (audit.Mta == "no_active_mta_verified")
            return inventory.Mta == "none"
                ? new("no_standard_mta_detected", false, true)
                : new("installed_but_not_active", true, true);
        return new("conflicting_or_unknown_mta", true, true);
    }

    internal string Explain(int language, MailRoutingInventory? inventory,
        ExistingSmtpAudit? audit, bool? isolatedDetected)
    {
        int lang = language is 0 or 1 or 2 ? language : 1;
        string detail = Code switch
        {
            "postfix_active" => Local(lang,
                "Postfix обнаружен как активный MTA. Рекомендация: сохранить существующую почту и использовать отдельный SMTP Relay на собственном порту.",
                "Active Postfix found. Recommend Preserve Existing Mail and a separate SMTP Relay on a dedicated port.",
                "Postfix פעיל. מומלץ לשמור את הדואר הקיים ולהשתמש בממסר נפרד."),
            "existing_isolated_relay" => Local(lang,
                "Обнаружены работающий Postfix и файлы отдельного Relay. Сначала проверьте действующий Relay — повторная установка не рекомендуется.",
                "Active Postfix and accessible isolated Relay configuration found. Audit the existing Relay before any reinstall.",
                "נמצאו Postfix ותצורת ממסר נפרד. יש לבדוק לפני התקנה חוזרת."),
            "postfix_needs_review" => Local(lang,
                "Postfix активен, но состояние SMTP или ограничений Relay не подтверждено. Сохраните существующую конфигурацию; перед установкой необходим повторный анализ.",
                "Postfix is active but SMTP listener or relay policy is not verified. Preserve the primary configuration and review it first.",
                "Postfix פעיל אך הגדרות SMTP אינן מאומתות. יש לבדוק לפני שינוי."),
            "foreign_mta_active" => Local(lang,
                "Работает Exim или Sendmail. Не заменяйте его. Для нового шлюза предусмотрен только отдельно проверяемый Connector/Direct Send с фиксированным отправителем; общий XOAUTH2 здесь не поддержан.",
                "Exim or Sendmail is active. Never replace it automatically. Guarded isolated fixed-sender Connector/Direct Send can be reviewed; the generic XOAUTH2 installer is not supported for this MTA.",
                "Exim או Sendmail פעיל. אין להחליפו; יש לבדוק ממסר נפרד."),
            "no_standard_mta_detected" => Local(lang,
                "Стандартный MTA не обнаружен и активная служба не подтверждена. Это не гарантирует, что сервер не использует SMTP: проверьте нестандартные службы перед новой установкой.",
                "No standard MTA package or active service was identified. This does NOT prove that no custom SMTP server is running. Inspect before a fresh setup.",
                "לא זוהה MTA סטנדרטי. יש לבדוק שירותי SMTP נוספים."),
            "installed_but_not_active" => Local(lang,
                "Обнаружены компоненты MTA, но активная стандартная служба не подтверждена. Не считайте сервер пустым: изучите службу и текущую конфигурацию.",
                "MTA components are installed, but no active standard MTA was verified. Do not assume an empty mail server.",
                "מותקנים רכיבי דואר אך שירות פעיל אינו מאומת."),
            "suspected_unsafe_relay" => Local(lang,
                "Обнаружены потенциально опасные ограничения Relay. Требуется ручная проверка до любых изменений. Это подозрение, а не доказательство открытого Relay.",
                "Potentially unsafe relay policy detected. Manual investigation is required before changes. This is NOT proof of an open relay.",
                "זוהה חשד למדיניות relay לא בטוחה. נדרשת בדיקה ידנית."),
            "conflicting_or_unknown_mta" => Local(lang,
                "Тип активного почтового сервера не установлен однозначно (возможны несколько MTA). Никаких автоматических замен или выбора маршрута.",
                "Active MTA identity is ambiguous or multiple MTA services may be active. Never auto-replace or infer an outbound route.",
                "זהות שרת הדואר אינה חד-משמעית. אין לשנות תצורה אוטומטית."),
            _ => Local(lang,
                "Анализ почтового сервера не завершён. Проверьте SSH и повторите проверку без изменений.",
                "Mail-server discovery is incomplete. Verify SSH access and rerun the read-only inspection.",
                "בדיקת שרת הדואר טרם הושלמה.")
        };
        string observed = inventory is null
            ? Local(lang, "Установленный MTA: неизвестно.", "Installed MTA: unverified.", "MTA לא מאומת.")
            : Local(lang, "Компоненты: ", "Installed components: ", "רכיבים: ") +
              inventory.Mta + (inventory.Mta == "postfix"
                ? Local(lang, "; relayhost: ", "; relayhost: ", "; relayhost: ") +
                  (string.IsNullOrEmpty(inventory.CurrentRelay)
                    ? Local(lang, "не указан", "not configured", "לא הוגדר")
                    : Local(lang, "задан", "configured", "הוגדר"))
                : "");
        string sidecar = isolatedDetected == true
            ? Local(lang, "Отдельный Relay: доступные файлы обнаружены.",
                "Isolated Relay: readable configuration detected.",
                "ממסר נפרד: נמצאה תצורה קריאה.")
            : isolatedDetected == false
                ? Local(lang, "Отдельный Relay: в доступных файлах не найден (не доказательство отсутствия).",
                    "Isolated Relay: not found among readable files (absence NOT proven).",
                    "ממסר נפרד: לא נמצא בקבצים קריאים.")
                : Local(lang, "Отдельный Relay: наличие не проверено.",
                    "Isolated Relay: presence not verified.",
                    "ממסר נפרד: לא אומת.");
        string caution = Local(lang,
            "Способ отправки в Microsoft 365 (XOAUTH2 / Connector / Direct Send) выбирается отдельно — по разрешениям tenant и получателям. Ничего не изменено.",
            "M365 delivery method (XOAUTH2 / Connector / Direct Send) must be selected separately based on tenant permissions and recipients. No changes were made.",
            "בחירת מסלול Microsoft 365 תלויה בהרשאות ובנמענים. לא בוצעו שינויים.");
        return observed + Environment.NewLine + sidecar + Environment.NewLine +
            detail + Environment.NewLine + caution +
            (audit?.PotentiallyPublic == true
                ? Environment.NewLine + Local(lang,
                    "Внимание: слушатель может быть публичным; доступ через интернет/NAT не проверен.",
                    "Attention: potentially public bind; Internet/NAT reachability was not verified.",
                    "שים לב: ייתכן שמאזין SMTP ציבורי; גישה מהאינטרנט לא אומתה.")
                : "");
    }

    private static string Local(int lang, string ru, string en, string he) =>
        lang == 0 ? ru : lang == 2 ? he : en;

    internal static bool SelfTest()
    {
        const string common = "SMTP_AUDIT_VERSION=1\nSMTP_EXTERNAL_REACHABILITY=not_tested_from_internet\n" +
            "SMTP_OPEN_RELAY_PROVEN=no_active_probe_performed\n";
        ExistingSmtpAudit Audit(string mta, string bind = "loopback_only",
            string policy = "relay_guard_present") =>
            ExistingSmtpAudit.Parse(common +
                "SMTP_AUDIT_MTA=" + mta + "\nSMTP_PUBLIC_BIND=" + bind +
                "\nSMTP_RELAY_POLICY_RISK=" + policy + "\n");
        var postfix = new MailRoutingInventory("postfix", "[relay.example]:587", "", new string('a', 64));
        var none = new MailRoutingInventory("none", "", "", "unavailable");
        var ready = Assess(postfix, Audit("postfix"), false);
        var sidecar = Assess(postfix, Audit("postfix"), true);
        var unsafePolicy = Assess(postfix,
            Audit("postfix", "potentially_public", "suspected_unsafe_relay"), true);
        var foreign = Assess(postfix, Audit("exim_manual_review"), false);
        var inactive = Assess(postfix, Audit("no_active_mta_verified"), false);
        var uninstalled = Assess(none, Audit("no_active_mta_verified"), false);
        var conflicting = Assess(postfix, Audit("multiple_active_mta_manual_review"), true);
        var unverified = Assess(postfix, null, false);
        return ready.Code == "postfix_active" && ready.PreserveRecommended &&
            !ready.ManualReviewRequired &&
            sidecar.Code == "existing_isolated_relay" &&
            unsafePolicy.Code == "suspected_unsafe_relay" && unsafePolicy.ManualReviewRequired &&
            foreign.Code == "foreign_mta_active" && foreign.PreserveRecommended &&
            inactive.Code == "installed_but_not_active" &&
            uninstalled.Code == "no_standard_mta_detected" && uninstalled.ManualReviewRequired &&
            conflicting.Code == "conflicting_or_unknown_mta" &&
            unverified.Code == "not_verified" &&
            ready.Explain(0, postfix, Audit("postfix"), false).Contains("сохранить",
                StringComparison.OrdinalIgnoreCase) &&
            foreign.Explain(1, postfix, Audit("exim_manual_review"), false)
                .Contains("Never replace", StringComparison.Ordinal);
    }
}
