namespace LinuxMailRelay365;

// Human-readable, read-only guidance. This never chooses a transport, changes
// a route, authorizes a tenant, or treats observed sockets as verified delivery.
internal sealed record MailDiscoveryFact(string Caption, string Value);

internal sealed record MailDiscoveryBrief(
    string Headline,
    IReadOnlyList<MailDiscoveryFact> Facts,
    string SuggestedNextStep,
    string ReviewWarning,
    string? ExtraNote)
{
    private static string T(int language, string ru, string en, string he) =>
        language == 0 ? ru : language == 2 ? he : en;

    private static string Known(string? value, int language) =>
        string.IsNullOrWhiteSpace(value) || value is "unknown" or "unavailable" or "unverified"
            ? T(language, "не подтверждено", "not verified", "לא אומת")
            : value;

    internal static MailDiscoveryBrief Build(
        MailRoutingInventory? inventory,
        ExistingSmtpAudit? audit,
        MailHostInspection? host,
        bool? isolatedRelay,
        MailServerDiscoveryDecision decision,
        int recipientScope,
        string? proposedPort,
        int language, string selectedScenario = MailScenarioPlanner.Choose,
        string destination = MailFlowIntent.TargetM365)
    {
        int l = language;
        bool postfix = inventory?.Mta == "postfix";
        string mailServer = inventory?.Mta switch
        {
            "postfix" => "Postfix",
            "sendmail" => "Sendmail",
            "exim" => "Exim",
            "none" => T(l, "не найден", "not detected", "לא זוהה"),
            _ => T(l, "не подтверждён", "unverified", "לא אומת")
        };
        string active = host?.MtaState == "active"
            ? T(l, "работает", "active", "פעיל")
            : T(l, "состояние требуется проверить", "state not verified", "המצב לא אומת");
        string existingRelay = Known(inventory?.CurrentRelay, l);
        string configuredPorts = host?.ConfiguredSmtpPortState ?? "";
        string smtpListener = audit?.PublicBind switch
        {
            "loopback_only" => T(l, "обнаружен только локальный listener", "local-only listener observed", "זוהתה האזנה מקומית בלבד"),
            "potentially_public" => T(l, "возможна внешняя привязка; доступ извне не доказан", "potential external binding; Internet access unverified", "חיבור חיצוני אפשרי; לא אומת"),
            "private_or_other" => T(l, "привязка к внутреннему/другому IP; доступ требует проверки", "private/other binding; access unverified", "האזנה בכתובת פרטית/אחרת"),
            _ => T(l, "фактический listener не подтверждён", "active listener not verified", "האזנה בפועל לא אומתה")
        };
        string inbound = T(l, "Настроены входящие порты: ", "Configured inbound ports: ", "יציאות נכנסות מוגדרות: ") +
            Known(configuredPorts, l) + "; " + smtpListener;
        string hostName = host?.HasFqdn == true ? host.Fqdn : Known(host?.ShortHostname, l);
        string domain = host?.HasDomain == true ? host.Domain :
            T(l, "не подтверждён", "not verified", "לא אומת");
        bool gmail = inventory?.CurrentRelay.Contains("smtp.gmail.com", StringComparison.OrdinalIgnoreCase) == true;

        var facts = new List<MailDiscoveryFact>
        {
            new(T(l, "Работающий MTA", "Mail server", "שרת דואר"), mailServer + " · " + active),
            new(T(l, "Текущая исходящая отправка", "Existing outbound relay", "ממסר יוצא קיים"),
                (gmail ? "Gmail · " : "") + existingRelay),
            new(T(l, "Локальный приём SMTP", "Inbound SMTP", "SMTP נכנס"), inbound),
            new(T(l, "Имя Linux", "Linux host", "שם שרת Linux"), hostName),
            new(destination == MailFlowIntent.TargetM365
                ? T(l, "Домен Linux (не проверен в M365)", "Linux domain (not M365 verified)", "דומיין Linux (לא אומת ב-M365)")
                : T(l, "Домен Linux (права отправителя не проверены)",
                    "Linux domain (sender authorization unverified)", "דומיין Linux (שולח לא אומת)"),
                domain)
        };
        if (postfix && host?.Mta == "postfix")
        {
            string localScope = host.Get("MAIL_HOST_POSTFIX_MYDESTINATION");
            bool declaredLocal = !string.IsNullOrWhiteSpace(localScope) &&
                localScope is not ("unverified" or "unavailable");
            string virtualMailbox = host.Get("MAIL_HOST_POSTFIX_ROLE_VIRTUAL_MAILBOX_DOMAINS");
            string virtualAlias = host.Get("MAIL_HOST_POSTFIX_ROLE_VIRTUAL_ALIAS_DOMAINS");
            string localSummary = virtualMailbox == "declared"
                ? T(l, "объявлены virtual mailbox domains; реальные ящики и доставка не проверены",
                    "virtual mailbox domains declared; accounts and delivery NOT verified",
                    "תחומי תיבות וירטואליות הוגדרו; המסירה לא אומתה")
                : declaredLocal
                ? T(l, "объявлена область локальных доменов (mydestination); наличие пользователей и доставка не доказаны",
                    "local domain scope declared (mydestination); users and delivery NOT verified",
                    "תחומי דואר מקומיים הוגדרו; משתמשים לא אומתו")
                : T(l, "локальная доставка не подтверждена",
                    "local delivery not verified", "מסירה מקומית לא אומתה");
            if (virtualAlias == "declared")
                localSummary += T(l, "; virtual aliases присутствуют",
                    "; virtual aliases declared", "; כינויים וירטואליים הוגדרו");
            facts.Add(new(T(l, "Локальная доставка", "Local delivery", "מסירה מקומית"),
                localSummary));
            bool complexRouting = new[] {
                "MAIL_HOST_POSTFIX_ROLE_TRANSPORT_MAPS",
                "MAIL_HOST_POSTFIX_ROLE_SENDER_DEPENDENT_RELAYHOST_MAPS",
                "MAIL_HOST_POSTFIX_ROLE_RELAY_DOMAINS"
            }.Any(key => host.Get(key) == "declared");
            facts.Add(new(T(l, "Дополнительная маршрутизация",
                    "Advanced routing declarations", "ניתוב מתקדם"),
                complexRouting
                ? T(l, "обнаружены дополнительные маршруты/домены — не заменять автоматически",
                    "additional routes/domains declared — do not overwrite automatically",
                    "הוגדרו נתיבים נוספים; אין להחליף אוטומטית")
                : T(l, "настройки не обнаружены или не подтверждены; необходима проверка",
                    "not declared or not verified; manual review still required",
                    "לא זוהו או לא אומתו הגדרות נוספות")));
            bool rewrite = host.Get("MAIL_HOST_POSTFIX_ROLE_MASQUERADE_DOMAINS") == "declared" ||
                host.Get("MAIL_HOST_POSTFIX_ROLE_SENDER_CANONICAL_MAPS") == "declared" ||
                host.Get("MAIL_HOST_POSTFIX_ROLE_SMTP_GENERIC_MAPS") == "declared";
            if (rewrite)
                facts.Add(new(T(l, "Изменение адресов отправителей",
                        "Sender rewriting", "שכתוב שולחים"),
                    T(l, "обнаружены правила переписывания — обязательно сохранить при смене upstream",
                        "rewriting declared — preserve during any upstream migration",
                        "הוגדר שכתוב שולחים; יש לשמור עליו")));
        }
        if (!string.IsNullOrWhiteSpace(proposedPort))
            facts.Add(new(T(l, "Порт нового Relay (предложение)", "Proposed new relay port", "יציאת ממסר חדשה מוצעת"),
                proposedPort + " · " + T(l, "не считайте работающим", "not evidence of an active listener", "לא מעיד על שירות פעיל")));

        string headline = isolatedRelay == true
            ? T(l, "Отдельный Relay уже обнаружен. Сначала проверьте его.",
                "An isolated relay was detected. Audit it before reinstalling.",
                "זוהה ממסר נפרד. יש לבדוק אותו לפני התקנה.")
            : postfix
                ? selectedScenario == MailScenarioPlanner.ReplaceRelay
                    ? T(l, "Postfix уже работает — можно планировать смену исходящего маршрута без нового SMTP-порта.",
                        "Postfix is running — an in-place upstream change needs no new inbound SMTP port.",
                        "Postfix כבר פועל; ניתן לשנות ניתוב יוצא ללא יציאה חדשה.")
                    : selectedScenario == MailScenarioPlanner.Rebuild
                    ? T(l, "Полная замена конфигурации — отдельная рискованная операция.",
                        "Full configuration rebuild is a separate high-risk operation.",
                        "התקנה מחדש היא פעולה מסוכנת ונפרדת.")
                    : T(l, "Postfix работает. Сначала выберите: оставить, добавить маршрут или заменить upstream.",
                        "Postfix is running. Choose to keep, add a separate route or migrate the upstream.",
                        "Postfix פועל. בחרו אם לשמור או לשנות את הניתוב.")
                : inventory?.Mta is "exim" or "sendmail"
                    ? T(l, "Существующий MTA нельзя автоматически заменять.",
                        "Do not automatically replace the existing MTA.",
                        "אין להחליף אוטומטית את שרת הדואר הקיים.")
                    : T(l, "Сначала подтвердите состояние почтовой службы.",
                        "Verify the existing mail service before configuring a route.",
                        "בדקו תחילה את שירות הדואר.");

        string steps = isolatedRelay == true
            ? T(l, "Проверьте настройки, порт и очередь существующего отдельного Relay. Повторная установка не рекомендуется.",
                "Inspect the existing isolated relay's port, queue and delivery before creating another instance.",
                "בדקו את היציאה, התור והניתוב של הממסר הקיים.")
            : postfix && selectedScenario == MailScenarioPlanner.ReplaceRelay
                ? T(l, "План замены upstream: сохранить локальную подачу почты, текущий SMTP listener и очередь Postfix; проверить целевой relay, backup и откат.",
                    "Upstream migration plan: preserve local mail submission, the active SMTP listener and Postfix queue; verify destination, backup and rollback.",
                    "שנו רק ניתוב יוצא, תוך שמירת התור והאזנה המקומית.")
            : postfix && selectedScenario == MailScenarioPlanner.Keep
                ? T(l, "Текущий Postfix и его исходящий маршрут останутся без изменений.",
                    "Current Postfix and its upstream route remain unchanged.",
                    "Postfix והניתוב הקיים יישארו ללא שינוי.")
            : postfix && selectedScenario == MailScenarioPlanner.Rebuild
                ? T(l, "Полная переустановка возможна только после проверки всех локальных отправителей, архивирования, анализа очереди и подтверждения.",
                    "Full rebuild requires an inventory of mail sources, a verified backup, queue review and explicit approval.",
                    "התקנה מחדש דורשת גיבוי ובדיקת תור.")
            : postfix
                ? T(l, "Выберите, кто отправляет почту (локальные пользователи, службы или SMTP-клиенты), затем решите: сохранить, изменить upstream или добавить отдельный Relay.",
                    "Choose the mail source (local users, services or SMTP clients), then keep, replace upstream or add an isolated relay.",
                    "בחרו מקורות דואר ואז את סוג השינוי.")
                : T(l, "Проверьте текущую почту и возможность отдельного Relay. Основную конфигурацию не изменяйте.",
                    "Inspect current mail delivery and the feasibility of an independent relay. Do not change the primary configuration.",
                    "בדקו ממסר נפרד, ללא שינוי התצורה הקיימת.");

        string audience = selectedScenario == MailScenarioPlanner.Keep ? ""
            : destination == MailFlowIntent.TargetM365 ? recipientScope switch
        {
            1 => T(l,
                "Только внутренние получатели M365: возможен Direct Send (исходящий TCP 25). XOAUTH2 — альтернатива при одобренном почтовом ящике.",
                "Internal M365 recipients only: Direct Send over outbound TCP 25 is a candidate. XOAUTH2 is another option with an approved mailbox.",
                "לנמענים פנימיים ניתן לשקול Direct Send ביציאה 25 או XOAUTH2."),
            2 => T(l,
                "Есть внешние получатели: кандидат — XOAUTH2 от разрешённого ящика через TCP 587. Connector через TCP 25 — альтернатива после проверки tenant и IP/сертификата. Direct Send не подходит.",
                "External recipients: consider XOAUTH2 from an approved mailbox over TCP 587. Connector over TCP 25 requires tenant and IP/certificate approval. Direct Send is unsuitable.",
                "לנמענים חיצוניים: XOAUTH2 או Connector מאושר; Direct Send אינו מתאים."),
            _ => T(l,
                "Укажите, нужны ли внешние получатели: только после этого можно выбирать XOAUTH2, Connector или Direct Send.",
                "Choose whether external recipients are needed before selecting XOAUTH2, Connector or Direct Send.",
                "בחרו אם נדרשים נמענים חיצוניים לפני בחירת שיטה.")
        } : T(l,
            "Для выбранного SMTP-провайдера проверьте разрешённые адреса отправителей, домены и политику доставки. Доступ TCP не доказывает разрешения или доставку.",
            "Verify authorized sender identities, domains and recipient policy for the selected SMTP provider. TCP connectivity proves neither permission nor delivery.",
            "יש לבדוק את מדיניות השולחים והנמענים של ספק SMTP.");

        string warning = decision.Code switch
        {
            "suspected_unsafe_relay" => T(l,
                "Внимание: возможны небезопасные правила Relay. Это не доказательство открытого Relay; выполните проверку перед изменениями.",
                "Possible unsafe relay rules. This does not prove an open relay; audit before making changes.",
                "חשד למדיניות relay לא בטוחה; יש לבדוק לפני שינוי."),
            "postfix_needs_review" or "not_verified" or "conflicting_or_unknown_mta" => T(l,
                "Нужно проверить ограничения Relay и привязку SMTP. Вывод предварительный, установка не разрешена автоматически.",
                "SMTP bindings and relay restrictions need review. This is guidance only, not approval to install.",
                "יש לבדוק הגבלות relay והאזנה. זו המלצה בלבד."),
            _ => T(l,
                "Выбор маршрута не подтверждает доставку, разрешения Microsoft 365 или безопасность SMTP. Изменения не выполнялись.",
                "The route choice does not prove delivery, M365 authorization or SMTP safety. No changes were made.",
                "בחירת מסלול אינה מאשרת משלוח או הרשאות. לא בוצעו שינויים.")
        };
        string? extra = inventory?.Mta == "postfix" &&
            !string.IsNullOrWhiteSpace(inventory.CurrentRelay)
            ? T(l,
                "Ротация сертификата OAuth сама по себе не переводит существующий relay на другой сервис.",
                "Rotating an OAuth certificate does not switch an existing upstream relay to another service.",
                "חידוש אישור OAuth אינו משנה את הניתוב היוצא.")
            : null;

        return new MailDiscoveryBrief(headline, facts,
            steps + (audience.Length > 0 ? Environment.NewLine + audience : ""),
            warning, extra);
    }

    internal static bool SelfTest()
    {
        var active = new MailRoutingInventory("postfix", "[smtp.gmail.com]:587",
            "smtp", new string('a', 64));
        var review = new MailServerDiscoveryDecision("postfix_needs_review", true, true);
        var result = Build(active, null, null, false, review, 2, "2525", 0);
        if (!result.Headline.Contains("Сначала выберите", StringComparison.Ordinal) ||
            !result.Facts.Any(x => x.Value.Contains("[smtp.gmail.com]:587", StringComparison.Ordinal)) ||
            !result.Facts.Any(x => x.Value.Contains("не считайте работающим", StringComparison.Ordinal)) ||
            !result.SuggestedNextStep.Contains("XOAUTH2", StringComparison.Ordinal) ||
            !result.SuggestedNextStep.Contains("Direct Send не подходит", StringComparison.Ordinal) ||
            !result.ReviewWarning.Contains("установка не разрешена", StringComparison.Ordinal) ||
            result.ExtraNote is null) return false;
        var internalOnly = Build(active, null, null, false,
            new MailServerDiscoveryDecision("postfix_active", true, false), 1, "25", 1);
        const string hostReport =
            "MAIL_HOST_VERSION=1\nMAIL_HOST_SHORT=mail\n" +
            "MAIL_HOST_FQDN=mail.example.org\nMAIL_HOST_DOMAIN=example.org\n" +
            "MAIL_HOST_MTA=postfix\nMAIL_HOST_MTA_STATE=active\n" +
            "MAIL_HOST_TRUST=os_report_unverified\nMAIL_HOST_CHANGES=no\n" +
            "MAIL_HOST_POSTFIX_MYDESTINATION=$myhostname, localhost\n" +
            "MAIL_HOST_POSTFIX_ROLE_VIRTUAL_MAILBOX_DOMAINS=declared\n" +
            "MAIL_HOST_POSTFIX_ROLE_TRANSPORT_MAPS=declared\n" +
            "MAIL_HOST_POSTFIX_ROLE_SENDER_CANONICAL_MAPS=declared\n";
        // Present advanced settings must not be interpreted as proof of live mail.
        var inspected = MailHostInspection.Parse(hostReport);
        var categorized = Build(active, null, inspected, false,
            new MailServerDiscoveryDecision("postfix_active", true, false),
            2, null, 1);
        return internalOnly.SuggestedNextStep.Contains("Direct Send", StringComparison.Ordinal) &&
               internalOnly.Facts.Any(x => x.Caption == "Proposed new relay port" &&
                   x.Value.Contains("not evidence", StringComparison.Ordinal)) &&
               categorized.Facts.Any(x => x.Caption == "Local delivery" &&
                   x.Value.Contains("NOT verified", StringComparison.Ordinal)) &&
               categorized.Facts.Any(x => x.Caption == "Advanced routing declarations" &&
                   x.Value.Contains("do not overwrite", StringComparison.Ordinal)) &&
               categorized.Facts.Any(x => x.Caption == "Sender rewriting");
    }
}
