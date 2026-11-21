using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    // Experimental Multi-mailbox work is scoped to one exact SSH endpoint,
    // an exact runtime sender map, delivery mode and sidecar input. An earlier
    // Preview must never authorize a new host or a changed route.
    private string? reviewedMultiMailboxPlanSha;
    private string? reviewedMultiMailboxPlanContext;
    private string multiMailboxRouteSummary = "";

    private void ResetMultiMailboxRouteReview()
    {
        reviewedMultiMailboxPlanSha = null;
        reviewedMultiMailboxPlanContext = null;
        multiMailboxRouteSummary = "";
    }

    private string CurrentMultiMailboxContext()
    {
        if (mailTransport.SelectedIndex != 0 || oauthSenderMode.SelectedIndex != 1)
            throw new InvalidOperationException("Select the isolated multi-mailbox XOAUTH2 route first.");
        if (!string.Equals(oauthSenderMapPath.Text.Trim(),
                "/etc/linuxmailrelay365/oauth-senders.tsv", StringComparison.Ordinal))
            throw new InvalidOperationException(
                "The experimental installer requires /etc/linuxmailrelay365/oauth-senders.tsv. " +
                "A custom sender-map path is read-only until a matching installer is implemented.");
        var endpoint = Endpoint();
        return string.Join("|",
            SecurityOptionsStore.Identity(endpoint),
            oauthSenderMapPath.Text.Trim(),
            mailTransport.SelectedIndex,
            oauthSenderMode.SelectedIndex,
            isolatedSmtpPort.Text.Trim());
    }

    private static string ValidatedMultiMailboxReportValue(
        string report, string key, string allowed)
    {
        var lines = report.Split('\n');
        var values = lines
            .Select(line => line.TrimEnd('\r'))
            .Where(line => line.StartsWith(key + "=", StringComparison.Ordinal))
            .ToArray();
        if (values.Length != 1)
            throw new InvalidDataException("Incomplete or duplicated multi-mailbox operation receipt.");
        string value = values[0][(key.Length + 1)..];
        if (!Regex.IsMatch(value, allowed, RegexOptions.CultureInvariant))
            throw new InvalidDataException("Unexpected multi-mailbox receipt value.");
        return value;
    }

    private async Task StageMultiMailboxRuntimeAsync()
    {
        string context = CurrentMultiMailboxContext();
        if (!ConfirmDestructive("LinuxMailRelay365 | Stage multi-mailbox source files",
            T("Экспериментальная подготовка: создаётся ТОЛЬКО новый каталог /opt/linuxmailrelay365/multi-oauth " +
              "с проверенными Python-файлами. Существующие папки не перезаписываются. SMTP, очереди, Microsoft 365 и службы не меняются. " +
              "Подготовка НЕ включает отправку и НЕ означает готовность к production.",
              "EXPERIMENTAL: create only a new root-owned /opt/linuxmailrelay365/multi-oauth source folder. " +
              "Existing folders are never overwritten. SMTP routes, queues, Microsoft 365 and services stay untouched. " +
              "This is NOT production activation or delivery verification.",
              "הכנת קבצי מקור בתיקייה חדשה בלבד. אין שינוי בשירותי SMTP או שליחת דואר."),
            "STAGE MULTI MAILBOX")) return;
        ResetMultiMailboxRouteReview();
        var endpoint = Endpoint();
        var result = await SshRemote.RunRootScriptAsync(
            endpoint, EmbeddedAssets.BuildMultiMailboxRuntimeStageBundle(), TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_SOURCE_STAGE", @"\Acreated_no_service_changes\z");
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_SOURCE_MAIL_SENT", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_SOURCE_PRIMARY_MTA_CHANGED", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException(
                "SSH identity or route changed during the source stage; reinspect the server.");
        multiMailboxRouteSummary = T(
            "Файлы подготовлены на Linux. Запустите Preview. Ничего не активировано.",
            "Protected Linux source files staged. Run Preview next. Nothing activated.",
            "הקבצים הוכנו. עדיין לא הופעלה שליחה.");
        WriteLine("Experimental multi-mailbox Python source staged on Linux. Primary MTA and queues untouched.");
        RenderPage();
    }

    private async Task PreviewMultiMailboxRouteAsync()
    {
        string context = CurrentMultiMailboxContext();
        ResetMultiMailboxRouteReview();
        var result = await SshRemote.RunRootScriptAsync(
            Endpoint(), EmbeddedAssets.BuildMultiMailboxRouteBundle("plan"), TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        string sha = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_OAUTH_PLAN_SHA256", @"\A[a-f0-9]{64}\z");
        string count = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_OAUTH_MAILBOXES", @"\A(?:[1-9]|[1-5][0-9]|6[0-4])\z");
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_OAUTH_STATUS", @"\Areview_only\z");
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_OAUTH_MESSAGES_SENT", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_OAUTH_SERVICES_CHANGED", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_OAUTH_PRIMARY_POSTFIX_CHANGED", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException(
                "SSH identity, map or route inputs changed during the reviewed Preview.");
        reviewedMultiMailboxPlanSha = sha;
        reviewedMultiMailboxPlanContext = context;
        multiMailboxRouteSummary = T(
            "План проверен для " + count + " ящиков. Изменений нет. SHA-256: " + sha[..16] +
                "… . Для применения нужен остановленный отдельный Postfix и пустая очередь.",
            "Reviewed " + count + " mailbox identities. No changes. Plan SHA-256: " +
                sha[..16] + "… . Offline apply requires a STOPPED isolated Postfix and EMPTY queue.",
            "נבדקו " + count + " תיבות. הממסר חייב להיות עצור והתור ריק לפני החלה.");
        WriteLine("Reviewed experimental offline multi-mailbox plan SHA256=" +
                  sha + "; mailboxes=" + count +
                  ". No Microsoft 365 token, message or server modification was performed.");
        RenderPage();
    }

    private async Task ApplyMultiMailboxRouteOfflineAsync()
    {
        string context = CurrentMultiMailboxContext();
        if (reviewedMultiMailboxPlanSha is null ||
            reviewedMultiMailboxPlanContext != context)
            throw new InvalidOperationException(
                "Run a new verified Preview on this exact SSH host, map, and sidecar configuration.");
        string sha = reviewedMultiMailboxPlanSha;
        if (!ConfirmDestructive("LinuxMailRelay365 | Experimental OFFLINE multi-mailbox",
            T("ОПАСНОЕ ИЗМЕНЕНИЕ: изменится маршрут отправки ТОЛЬКО отдельного Postfix. " +
              "Остановите sidecar вручную; очередь должна быть ПУСТА. Создаётся backup с проверкой. " +
              "Рабочие SMTP-письма НЕ отправляются. Служба НЕ будет запущена. " +
              "Нужны реальные тесты Microsoft 365 и отдельный проверенный Restore перед production.",
              "EXPERIMENTAL ROUTE CHANGE: modifies ONLY the isolated Postfix route. " +
              "STOP the sidecar manually and verify its queue is EMPTY. Root-only safety backup is required. " +
              "This does NOT start services or send SMTP. Live M365 acceptance and verified Restore " +
              "are still required before production.",
              "שינוי ניסיוני של הנתיב המבודד בלבד. יש לעצור שירות ולוודא תור ריק. גיבוי נדרש."),
            "INSTALL MULTI MAILBOX OFFLINE")) return;
        // Approval is single-use even if SSH fails or the operator loses the session.
        ResetMultiMailboxRouteReview();
        var result = await SshRemote.RunRootScriptAsync(
            Endpoint(), EmbeddedAssets.BuildMultiMailboxRouteBundle("apply", sha),
            TimeSpan.FromMinutes(8));
        result.EnsureSuccess();
        string count = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_OAUTH_MAILBOXES", @"\A(?:[1-9]|[1-5][0-9]|6[0-4])\z");
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_OAUTH_STATUS", @"\Aoffline_installed_NOT_started\z");
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_OAUTH_MESSAGES_SENT", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_OAUTH_SERVICES_CHANGED", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_OAUTH_PRIMARY_POSTFIX_CHANGED", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException(
                "Host or route changed during offline installation; leave the service stopped and reinspect.");
        multiMailboxRouteSummary = T(
            "Офлайн-конфигурация установлена для " + count + " ящиков. Служба НЕ запущена. " +
              "Не включайте отправку до реальных SMTP/Exchange-тестов.",
            "Offline configuration installed for " + count + " mailboxes. Service NOT started. " +
              "Do not enable sending before real SMTP/Exchange acceptance.",
            "התצורה הותקנה במצב לא מקוון. השירות לא הופעל.");
        WriteLine("Experimental multi-mailbox offline configuration installed; no daemon started. " +
                  "Backups remain on the Linux host under /var/backups/linuxmailrelay365-multi-oauth. " +
                  "No inbox delivery or production readiness proven.");
        RenderPage();
    }

    private async Task RefreshMultiMailboxIngressProofAsync()
    {
        string context = CurrentMultiMailboxContext();
        if (!ConfirmDestructive("LinuxMailRelay365 | Refresh experimental ingress proof",
            T("Только для контролируемого тестирования: обновляется root-only проверка SMTP AUTH и From Guard, " +
              "действительная всего 120 секунд. Отдельный Postfix, Dovecot и From-Guard должны уже работать. " +
              "Операция НЕ отправляет письма и НЕ запускает службы. Для production нужен отдельный мониторинг и реальные тесты.",
              "SUPERVISED TESTS ONLY: refresh a root-issued SMTP AUTH/From Guard proof valid for 120 seconds. " +
              "The independent Postfix, Dovecot and From Guard must already be RUNNING. " +
              "No mail is sent and no service is started. Production requires a vetted renewal timer and live acceptance.",
              "בדיקה מבוקרת בלבד. אישור אבטחה ל-120 שניות, ללא שליחת דואר או הפעלת שירותים."),
            "REFRESH MULTI INGRESS PROOF")) return;
        var endpoint = Endpoint();
        string map = oauthSenderMapPath.Text.Trim();
        var audit = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildOAuthSenderMapAuditBundle(map),
            TimeSpan.FromSeconds(90));
        audit.EnsureSuccess();
        _ = ValidatedMultiMailboxReportValue(audit.StdOut,
            "OAUTH_SENDER_MAP_RESULT", @"\Astructural_review_only\z");
        string sha = ValidatedMultiMailboxReportValue(audit.StdOut,
            "OAUTH_SENDER_MAP_MAP_SHA256", @"\A[a-f0-9]{64}\z");
        _ = ValidatedMultiMailboxReportValue(audit.StdOut,
            "OAUTH_SENDER_MAP_SENDAS_DIFFERENT_FROM", @"\A0\z");
        _ = ValidatedMultiMailboxReportValue(audit.StdOut,
            "OAUTH_SENDER_MAP_MESSAGES_SENT", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException("The approved SSH host or sender map changed during read-only review.");
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildMultiMailboxProofRefreshBundle(sha),
            TimeSpan.FromMinutes(2));
        result.EnsureSuccess();
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_INGRESS_PROOF", @"\Arefreshed_static_audit_only\z");
        string seconds = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_INGRESS_PROOF_EXPIRES_SECONDS", @"\A120\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_INGRESS_MAILBOXES", @"\A(?:[1-9]|[1-5][0-9]|6[0-4])\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_INGRESS_MESSAGES_SENT", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_INGRESS_MTA_SERVICES_CHANGED", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException(
                "SSH host or multi-mailbox route changed; do not rely on the previous proof.");
        multiMailboxRouteSummary = T(
            "Привилегированная проверка активных SMTP AUTH/From Guard завершена. " +
              "Действует " + seconds + " секунд. Доставка Microsoft 365 НЕ подтверждена.",
            "Live service configuration proof refreshed for " + seconds +
              " seconds. No SMTP message or recipient delivery is verified.",
            "אישור תצורה זמני ל-" + seconds + " שניות. שליחת דואר לא אומתה.");
        WriteLine("Privileged multi-mailbox ingress receipt refreshed for supervised tests only. " +
            "No message transmitted; never interpret the receipt as Exchange delivery proof.");
        RenderPage();
    }

}
