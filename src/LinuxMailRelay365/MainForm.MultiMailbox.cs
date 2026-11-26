using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    // Experimental Multi-mailbox work is scoped to one exact SSH endpoint,
    // an exact runtime sender map, delivery mode and sidecar input. An earlier
    // Preview must never authorize a new host or a changed route.
    private string? reviewedMultiMailboxPlanSha;
    private string? reviewedMultiMailboxPlanContext;
    private string multiMailboxRouteSummary = "";
    private string? reviewedMultiMailboxRestoreSha;
    private string? reviewedMultiMailboxRestoreBackupId;
    private string? reviewedMultiMailboxRestoreContext;
    private string multiMailboxRestoreSummary = "";
    private string? reviewedMultiProofTimerSha;
    private string? reviewedMultiProofTimerContext;
    private string multiProofTimerSummary = "";

    private readonly TextBox multiTestSender = Field("");
    private readonly TextBox multiTestInternal = Field("");
    private readonly TextBox multiTestExternal = Field("");
    private string? reviewedMultiTestSha;
    private string? reviewedMultiTestRunId;
    private string? reviewedMultiTestContext;
    private string multiTestSummary = "";
    private string? lastMultiTestRunId;
    private string? lastMultiTestContext;
    private string multiTestLedgerSummary = "";

    private void ResetMultiMailboxTestApproval()
    {
        reviewedMultiTestSha = null;
        reviewedMultiTestRunId = null;
        reviewedMultiTestContext = null;
        multiTestSummary = "";
    }

    private void ResetMultiMailboxTestReview()
    {
        ResetMultiMailboxTestApproval();
        lastMultiTestRunId = null;
        lastMultiTestContext = null;
        multiTestLedgerSummary = "";
    }

    private string CurrentMultiMailboxTestContext() =>
        CurrentMultiMailboxContext() + "|" + multiTestSender.Text.Trim() +
        "|" + multiTestInternal.Text.Trim() + "|" + multiTestExternal.Text.Trim();

    private async Task PreviewMultiMailboxDeliveryTestAsync()
    {
        string context = CurrentMultiMailboxTestContext();
        ResetMultiMailboxTestApproval();
        string runId = Guid.NewGuid().ToString("N");
        var result = await SshRemote.RunRootScriptAsync(
            Endpoint(),
            EmbeddedAssets.BuildMultiMailboxAcceptanceBundle(
                runId, multiTestSender.Text.Trim(),
                multiTestInternal.Text.Trim(), multiTestExternal.Text.Trim()),
            TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        string sha = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_PLAN_SHA256", @"\A[a-f0-9]{64}\z");
        string reported = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_RUN_ID", @"\A[a-f0-9]{32}\z");
        if (reported != runId)
            throw new InvalidDataException("Acceptance report returned a different run ID.");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_STATUS", @"\Apreview_only\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_SENDER_SHA256", @"\A[a-f0-9]{64}\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_INTERNAL_SHA256", @"\A[a-f0-9]{64}\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_EXTERNAL_SHA256", @"\A[a-f0-9]{64}\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_MAIL_SENT", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED", @"\Ano\z");
        if (context != CurrentMultiMailboxTestContext())
            throw new InvalidOperationException(
                "Test recipients, selected sender, SSH host or route changed during Preview.");
        reviewedMultiTestSha = sha;
        reviewedMultiTestRunId = runId;
        reviewedMultiTestContext = context;
        multiTestSummary = T(
            "План двух реальных тестов проверен, без отправки. ID: " + runId +
              ". SHA-256: " + sha[..16] + "… . Отправка требует отдельного подтверждения.",
            "Reviewed TWO fixed test messages; nothing sent. Trace ID: " + runId +
              ". SHA-256: " + sha[..16] + "… . Delivery requires separate consent.",
            "תוכנית שתי הודעות הבדיקה אושרה ללא שליחה. נדרש אישור נפרד.");
        WriteLine("Multi-mailbox acceptance plan approved; no SMTP was attempted. " +
                  "Trace ID=" + runId + ", review SHA=" + sha);
        RenderPage();
    }

    private async Task ApplyMultiMailboxDeliveryTestAsync()
    {
        string context = CurrentMultiMailboxTestContext();
        if (reviewedMultiTestSha is null || reviewedMultiTestRunId is null ||
            reviewedMultiTestContext != context)
            throw new InvalidOperationException(
                "Run a fresh TWO-recipient Preview for this exact host, route, sender and recipient set.");
        string sha = reviewedMultiTestSha;
        string runId = reviewedMultiTestRunId;
        if (!ConfirmDestructive("LinuxMailRelay365 | Send TWO real Microsoft 365 messages",
            T("Будут отправлены ДВА РЕАЛЬНЫХ письма через выбранный Microsoft 365 mailbox: " +
              multiTestSender.Text.Trim() + ". Внутренний получатель: " + multiTestInternal.Text.Trim() +
              ", внешний: " + multiTestExternal.Text.Trim() + ". Только согласованные тестовые адреса! " +
              "Этот прямой тест OAuth НЕ доказывает аутентификацию клиента в локальном Postfix. " +
              "При ошибке или потере SSH НЕ повторяйте тот же тест: сначала проверьте обе почты и Message Trace.",
              "TWO REAL messages will be sent through the reviewed mailbox " +
              multiTestSender.Text.Trim() + " to internal " + multiTestInternal.Text.Trim() +
              " and external " + multiTestExternal.Text.Trim() + ". Use only consenting test inboxes. " +
              "This direct OAuth test does NOT prove local Postfix SMTP AUTH. " +
              "On failure/SSH loss, DO NOT retry before independent inbox and Exchange message-trace review.",
              "יישלחו שתי הודעות אמיתיות לתיבות בדיקה מאושרות. אין לחזור על ניסוי לאחר תקלה ללא בדיקה."),
            "SEND TWO MULTI MAILBOX TESTS")) return;
        // Single-use approval, including uncertain SSH timeout or partial run.
        // Preserve this exact run ID so the operator can inspect a partial
        // acceptance ledger after an interrupted SSH session, without resend.
        ResetMultiMailboxTestApproval();
        lastMultiTestRunId = runId;
        lastMultiTestContext = context;
        multiTestLedgerSummary = "";
        var result = await SshRemote.RunRootScriptAsync(
            Endpoint(), EmbeddedAssets.BuildMultiMailboxAcceptanceBundle(
                runId, multiTestSender.Text.Trim(), multiTestInternal.Text.Trim(),
                multiTestExternal.Text.Trim(), sha),
            TimeSpan.FromMinutes(7));
        result.EnsureSuccess();
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_INTERNAL_SMTP_SUBMITTED", @"\Ayes\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_EXTERNAL_SMTP_SUBMITTED", @"\Ayes\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_TWO_SMTP_SUBMISSIONS_ACCEPTED", @"\Ayes\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_EXCHANGE_TRACE_VERIFIED", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_AUTOMATIC_RETRY", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_QUEUE_OR_SERVICE_CHANGED", @"\Ano\z");
        if (context != CurrentMultiMailboxTestContext())
            throw new InvalidOperationException(
                "Test host, sender or recipients changed while sending. Review recipient inboxes.");
        multiTestSummary = T(
            "Microsoft 365 принял две SMTP-отправки для теста " + runId +
              ". ДОСТАВКА НЕ подтверждена. Проверьте оба ящика и Exchange Message Trace.",
            "Two SMTP submissions accepted for trace " + runId +
              ". INBOX DELIVERY NOT VERIFIED. Check both inboxes and Exchange message trace.",
            "שתי הודעות התקבלו ב-SMTP. המסירה לתיבות עדיין לא אומתה.");
        WriteLine("Multi-mailbox two-recipient SMTP submission accepted. Trace ID=" + runId +
                  ". Inbox delivery and Exchange message trace NOT verified. No automatic retry.");
        RenderPage();
    }


    private async Task InspectLastMultiMailboxDeliveryTestAsync()
    {
        string context = CurrentMultiMailboxTestContext();
        if (lastMultiTestRunId is null || lastMultiTestContext != context)
            throw new InvalidOperationException(
                "No inspected acceptance attempt belongs to the current SSH host and sender/recipient set.");
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildMultiMailboxAcceptanceStatusBundle(lastMultiTestRunId),
            TimeSpan.FromSeconds(90));
        result.EnsureSuccess();
        string reportedId = ValidatedMultiMailboxReportValue(
            result.StdOut, "MULTI_ACCEPTANCE_RUN_ID", @"\A[a-f0-9]{32}\z");
        if (reportedId != lastMultiTestRunId)
            throw new InvalidDataException("The acceptance ledger belongs to a different run.");
        string state = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_LEDGER_STATE",
            @"\A(?:reserved_no_send_recorded|internal_attempted_result_uncertain|internal_smtp_accepted_external_not_attempted|external_attempted_result_uncertain|both_smtp_accepted_completion_not_recorded|smtp_submissions_complete_not_inbox_verified)\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_EVENT_COUNT", @"\A[1-6]\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_ACCEPTANCE_AUTOMATIC_RETRY", @"\Ano\z");
        if (context != CurrentMultiMailboxTestContext())
            throw new InvalidOperationException(
                "Host or recipient set changed during acceptance ledger inspection.");
        multiTestLedgerSummary = T(
            "Журнал теста " + reportedId + ": " + state +
              ". Никакой автоматической повторной отправки. Проверьте оба почтовых ящика и Exchange Message Trace.",
            "Acceptance ledger " + reportedId + ": " + state +
              ". NO automatic retries; check both inboxes and Exchange message trace.",
            "יומן בדיקה: " + state + ". אין שליחה חוזרת; בדוק שתי תיבות ואת Message Trace.");
        WriteLine("Read-only acceptance ledger inspection: run " + reportedId +
                  ", status " + state + "; no retry, no inbox delivery proven.");
        RenderPage();
    }


    private void ResetMultiMailboxRouteReview()
    {
        reviewedMultiMailboxPlanSha = null;
        reviewedMultiMailboxPlanContext = null;
        multiMailboxRouteSummary = "";
        reviewedMultiMailboxRestoreSha = null;
        reviewedMultiMailboxRestoreBackupId = null;
        reviewedMultiMailboxRestoreContext = null;
        multiMailboxRestoreSummary = "";
        reviewedMultiProofTimerSha = null;
        reviewedMultiProofTimerContext = null;
        multiProofTimerSummary = "";
        ResetMultiMailboxTestReview();
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

    private Task StageMultiMailboxRuntimeAsync() => StageMultiMailboxRuntimeForOwnerAsync(null);
    private async Task StageMultiMailboxRuntimeForOwnerAsync(IWin32Window? owner)
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
            "STAGE MULTI MAILBOX",owner)) return;
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

    private Task ApplyMultiMailboxRouteOfflineAsync() => ApplyMultiMailboxRouteOfflineForOwnerAsync(null);
    private async Task ApplyMultiMailboxRouteOfflineForOwnerAsync(IWin32Window? owner)
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
            "INSTALL MULTI MAILBOX OFFLINE",owner)) return;
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


    private async Task PreviewMultiMailboxProofTimerAsync()
    {
        string context = CurrentMultiMailboxContext();
        reviewedMultiProofTimerSha = null;
        reviewedMultiProofTimerContext = null;
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildMultiMailboxProofTimerBundle("plan"),
            TimeSpan.FromMinutes(2));
        result.EnsureSuccess();
        string sha = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_TIMER_PLAN_SHA256", @"\A[a-f0-9]{64}\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_TIMER", @"\Areview_only\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_TIMER_M365_DELIVERY_VERIFIED", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException("SSH host or sender map changed during timer Preview.");
        reviewedMultiProofTimerSha = sha;
        reviewedMultiProofTimerContext = context;
        multiProofTimerSummary = T(
            "План таймера проверен (SHA " + sha[..16] + "…). Ничего не включено.",
            "Timer plan reviewed (SHA " + sha[..16] + "…). Nothing enabled.",
            "תוכנית התזמון נבדקה ללא הפעלה.");
        WriteLine("Optional SMTP ingress-proof timer Preview: no service changes.");
        RenderPage();
    }

    private async Task EnableMultiMailboxProofTimerAsync()
    {
        string context = CurrentMultiMailboxContext();
        if (reviewedMultiProofTimerSha is null ||
            reviewedMultiProofTimerContext != context)
            throw new InvalidOperationException("Run a fresh timer Preview for this exact host and route.");
        string sha = reviewedMultiProofTimerSha;
        if (!ConfirmDestructive("LinuxMailRelay365 | Enable experimental proof timer",
            T("Только для контролируемого тестирования: таймер обновляет 120-секундное " +
                "подтверждение безопасности каждые 60 секунд. SMTP и Microsoft 365 НЕ активируются.",
              "EXPERIMENTAL: enable a local 60-second systemd timer for static ingress " +
                "proof renewal. It does NOT start the MTA or prove M365 delivery.",
              "הפעלה ניסיונית של תזמון מקומי בלבד. אין הפעלת דואר או אישור מסירה."),
            "ENABLE MULTI PROOF TIMER")) return;
        reviewedMultiProofTimerSha = null;
        reviewedMultiProofTimerContext = null;
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildMultiMailboxProofTimerBundle("enable", sha),
            TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_TIMER", @"\Aenabled_static_audit_only\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_TIMER_MESSAGES_SENT", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_TIMER_M365_DELIVERY_VERIFIED", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException("SSH host or route changed during timer activation.");
        multiProofTimerSummary = T(
            "Таймер включён; доставка Microsoft 365 НЕ подтверждена.",
            "Experimental timer enabled. M365 delivery NOT verified.",
            "התזמון הופעל. מסירת דואר לא אומתה.");
        WriteLine("Experimental multi-mailbox ingress-proof renewal enabled with reviewed SHA.");
        RenderPage();
    }

    private async Task InspectMultiMailboxProofTimerAsync()
    {
        string context = CurrentMultiMailboxContext();
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildMultiMailboxProofTimerBundle("status"),
            TimeSpan.FromSeconds(90));
        result.EnsureSuccess();
        string state = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_TIMER", @"\A(?:not_installed|active|inactive)\z");
        string receipt = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_RECEIPT",
            @"\A(?:not_applicable|missing|map_changed|expired|fresh_ttl_only)\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_TIMER_M365_DELIVERY_VERIFIED", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException("Host or route changed during timer inspection.");
        string receiptDescription = receipt switch
        {
            "fresh_ttl_only" => T("срок действия не истёк, но SMTP не проверен",
                "within 120-second TTL; SMTP not reverified",
                "בתוקף לפי זמן בלבד; SMTP לא אומת מחדש"),
            "expired" => T("срок действия истёк",
                "expired", "פג תוקף"),
            "map_changed" => T("изменена карта отправителей",
                "sender map changed", "מפת השולחים השתנתה"),
            "missing" => T("подтверждение отсутствует",
                "receipt missing", "אין אישור"),
            _ => T("таймер не установлен",
                "timer not installed", "התזמון לא הותקן"),
        };
        multiProofTimerSummary = T(
            "Таймер: " + state + ". Подтверждение: " + receiptDescription +
              ". Доставка Microsoft 365 НЕ проверена.",
            "Timer: " + state + ". Receipt: " + receiptDescription +
              ". M365 delivery NOT verified.",
            "מצב תזמון: " + state + ". אישור: " + receiptDescription +
              ". מסירת Microsoft 365 לא אומתה.");
        RenderPage();
    }

    private async Task DisableMultiMailboxProofTimerAsync()
    {
        string context = CurrentMultiMailboxContext();
        if (!ConfirmDestructive("LinuxMailRelay365 | Disable experimental proof timer",
            T("Таймер будет остановлен и подтверждение отозвано. " +
                "Multi-mailbox может прекратить доставку до нового разрешения.",
              "Stop the timer and REVOKE the local proof. Multi-mailbox delivery " +
                "may fail closed until re-authorized; no messages will be sent.",
              "עצירת התזמון וביטול האישור המקומי. תיתכן עצירת שליחה."),
            "DISABLE MULTI PROOF TIMER")) return;
        reviewedMultiProofTimerSha = null;
        reviewedMultiProofTimerContext = null;
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildMultiMailboxProofTimerBundle("disable"),
            TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_TIMER", @"\Adisabled_and_receipt_revoked\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_PROOF_TIMER_MESSAGES_SENT", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException("Host or route changed after timer shutdown.");
        multiProofTimerSummary = T(
            "Таймер остановлен и подтверждение отозвано.",
            "Timer disabled and local proof revoked.",
            "התזמון נעצר והאישור בוטל.");
        WriteLine("Experimental ingress-proof timer disabled; mail services untouched.");
        RenderPage();
    }

    private async Task PreviewMultiMailboxRestoreAsync()
    {
        string context = CurrentMultiMailboxContext();
        reviewedMultiMailboxRestoreSha = null;
        reviewedMultiMailboxRestoreBackupId = null;
        reviewedMultiMailboxRestoreContext = null;
        multiMailboxRestoreSummary = "";
        var result = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildMultiMailboxRestoreBundle("preview"),
            TimeSpan.FromMinutes(4));
        result.EnsureSuccess();
        string sha = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_RESTORE_PLAN_SHA256", @"\A[a-f0-9]{64}\z");
        string id = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_RESTORE_BACKUP_ID", @"\Apre-multi-[A-Za-z0-9_-]{8}\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_RESTORE_STATUS", @"\Apreview_only\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_RESTORE_MESSAGES_SENT", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_RESTORE_SERVICES_STARTED", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(result.StdOut,
            "MULTI_RESTORE_PRIMARY_POSTFIX_CHANGED", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException("The SSH server, sender map, or route changed during Restore Preview.");
        reviewedMultiMailboxRestoreSha = sha;
        reviewedMultiMailboxRestoreBackupId = id;
        reviewedMultiMailboxRestoreContext = context;
        multiMailboxRestoreSummary = T(
            "Restore Preview проверен: " + id + ". SHA-256: " + sha[..16] +
              "… . Для применения остановите отдельный Postfix и проверьте пустую очередь.",
            "Restore Preview verified: " + id + ". SHA-256: " + sha[..16] +
              "… . Apply requires manually stopped sidecar, empty queue and separate approval.",
            "בדיקת השחזור הושלמה. יש לעצור את השירות ולוודא שהתור ריק.");
        WriteLine("Read-only experimental Multi-mailbox Restore Preview verified backup " + id +
                  ", approved SHA256=" + sha + ". No configuration was changed.");
        RenderPage();
    }

    private async Task RestoreMultiMailboxRouteOfflineAsync()
    {
        string context = CurrentMultiMailboxContext();
        if (reviewedMultiMailboxRestoreSha is null ||
            reviewedMultiMailboxRestoreBackupId is null ||
            reviewedMultiMailboxRestoreContext != context)
            throw new InvalidOperationException(
                "Run a NEW Multi-mailbox Restore Preview on this exact SSH host and route.");
        string sha = reviewedMultiMailboxRestoreSha;
        string id = reviewedMultiMailboxRestoreBackupId;
        if (!ConfirmDestructive("LinuxMailRelay365 | Restore OFFLINE multi-mailbox route",
            T("ОПАСНОЕ ДЕЙСТВИЕ: восстановить прежний SMTP-маршрут из архива " + id +
              ". ОБЯЗАТЕЛЬНО остановите отдельный Postfix и проверьте ПУСТУЮ очередь. " +
              "Перед заменой создаётся аварийная копия. OAuth-файлы сохраняются в закрытом архиве, " +
              "службы НЕ запускаются, очередь писем, основной MTA и Microsoft 365 не меняются. " +
              "Если откат не подтверждён, не запускайте SMTP.",
              "OFFLINE RESTORE from exact archive " + id + ". STOP the isolated sidecar manually " +
              "and confirm the queue is EMPTY. A fresh safety snapshot is created first; " +
              "OAuth files are quarantined, never silently deleted. No services are started, " +
              "no mail is sent, and primary Postfix/M365 are not modified. " +
              "If rollback is unverified, do NOT restart SMTP.",
              "שחזור לא מקוון מתוך גיבוי מוגן. חובה לעצור את השירות ולוודא תור ריק."),
            "RESTORE MULTI MAILBOX OFFLINE")) return;
        // Approval cannot be replayed after a failure or uncertain SSH result.
        reviewedMultiMailboxRestoreSha = null;
        reviewedMultiMailboxRestoreBackupId = null;
        reviewedMultiMailboxRestoreContext = null;
        multiMailboxRestoreSummary = "";
        var report = await SshRemote.RunRootScriptAsync(Endpoint(),
            EmbeddedAssets.BuildMultiMailboxRestoreBundle("restore", sha, id),
            TimeSpan.FromMinutes(8));
        report.EnsureSuccess();
        string restored = ValidatedMultiMailboxReportValue(report.StdOut,
            "MULTI_RESTORE_BACKUP_ID", @"\Apre-multi-[A-Za-z0-9_-]{8}\z");
        if (restored != id)
            throw new InvalidDataException("Restore receipt referred to a different backup.");
        _ = ValidatedMultiMailboxReportValue(report.StdOut,
            "MULTI_RESTORE_STATUS", @"\Arestored_offline_not_started\z");
        _ = ValidatedMultiMailboxReportValue(report.StdOut,
            "MULTI_RESTORE_MESSAGES_SENT", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(report.StdOut,
            "MULTI_RESTORE_SERVICES_STARTED", @"\Ano\z");
        _ = ValidatedMultiMailboxReportValue(report.StdOut,
            "MULTI_RESTORE_PRIMARY_POSTFIX_CHANGED", @"\Ano\z");
        if (context != CurrentMultiMailboxContext())
            throw new InvalidOperationException(
                "SSH host or route changed during restoration; keep the sidecar stopped and reinspect.");
        multiMailboxRestoreSummary = T(
            "Прежний SMTP-маршрут восстановлен из " + id +
              ". Служба ОСТАНОВЛЕНА. Аварийная копия и архив OAuth сохранены на Linux.",
            "Original SMTP route restored from " + id +
              ". The sidecar remains STOPPED. Emergency backup and old OAuth files are retained on Linux.",
            "נתיב הדואר המקורי שוחזר. השירות עדיין עצור והגיבויים נשמרו.");
        WriteLine("Multi-mailbox route restored offline from verified archive " + id +
                  ". Original backup and emergency snapshot retained in root-only recovery. " +
                  "No automatic service restart, email or Microsoft 365 change.");
        RenderPage();
    }

}
