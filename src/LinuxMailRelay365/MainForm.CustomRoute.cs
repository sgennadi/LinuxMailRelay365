using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    // Selected only for the primary Postfix outbound smarthost. Never mixed
    // with the Linux inbound SMTP listener port or a sidecar listener.
    private readonly ComboBox customRouteAuth = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList, Width = 590,
        Margin = new Padding(0, 3, 0, 12), Font = new Font("Segoe UI", 10f),
        AccessibleName = "Outgoing SMTP authentication mode"
    };
    private bool customRouteAuthWired;
    private CustomRoutePreview? customRoutePreview;
    private string? customRoutePreviewContext;

    private string CustomAuthMode()
    {
        if (customRouteAuth.Items.Count == 0)
        {
            customRouteAuth.Items.AddRange([
                "No SMTP AUTH (IP-allowed / trusted relay)",
                "SMTP AUTH username + password (TLS required)"
            ]);
            customRouteAuth.SelectedIndex = 0;
        }
        return customRouteAuth.SelectedIndex switch
        {
            0 => "none", 1 => "password",
            _ => throw new InvalidDataException("Choose an outbound SMTP authentication mode.")
        };
    }

    private string CurrentCustomRouteContext(string sha) =>
        CurrentCustomSmtpContext() + "|" + selectedMailScenario + "|" +
        CustomAuthMode() + "|" + customSmtpUser.Text + "|" +
        (inspectedMail?.ConfigSha256 ?? "") + "|" + sha;

    private bool HasCustomRouteEvidence()
    {
        if (!HasMailDiscovery() ||
            selectedMailTarget != MailFlowIntent.TargetCustom ||
            selectedMailScenario != MailScenarioPlanner.ReplaceRelay ||
            inspectedMail?.Mta != "postfix" ||
            inspectedHost?.MtaState != "active" ||
            existingSmtpAudit?.SuspectedUnsafeRelay == true ||
            customSmtpAudit is not { Tcp: "reachable" } audit ||
            customSmtpAuditContext != CurrentCustomSmtpContext())
            return false;
        string mode = CustomSmtpMode();
        if (mode == "plain" && CustomAuthMode() == "password")
            return false;
        if (mode == "plain")
            return audit.Tls == "not_used";
        if (audit.Tls != "verified")
            return false;
        return CustomAuthMode() != "password" ||
            (audit.AuthResult == "accepted" && audit.Auth is "plain" or "login");
    }

    private void RequireCustomRouteEvidence()
    {
        if (!HasCustomRouteEvidence())
            throw new InvalidOperationException(
                "Run read-only Linux MTA discovery, select Replace outbound route, " +
                "and verify exactly the chosen SMTP host/port/TLS. If using a " +
                "password, first complete a successful one-shot SMTP AUTH check. " +
                "No mail configuration was changed.");
    }

    private void ShowCustomRouteActions(TableLayoutPanel page, int width, int l)
    {
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Настройка исходящего маршрута существующего Postfix",
            "Configure outbound relay of existing Postfix",
            "הגדרת ממסר יוצא של Postfix קיים"), true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Сначала выберите сценарий «Изменить исходящий маршрут» ниже. Настройки входящего SMTP, локальных пользователей, доменов и очереди сохраняются. Отдельный входящий порт НЕ нужен.",
            "First choose Replace outbound route below. Existing inbound SMTP, local users, domains and queue remain unchanged. NO extra Linux inbound port is required.",
            "יש לבחור שינוי ממסר יוצא בלבד; הגדרות SMTP נכנסות נשמרות."),
            width));
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Авторизация ИСХОДЯЩЕГО SMTP",
            "OUTBOUND SMTP authentication",
            "אימות SMTP יוצא")));
        AddLine(page, customRouteAuth);
        if (!customRouteAuthWired)
        {
            customRouteAuthWired = true;
            customRouteAuth.SelectedIndexChanged += (_, _) =>
            {
                customRoutePreview = null;
                customRoutePreviewContext = null;
                if (!busy && !IsDisposed) RenderPage();
            };
        }
        if (CustomAuthMode() == "password")
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Перед Preview проверьте AUTH кнопкой выше. Перед Apply пароль нужно ввести повторно. Он сохраняется только в root-only Postfix DB на Linux (root может его прочитать).",
                "Test SMTP AUTH above before Preview. Re-enter the password for Apply. It is stored ONLY in a root-only Postfix DB on Linux (recoverable by root).",
                "יש לאמת שם משתמש וסיסמה; הסיסמה נשמרת רק בשרת Linux."),
                width, warning: true));
        if (CustomSmtpMode() == "plain")
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "БЕЗ TLS: исходящее письмо будет передаваться без шифрования. AUTH отключён. Для Apply потребуется отдельное подтверждение риска.",
                "NO TLS: outgoing messages travel without transport encryption. SMTP AUTH is disabled. Applying requires separate typed risk approval.",
                "ללא TLS הודעות אינן מוצפנות ויידרש אישור מפורש."),
                width, warning: true));
        if (!HasMailDiscovery() ||
            selectedMailScenario != MailScenarioPlanner.ReplaceRelay)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Выберите ниже «Заменить исходящий маршрут» для безопасного Preview/Apply.",
                "Select Replace outbound route below to enable guarded Preview/Apply.",
                "בחרו למטה שינוי ניתוב יוצא."),
                width));
            return;
        }
        if (inspectedMail?.Mta != "postfix" ||
            inspectedHost?.MtaState != "active" ||
            existingSmtpAudit?.SuspectedUnsafeRelay == true)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Автоматическое применение доступно только для исправного активного основного Postfix без признаков открытого relay. Exim/Sendmail остаются без изменений.",
                "Automatic Apply currently requires a healthy active primary Postfix without suspected open-relay conditions. Exim/Sendmail are not modified.",
                "התקנה אוטומטית זמינה כרגע רק ל-Postfix תקין."),
                width, warning: true));
            return;
        }
        if (customRoutePreview is { } plan &&
            customRoutePreviewContext == CurrentCustomRouteContext(plan.Fingerprint))
        {
            AddLine(page, MailFlowText(
                "Postfix: " + plan.Host + ":" + plan.Port +
                "  ·  TLS: " + plan.Tls +
                "  ·  AUTH: " + plan.AuthMode + Environment.NewLine +
                "Queue: " + plan.Queue +
                "  ·  Alternate routes: " + (plan.HasConflictingMaps ? "present" : "none") +
                "  ·  Postfix scope: " + plan.PostfixScope +
                "  ·  Client SASL: " + plan.ClientSasl + Environment.NewLine +
                "Self-loop warning: " + (plan.HasSelfLoopRisk ? "yes" : "no") +
                "  ·  Apply: " + (plan.ApplyAllowed ? "eligible" : "BLOCKED"),
                width, warning: !plan.ApplyAllowed));
        }
        if (!HasCustomRouteEvidence())
        {
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Сначала подтвердите доступность выбранного адреса и TLS на Linux. Если используется SMTP AUTH, нужна успешная проверка учётных данных.",
                "Run a matching SMTP/TLS test from Linux first. For password mode, a successful one-shot AUTH check is required.",
                "תחילה יש לבדוק חיבור ואימות בשרת Linux."),
                width, warning: true));
            return;
        }
        AddAction(page, TranslateMailFlow(l,
            "Preview исходящего Postfix (только чтение)",
            "Preview Postfix outbound migration (read-only)",
            "תצוגה מקדימה ללא שינוי"),
            PreviewCustomRouteAsync, false, "check", "custom-route-preview");
        if (customRoutePreview is { ApplyAllowed: true } ready &&
            customRoutePreviewContext == CurrentCustomRouteContext(ready.Fingerprint))
            AddAction(page, TranslateMailFlow(l,
                "Применить выбранный SMTP с Backup/Verify/Rollback...",
                "Apply selected SMTP with Backup/Verify/Rollback...",
                "החל SMTP עם גיבוי ושחזור..."),
                ApplyCustomRouteAsync, false, "shield", "custom-route-apply");
    }

    private async Task PreviewCustomRouteAsync()
    {
        RequireCustomRouteEvidence();
        string host = CustomSmtpAudit.CheckedHost(alternateUpstreamHost.Text.Trim());
        if (!int.TryParse(alternateUpstreamPort.Text.Trim(), out int port))
            throw new InvalidDataException("Invalid outbound port.");
        string mode = CustomSmtpMode(), authMode = CustomAuthMode();
        string identity = TryCurrentIdentity() ??
            throw new InvalidOperationException("Linux SSH identity not verified.");
        customRoutePreview = null;
        customRoutePreviewContext = null;
        string script = CustomPostfixRoute.BuildScript(
            EmbeddedAssets.CustomPostfixRoute, EmbeddedAssets.Recovery,
            host, port, mode, authMode, "preview");
        var response = await SshRemote.RunRootScriptAsync(
            Endpoint(), script, TimeSpan.FromMinutes(2));
        if (response.ExitCode != 0)
            throw new InvalidOperationException(
                "Custom Postfix preflight could not inspect current configuration.");
        var planned = CustomPostfixRoute.ParsePreview(
            response.StdOut, host, port, mode, authMode);
        if (TryCurrentIdentity() != identity || !HasCustomRouteEvidence())
            throw new InvalidOperationException("Linux/SMTP selection changed during Preview.");
        customRoutePreview = planned;
        customRoutePreviewContext = CurrentCustomRouteContext(planned.Fingerprint);
        WriteLine("Read-only custom Postfix preview: queue=" + planned.Queue +
            "; protected routes=" + (planned.HasConflictingMaps ? "present" : "absent") +
            "; Apply=" + (planned.ApplyAllowed ? "eligible" : "blocked") +
            "; no mail sent or Linux configuration changed.");
        RenderPage();
    }

    private async Task ApplyCustomRouteAsync()
    {
        RequireCustomRouteEvidence();
        var plan = customRoutePreview;
        if (plan is null || !plan.ApplyAllowed ||
            customRoutePreviewContext != CurrentCustomRouteContext(plan.Fingerprint))
            throw new InvalidOperationException(
                "Run a fresh matching read-only Custom SMTP route Preview first.");
        string identity = TryCurrentIdentity() ??
            throw new InvalidOperationException("SSH identity unavailable.");
        string host = CustomSmtpAudit.CheckedHost(alternateUpstreamHost.Text.Trim());
        int port = int.Parse(alternateUpstreamPort.Text.Trim());
        string tls = CustomSmtpMode(), authMode = CustomAuthMode();
        string user = customSmtpUser.Text;
        string secret = customSmtpPassword.Text;
        customSmtpPassword.Clear();
        try
        {
            string caution = authMode == "password"
                ? "A root-recoverable SMTP credential DB will be stored on the Linux host. Re-enter the password now. "
                : "This selected upstream will use NO SMTP AUTH; ensure the provider authorizes the Linux host/public IP. ";
            if (tls == "plain")
                caution += "DANGER: SMTP transport will be UNENCRYPTED and is NOT recommended. ";
            if (!ConfirmDestructive(
                "LinuxMailRelay365 | Replace primary Postfix outbound relay",
                "Change ONLY the outgoing route to " + host + ":" + port +
                " (" + tls + ", AUTH=" + authMode + "). " +
                "Do not change existing Linux inbound ports, local mail users or domains. " +
                caution + "Requires a fresh exact SHA256, EMPTY queue, verified root-only backup, " +
                "Postfix reload and post-apply verification. Automatic rollback is attempted on failure. " +
                "SMTP AUTH attempts and test-message submission can have account/provider effects.",
                "CHANGE_CUSTOM_OUTBOUND_RELAY"))
                return;
            RequireCustomRouteEvidence();
            if (TryCurrentIdentity() != identity ||
                customRoutePreviewContext != CurrentCustomRouteContext(plan.Fingerprint) ||
                CustomSmtpMode() != tls || CustomAuthMode() != authMode)
                throw new InvalidOperationException(
                    "SSH endpoint or custom SMTP configuration changed after approval.");
            if (authMode == "password" && string.IsNullOrEmpty(secret))
                throw new InvalidOperationException(
                    "Re-enter the one-use SMTP password for guarded Apply.");

            // Fresh independent TLS/AUTH preflight using the exact credential
            // to be persisted on Linux; at most ONE auth attempt.
            string diagnostic = CustomSmtpAudit.BuildScript(
                EmbeddedAssets.CustomSmtpProbe, host, port, tls,
                authMode == "password" ? user : null,
                authMode == "password" ? secret : null);
            var test = await SshRemote.ExecuteAsync(
                Endpoint(), "bash -s", diagnostic, TimeSpan.FromSeconds(65));
            if (test.ExitCode != 0)
                throw new InvalidOperationException(
                    "Custom SMTP network/AUTH preflight incomplete; Linux unchanged.");
            var evidence = CustomSmtpAudit.Parse(
                test.StdOut, host, port, tls, authMode == "password");
            if (evidence.Tcp != "reachable" ||
                (tls == "plain" ? evidence.Tls != "not_used" :
                    evidence.Tls != "verified") ||
                (authMode == "password" && evidence.AuthResult != "accepted"))
                throw new InvalidOperationException(
                    "Selected SMTP transport or one-shot AUTH failed preflight; Linux unchanged.");
            if (TryCurrentIdentity() != identity ||
                customRoutePreviewContext != CurrentCustomRouteContext(plan.Fingerprint))
                throw new InvalidOperationException("Linux selection changed during SMTP verification.");

            string freshScript = CustomPostfixRoute.BuildScript(
                EmbeddedAssets.CustomPostfixRoute, EmbeddedAssets.Recovery,
                host, port, tls, authMode, "preview");
            var fresh = await SshRemote.RunRootScriptAsync(
                Endpoint(), freshScript, TimeSpan.FromMinutes(2));
            if (fresh.ExitCode != 0)
                throw new InvalidOperationException(
                    "Fresh read-only Postfix Preview failed; nothing applied.");
            var updated = CustomPostfixRoute.ParsePreview(
                fresh.StdOut, host, port, tls, authMode);
            if (!updated.ApplyAllowed || updated.Fingerprint != plan.Fingerprint)
                throw new InvalidOperationException(
                    "Postfix configuration, routing or queue drift detected; nothing applied.");

            string? plaintextConsent = tls == "plain"
                ? "I_ACCEPT_UNENCRYPTED_OUTBOUND_SMTP" : null;
            string applyScript = CustomPostfixRoute.BuildScript(
                EmbeddedAssets.CustomPostfixRoute, EmbeddedAssets.Recovery,
                host, port, tls, authMode, "apply", plan.Fingerprint,
                authMode == "password" ? user : null,
                authMode == "password" ? secret : null,
                plaintextConsent);
            customRoutePreview = null;
            customRoutePreviewContext = null;
            var result = await SshRemote.RunRootScriptAsync(
                Endpoint(), applyScript, TimeSpan.FromMinutes(6));
            if (result.ExitCode != 0)
            {
                if (result.StdOut.Contains("CUSTOM_ROUTE_ROLLBACK=failed",
                        StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        "CRITICAL: Postfix route Apply AND automatic rollback failed. " +
                        "Stop changes; inspect the protected Linux backup and recover manually.");
                throw new InvalidOperationException(
                    "Custom Postfix route migration failed/refused. Inspect verified Linux backups. " +
                    "No email test was sent.");
            }
            var applied = CustomPostfixRoute.ParseApply(
                result.StdOut, host, port, tls, authMode);
            if (TryCurrentIdentity() != identity)
                throw new InvalidOperationException(
                    "Linux SSH identity changed after custom route Apply.");
            WriteLine("Custom Postfix outbound relay " + host + ":" + port +
                " activated; backup=" + applied.BackupId +
                "; inbound SMTP unchanged; credential stored on Linux=" +
                (applied.CredentialStoredOnLinux ? "yes (root-only)" : "no") + ".");
            await InspectMailRoutingAsync();
            RenderPage();
        }
        finally
        {
            customSmtpPassword.Clear();
            secret = "";
        }
    }
}
