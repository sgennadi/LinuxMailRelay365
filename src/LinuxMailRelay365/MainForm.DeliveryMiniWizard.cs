using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private string? certificateHardwareContext;
    private string certificateProviderSummary = "";

    private bool DeliveryHasPlan() => HasMailDiscovery() &&
        selectedMailSource != MailFlowIntent.Unknown &&
        selectedMailScenario != MailScenarioPlanner.Choose;

    private bool RequiresOAuthCertificate() => DeliveryHasPlan() &&
        selectedMailTarget == MailFlowIntent.TargetM365 &&
        selectedMailScenario != MailScenarioPlanner.Keep &&
        mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 0;

    private static int[] DeliverySequence(bool keep, bool oauth) =>
        keep ? [0, DeliveryReviewPhase] :
        oauth ? [0, 1, 2, 3, DeliveryReviewPhase] :
        [0, 1, DeliveryReviewPhase];

    private static int AdjacentDeliveryPhase(int phase, bool keep, bool oauth, bool forward)
    {
        if (!forward && phase == DeliveryAdvancedPhase) return DeliveryReviewPhase;
        if (!forward && phase == DeliveryCertificateToolsPhase)
            return oauth && !keep ? 2 : DeliveryReviewPhase;
        int[] sequence = DeliverySequence(keep, oauth);
        int index = Array.IndexOf(sequence, phase);
        // Route changes can invalidate a previously visible certificate page.
        if (index < 0) return forward ? DeliveryReviewPhase : 0;
        return sequence[Math.Clamp(index + (forward ? 1 : -1), 0, sequence.Length - 1)];
    }

    private int NextDeliveryPhase() => AdjacentDeliveryPhase(deliveryPhase,
        selectedMailScenario == MailScenarioPlanner.Keep, RequiresOAuthCertificate(), true);

    private int PreviousDeliveryPhase() => AdjacentDeliveryPhase(deliveryPhase,
        selectedMailScenario is MailScenarioPlanner.Keep or MailScenarioPlanner.Choose,
        RequiresOAuthCertificate(), false);

    internal static bool DeliveryNavigationSelfTest()
    {
        foreach (var (keep, oauth, expected) in new[]
        {
            (true, false, new[] { 0, 4 }),
            (true, true, new[] { 0, 4 }),
            (false, false, new[] { 0, 1, 4 }),
            (false, true, new[] { 0, 1, 2, 3, 4 })
        })
        {
            if (!DeliverySequence(keep, oauth).SequenceEqual(expected)) return false;
            for (int i = 0; i < expected.Length; i++)
            {
                if (AdjacentDeliveryPhase(expected[i], keep, oauth, true) !=
                    expected[Math.Min(i + 1, expected.Length - 1)]) return false;
                if (AdjacentDeliveryPhase(expected[i], keep, oauth, false) !=
                    expected[Math.Max(0, i - 1)]) return false;
            }
            if (AdjacentDeliveryPhase(DeliveryAdvancedPhase, keep, oauth, false) != DeliveryReviewPhase)
                return false;
            if (AdjacentDeliveryPhase(DeliveryCertificateToolsPhase, keep, oauth, false) !=
                (oauth && !keep ? 2 : DeliveryReviewPhase)) return false;
        }
        return AdjacentDeliveryPhase(2, false, false, false) == 0 &&
            AdjacentDeliveryPhase(3, false, false, true) == DeliveryReviewPhase;
    }

    private void ShowOAuthMailboxChoice(TableLayoutPanel page)
    {
        int width=Math.Max(260,pageHost.ClientSize.Width-90);
        AddLine(page,UiTheme.Emphasis(T("Кто будет отправителем?", "Choose the sender identity model", "בחירת זהות השולח"),width));
        AddLine(page,oauthSenderMode);
        string explanation=oauthSenderMode.SelectedIndex==1 ?
            T("Несколько разрешённых ящиков, привязка отправителей. Рабочий маршрут пока только на отдельном Postfix.",
              "Multiple authorized mailboxes with sender mappings. Runtime currently restricted to an isolated Postfix.",
              "תיבות מרובות עם מיפוי שולחים במופע Postfix מבודד.") :
            T("Один ящик для исходящей почты. Все сообщения, проходящие через XOAUTH2, получают общий From и envelope sender. Не меняет локальную доставку автоматически.",
              "One mailbox for outbound mail. Messages handled by XOAUTH2 use the shared From and envelope sender. This does not automatically change local delivery.",
              "תיבה אחת לדואר יוצא. כתובת השולח תוחלף; מסירה מקומית לא משתנה אוטומטית.");
        AddLine(page,MailFlowText(explanation,width,warning:oauthSenderMode.SelectedIndex==0));
    }

    private void ShowDeliveryProgress(TableLayoutPanel page)
    {
        int width = Math.Max(260, pageHost.ClientSize.Width - 90);
        string method = T("Способ", "Method", "שיטה");
        string settings = T("Параметры", "Settings", "הגדרות");
        string certificate = T("Сертификат", "Certificate", "אישור");
        string cloud = "Entra / Exchange";
        string review = T("Итог", "Review", "סיכום");
        bool oauth = RequiresOAuthCertificate();
        bool keep = selectedMailScenario == MailScenarioPlanner.Keep;
        string progress = deliveryPhase switch
        {
            0 => "1/" + (keep ? "2" : oauth ? "5" : "3") + " · " + method,
            1 => "2/" + (oauth ? "5" : "3") + " · " + settings,
            2 => "3/5 · " + certificate,
            3 => "4/5 · " + cloud,
            DeliveryReviewPhase => (keep ? "2/2" : oauth ? "5/5" : "3/3") + " · " + review,
            DeliveryCertificateToolsPhase => T("Управление сертификатами и ключами", "Certificate and key management", "ניהול אישורים ומפתחות"),
            _ => T("Расширенные настройки", "Advanced tools", "כלים מתקדמים")
        };
        AddLine(page, UiTheme.Emphasis(T("Способ отправки", "Delivery setup", "הגדרת שליחה") +
            " · " + progress, width));
        string[] names = [method, settings, certificate, cloud, review];
        AddLine(page, MailFlowText(string.Join("  →  ", DeliverySequence(keep, oauth)
            .Select(phase => phase == deliveryPhase ? "[" + names[phase] + "]" : names[phase])), width));
    }

    private void AddDeliveryAdvancedAction(TableLayoutPanel page)
    {
        var button = UiTheme.Action(T("Расширенные маршруты и обслуживание",
            "Advanced routing and maintenance", "ניתוב ותחזוקה מתקדמים"), glyph: "shield");
        button.Enabled = !busy;
        button.Click += (_, _) => { deliveryPhase = DeliveryAdvancedPhase; RenderPage(); };
        AddLine(page, button);
        if (DeliveryHasPlan() && selectedMailTarget == MailFlowIntent.TargetM365 &&
            selectedMailScenario != MailScenarioPlanner.Keep && mailTransport.SelectedIndex == 1)
        {
            var smtp = UiTheme.Action(T("Настройка SMTP Connector и TLS",
                "SMTP Connector and TLS setup", "הגדרת SMTP Connector ו-TLS"), glyph: "shield");
            smtp.Enabled = !busy;
            smtp.Click += (_, _) =>
            {
                var context = TryCurrentIdentity();
                if (context is null) return;
                using var dialog = new SmtpCertificateWizardDialog(async () =>
                {
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    var result = await SshRemote.RunRootScriptAsync(Endpoint(),
                        EmbeddedAssets.SmtpCertificateDiscovery, TimeSpan.FromSeconds(90));
                    result.EnsureSuccess();
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    return result.StdOut;
                }, async (cert, chain, key, domain) =>
                {
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    var result = await SshRemote.RunRootScriptAsync(Endpoint(),
                        EmbeddedAssets.BuildSmtpCertificateCheck(cert, chain, key, domain, "auto"),
                        TimeSpan.FromSeconds(90));
                    result.EnsureSuccess();
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    return result.StdOut;
                }, async (leaf, chain, domain) =>
                {
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    var generation = await SmtpCertificateTransfer.StageAsync(Endpoint(), leaf, chain, domain);
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    return generation;
                }, async request =>
                {
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    var result = await SshRemote.ExecuteAsync(Endpoint(),
                        EmbeddedAssets.SmtpAcmeInspectCommand, request, TimeSpan.FromSeconds(45));
                    if (result.ExitCode != 0) throw new InvalidOperationException("ACME inspection refused.");
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    return result.StdOut;
                }, async (accepted, name) =>
                {
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    var endpoint = Endpoint();
                    string script = EmbeddedAssets.BuildSmtpAcmeProviderDiscovery(accepted, name);
                    var timeout = TimeSpan.FromSeconds(160);
                    var result = endpoint.Username == "root"
                        ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script, timeout)
                        : await SshRemote.RunRootScriptAsync(endpoint, script, timeout);
                    if (result.ExitCode != 0) throw new InvalidOperationException("ACME provider discovery unavailable.");
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    return result.StdOut;
                }, async (request, challenge) =>
                {
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    var endpoint = Endpoint();
                    string script = challenge ? EmbeddedAssets.BuildSmtpAcmeStagingChallenge(request) :
                        EmbeddedAssets.BuildSmtpAcmeIssuanceReview(request);
                    var timeout = TimeSpan.FromSeconds(challenge ? 800 : 105);
                    var result = endpoint.Username == "root"
                        ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script, timeout)
                        : await SshRemote.RunRootScriptAsync(endpoint, script, timeout);
                    if (result.ExitCode != 0) throw new InvalidOperationException("Local issuance review refused.");
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    return result.StdOut;
                }, acceptedDomain.Text.Trim(), async () =>
                {
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    var result = await SshRemote.RunRootScriptAsync(Endpoint(),
                        EmbeddedAssets.SmtpRenewalInventory, TimeSpan.FromSeconds(60));
                    if (result.ExitCode != 0) throw new InvalidOperationException("Renewal inspection refused.");
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    return result.StdOut;
                }, async expectedSha =>
                {
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    var endpoint = Endpoint();
                    string script = EmbeddedAssets.BuildSmtpAcmeDryRun(expectedSha);
                    var timeout = TimeSpan.FromSeconds(expectedSha is null ? 60 : 660);
                    var result = endpoint.Username == "root"
                        ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script, timeout)
                        : await SshRemote.RunRootScriptAsync(endpoint, script, timeout);
                    if (result.ExitCode != 0) throw new InvalidOperationException("Renewal review or test refused.");
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    return result.StdOut;
                }, async (action, candidate, domain, sha) =>
                {
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    var endpoint = Endpoint();
                    if (action == "avc-preview" && (candidate is not null || domain is not null || sha is not null))
                        throw new ArgumentException("Unexpected AVC review arguments.");
                    string script = action == "avc-preview" ? EmbeddedAssets.BuildSmtpTlsAvcDiagnosis() :
                        EmbeddedAssets.BuildSmtpTlsRotation(action, candidate, domain, sha);
                    var timeout = TimeSpan.FromSeconds(action is "activate" or "recover" ? 600 : 180);
                    var result = endpoint.Username == "root"
                        ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script, timeout)
                        : await SshRemote.RunRootScriptAsync(endpoint, script, timeout);
                    if (result.ExitCode != 0) throw new InvalidOperationException("TLS review or activation refused.");
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    return result.StdOut;
                }, async (action, sha) =>
                {
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    var endpoint = Endpoint();
                    string script = EmbeddedAssets.BuildSmtpTlsSystemd(action, sha);
                    var timeout = TimeSpan.FromSeconds(sha is null ? 240 : 420);
                    var result = endpoint.Username == "root"
                        ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script, timeout)
                        : await SshRemote.RunRootScriptAsync(endpoint, script, timeout);
                    if (result.ExitCode != 0) throw new InvalidOperationException("Systemd action refused.");
                    if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                    return result.StdOut;
                }, (owner, dns) => ReviewManagedConnectorBindingAsync(owner, context, dns), owner =>
                {
                    using var probe = new PostfixM365DeliveryDialog(async (action, request, sha) =>
                    {
                        if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                        var endpoint = Endpoint();
                        string script = EmbeddedAssets.BuildPostfixM365DeliveryProbe(action, request, sha);
                        var timeout = TimeSpan.FromSeconds(420);
                        var result = endpoint.Username == "root"
                            ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script, timeout)
                            : await SshRemote.RunRootScriptAsync(endpoint, script, timeout);
                        if (result.ExitCode != 0) throw new InvalidOperationException("Postfix probe refused or uncertain.");
                        if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                        return result.StdOut;
                    }, acceptedDomain.Text.Trim(), outboundFixedSender.Text.Trim(), outboundMxHost.Text.Trim(),
                        (request, local) => ReadPostfixExchangeTraceAsync(context, request, local),
                        async (mx, managed) =>
                        {
                            if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                            var endpoint = Endpoint();
                            var result = managed
                                ? endpoint.Username == "root"
                                    ? await SshRemote.ExecuteAsync(endpoint, "bash -s", EmbeddedAssets.BuildM365ManagedStartTlsDiagnosis(mx), TimeSpan.FromSeconds(200))
                                    : await SshRemote.RunRootScriptAsync(endpoint, EmbeddedAssets.BuildM365ManagedStartTlsDiagnosis(mx), TimeSpan.FromSeconds(200))
                                : await SshRemote.ExecuteAsync(endpoint,
                                    EmbeddedAssets.BuildM365StartTlsDiagnosis(mx), "", TimeSpan.FromSeconds(75));
                            if (result.ExitCode != 0) throw new InvalidOperationException("STARTTLS diagnosis refused or timed out.");
                            if (TryCurrentIdentity() != context) throw new InvalidOperationException("Linux endpoint changed.");
                            return result.StdOut;
                        });
                    probe.ShowDialog(owner);
                });
                dialog.ShowDialog(this);
            };
            AddLine(page, smtp);
        }
    }

    private bool CertificateHardwareProbeCurrent() =>
        certificateHardwareContext is not null &&
        certificateHardwareContext == TryCurrentIdentity();

    private async Task AutoProbeCertificateHardwareAsync()
    {
        if (!RequiresOAuthCertificate() || deliveryPhase is not (2 or DeliveryCertificateToolsPhase))
            throw new InvalidOperationException("Select the XOAUTH2 certificate page first.");
        string? context = TryCurrentIdentity();
        if (context is null) throw new InvalidOperationException("A verified Linux endpoint is required.");
        EnsureSecurityLoaded();
        linuxSecurity = null;
        certificateHardwareContext = null;
        certificateProviderSummary = "";
        reviewedTpmPlanSha = null;
        reviewedTpmPlanContext = null;
        tpmPlanSummary = "";
        try
        {
            await CheckLinuxSecurityAsync();
            if (TryCurrentIdentity() != context || linuxSecurity is null)
                throw new InvalidOperationException("Linux connection changed during hardware discovery.");
            if (linuxSecurity.HasTpm2 && (linuxSecurity.Get("OS_ID") is "rhel" or "ol" or "rocky" or "almalinux"))
            {
                // Both commands are read-only. Inspect first; the dependency
                // preview follows because provider inspection invalidates an old plan.
                try
                {
                    await InspectTpmProviderAsync();
                    certificateProviderSummary = tpmPlanSummary;
                }
                catch (Exception ex)
                {
                    certificateProviderSummary = "Provider access unverified (" + ex.GetType().Name + ").";
                    WriteLine("WARNING: " + certificateProviderSummary);
                }
                try { await PreviewTpmDependenciesAsync(); }
                catch (Exception ex)
                {
                    reviewedTpmPlanSha = null;
                    reviewedTpmPlanContext = null;
                    tpmPlanSummary = "Package availability unverified (" + ex.GetType().Name + ").";
                    WriteLine("WARNING: " + tpmPlanSummary);
                }
            }
            if (TryCurrentIdentity() != context)
                throw new InvalidOperationException("Linux connection changed during hardware discovery.");
            certificateHardwareContext = context;
        }
        catch
        {
            linuxSecurity = null;
            certificateHardwareContext = null;
            throw;
        }
    }

    private void ShowCertificateProtection(TableLayoutPanel page)
    {
        EnsureSecurityLoaded();
        int width = Math.Max(260, pageHost.ClientSize.Width - 90);
        AddLine(page, UiTheme.Emphasis(T("Создание сертификата — защита закрытого ключа",
            "Certificate creation — private-key protection", "יצירת אישור — הגנת המפתח הפרטי"), width));
        if (!CertificateHardwareProbeCurrent() || linuxSecurity is null)
        {
            AddLine(page, UiTheme.Emphasis(T("TPM/HSM ещё не проверен. Проверка запускается при входе на эту страницу.",
                "TPM/HSM not yet verified. Inspection runs on entering this page.", "TPM/HSM טרם נבדק."), width, warning: true));
        }
        else
        {
            var inventory = linuxSecurity;
            bool detected = inventory.HasTpm2 || inventory.HasPkcs11TokenHint;
            AddLine(page, UiTheme.Emphasis(detected
                ? T("Аппаратное устройство обнаружено — требуется проверка подписи",
                    "Hardware detected — signing still requires verification", "זוהתה חומרה — נדרש אימות חתימה")
                : T("TPM/HSM не подтверждён — доступен программный PEM",
                    "TPM/HSM not established — software PEM is available", "חומרה לא אומתה — PEM זמין"),
                width, warning: !detected, success: detected));
            AddLine(page, MailFlowText("TPM: " + inventory.Get("TPM_DEVICE") +
                " · Tools: " + inventory.Get("TPM2_TOOLS") +
                " · Response: " + inventory.Get("TPM2_COMMAND_PROBE") +
                Environment.NewLine + "OpenSSL TPM2: " + inventory.Get("OPENSSL_TPM2_PROVIDER") +
                " · PKCS#11: " + inventory.Get("OPENSSL_PKCS11_PROVIDER"), width));
            if (detected || hardwareRequest.Checked)
            {
                hardwareRequest.Text = T("Предпочитаю аппаратную защиту (требуется отдельное подтверждение)",
                    "Prefer hardware-backed protection (separate approval required)", "העדפת הגנת חומרה (נדרש אישור נפרד)");
                hardwareRequest.Enabled = !busy;
                AddLine(page, hardwareRequest);
            }
            AddLine(page, MailFlowText(T("Обнаружение устройства и пакетов не подтверждает PS256, регистрацию в Entra или неэкспортируемость ключа. При необходимости откройте управление сертификатами для проверки зависимостей, установки и создания аппаратного ключа.",
                "Device/package discovery does not prove PS256 signing, Entra registration or key non-exportability. Open certificate management to review dependencies, install approved packages and provision a hardware key.",
                "גילוי חומרה וחבילות אינו מאמת חתימה או רישום ב-Entra."), width, warning: true));
        }
        AddAction(page, T("Обновить проверку TPM/HSM", "Refresh TPM/HSM inspection", "רענון בדיקת TPM/HSM"),
            AutoProbeCertificateHardwareAsync, false, "check", "linux-security");
        var details = UiTheme.Action(T("Управление сертификатами и аппаратными ключами",
            "Certificate and hardware key management", "ניהול אישורים ומפתחות חומרה"), glyph: "shield");
        details.Enabled = !busy;
        details.Click += (_, _) => { deliveryPhase = DeliveryCertificateToolsPhase; RenderPage(); };
        AddLine(page, details);
    }
}
