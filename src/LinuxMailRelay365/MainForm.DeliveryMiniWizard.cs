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
        mailTransport.SelectedIndex == 0;

    private int NextDeliveryPhase()
    {
        if (selectedMailScenario == MailScenarioPlanner.Keep) return DeliveryReviewPhase;
        if (deliveryPhase == 0) return 1;
        if (deliveryPhase == 1) return RequiresOAuthCertificate() ? 2 : DeliveryReviewPhase;
        if (deliveryPhase == 2) return 3;
        return DeliveryReviewPhase;
    }

    private int PreviousDeliveryPhase() => deliveryPhase switch
    {
        DeliveryAdvancedPhase => DeliveryReviewPhase,
        DeliveryCertificateToolsPhase => 2,
        DeliveryReviewPhase => RequiresOAuthCertificate() ? 3 :
            selectedMailScenario is MailScenarioPlanner.Keep or MailScenarioPlanner.Choose ? 0 : 1,
        _ => Math.Max(0, deliveryPhase - 1)
    };

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
        AddLine(page, MailFlowText(string.Join("  →  ", keep ? new[] { method, review } :
            oauth ? new[] { method, settings, certificate, cloud, review } :
            new[] { method, settings, review }), width));
    }

    private void AddDeliveryAdvancedAction(TableLayoutPanel page)
    {
        var button = UiTheme.Action(T("Расширенные маршруты и обслуживание",
            "Advanced routing and maintenance", "ניתוב ותחזוקה מתקדמים"), glyph: "shield");
        button.Enabled = !busy;
        button.Click += (_, _) => { deliveryPhase = DeliveryAdvancedPhase; RenderPage(); };
        AddLine(page, button);
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
