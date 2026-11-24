using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private string? conditionalRouteAuditContext;
    private readonly Dictionary<int, ConditionalRouteAudit> conditionalRouteAudits = [];

    private string? ConditionalRouteContext()
    {
        if (!HasMailDiscovery() || TryCurrentIdentity() is not { } identity ||
            advancedRoutingIdentity != identity || advancedRoutingRules.Count == 0)
            return null;
        return identity + "|" + inspectedHost?.Fqdn + "|" +
            inspectedMail!.ConfigSha256 + "|" +
            AdvancedRoutePlanner.PlanSha256(advancedRoutingRules);
    }

    private bool CurrentRouteIs(string context, int index, AdvancedRouteRule rule) =>
        ConditionalRouteContext() == context && index >= 0 &&
        index < advancedRoutingRules.Count && advancedRoutingRules[index] == rule;

    private void ShowConditionalRouteDiagnostics(TableLayoutPanel card, int width, int l,
        int index, AdvancedRouteRule rule)
    {
        string? context = ConditionalRouteContext();
        if (conditionalRouteAuditContext != context)
        {
            conditionalRouteAudits.Clear();
            conditionalRouteAuditContext = context;
        }
        if (context is null) return;
        AddAction(card, TranslateMailFlow(l,
            "Проверить DNS / TCP / TLS", "Test this route: DNS / TCP / TLS",
            "בדוק נתיב: DNS / TCP / TLS"),
            () => RunConditionalRouteAudit(context, index, rule, false),
            false, "check", "conditional-smtp-audit");
        if (rule.AuthMode == "password" && rule.TlsMode != "plain")
            AddAction(card, TranslateMailFlow(l,
                "Проверить SMTP AUTH этого маршрута...",
                "Test this route's SMTP AUTH once...", "בדיקת אימות SMTP חד-פעמית..."),
                () => RunConditionalRouteAudit(context, index, rule, true),
                false, "shield", "conditional-smtp-auth");
        if (conditionalRouteAudits.TryGetValue(index, out var evidence) &&
            evidence.Rule == rule)
        {
            var report = evidence.Report;
            AddLine(card, MailFlowText(
                "DNS: " + report.Dns + " · TCP: " + report.Tcp +
                Environment.NewLine + "TLS: " + report.Tls +
                " · AUTH: " + report.Auth + " / " + report.AuthResult +
                Environment.NewLine + TranslateMailFlow(l,
                    "Только проверка соединения; разрешение отправителя и доставка не подтверждены. Пароль не сохранён.",
                    "Connection check only; sender authorization and delivery are unverified. No password retained.",
                    "בדיקת חיבור בלבד. הרשאות שליחה ומסירה לא אומתו."),
                width, warning: !evidence.Passed));
        }
    }

    private (string User, string Secret)? PromptRouteCredential(AdvancedRouteRule rule, bool forApply = false)
    {
        int l = language.SelectedIndex;
        using var dialog = new Form
        {
            Text = "LinuxMailRelay365 | SMTP AUTH",
            StartPosition = FormStartPosition.CenterParent,
            AutoScaleMode = AutoScaleMode.Dpi, Font = new Font("Segoe UI", 10f),
            ClientSize = PreferredDialogSize(Screen.FromControl(this).WorkingArea.Size,
                DeviceDpi, 680, 430),
            MinimizeBox = false, MaximizeBox = false
        };
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2,
            Padding = new Padding(12)
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        var fields = new TableLayoutPanel
        {
            Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1
        };
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var user = new TextBox { Dock = DockStyle.Fill, MaxLength = 254 };
        var secret = new TextBox { Dock = DockStyle.Fill, MaxLength = 256,
            UseSystemPasswordChar = true };
        int width = Math.Max(240, dialog.ClientSize.Width - 65);
        AddLine(fields, MailFlowText(rule.Pattern + " → " + rule.Endpoint +
            Environment.NewLine + rule.TlsMode.ToUpperInvariant() + Environment.NewLine +
            (forApply ? TranslateMailFlow(l,
                "Учётные данные этого транспорта будут записаны в читаемую SASL-базу на Linux. Windows не сохраняет пароль. Проверка AUTH и отправка письма сейчас не выполняются.",
                "This transport's credentials will be installed in a readable SASL database on Linux. Windows does not save the password. No AUTH attempt or mail submission now.",
                "פרטי ההתחברות יישמרו במפת SASL קריאה ב-Linux, לא ב-Windows. אין שליחת דואר כעת.")
                : TranslateMailFlow(l,
                "Одна попытка AUTH только после проверки TLS-сертификата. Неудачный вход может привести к блокировке аккаунта. Письмо не отправляется.",
                "ONE AUTH attempt, only after certificate verification. Failed authentication may trigger account lockout. No mail is sent.",
                "ניסיון אימות יחיד לאחר אימות תעודה. אין שליחת דואר.")), width, warning: true));
        AddField(fields, TranslateMailFlow(l, "Логин SMTP", "SMTP username", "שם משתמש SMTP"), user);
        AddField(fields, forApply
            ? TranslateMailFlow(l, "Пароль для SASL на Linux", "SMTP password for Linux SASL", "סיסמת SMTP עבור Linux")
            : TranslateMailFlow(l, "Пароль (не сохраняется)",
                "One-use SMTP password (not saved)", "סיסמה חד-פעמית"), secret);
        scroll.Controls.Add(fields);
        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft, WrapContents = true
        };
        var cancel = new Button { Text = TranslateMailFlow(l, "Отмена", "Cancel", "ביטול"),
            AutoSize = true, DialogResult = DialogResult.Cancel };
        var test = new Button { Text = forApply
            ? TranslateMailFlow(l, "Использовать для транспорта", "Use for this transport", "השתמש עבור נתיב זה")
            : TranslateMailFlow(l, "Проверить один раз", "Test once", "בדוק פעם אחת"),
            AutoSize = true, Enabled = false,
            DialogResult = DialogResult.OK };
        void UpdateButton() => test.Enabled = forApply
            ? MultiTransportClient.ValidCredential(user.Text, secret.Text)
            : user.Text.Length > 0 && secret.Text.Length > 0;
        user.TextChanged += (_, _) => UpdateButton();
        secret.TextChanged += (_, _) => UpdateButton();
        actions.Controls.Add(cancel);
        actions.Controls.Add(test);
        root.Controls.Add(scroll, 0, 0);
        root.Controls.Add(actions, 0, 1);
        dialog.Controls.Add(root);
        dialog.AcceptButton = test;
        dialog.CancelButton = cancel;
        try
        {
            return dialog.ShowDialog(this) == DialogResult.OK
                ? (user.Text, secret.Text) : null;
        }
        finally
        {
            secret.Clear();
            user.Clear();
        }
    }

    private async Task RunConditionalRouteAudit(string context, int index,
        AdvancedRouteRule rule, bool withAuth)
    {
        if (!CurrentRouteIs(context, index, rule))
            throw new InvalidOperationException("Route or Linux discovery changed. Select the rule again.");
        if (withAuth && (rule.AuthMode != "password" || rule.TlsMode == "plain"))
            throw new InvalidOperationException("This rule does not allow SMTP password diagnostics.");
        string? username = null, password = null;
        if (withAuth)
        {
            var credential = PromptRouteCredential(rule);
            if (credential is null) return;
            (username, password) = credential.Value;
        }
        if (!CurrentRouteIs(context, index, rule))
            throw new InvalidOperationException("Route or Linux discovery changed after confirmation.");
        conditionalRouteAudits.Remove(index);
        try
        {
            string script = CustomSmtpAudit.BuildScript(EmbeddedAssets.CustomSmtpProbe,
                rule.Host, rule.Port, rule.TlsMode, username, password);
            var result = await SshRemote.ExecuteAsync(Endpoint(), "bash -s", script,
                TimeSpan.FromSeconds(65));
            if (result.ExitCode != 0)
                throw new InvalidOperationException("SMTP probe refused or failed.");
            var report = ConditionalRouteAudit.Parse(rule, result.StdOut, withAuth);
            if (!CurrentRouteIs(context, index, rule))
                throw new InvalidOperationException("Route changed during diagnostic.");
            conditionalRouteAuditContext = context;
            conditionalRouteAudits[index] = report;
            WriteLine("Conditional route #" + (index + 1) + ": TCP=" + report.Report.Tcp +
                "; TLS=" + report.Report.Tls + "; AUTH=" + report.Report.AuthResult +
                "; no mail sent or configuration changed.");
        }
        catch (Exception)
        {
            // Do not propagate remote stderr, embedded source, credential or
            // server response text into the activity log or exception chain.
            throw new InvalidOperationException(
                "Route SMTP diagnostic failed or became stale. No Apply was requested.");
        }
        finally
        {
            username = null;
            password = null;
        }
    }
}
