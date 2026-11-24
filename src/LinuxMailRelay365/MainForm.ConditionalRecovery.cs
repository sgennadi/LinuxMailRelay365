using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private string? conditionalRecoveryContext;
    private IReadOnlyList<ConditionalRecoveryEntry>? conditionalRecoveryEntries;

    private string? RecoveryInventoryContext()
    {
        if (!HasMailDiscovery() || inspectedHost?.Mta != "postfix" ||
            TryCurrentIdentity() is not { } identity)
            return null;
        return identity + "|" + inspectedHost.Fqdn + "|" + inspectedMail!.ConfigSha256;
    }

    private void ShowConditionalRecovery(TableLayoutPanel page, int width, int l)
    {
        string? context = RecoveryInventoryContext();
        if (context is null || conditionalRecoveryContext != context)
        {
            conditionalRecoveryEntries = null;
            conditionalRecoveryContext = null;
        }
        if (context is null) return;
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Резервные копии условных маршрутов",
            "Conditional routing recovery inventory",
            "גיבויי ניתוב מותנה"), true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Просмотр сохранённых резервных копий после обрыва SSH или перезапуска приложения. Только чтение; результат не разрешает Restore или запуск Postfix.",
            "Find retained recovery records after SSH interruption or application restart. Read-only observations never authorize Restore or starting Postfix.",
            "איתור גיבויים לאחר ניתוק SSH. תצפית לקריאה בלבד אינה מאשרת שחזור או הפעלה."), width, warning: true));
        AddAction(page, TranslateMailFlow(l, "Найти резервные копии на Linux",
            "Scan recovery backups on Linux", "סרוק גיבויים ב-Linux"),
            ScanConditionalRecoveryAsync, false, "search", "conditional-recovery");
        if (conditionalRecoveryEntries is not { } entries) return;
        if (entries.Count == 0)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Записи восстановления не найдены.", "No recovery records found.",
                "לא נמצאו רשומות שחזור."), width));
            return;
        }
        string details = string.Join(Environment.NewLine + Environment.NewLine,
            entries.Select(x => x.Sha + Environment.NewLine + x.State));
        AddLine(page, new TextBox
        {
            Multiline = true, ReadOnly = true, WordWrap = false,
            ScrollBars = ScrollBars.Both, TabStop = true,
            Width = Math.Max(250, width - 25), Height = 220,
            Font = new Font("Consolas", 9.5f), Text = details,
            AccessibleName = "Read-only recovery SHA-256 and observation"
        });
    }

    private async Task ScanConditionalRecoveryAsync()
    {
        string context = RecoveryInventoryContext() ??
            throw new InvalidOperationException("Reinspect the Postfix host first.");
        conditionalRecoveryContext = null;
        conditionalRecoveryEntries = null;
        string script = ConditionalRecoveryClient.Build(EmbeddedAssets.ConditionalStageManager,
            EmbeddedAssets.ConditionalTransactionManager, EmbeddedAssets.ConditionalActivationPreflight,
            EmbeddedAssets.ConditionalOfflineManager, EmbeddedAssets.ConditionalRecoveryManager);
        var result = await SshRemote.RunRootScriptAsync(Endpoint(), script, TimeSpan.FromMinutes(3));
        if (result.ExitCode != 0 || RecoveryInventoryContext() != context)
            throw new InvalidOperationException("Recovery scan refused, failed or SSH context changed.");
        conditionalRecoveryEntries = ConditionalRecoveryClient.Parse(result.StdOut);
        conditionalRecoveryContext = context;
        WriteLine("Read-only conditional recovery inventory: " + conditionalRecoveryEntries.Count +
            " record(s). No Restore or service start authorized.");
        RenderPage();
    }
}
