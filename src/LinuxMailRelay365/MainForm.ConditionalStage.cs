using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private ConditionalStageReceipt? conditionalStageReceipt;
    private string? conditionalStageContext;

    private string? CurrentConditionalStageContext()
    {
        if (!HasMailDiscovery() || inspectedMail?.Mta != "postfix" ||
            inspectedHost is not { Mta: "postfix", MtaState: "active" or "installed_inactive" } ||
            advancedRoutingIdentity != TryCurrentIdentity() ||
            advancedRoutingRules.Count == 0)
            return null;
        var review = PostfixConditionalMapPreview.Build(inspectedHost, advancedRoutingRules);
        return TryCurrentIdentity() + "|" + inspectedMail.ConfigSha256 + "|" +
            review.PlanSha256 + "|" + review.InventorySha256;
    }

    private void ShowConditionalStageActions(TableLayoutPanel page, int width, int l)
    {
        string? context = CurrentConditionalStageContext();
        if (context is null) return;
        AddLine(page, UiTheme.Text(TranslateMailFlow(l,
            "Подготовка карт на Linux — без активации",
            "Prepare maps on Linux — no activation",
            "הכנת מפות ב-Linux ללא הפעלה"), true));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Stage и Compile создают защищённые файлы в отдельных каталогах /var/lib. Действующий Postfix, локальная почта и порты не изменяются. Начальная реализация поддерживает только непересекающиеся правила STARTTLS без AUTH; это НЕ настройка TLS.",
            "Stage and Compile create private files in separate /var/lib directories. Active Postfix, local mail and ports stay unchanged. The initial subset supports disjoint STARTTLS/no-AUTH rules only; this does NOT configure TLS.",
            "Stage ו-Compile יוצרים קבצים מוגנים בלבד. Postfix פעיל לא משתנה; TLS אינו מוגדר."), width, warning: true));
        try { ConditionalStageClient.Eligible(advancedRoutingRules); }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "Текущий набор правил пока не поддерживает Stage/Compile.",
                "This rule set is not yet supported by Stage/Compile.",
                "כללים אלה עדיין אינם נתמכים בהכנה."), width, warning: true));
            return;
        }
        AddAction(page, TranslateMailFlow(l, "Проверить план на Linux",
            "Validate plan on Linux (no retained files)", "בדוק תוכנית ב-Linux"),
            () => RunConditionalStageAsync("plan"), false, "check", "conditional-stage");
        if (conditionalStageReceipt is not { } receipt ||
            conditionalStageContext != context)
            return;

        AddLine(page, MailFlowText("Candidate: " + receipt.Status +
            Environment.NewLine + "Plan SHA-256: " + receipt.PlanSha +
            (receipt.ManifestSha is null ? "" : Environment.NewLine +
                "Stage manifest: " + receipt.ManifestSha) +
            (receipt.CompiledSha is null ? "" : Environment.NewLine +
                "Compiled manifest: " + receipt.CompiledSha +
                Environment.NewLine + "Backend: " + receipt.Backend +
                " · checked raw keys: " + receipt.LookupCount) +
            Environment.NewLine + "Candidate inactive · activation is separate", width));
        if (receipt.ManifestSha is null)
            AddAction(page, TranslateMailFlow(l, "Stage — сохранить карты-кандидаты...",
                "Stage private candidate maps...", "שמור מפות מועמדות..."),
                () => RunConditionalStageAsync("stage"), false, "shield", "conditional-stage");
        AddAction(page, TranslateMailFlow(l, "Проверить сохранённый Stage",
            "Verify existing staged candidate", "אמת מועמד שמור"),
            () => RunConditionalStageAsync("verify"), false, "search", "conditional-stage");
        if (receipt.ManifestSha is not null && receipt.CompiledSha is null)
            AddAction(page, TranslateMailFlow(l, "Compile — собрать отдельные карты...",
                "Compile isolated maps...", "הכן מפות מבודדות..."),
                () => RunConditionalStageAsync("compile"), false, "shield", "conditional-stage");
        AddAction(page, TranslateMailFlow(l, "Проверить скомпилированные карты",
            "Verify compiled maps (native lookup)", "אמת מפות מהודרות"),
            () => RunConditionalStageAsync("verify-compiled"), false, "check", "conditional-stage");
    }

    private async Task RunConditionalStageAsync(string operation)
    {
        string context = CurrentConditionalStageContext() ??
            throw new InvalidOperationException("Reinspect this Postfix host.");
        var rules = ConditionalStageClient.Eligible(advancedRoutingRules).ToArray();
        string sha = AdvancedRoutePlanner.PlanSha256(rules);
        string? manifest = null;
        if (operation != "plan")
        {
            if (conditionalStageReceipt is not { } prior ||
                conditionalStageContext != context || prior.PlanSha != sha)
                throw new InvalidOperationException("Validate the exact plan on this Linux host first.");
            if (operation == "compile")
                manifest = prior.ManifestSha ??
                    throw new InvalidOperationException("Verify the staged manifest first.");
            if (operation is "stage" or "compile")
            {
                string phrase = operation == "stage" ? "STAGE_CONDITIONAL_MAPS_ONLY"
                    : "COMPILE_CONDITIONAL_MAPS_ONLY";
                if (!ConfirmDestructive("LinuxMailRelay365 | Conditional maps",
                    TranslateMailFlow(language.SelectedIndex,
                        "Будут созданы только защищённые файлы-кандидаты. Активная конфигурация не меняется. Повторная перезапись запрещена.",
                        "Create private candidate files only. No active Postfix changes. Existing candidates are never overwritten.",
                        "יצירת קבצי מועמדות בלבד, ללא שינוי Postfix או החלפה.") +
                    Environment.NewLine + "Plan SHA-256: " + sha, phrase))
                    return;
            }
        }
        if (CurrentConditionalStageContext() != context)
            throw new InvalidOperationException("Host or routing plan changed after review.");
        string script = ConditionalStageClient.Build(EmbeddedAssets.ConditionalStageManager,
            rules, operation, manifest);
        conditionalStageReceipt = null;
        conditionalStageContext = null;
        var endpoint = Endpoint();
        var result = operation == "plan"
            ? await SshRemote.ExecuteAsync(endpoint, "bash -s", script, TimeSpan.FromSeconds(75))
            : await SshRemote.RunRootScriptAsync(endpoint, script, TimeSpan.FromMinutes(3));
        if (result.ExitCode != 0)
            throw new InvalidOperationException(
                "Candidate operation failed or was refused. No activation requested. Validate again and use Verify to inspect an existing candidate.");
        var receipt = ConditionalStageClient.Parse(result.StdOut, operation, sha, rules.Length);
        if (operation == "compile" && receipt.ManifestSha != manifest)
            throw new InvalidDataException("Compiled receipt refers to another stage manifest.");
        if (CurrentConditionalStageContext() != context)
            throw new InvalidOperationException("Host or routing plan changed during candidate operation.");
        conditionalStageReceipt = receipt;
        conditionalStageContext = context;
        WriteLine("Conditional map candidate: " + receipt.Status +
            "; active=no; Postfix changed=no.");
        RenderPage();
    }
}
