using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private TransportSelinuxReadiness? transportSelinuxReport;
    private string? transportSelinuxContext;

    private string? TransportSelinuxContext()
    {
        if (RecoveryInventoryContext() is not { } host ||
            advancedRoutingIdentity != TryCurrentIdentity()) return null;
        try
        {
            return host + "|" + AdvancedRoutePlanner.PlanSha256(
                MultiTransportClient.Eligible(advancedRoutingRules));
        }
        catch (ArgumentException) { return null; }
    }

    private void ShowTransportSelinuxReadiness(TableLayoutPanel page, int width, int l)
    {
        string? context = TransportSelinuxContext();
        if (context is null || context != transportSelinuxContext)
        {
            transportSelinuxReport = null;
            transportSelinuxContext = null;
        }
        if (context is null) return;
        AddAction(page, TranslateMailFlow(l, "SELinux — проверить исходящие маршруты",
            "SELinux — check outbound routes", "SELinux — בדיקת נתיבים יוצאים"),
            () => InspectTransportSelinuxAsync(context), false, "search", "multi-selinux-readiness");
        if (transportSelinuxReport is not { } report) return;
        AddLine(page, MailFlowText("SELinux: " + report.Mode + " · Backend: " + report.Backend +
            " · SASL: " + report.Sasl + Environment.NewLine + "File labels: " + report.Labels,
            width, warning: report.Labels != "policy_match_read_only"));
        foreach (var entry in report.Ports)
            AddLine(page, MailFlowText("TCP " + entry.Key + " · " + entry.Value, width,
                warning: entry.Value != "smtp_port_t"));
        AddLine(page, MailFlowText(TranslateMailFlow(l,
            "Только проверка политики. Метка smtp_port_t не подтверждает разрешение name_connect. Нет проверки доставки или разрешения на запись. Для уже существующих карт проверка нового набора может быть неопределённой.",
            "Policy inspection only. smtp_port_t is not proof of name_connect permission. No delivery verification or write approval. Draft checks may be unverified if destination maps already exist.",
            "בדיקת מדיניות בלבד. התווית אינה מאמתת הרשאת חיבור או מסירה ואינה מאשרת כתיבה."),
            width, warning: true));
    }

    private async Task InspectTransportSelinuxAsync(string context)
    {
        transportSelinuxReport = null;
        transportSelinuxContext = null;
        if (TransportSelinuxContext() != context)
            throw new InvalidOperationException("Reinspect the Postfix host and draft.");
        try
        {
            var rules = MultiTransportClient.Eligible(advancedRoutingRules);
            var result = await SshRemote.RunRootScriptAsync(Endpoint(),
                TransportSelinuxClient.Build(rules), TimeSpan.FromMinutes(4));
            if (TransportSelinuxContext() != context)
                throw new InvalidOperationException();
            transportSelinuxReport = TransportSelinuxClient.Parse(result.StdOut, result.ExitCode, rules);
            transportSelinuxContext = context;
            WriteLine("Outbound SELinux policy inspection completed. No configuration or policy changes.");
        }
        catch
        {
            transportSelinuxReport = null;
            transportSelinuxContext = null;
            throw new InvalidOperationException("Outbound SELinux policy inspection failed or became stale.");
        }
    }
}
