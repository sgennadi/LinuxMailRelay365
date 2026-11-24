using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private TransportSelinuxReadiness? transportSelinuxReport;
    private string? transportSelinuxContext;
    private TransportAvcReport? transportAvcReport;
    private string? transportAvcContext;

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
        if (context is null || context != transportAvcContext)
        {
            transportAvcReport = null;
            transportAvcContext = null;
        }
        if (context is null) return;
        AddAction(page, TranslateMailFlow(l, "SELinux — проверить исходящие маршруты",
            "SELinux — check outbound routes", "SELinux — בדיקת נתיבים יוצאים"),
            () => InspectTransportSelinuxAsync(context), false, "search", "multi-selinux-readiness");
        AddAction(page, TranslateMailFlow(l, "SELinux — недавние отказы AVC",
            "SELinux — recent AVC denials", "SELinux — חסימות AVC אחרונות"),
            () => InspectTransportAvcAsync(context), false, "search", "multi-selinux-avc");
        if (transportAvcReport is { } avc)
        {
            AddLine(page, MailFlowText("AVC · " + avc.Mode + " · " + avc.Status, width,
                warning: avc.Status != "records_read"));
            if (avc.Status == "records_read")
            {
                foreach (var entry in avc.Ports)
                    AddLine(page, MailFlowText("TCP " + entry.Key + " · Enforced: " +
                        entry.Value.Enforced + " · Permissive: " + entry.Value.Permissive +
                        " · Unknown: " + entry.Value.Unknown, width,
                        warning: entry.Value != new TransportAvcCounts(0, 0, 0)));
            }
            AddLine(page, MailFlowText(TranslateMailFlow(l,
                "История name_connect для postfix_smtp_t за последние 10 минут. Совпадение порта не доказывает связь с выбранным провайдером. Отсутствие события или журнала не доказывает доступ.",
                "Recent (10-minute) postfix_smtp_t name_connect history. Matching a port does not identify the selected provider. Missing events or logs do not prove access.",
                "היסטוריית name_connect בעשר הדקות האחרונות. התאמת פורט אינה מזהה ספק; היעדר אירועים אינו מוכיח גישה."),
                width, warning: true));
        }
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

    private async Task InspectTransportAvcAsync(string context)
    {
        transportAvcReport = null;
        transportAvcContext = null;
        if (TransportSelinuxContext() != context)
            throw new InvalidOperationException("Reinspect the Postfix host and draft.");
        try
        {
            var rules = MultiTransportClient.Eligible(advancedRoutingRules);
            var result = await SshRemote.RunRootScriptAsync(Endpoint(),
                TransportSelinuxClient.Build(rules, audit: true), TimeSpan.FromMinutes(2));
            if (TransportSelinuxContext() != context)
                throw new InvalidOperationException();
            transportAvcReport = TransportSelinuxClient.ParseAvc(result.StdOut, result.ExitCode, rules);
            transportAvcContext = context;
            WriteLine("Recent outbound AVC inspection completed. No configuration or policy changes.");
        }
        catch
        {
            transportAvcReport = null;
            transportAvcContext = null;
            throw new InvalidOperationException("Recent outbound AVC inspection failed or became stale.");
        }
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
