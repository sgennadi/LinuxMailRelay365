using System.Security.Cryptography;
using System.Text.Json;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private void ShowPrimaryMailboxRoutePreviewAction(TableLayoutPanel page,int width)
    {
        AddLine(page, UiTheme.Emphasis(T("Один ящик для исходящей почты основного Postfix",
            "One mailbox for the primary Postfix outbound route",
            "תיבה אחת לדואר יוצא של Postfix הראשי"),width));
        AddLine(page,MailFlowText(T(
            "Все письма, направленные в общий внешний транспорт, отправляются от одного ящика M365. From и envelope sender заменяются. Локальная доставка и существующий SMTP-порт должны сохраняться.",
            "Mail routed to the common outbound transport uses one M365 sender. From and envelope sender are rewritten. Existing SMTP listeners and local delivery must be preserved.",
            "דואר יוצא דרך תיבה אחת; כתובת השולח תוחלף. מסירה מקומית ויציאות קיימות יישמרו."),width,warning:true));
        AddField(page,T("Общий почтовый ящик M365","Shared M365 sender mailbox","תיבת שולח משותפת"),mailbox);
        AddAction(page,T("Preview общего маршрута (только чтение)",
            "Preview primary single-mailbox route (read-only)","בדיקת נתיב תיבה יחידה"),
            PreviewPrimaryMailboxRouteAsync,false,"check","primary-mailbox-route-preview");
        AddAction(page,T("Экспериментальный Offline Apply / Restore",
            "Experimental offline Apply / Restore","החלה ושחזור במצב לא מקוון (ניסיוני)"),
            OpenPrimaryMailboxOfflineAsync,false,"check","primary-mailbox-offline");
        AddLine(page,MailFlowText(T(
            "Требуется остановленный Postfix, пустая очередь, установленная PEM-идентичность и отдельное подтверждение. Служба не запускается автоматически.",
            "Requires stopped Postfix, empty queues, an installed PEM identity and separate approval. No automatic service start.",
            "נדרש Postfix כבוי, תורים ריקים וזהות PEM מותקנת. אין הפעלה אוטומטית."),width,warning:true));
    }

    private async Task PreviewPrimaryMailboxRouteAsync()
    {
        string chosen=mailbox.Text.Trim().ToLowerInvariant();
        if(!PrimaryMailboxRoutePreview.ValidMailbox(chosen)) throw new InvalidDataException("Enter a valid M365 sender mailbox.");
        string context=TryCurrentIdentity() ?? throw new InvalidOperationException("Discover Linux first.");
        if(!HasMailDiscovery() || inspectedMail?.Mta!="postfix" ||
            selectedMailTarget!=MailFlowIntent.TargetM365 || selectedMailScenario!=MailScenarioPlanner.ReplaceRelay ||
            mailTransport.SelectedIndex!=0 || oauthSenderMode.SelectedIndex!=0)
            throw new InvalidOperationException("Select the primary Postfix outbound migration and single-mailbox XOAUTH2.");
        var endpoint=Endpoint();
        RequireSameArchiveConnection(endpoint,allowFirstPin:true);
        string nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var request=JsonSerializer.Serialize(new {mailbox=chosen,nonce});
        var result=await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildPrimaryMailboxRoutePreviewBundle(request),TimeSpan.FromMinutes(3));
        RequireSameArchiveConnection(endpoint,allowFirstPin:true);
        if(result.ExitCode!=0 || TryCurrentIdentity()!=context || !HasMailDiscovery() ||
            selectedMailTarget!=MailFlowIntent.TargetM365 || selectedMailScenario!=MailScenarioPlanner.ReplaceRelay ||
            mailTransport.SelectedIndex!=0 || oauthSenderMode.SelectedIndex!=0 ||
            mailbox.Text.Trim().ToLowerInvariant()!=chosen)
            throw new InvalidOperationException("Primary mailbox route preview unavailable or stale. No changes requested.");
        var report=PrimaryMailboxRoutePreview.Parse(result.StdOut,chosen,nonce);
        WriteLine("Primary mailbox route preview: "+report.Route+"; queue="+report.Queue+"; scope="+report.Scope+". No mail or changes.");
        MessageBox.Show(this,report.Describe(),"LinuxMailRelay365 | Primary mailbox route Preview",
            MessageBoxButtons.OK,MessageBoxIcon.Information);
    }
}
