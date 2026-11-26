using System.Drawing;
using System.Security.Cryptography;
using System.Windows.Forms;
using Microsoft365Auth;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private (MultiMailboxNewAppRequest Request, bool Resume)? PromptNewMailboxApp(Form owner, MultiMailboxIdentityInventory inventory)
    {
        using var dialog=new Form { Text="LinuxMailRelay365 | New Entra app / recover pending creation",
            StartPosition=FormStartPosition.CenterParent,AutoScaleMode=AutoScaleMode.Dpi,
            ClientSize=PreferredDialogSize(Screen.FromControl(owner).WorkingArea.Size,owner.DeviceDpi,730,650),
            Font=new Font("Segoe UI",10f),MinimizeBox=false };
        var root=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=2,Padding=new Padding(12)};
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100)); root.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var scroll=new Panel {Dock=DockStyle.Fill,AutoScroll=true};
        var fields=new TableLayoutPanel {Dock=DockStyle.Top,ColumnCount=1,AutoSize=true};
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        var help=UiTheme.Text("Create one dedicated single-tenant Entra application with its initial public certificate. " +
            "The private key is generated on Linux. No Exchange permissions, source-map binding or Postfix activation. " +
            "To recover an interrupted creation, enter the original mailbox, tenant, validity and recovery code; " +
            "if a cloud create was claimed, enter the exact Client ID from Entra. A claimed creation is never automatically repeated.");
        void Fit()=>help.MaximumSize=new Size(Math.Max(150,dialog.ClientSize.Width-70),0);
        Fit(); dialog.ClientSizeChanged+=(_,_)=>Fit();
        AddLine(fields,help);
        var t=new TextBox {Dock=DockStyle.Fill,MaxLength=36,Text=tenant.Text.Trim()};
        var m=new TextBox {Dock=DockStyle.Fill,MaxLength=254};
        var days=new NumericUpDown {Dock=DockStyle.Fill,Minimum=4,Maximum=365,Value=365};
        var recovery=new TextBox {Dock=DockStyle.Fill,MaxLength=64};
        var client=new TextBox {Dock=DockStyle.Fill,MaxLength=36};
        AddField(fields,"Tenant ID",t); AddField(fields,"Primary Microsoft 365 mailbox",m);
        AddLine(fields,UiTheme.Text("Certificate validity (days)")); AddLine(fields,days);
        AddField(fields,"Recovery code (empty for new application)",recovery);
        AddField(fields,"Recovered Entra Client ID (only after creation was claimed)",client);
        var buttons=new FlowLayoutPanel {Dock=DockStyle.Fill,AutoSize=true,FlowDirection=FlowDirection.RightToLeft,WrapContents=true};
        var cancel=new Button {Text=T("Отмена","Cancel","ביטול"),AutoSize=true,DialogResult=DialogResult.Cancel};
        var next=new Button {Text=T("Предпросмотр","Preview","תצוגה מקדימה"),AutoSize=true,DialogResult=DialogResult.OK};
        string nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        MultiMailboxNewAppRequest Request()=>new(Guid.TryParse(t.Text.Trim(),out var ti)?ti:Guid.Empty,
            m.Text.Trim().ToLowerInvariant(),(int)days.Value,inventory.Source.Sha256,inventory.Runtime.Sha256,
            recovery.Text.Trim().Length==0?nonce:recovery.Text.Trim().ToLowerInvariant(),
            client.Text.Trim().Length==0?null:Guid.TryParse(client.Text.Trim(),out var ci)?ci:Guid.Empty);
        void Validate()=>next.Enabled=Request().Valid && (recovery.Text.Trim().Length>0 || client.Text.Trim().Length==0);
        t.TextChanged+=(_,_)=>Validate(); m.TextChanged+=(_,_)=>Validate(); days.ValueChanged+=(_,_)=>Validate();
        recovery.TextChanged+=(_,_)=>Validate(); client.TextChanged+=(_,_)=>Validate(); Validate();
        buttons.Controls.Add(cancel); buttons.Controls.Add(next); scroll.Controls.Add(fields);
        root.Controls.Add(scroll,0,0);root.Controls.Add(buttons,0,1);dialog.Controls.Add(root);
        dialog.CancelButton=cancel;dialog.AcceptButton=next;
        return dialog.ShowDialog(owner)==DialogResult.OK && Request().Valid ? (Request(),recovery.Text.Trim().Length>0) : null;
    }

    private async Task<Guid> VerifyNewMailboxAppAsync(MultiMailboxNewAppRequest req, MultiMailboxNewAppReceipt stage,
        Guid clientId, Guid bootstrap, Form owner, Action validate)
    {
        validate();
        var graph=await WithNativeMicrosoftSignInAsync((show,ct)=>
            EntraGraphInventoryClient.InspectAsync(req.Tenant,clientId,bootstrap,show,ct),signInOwner:owner);
        validate();
        var now=DateTimeOffset.UtcNow;
        if (graph.ClientId!=clientId || graph.AppObjectId==Guid.Empty || graph.DisplayName!=req.Name ||
            graph.EnterpriseStatus!="found" || graph.EnterpriseObjectId is not Guid enterprise || enterprise==Guid.Empty ||
            graph.Certificates.Count!=1 || !graph.Certificates.Any(k=>k.Type=="AsymmetricX509Cert" && k.Usage=="Verify" &&
                k.CertificateSha256==stage.CertificateSha && k.ValidFrom<=now && k.ValidUntil>now))
            throw new InvalidDataException("Exact dedicated app, initial certificate and Enterprise Application were not verified.");
        return enterprise;
    }
}
