using System.Drawing;
using System.Text.Json;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private Task OpenPrimaryMailboxDeliveryAsync()
    {
        string context=TryCurrentIdentity() ?? throw new InvalidOperationException("Discover Linux first.");
        var endpoint=Endpoint();
        void Guard()
        {
            RequireSameArchiveConnection(endpoint);
            if(TryCurrentIdentity()!=context || !HasMailDiscovery() || inspectedMail?.Mta!="postfix" ||
                selectedMailTarget!=MailFlowIntent.TargetM365 || selectedMailScenario!=MailScenarioPlanner.ReplaceRelay ||
                mailTransport.SelectedIndex!=0 || oauthSenderMode.SelectedIndex!=0)
                throw new InvalidOperationException("Linux host or primary mailbox route selection changed. Rediscover.");
        }
        Guard();
        using var dialog=new Form {
            Text="Experimental | Primary Postfix XOAUTH2 delivery test",
            StartPosition=FormStartPosition.CenterParent,AutoScaleMode=AutoScaleMode.Dpi,
            ClientSize=PreferredDialogSize(Screen.FromControl(this).WorkingArea.Size,DeviceDpi,920,740),
            MinimumSize=PreferredDialogSize(Screen.FromControl(this).WorkingArea.Size,DeviceDpi,480,400)
        };
        var layout=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=6,Padding=new Padding(12),AutoScroll=true};
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        for(int i=0;i<4;i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var intro=new Label {AutoSize=true,Text="Host: "+endpoint.Username+"@"+endpoint.Host+":"+endpoint.Port+
            Environment.NewLine+"Actual Postfix queue → XOAUTH2 → Microsoft 365. Use a controlled test host; keep unrelated submissions blocked."};
        var fields=new TableLayoutPanel {Dock=DockStyle.Top,AutoSize=true,ColumnCount=2,RowCount=8};
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,38));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,62));
        TextBox Box(string value,int max)=>new(){Text=value,MaxLength=max,Dock=DockStyle.Fill};
        var sender=Box(mailbox.Text.Trim().ToLowerInvariant(),254);
        var tenantInput=Box(tenant.Text.Trim(),36);
        var clientInput=Box(existingAppId.Text.Trim(),36);
        var backup=Box("",64);
        var domain=Box(sender.Text.Contains('@')?sender.Text[(sender.Text.LastIndexOf('@')+1)..]:"",253);
        var internalRecipient=Box("",254);
        var externalRecipient=Box("",254);
        var run=Box(Guid.NewGuid().ToString("N"),32);
        TextBox[] inputs=[sender,tenantInput,clientInput,backup,domain,internalRecipient,externalRecipient,run];
        string[] labels=["M365 sender mailbox","Tenant ID","Application ID","Recovery SHA-256","Sender domain",
            "Internal test recipient","External test recipient","Run ID (retain for trace)"];
        for(int i=0;i<inputs.Length;i++)
        {
            fields.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            fields.Controls.Add(new Label {Text=labels[i],AutoSize=true,Anchor=AnchorStyles.Left},0,i);
            fields.Controls.Add(inputs[i],1,i);
        }
        var controlled=new CheckBox {AutoSize=true,Dock=DockStyle.Top,
            Text="I control or have permission for both recipients; unrelated submissions are blocked."};
        var status=new Label {AutoSize=true,Text="Enter the recovery SHA from Apply / Start, then review the running route."};
        var results=new DataGridView {Dock=DockStyle.Top,Height=140,ReadOnly=true,AllowUserToAddRows=false,
            AllowUserToDeleteRows=false,AllowUserToOrderColumns=false,RowHeadersVisible=false,
            AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,SelectionMode=DataGridViewSelectionMode.FullRowSelect};
        foreach(string name in new[]{"Role","Submission","Transport","Queue ID","Queue","DSN","Exchange trace"})
            results.Columns.Add(name,name);
        var details=new TextBox {Dock=DockStyle.Fill,ReadOnly=true,Multiline=true,ScrollBars=ScrollBars.Both,
            WordWrap=false,MinimumSize=new Size(0,100)};
        var resultPanel=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=2};
        resultPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        resultPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        resultPanel.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        resultPanel.Controls.Add(results,0,0);resultPanel.Controls.Add(details,0,1);
        var review=new Button {Text="Review running route",AutoSize=true};
        var send=new Button {Text="Send two reviewed tests",AutoSize=true};
        var trace=new Button {Text="Refresh trace (no send)",AutoSize=true};
        var cloudTrace=new Button {Text="Exchange Message Trace",AutoSize=true};
        var localMailbox=new Button {Text="Test local UNIX delivery",AutoSize=true};
        var copy=new Button {Text="Copy trace request",AutoSize=true};
        var resume=new Button {Text="Resume trace from clipboard",AutoSize=true};
        var close=new Button {Text="Close",AutoSize=true,DialogResult=DialogResult.Cancel};
        var buttons=new FlowLayoutPanel {Dock=DockStyle.Fill,AutoSize=true,WrapContents=true};
        buttons.Controls.AddRange([review,send,trace,cloudTrace,localMailbox,copy,resume,close]);
        bool busy=false,traceOnly=false;
        PrimaryMailboxDeliveryRequest? approvedRequest=null,lockedRequest=null;
        string? approvedSha=null,traceSha=null;
        bool TryRequest(out PrimaryMailboxDeliveryRequest request)
        {
            request=null!;
            if(!Guid.TryParse(tenantInput.Text.Trim(),out Guid tid) ||
                !Guid.TryParse(clientInput.Text.Trim(),out Guid cid) ||
                (discoveredTenants.Count>1 && tenantSelector.SelectedItem is not TenantOption) ||
                (tenantSelector.SelectedItem is TenantOption selected && selected.Id!=tid)) return false;
            request=new(run.Text.Trim(),sender.Text.Trim().ToLowerInvariant(),
                internalRecipient.Text.Trim().ToLowerInvariant(),externalRecipient.Text.Trim().ToLowerInvariant(),
                domain.Text.Trim().ToLowerInvariant(),backup.Text.Trim(),tid,cid);
            return request.Valid();
        }
        void ClearReview(){approvedRequest=null;approvedSha=null;}
        void SetStatus(string text,Color color){status.Text=text;status.ForeColor=color;}
        void Update()
        {
            bool valid=TryRequest(out var request);
            review.Enabled=!busy && !traceOnly && controlled.Checked && valid;
            send.Enabled=review.Enabled && approvedRequest==request && PrimaryMailboxOfflineClient.IsSha(approvedSha);
            trace.Enabled=cloudTrace.Enabled=!busy && valid;
            localMailbox.Enabled=!busy && PrimaryMailboxOfflineClient.IsSha(backup.Text.Trim());
            copy.Enabled=!busy && valid;
            resume.Enabled=!busy && !traceOnly;
            foreach(var field in inputs) field.ReadOnly=busy || traceOnly;
            controlled.Enabled=!busy && !traceOnly;
            close.Enabled=!busy;
        }
        void LockTrace(PrimaryMailboxDeliveryRequest request,string? sha)
        {
            lockedRequest=request;traceSha=sha;traceOnly=true;ClearReview();Update();
        }
        void ShowReceipt(PrimaryMailboxDeliveryReceipt receipt)
        {
            results.Rows.Clear();
            foreach(var row in receipt.Rows)
            {
                int index=results.Rows.Add(row.Role,row.Submission,row.Transport,row.QueueId,row.Queue,row.Dsn);
                results.Rows[index].DefaultCellStyle.ForeColor=row.Transport switch {
                    "exchange_smtp_accepted"=>Color.SeaGreen,"deferred" or "correlation_unavailable"=>Color.DarkOrange,
                    "bounced"=>Color.Firebrick,_=>SystemColors.ControlText};
            }
            details.Text="Plan SHA-256: "+receipt.PlanSha+Environment.NewLine+
                (receipt.RuntimeSha is null?"":"Runtime SHA-256: "+receipt.RuntimeSha+Environment.NewLine)+
                (receipt.Source.Length==0?"":"Journal: "+receipt.Source+Environment.NewLine)+
                "SMTP acceptance is not verified inbox delivery. No automatic resubmission.";
        }
        async Task<PrimaryMailboxDeliveryReceipt> Remote(string action,PrimaryMailboxDeliveryRequest request,
            string? sha,string? confirmation=null)
        {
            Guard();
            string script=EmbeddedAssets.BuildPrimaryMailboxDeliveryProbe(action,request,
                action=="submit"?sha:null,confirmation);
            var result=endpoint.Username=="root"
                ? await SshRemote.ExecuteAsync(endpoint,"bash -s",script,TimeSpan.FromMinutes(9))
                : await SshRemote.RunRootScriptAsync(endpoint,script,TimeSpan.FromMinutes(9));
            Guard();
            if(result.ExitCode!=0) throw new InvalidOperationException("Probe refused or outcome unavailable.");
            return PrimaryMailboxDeliveryClient.Parse(result.StdOut,action,request,sha);
        }
        async Task Execute(string message,Func<Task> work,bool submission=false)
        {
            if(busy) return;
            busy=true;Update();SetStatus(message,SystemColors.ControlText);
            try { Guard();await work();Guard(); }
            catch(Exception ex)
            {
                ClearReview();
                SetStatus(submission?"Submission outcome uncertain. Retain the exact request; refresh trace, do not resend.":
                    "Review or trace unavailable ("+ex.GetType().Name+"). No automatic send.",Color.DarkOrange);
                details.Text="Run ID: "+run.Text+Environment.NewLine+"Use the original host and exact request. Do not infer delivery from a missing queue entry.";
            }
            finally {busy=false;Update();}
        }
        review.Click+=async (_,_) =>
        {
            if(!review.Enabled || !TryRequest(out var request)) return;
            ClearReview();
            await Execute("Reviewing the running applied route and installed OAuth runtime...",async ()=>{
                var receipt=await Remote("preview",request,null);
                approvedRequest=request;approvedSha=receipt.PlanSha;ShowReceipt(receipt);
                SetStatus("Route reviewed. No message sent. Confirm recipients separately.",Color.SeaGreen);
            });
        };
        send.Click+=async (_,_) =>
        {
            if(!send.Enabled || approvedRequest is not { } request || approvedSha is not { } sha ||
                !TryRequest(out var current) || current!=request) return;
            if(!ConfirmDestructive("Send two real Postfix delivery tests",
                "Host: "+endpoint.Host+":"+endpoint.Port+Environment.NewLine+
                "Sender: "+request.Sender+Environment.NewLine+"Internal: "+request.Internal+Environment.NewLine+
                "External: "+request.External+Environment.NewLine+"Run ID: "+request.RunId+Environment.NewLine+
                "Keep unrelated submissions blocked. Postfix may retry normal delivery. Domain comparison is not tenant membership proof. "+
                "This manager will not resubmit this run. Copy the trace request before sending.",
                PrimaryMailboxDeliveryClient.Confirm,dialog)) return;
            // Lock the exact request before SSH, including timeout/refusal.
            LockTrace(request,sha);
            WriteLine("Primary XOAUTH2 delivery probe requested. Retain run ID: "+request.RunId);
            await Execute("Submitting two explicitly approved messages through native Postfix...",async ()=>{
                var receipt=await Remote("submit",request,sha,PrimaryMailboxDeliveryClient.Confirm);
                ShowReceipt(receipt);SetStatus("Local submission results recorded. Refresh trace; delivery not yet verified.",Color.SeaGreen);
            },submission:true);
        };
        trace.Click+=async (_,_) =>
        {
            if(!trace.Enabled || !TryRequest(out var request) || (lockedRequest is not null && lockedRequest!=request)) return;
            LockTrace(request,traceSha);
            await Execute("Reading the protected run ledger, matching journal and queue...",async ()=>{
                var receipt=await Remote("trace",request,traceSha);
                traceSha=receipt.PlanSha;ShowReceipt(receipt);
                SetStatus("Trace observed; no new message submitted. Inbox arrival remains unverified.",Color.SeaGreen);
            });
        };
        cloudTrace.Click+=async (_,_) =>
        {
            if(!cloudTrace.Enabled || !TryRequest(out var request) ||
                (lockedRequest is not null && lockedRequest!=request)) return;
            LockTrace(request,traceSha);
            await Execute("Validating the local run ledger before Exchange Online trace...",async ()=>{
                var local=await Remote("trace",request,traceSha);
                traceSha=local.PlanSha;ShowReceipt(local);
                try
                {
                    SetStatus("Reading Exchange Online; sign in to the selected tenant if prompted.",SystemColors.ControlText);
                    string raw=await ReadPrimaryMailboxExchangeTraceAsync(request,local,Guard);
                    Guard();
                    using var document=JsonDocument.Parse(raw);
                    var outcomes=document.RootElement.GetProperty("outcomes");
                    foreach(DataGridViewRow row in results.Rows)
                    {
                        string role=(string)row.Cells[0].Value!;
                        row.Cells[6].Value=outcomes.GetProperty(role).GetProperty("state").GetString();
                    }
                    details.AppendText(Environment.NewLine+Environment.NewLine+"Exchange Online (service-reported):"+
                        Environment.NewLine+raw+Environment.NewLine+
                        "Delivered is service-reported; inbox arrival is not verified. Not observed can mean trace latency.");
                    SetStatus("Exchange trace observed. No mail sent and no tenant changes.",Color.SeaGreen);
                }
                catch(Exception ex)
                {
                    details.AppendText(Environment.NewLine+"Exchange trace unavailable ("+ex.GetType().Name+
                        "). Check the selected tenant, permissions, run age and trace latency. Local evidence retained.");
                    SetStatus("Exchange trace unavailable; local evidence retained. Do not resend.",Color.DarkOrange);
                }
            });
        };
        localMailbox.Click+=(_,_) =>
        {
            if(!localMailbox.Enabled) return;
            string recoverySha=backup.Text.Trim();
            ClearReview();Update();
            async Task<string> LocalRemote(string action,string request,string? sha)
            {
                Guard();
                if(backup.Text.Trim()!=recoverySha)
                    throw new InvalidOperationException("Local migration context changed.");
                string script=EmbeddedAssets.BuildPrimaryMailboxLocalProbe(action,request,recoverySha,sha);
                var result=endpoint.Username=="root"
                    ? await SshRemote.ExecuteAsync(endpoint,"bash -s",script,TimeSpan.FromMinutes(9))
                    : await SshRemote.RunRootScriptAsync(endpoint,script,TimeSpan.FromMinutes(9));
                Guard();
                if(result.ExitCode!=0 || result.StdOut.Length>65536)
                    throw new InvalidOperationException("Migration local probe refused or outcome unavailable.");
                return result.StdOut;
            }
            using var localDialog=new PostfixLocalDeliveryDialog(LocalRemote,recoverySha);
            localDialog.ShowDialog(dialog);
            SetStatus("Local mailbox test closed. Review again before any cloud submission.",SystemColors.ControlText);
            Update();
        };
        copy.Click+=(_,_) =>
        {
            if(!copy.Enabled || !TryRequest(out var request)) return;
            try {Clipboard.SetText(request.Json());SetStatus("Trace request copied. Contains addresses and IDs, but no secrets; keep it private.",SystemColors.ControlText);}
            catch(System.Runtime.InteropServices.ExternalException){SetStatus("Clipboard unavailable.",Color.DarkOrange);}
        };
        resume.Click+=(_,_) =>
        {
            if(!resume.Enabled) return;
            try
            {
                var request=PrimaryMailboxDeliveryRequest.Parse(Clipboard.GetText());
                if(tenantSelector.SelectedItem is TenantOption selected && selected.Id!=request.Tenant)
                    throw new InvalidDataException("Selected tenant differs.");
                sender.Text=request.Sender;tenantInput.Text=request.Tenant.ToString("D");
                clientInput.Text=request.Client.ToString("D");backup.Text=request.BackupSha;domain.Text=request.Domain;
                internalRecipient.Text=request.Internal;externalRecipient.Text=request.External;run.Text=request.RunId;
                LockTrace(request,null);
                SetStatus("Trace-only session restored. Verify the original host; refresh trace, no sending.",SystemColors.ControlText);
            }
            catch(Exception){SetStatus("Clipboard request invalid or tenant mismatch.",Color.DarkOrange);}
        };
        foreach(var field in inputs) field.TextChanged+=(_,_)=>{ClearReview();results.Rows.Clear();Update();};
        controlled.CheckedChanged+=(_,_)=>{ClearReview();Update();};
        dialog.FormClosing+=(_,e)=>{if(busy)e.Cancel=true;};
        void Wrap()=>intro.MaximumSize=status.MaximumSize=controlled.MaximumSize=new Size(Math.Max(200,dialog.ClientSize.Width-36),0);
        dialog.ClientSizeChanged+=(_,_)=>Wrap();Wrap();
        layout.Controls.Add(intro,0,0);layout.Controls.Add(fields,0,1);layout.Controls.Add(controlled,0,2);
        layout.Controls.Add(status,0,3);layout.Controls.Add(resultPanel,0,4);layout.Controls.Add(buttons,0,5);
        dialog.Controls.Add(layout);dialog.CancelButton=close;Update();dialog.ShowDialog(this);
        return Task.CompletedTask;
    }
}
