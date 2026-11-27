using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private sealed class PrimaryMailboxReviewRefusedException(string guidance) : Exception
    {
        internal string Guidance { get; }=guidance;
    }

    private Task OpenPrimaryMailboxOfflineAsync()
    {
        string context=TryCurrentIdentity() ?? throw new InvalidOperationException("Discover Linux first.");
        var endpoint=Endpoint();
        void Guard()
        {
            RequireSameArchiveConnection(endpoint);
            if (TryCurrentIdentity()!=context || !HasMailDiscovery() || inspectedMail?.Mta!="postfix" ||
                selectedMailTarget!=MailFlowIntent.TargetM365 ||
                selectedMailScenario!=MailScenarioPlanner.ReplaceRelay ||
                mailTransport.SelectedIndex!=0 || oauthSenderMode.SelectedIndex!=0)
                throw new InvalidOperationException("Linux or selected primary route context changed. Reinspect.");
        }
        Guard();
        using var dialog=new Form {
            Text="Experimental | Primary Postfix single-mailbox XOAUTH2",
            StartPosition=FormStartPosition.CenterParent,AutoScaleMode=AutoScaleMode.Dpi,
            ClientSize=PreferredDialogSize(Screen.FromControl(this).WorkingArea.Size,DeviceDpi,900,700),
            MinimumSize=PreferredDialogSize(Screen.FromControl(this).WorkingArea.Size,DeviceDpi,450,360)
        };
        var layout=new TableLayoutPanel {
            Dock=DockStyle.Fill,Padding=new Padding(12),ColumnCount=1,RowCount=7
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        for(int i=0;i<5;i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var intro=new TextBox {
            Dock=DockStyle.Top,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Height=82,
            Text="Host: "+endpoint.Username+"@"+endpoint.Host+":"+endpoint.Port+Environment.NewLine+
                "Changes the common outbound transport to one M365 sender. From and envelope sender are rewritten. "+
                "Local routes and existing SMTP listeners must be preserved. Active PEM or managed persistent TPM2 identity; no SELinux/ACL support. "+
                "No automatic service start."
        };
        var inputs=new TableLayoutPanel { Dock=DockStyle.Top,AutoSize=true,ColumnCount=2,RowCount=3 };
        inputs.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        inputs.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        var sender=new TextBox { Dock=DockStyle.Fill,MaxLength=254,Text=mailbox.Text.Trim().ToLowerInvariant() };
        var tenantInput=new TextBox { Dock=DockStyle.Fill,MaxLength=36,Text=tenant.Text.Trim() };
        var appInput=new TextBox { Dock=DockStyle.Fill,MaxLength=36,Text=existingAppId.Text.Trim() };
        void AddInput(string name,TextBox field,int row)
        {
            inputs.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            inputs.Controls.Add(new Label { Text=name,AutoSize=true,Anchor=AnchorStyles.Left },0,row);
            inputs.Controls.Add(field,1,row);
        }
        AddInput("M365 mailbox",sender,0);AddInput("Tenant ID",tenantInput,1);AddInput("Application (client) ID",appInput,2);
        var maintenance=new CheckBox { AutoSize=true,Dock=DockStyle.Top,Text=
            "Postfix is stopped; queues are empty; I prevent concurrent mail, starts, edits and runtime updates." };
        void WrapMaintenance() => maintenance.MaximumSize=new Size(Math.Max(180,dialog.ClientSize.Width-36),0);
        dialog.ClientSizeChanged+=(_,_)=>WrapMaintenance();
        WrapMaintenance();
        var recoveryPanel=new TableLayoutPanel { Dock=DockStyle.Top,AutoSize=true,ColumnCount=1,RowCount=2 };
        recoveryPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        recoveryPanel.Controls.Add(new Label { Text="Review / recovery SHA-256 (copy and retain before Apply)",AutoSize=true },0,0);
        var recovery=new TextBox { Dock=DockStyle.Fill,MaxLength=64 };
        recoveryPanel.Controls.Add(recovery,0,1);
        var status=new TextBox { Dock=DockStyle.Top,ReadOnly=true,Multiline=true,Height=46,ScrollBars=ScrollBars.Vertical,
            Text="Review requires the exact installed mailbox and application. Recovery does not require working cloud credentials." };
        var report=new TextBox { Dock=DockStyle.Fill,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Both,WordWrap=false };
        var review=new Button { Text="Review + SMTP AUTH",AutoSize=true };
        var apply=new Button { Text="Backup / Apply",AutoSize=true };
        var inspect=new Button { Text="Inspect backup",AutoSize=true };
        var verifyApplied=new Button { Text="Reverify applied + AUTH",AutoSize=true };
        var start=new Button { Text="Check / Start Postfix",AutoSize=true };
        var restore=new Button { Text="Restore",AutoSize=true };
        var copy=new Button { Text="Copy SHA",AutoSize=true };
        var close=new Button { Text="Close",AutoSize=true,DialogResult=DialogResult.Cancel };
        var actions=new FlowLayoutPanel { Dock=DockStyle.Fill,AutoSize=true,WrapContents=true };
        actions.Controls.AddRange([review,apply,inspect,verifyApplied,start,restore,copy,close]);
        bool busy=false, mutationAttempted=false, startAttempted=false;
        PrimaryMailboxOfflineReceipt? approved=null;
        string? inspectedSha=null, inspectedPhase=null;
        (string Mailbox,Guid Tenant,Guid Client)? approvedIdentity=null, verifiedIdentity=null;
        PrimaryMailboxOfflineReceipt? verifiedApplied=null;
        void ClearVerified() { verifiedApplied=null;verifiedIdentity=null; }
        void ClearReview() { approved=null;approvedIdentity=null;ClearVerified(); }
        void ClearInspection() { inspectedSha=inspectedPhase=null;ClearVerified(); }
        bool TryTarget(out (string Mailbox,Guid Tenant,Guid Client) value)
        {
            value=default;
            string mail=sender.Text.Trim().ToLowerInvariant();
            if(!PrimaryMailboxRoutePreview.ValidMailbox(mail) ||
                !Guid.TryParse(tenantInput.Text.Trim(),out Guid tenantId) || tenantId==Guid.Empty ||
                !Guid.TryParse(appInput.Text.Trim(),out Guid appId) || appId==Guid.Empty ||
                (discoveredTenants.Count>1 && tenantSelector.SelectedItem is not TenantOption) ||
                (tenantSelector.SelectedItem is TenantOption chosen && chosen.Id!=tenantId))
                return false;
            value=(mail,tenantId,appId);
            return true;
        }
        void Update()
        {
            bool ready=!busy && !startAttempted && maintenance.Checked, target=TryTarget(out var identity);
            review.Enabled=ready && target && !mutationAttempted;
            apply.Enabled=review.Enabled && approved is not null && approvedIdentity==identity &&
                recovery.Text.Trim()==approved.Sha;
            inspect.Enabled=ready && PrimaryMailboxOfflineClient.IsSha(recovery.Text.Trim());
            restore.Enabled=inspect.Enabled && inspectedSha==recovery.Text.Trim() &&
                inspectedPhase is "after" or "pipe_only";
            verifyApplied.Enabled=inspect.Enabled && inspectedSha==recovery.Text.Trim() &&
                inspectedPhase=="after" && target;
            start.Enabled=verifyApplied.Enabled && verifiedApplied is not null &&
                verifiedApplied.Sha==recovery.Text.Trim() && verifiedIdentity==identity &&
                PrimaryMailboxOfflineClient.IsSha(verifiedApplied.RuntimeSha);
            sender.Enabled=tenantInput.Enabled=appInput.Enabled=!busy && !mutationAttempted && !startAttempted;
            recovery.Enabled=maintenance.Enabled=!busy && !startAttempted;
            recovery.ReadOnly=startAttempted;
            close.Enabled=!busy;
            copy.Enabled=!busy && PrimaryMailboxOfflineClient.IsSha(recovery.Text.Trim());
        }
        async Task RunAsync(string message,Func<Task> work)
        {
            if(busy || startAttempted || !maintenance.Checked) return;
            busy=true;Update();
            status.ForeColor=SystemColors.ControlText;status.Text=message;
            try { Guard();await work();Guard(); }
            catch(Exception ex)
            {
                ClearReview();ClearInspection();
                status.ForeColor=Color.DarkOrange;
                if(startAttempted)
                {
                    status.Text="Start outcome unverified. Postfix MAY be running. Do not retry or restore automatically.";
                    report.Text="Recovery SHA-256: "+recovery.Text.Trim()+Environment.NewLine+
                        "SSH or startup result unverified ("+ex.GetType().Name+"). Keep submissions blocked. "+
                        "Check actual service and queue state on the host. No automatic stop or rollback. "+
                        "Close and rediscover before any further operation.";
                }
                else if(ex is PrimaryMailboxReviewRefusedException refusal && !mutationAttempted)
                {
                    status.Text="Review refused. No configuration change or mail submission reported.";
                    report.Text=refusal.Guidance+Environment.NewLine+
                        "Keep the maintenance conditions in force and request a new review after resolving the issue.";
                }
                else
                    status.Text="Refused or uncertain ("+ex.GetType().Name+"). Keep Postfix stopped. Retain SHA and inspect recovery before retrying.";
            }
            finally
            {
                if(startAttempted)
                {
                    maintenance.Checked=false;
                    maintenance.Text="Startup attempted. Offline operations locked; retain the SHA and rediscover.";
                    WrapMaintenance();
                }
                busy=false;Update();
            }
        }
        async Task<PrimaryMailboxOfflineReceipt> LinuxAsync(string action,
            (string Mailbox,Guid Tenant,Guid Client)? target,string? sha,string? approval,string? authApproval=null)
        {
            Guard();
            if(!maintenance.Checked) throw new InvalidOperationException("Maintenance approval missing.");
            string script=EmbeddedAssets.BuildPrimaryMailboxOffline(action,PrimaryMailboxOfflineClient.Maintenance,
                target?.Mailbox,target?.Tenant,target?.Client,sha,approval,authApproval);
            var result=endpoint.Username=="root"
                ? await SshRemote.ExecuteAsync(endpoint,"bash -s",script,TimeSpan.FromMinutes(9))
                : await SshRemote.RunRootScriptAsync(endpoint,script,TimeSpan.FromMinutes(9));
            Guard();
            if(result.ExitCode!=0)
            {
                if(result.ExitCode==2 && action=="review" &&
                    PrimaryMailboxOfflineClient.ReviewFailureGuidance(result.StdOut) is { } guidance)
                    throw new PrimaryMailboxReviewRefusedException(guidance);
                throw new InvalidOperationException("Offline manager refused or result unavailable.");
            }
            return PrimaryMailboxOfflineClient.Parse(result.StdOut,action,sha);
        }
        string TargetDescription((string Mailbox,Guid Tenant,Guid Client) identity)=>
            "Host: "+endpoint.Host+":"+endpoint.Port+Environment.NewLine+"Mailbox: "+identity.Mailbox+
            Environment.NewLine+"Tenant: "+identity.Tenant.ToString("D")+
            Environment.NewLine+"Application: "+identity.Client.ToString("D");
        review.Click+=async (_,_) =>
        {
            if(!review.Enabled || !TryTarget(out var identity)) return;
            ClearReview();ClearInspection();Update();
            if(!ConfirmDestructive("Review primary mailbox and SMTP AUTH",
                TargetDescription(identity)+Environment.NewLine+
                "Use the exact installed PEM or managed TPM2 identity to authenticate to Microsoft 365 as m365mailer. "+
                "No message will be submitted. Confirm the exclusive offline maintenance conditions.",
                PrimaryMailboxOfflineClient.Auth,dialog)) return;
            await RunAsync("Reviewing installed runtime, SMTP AUTH and native Postfix candidate...",async () =>
            {
                var result=await LinuxAsync("review",identity,null,PrimaryMailboxOfflineClient.Auth);
                if(!TryTarget(out var current) || current!=identity) throw new InvalidOperationException("Mailbox identity changed.");
                recovery.Text=result.Sha;
                approved=result;approvedIdentity=identity;
                report.Text=TargetDescription(identity)+Environment.NewLine+
                    "Review SHA-256: "+result.Sha+Environment.NewLine+"Runtime SHA-256: "+result.RuntimeSha+
                    Environment.NewLine+"Proposed: default_transport and relay_transport = m365xoauth2:"+
                    Environment.NewLine+"Clear prior relayhost; add dedicated pipe and reviewed limits."+
                    Environment.NewLine+"Native comparison and no-mail SMTP AUTH observed. No delivery test."+
                    Environment.NewLine+"Retain the review SHA before the separate Apply.";
                status.Text="Reviewed; no configuration change or mail submission.";
                status.ForeColor=Color.SeaGreen;
            });
        };
        apply.Click+=async (_,_) =>
        {
            if(!apply.Enabled || approved is not { } plan || !TryTarget(out var identity) ||
                approvedIdentity!=identity || recovery.Text.Trim()!=plan.Sha) return;
            if(!ConfirmDestructive("Apply primary Postfix single-mailbox route",
                TargetDescription(identity)+Environment.NewLine+
                "Recovery SHA-256: "+plan.Sha+Environment.NewLine+
                "This changes main.cf and master.cf and affects ALL mail using the default/relay outbound transport. "+
                "From and envelope sender will be rewritten. Approve fresh SMTP AUTH without message submission, "+
                "exact backup and the two-file transition. Keep Postfix stopped. Do not use a production host before acceptance testing.",
                PrimaryMailboxOfflineClient.Apply,dialog)) return;
            await RunAsync("Repeating the review and applying the offline route...",async () =>
            {
                if(!TryTarget(out var current) || current!=identity || approved?.Sha!=plan.Sha ||
                    recovery.Text.Trim()!=plan.Sha) throw new InvalidOperationException("Approval context changed.");
                Guard();
                ClearReview();ClearInspection();
                mutationAttempted=true;
                WriteLine("Primary mailbox offline Apply requested. Recovery SHA-256: "+plan.Sha+
                    ". Keep Postfix stopped until inspected.");
                await LinuxAsync("apply",identity,plan.Sha,PrimaryMailboxOfflineClient.Apply,PrimaryMailboxOfflineClient.Auth);
                report.Text="Applied offline; Postfix remains stopped."+Environment.NewLine+
                    "Recovery: /var/lib/linuxmailrelay365-primary-mailbox-recovery/"+plan.Sha+
                    Environment.NewLine+"Inspect backup to verify the exact current pair. "+
                    "Native postfix check and service start are separate administrator tasks; delivery remains unverified.";
                status.Text="Applied offline. Inspect backup before any further action.";
                status.ForeColor=Color.SeaGreen;
            });
        };
        inspect.Click+=async (_,_) =>
        {
            if(!inspect.Enabled) return;
            string sha=recovery.Text.Trim();
            ClearReview();ClearInspection();Update();
            await RunAsync("Inspecting exact recovery pair and maintenance state...",async () =>
            {
                var result=await LinuxAsync("inspect-backup",null,sha,null);
                inspectedSha=sha;inspectedPhase=result.Phase;
                report.Text="Recovery SHA-256: "+sha+Environment.NewLine+
                    "Observed phase: "+result.Phase+Environment.NewLine+
                    (result.Phase switch {
                        "before"=>"Original pair and native snapshot observed. Restore is not necessary.",
                        "after"=>"Applied pair and native snapshot observed. No delivery or service-start authorization.",
                        _=>"Interrupted pair: original main.cf, new master.cf. Do not start Postfix. Restore is available."
                    });
                status.Text="Recovery phase observed; no configuration change.";
                status.ForeColor=result.Phase=="pipe_only"?Color.DarkOrange:Color.SeaGreen;
            });
        };
        verifyApplied.Click+=async (_,_) =>
        {
            if(!verifyApplied.Enabled || inspectedSha is not { } sha || inspectedPhase!="after" ||
                recovery.Text.Trim()!=sha || !TryTarget(out var identity)) return;
            ClearVerified();Update();
            if(!ConfirmDestructive("Reverify applied primary mailbox",
                TargetDescription(identity)+Environment.NewLine+"Recovery SHA-256: "+sha+Environment.NewLine+
                "Recheck the exact applied configuration and original installed runtime, with fresh SMTP AUTH. "+
                "No service start, configuration change or message submission.",
                PrimaryMailboxOfflineClient.Auth,dialog)) return;
            await RunAsync("Rechecking applied configuration and SMTP AUTH...",async () =>
            {
                if(inspectedSha!=sha || inspectedPhase!="after" || recovery.Text.Trim()!=sha ||
                    !TryTarget(out var current) || current!=identity)
                    throw new InvalidOperationException("Verification context changed.");
                var result=await LinuxAsync("verify-applied",identity,sha,PrimaryMailboxOfflineClient.Auth);
                verifiedApplied=result;verifiedIdentity=identity;
                report.Text=TargetDescription(identity)+Environment.NewLine+"Recovery SHA-256: "+sha+
                    Environment.NewLine+"Runtime SHA-256: "+result.RuntimeSha+
                    Environment.NewLine+"Applied pair, native snapshot and original runtime reverified. Fresh no-mail SMTP AUTH observed."+
                    Environment.NewLine+"Postfix remains stopped. Check / Start requires separate approval; delivery remains unverified.";
                status.Text="Applied route reverified offline; service start and delivery not tested.";
                status.ForeColor=Color.SeaGreen;
            });
        };
        start.Click+=async (_,_) =>
        {
            if(!start.Enabled || verifiedApplied is not { } evidence || !TryTarget(out var identity) ||
                verifiedIdentity!=identity || inspectedPhase!="after" || inspectedSha!=evidence.Sha ||
                recovery.Text.Trim()!=evidence.Sha) return;
            if(!ConfirmDestructive("Check and start primary Postfix",
                TargetDescription(identity)+Environment.NewLine+"Recovery SHA-256: "+evidence.Sha+Environment.NewLine+
                "Keep all external and local submissions blocked. This repeats fresh SMTP AUTH and "+
                "runs native postfix check (may repair metadata), then starts postfix.service. "+
                "Existing listeners may become active. Queue activity and delivery are not verified. "+
                "A timeout may leave the service running; no automatic stop or rollback will be attempted. "+
                "Use only on a controlled test host until acceptance is complete.",
                PrimaryMailboxOfflineClient.Start,dialog)) return;
            await RunAsync("Rechecking the reviewed route, native Postfix check and controlled startup...",async () =>
            {
                if(verifiedApplied!=evidence || verifiedIdentity!=identity || !TryTarget(out var current) ||
                    current!=identity || recovery.Text.Trim()!=evidence.Sha || inspectedPhase!="after" ||
                    inspectedSha!=evidence.Sha) throw new InvalidOperationException("Startup approval changed.");
                Guard();
                // Mark before SSH: a lost response cannot prove the service did not start.
                startAttempted=true;
                mutationAttempted=true;
                ClearReview();ClearInspection();Update();
                WriteLine("Primary mailbox controlled Start requested. Recovery SHA-256: "+evidence.Sha+
                    ". Service and queue state must be checked after any uncertainty.");
                var result=await LinuxAsync("start",identity,evidence.Sha,PrimaryMailboxOfflineClient.Start,PrimaryMailboxOfflineClient.Auth);
                if(result.RuntimeSha!=evidence.RuntimeSha)
                    throw new InvalidDataException("Startup runtime receipt differs from the verified runtime.");
                report.Text=TargetDescription(identity)+Environment.NewLine+"Recovery SHA-256: "+result.Sha+
                    Environment.NewLine+"Runtime SHA-256: "+result.RuntimeSha+
                    Environment.NewLine+"Native check, active service and applied configuration observed."+
                    Environment.NewLine+"No delivery test; external submissions and queue activity not verified."+
                    Environment.NewLine+"Close and rediscover. Offline operations remain locked.";
                status.Text="Postfix running observed; actual mail delivery not verified.";
                status.ForeColor=Color.SeaGreen;
            });
        };
        restore.Click+=async (_,_) =>
        {
            if(!restore.Enabled || inspectedSha is not { } sha || recovery.Text.Trim()!=sha ||
                inspectedPhase is not ("after" or "pipe_only")) return;
            string phase=inspectedPhase;
            if(!ConfirmDestructive("Restore original primary Postfix configuration",
                "Host: "+endpoint.Host+":"+endpoint.Port+Environment.NewLine+
                "Recovery SHA-256: "+sha+Environment.NewLine+"Observed phase: "+phase+Environment.NewLine+
                "Restore the exact backed-up main.cf and master.cf. No Microsoft 365 authentication required. "+
                "Unrelated changes will be refused. Keep Postfix stopped.",
                PrimaryMailboxOfflineClient.Restore,dialog)) return;
            await RunAsync("Restoring the verified original configuration...",async () =>
            {
                if(inspectedSha!=sha || inspectedPhase!=phase || recovery.Text.Trim()!=sha)
                    throw new InvalidOperationException("Recovery selection changed.");
                Guard();
                ClearReview();ClearInspection();
                mutationAttempted=true;
                WriteLine("Primary mailbox offline Restore requested. Recovery SHA-256: "+sha);
                await LinuxAsync("restore",null,sha,PrimaryMailboxOfflineClient.Restore);
                report.Text="Original configuration pair restored and native readback verified."+Environment.NewLine+
                    "Recovery SHA-256: "+sha+Environment.NewLine+"Postfix remains stopped. Reinspect before administrator start.";
                status.Text="Restore verified. Service not started.";
                status.ForeColor=Color.SeaGreen;
            });
        };
        foreach(var field in new[]{sender,tenantInput,appInput})
            field.TextChanged+=(_,_)=>{ClearReview();Update();};
        recovery.TextChanged+=(_,_)=>{ClearReview();ClearInspection();Update();};
        maintenance.CheckedChanged+=(_,_)=>{ClearReview();ClearInspection();Update();};
        copy.Click+=(_,_)=>{
            if(!copy.Enabled) return;
            try { Clipboard.SetText(recovery.Text.Trim()); }
            catch(System.Runtime.InteropServices.ExternalException) { status.Text="Clipboard unavailable; copy the SHA manually."; }
        };
        dialog.FormClosing+=(_,e)=>{if(busy)e.Cancel=true;};
        layout.Controls.Add(intro,0,0);layout.Controls.Add(inputs,0,1);
        layout.Controls.Add(maintenance,0,2);layout.Controls.Add(recoveryPanel,0,3);
        layout.Controls.Add(status,0,4);layout.Controls.Add(report,0,5);layout.Controls.Add(actions,0,6);
        dialog.Controls.Add(layout);dialog.CancelButton=close;Update();
        try { dialog.ShowDialog(this); }
        finally
        {
            if(mutationAttempted)
            {
                // Allow inspection/restore in the bound modal session, then
                // invalidate prior discovery for other application workflows.
                discoveredMailIdentity=null;
                inspectedServerIdentity=null;
                existingSmtpAuditIdentity=null;
                inspectedHostIdentity=null;
            }
        }
        return Task.CompletedTask;
    }
}
