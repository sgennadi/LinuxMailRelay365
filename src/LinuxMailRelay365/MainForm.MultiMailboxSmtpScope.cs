using System.Diagnostics;
using System.Text;
using System.Windows.Forms;
using Microsoft365Auth;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private async Task<MultiMailboxSmtpScopePlan> RunMailboxSmtpScopeAsync(MultiMailboxSmtpScopeRequest req,
        MultiMailboxSmtpScopePlan? approved, Action validate)
    {
        if (!req.Valid || (approved is not null && !approved.ChangesNeeded)) throw new InvalidDataException("Invalid scoped operation.");
        validate();
        string work = Path.Combine(dataDirectory,"smtp-scope-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        string script = Path.Combine(work,"Manage-LinuxMailRelay365MailboxScope.ps1"), report = Path.Combine(work,"result.json");
        try
        {
            await File.WriteAllTextAsync(script,EmbeddedAssets.MultiMailboxSmtpScopeManager,new UTF8Encoding(false));
            validate();
            var psi = new ProcessStartInfo("pwsh.exe") { UseShellExecute=true, WorkingDirectory=work };
            foreach (string arg in new[] {"-NoLogo","-NoProfile","-File",script,"-Phase",approved is null ? "Preview" : "Apply",
                "-TenantId",req.Tenant.ToString("D"),"-ClientId",req.Client.ToString("D"),"-EnterpriseObjectId",req.Enterprise.ToString("D"),
                "-Mailbox",req.Mailbox,"-Nonce",req.Nonce,"-ResultPath",report}) psi.ArgumentList.Add(arg);
            if (req.EnableMailboxSmtp) psi.ArgumentList.Add("-EnableMailboxSmtp");
            if (approved is not null)
                foreach (string arg in new[] {"-ExpectedSha256",approved.PlanSha,"-TypedConfirmation",MultiMailboxSmtpScopeRequest.Confirmation})
                    psi.ArgumentList.Add(arg);
            using var process = Process.Start(psi) ?? throw new IOException("PowerShell 7 did not start.");
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(12));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException)
            {
                try { if (!process.HasExited) process.Kill(); }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
                throw new IOException("Exchange session timed out; review actual configuration before retry.");
            }
            validate();
            if (process.ExitCode != 0 || !File.Exists(report) || new FileInfo(report).Length > 16384)
                throw new IOException("Exchange scoped operation refused or requires review.");
            return MultiMailboxSmtpScopePlan.Parse(await File.ReadAllTextAsync(report),req,approved);
        }
        finally
        {
            try { File.Delete(report); File.Delete(script); Directory.Delete(work); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { WriteLine("Scoped mailbox operation temporary report cleanup incomplete."); }
        }
    }

    private async Task<Guid> ReadScopeEnterpriseAsync(MultiMailboxIdentityRow row, Guid bootstrap, Form owner, Action validate)
    {
        validate();
        if (row.Status != "public_certificate_read" || row.Tenant is not Guid tenantId || row.Client is not Guid clientId)
            throw new InvalidDataException("Verified local public certificate required.");
        var graph = await WithNativeMicrosoftSignInAsync((show,ct) =>
            EntraGraphInventoryClient.InspectAsync(tenantId,clientId,bootstrap,show,ct), signInOwner:owner);
        validate();
        var now=DateTimeOffset.UtcNow;
        if (graph.ClientId != clientId || graph.AppObjectId == Guid.Empty ||
            graph.EnterpriseStatus != "found" || graph.EnterpriseObjectId is not Guid enterprise || enterprise == Guid.Empty ||
            !graph.Certificates.Any(k => k.Type == "AsymmetricX509Cert" && k.Usage == "Verify" &&
                k.CertificateSha256 == row.CertificateSha && k.ValidFrom <= now && k.ValidUntil > now))
            throw new InvalidDataException("Exact application, Enterprise ID and valid registered local certificate required.");
        return enterprise;
    }
}
