using System.Diagnostics;
using System.Text;
using System.Windows.Forms;
using Microsoft365Auth;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    // Separate from the main Objects Manager: never fill or overwrite the
    // global tenant/app/mailbox fields to perform a row-specific audit.
    private async Task<CloudObjectsInventory> QueryMultiMailboxCloudAsync(
        MultiMailboxCloudSelection selection, Form owner, Guid bootstrap, Action validateContext)
    {
        var row = selection.Row;
        if (row.Tenant is not Guid tenantId || row.Client is not Guid clientId ||
            tenantId == Guid.Empty || clientId == Guid.Empty ||
            !InstalledPostfixRoute.ValidAddress(row.Mailbox))
            throw new InvalidDataException("Select a verified mailbox identity first.");
        validateContext();
        var graph = await WithNativeMicrosoftSignInAsync((show, ct) =>
            EntraGraphInventoryClient.InspectAsync(tenantId, clientId, bootstrap, show, ct),
            signInOwner: owner);
        validateContext();
        if (graph.ClientId != clientId || graph.AppObjectId == Guid.Empty)
            throw new InvalidDataException("Graph returned a different application.");
        var keys = graph.Certificates.Select(c => new CloudCredentialObject(c.KeyId, c.Label,
            c.Type, c.Usage, c.ValidFrom, c.ValidUntil, c.CertificateSha256)).ToArray();
        if (keys.GroupBy(c => c.KeyId).Any(g => g.Count() != 1))
            throw new InvalidDataException("Duplicate Graph credential IDs.");

        CloudSmtpMailboxAudit? mailboxAudit = null;
        if (graph.EnterpriseStatus == "found" && graph.EnterpriseObjectId is Guid enterprise &&
            enterprise != Guid.Empty)
        {
            // A separate private report path avoids mixing results from
            // concurrent application instances. The EXO-only script does not
            // enumerate connectors/scopes/assignments in MailboxOnly mode.
            string work = Path.Combine(dataDirectory, "mailbox-audit-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);
            string script = Path.Combine(work, "Inspect-LinuxMailRelay365Objects.ps1");
            string report = Path.Combine(work, "result.json");
            try
            {
                await File.WriteAllTextAsync(script, EmbeddedAssets.CloudObjectsInspector, new UTF8Encoding(false));
                validateContext();
                var psi = new ProcessStartInfo("pwsh.exe") { UseShellExecute = true, WorkingDirectory = work };
                foreach (string item in new[] { "-NoLogo", "-NoProfile", "-File", script,
                    "-MailboxOnly", "-TenantId", tenantId.ToString("D"), "-ClientId", clientId.ToString("D"),
                    "-EnterpriseObjectId", enterprise.ToString("D"), "-Mailbox", row.Mailbox, "-ResultPath", report })
                    psi.ArgumentList.Add(item);
                WriteLine("Selected mailbox: Exchange-only read audit. Sign in to the tenant shown in the selected row.");
                using var process = Process.Start(psi) ?? throw new IOException("PowerShell 7 did not start.");
                using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(12));
                try { await process.WaitForExitAsync(timeout.Token); }
                catch (OperationCanceledException)
                {
                    // Only our own read-only PowerShell process, not its
                    // browser or unrelated processes, may be stopped.
                    try { if (!process.HasExited) process.Kill(); }
                    catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
                    throw new IOException("Exchange read-only sign-in expired. No result accepted.");
                }
                validateContext();
                if (process.ExitCode != 0 || !File.Exists(report) || new FileInfo(report).Length > 1200000)
                    throw new IOException("Exchange mailbox audit unavailable. Check the selected tenant and read permissions.");
                var exchange = CloudObjectsInventory.Parse(await File.ReadAllTextAsync(report),
                    tenantId, clientId, row.Mailbox, enterprise);
                if (exchange.Connectors.Count != 0 || exchange.Scopes.Count != 0 || exchange.RoleAssignments.Count != 0 ||
                    exchange.Certificates.Count != 0 || exchange.ApplicationStatus != "not_selected" ||
                    exchange.ServicePrincipalStatus != "not_selected")
                    throw new InvalidDataException("Unexpected non-mailbox inventory.");
                mailboxAudit = exchange.MailboxAudit ??
                    throw new InvalidDataException("Missing exact mailbox audit.");
                validateContext();
            }
            finally
            {
                // Only known files belonging to this one read operation.
                try { File.Delete(report); File.Delete(script); Directory.Delete(work); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    WriteLine("Mailbox audit temporary report cleanup incomplete; review local application data.");
                }
            }
        }
        else if (graph.EnterpriseStatus != "unverified" || graph.EnterpriseObjectId is not null)
            throw new InvalidDataException("Inconsistent Graph Enterprise Application evidence.");

        validateContext();
        return new CloudObjectsInventory(tenantId, clientId, "found", graph.AppObjectId, graph.DisplayName,
            graph.EnterpriseStatus, graph.EnterpriseObjectId, keys, [], [], [], mailboxAudit);
    }
}
