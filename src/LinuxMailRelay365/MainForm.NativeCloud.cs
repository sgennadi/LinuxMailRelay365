using Microsoft.Identity.Client;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private Guid ApprovedGraphPublicClientId()
    {
        string raw = entraSignInClientId.Text.Trim();
        if (raw.Length == 0)
            return Microsoft365Auth.EntraTenantDiscoveryClient.DefaultGraphClientId;
        if (!Guid.TryParse(raw, out var id) || id == Guid.Empty)
            throw new ArgumentException(
                "Enter the approved Microsoft Graph public Client ID as a GUID.");
        return id;
    }

    /// <summary>Reusable WinForms Device Code interaction for Graph and ARM C# calls.</summary>
    private async Task<T> WithNativeMicrosoftSignInAsync<T>(
        Func<Func<DeviceCodeResult, Task>, CancellationToken, Task<T>> operation,
        bool mayModifyEntra = false)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(12));
        using var dialog = new NativeDeviceCodeDialog(cancellation.Cancel);

        async Task ShowDeviceCodeAsync(DeviceCodeResult deviceCode)
        {
            var displayed = new TaskCompletionSource<bool>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            void OnUiThread()
            {
                try
                {
                    if (IsDisposed || cancellation.IsCancellationRequested)
                        throw new OperationCanceledException("Sign-in cancelled.");
                    dialog.Present(deviceCode, this);
                    displayed.TrySetResult(true);
                }
                catch (Exception ex) { displayed.TrySetException(ex); }
            }
            if (InvokeRequired)
            {
                try { BeginInvoke((Action)OnUiThread); }
                catch (InvalidOperationException) { cancellation.Cancel(); throw; }
            }
            else OnUiThread();
            await displayed.Task;
        }

        try { return await operation(ShowDeviceCodeAsync, cancellation.Token); }
        catch (Microsoft365Auth.EntraDiscoveryException ex)
        {
            // Only allowlisted reason codes are displayed; never print tenant
            // challenge bodies, usernames, OAuth token or sign-in URL parameters.
            WriteLine("Native Microsoft Entra operation failed (" + ex.Code +
                "). " + (mayModifyEntra
                    ? "Entra App Registration or certificate MAY ALREADY HAVE CHANGED. " +
                      "Review the exact application before retrying; no automatic deletion."
                    : "This was a read-only operation; no cloud settings were changed."));
            throw new IOException("Microsoft Entra C# operation failed (" + ex.Code +
                "). " + (mayModifyEntra
                    ? "Review potentially partial Entra changes before retrying."
                    : "Verify delegated client permissions or use manual Tenant ID."));
        }
        finally { dialog.Finish(); }
    }
}
