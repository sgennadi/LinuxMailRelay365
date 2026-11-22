using Microsoft.Identity.Client;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    /// <summary>Reusable WinForms Device Code interaction for Graph and ARM C# calls.</summary>
    private async Task<T> WithNativeMicrosoftSignInAsync<T>(
        Func<Func<DeviceCodeResult, Task>, CancellationToken, Task<T>> operation)
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
                "). Cloud settings unchanged by this read-only operation.");
            throw new IOException("Microsoft Entra C# operation failed (" + ex.Code +
                "). Verify client permissions or use the manual fallback.");
        }
        finally { dialog.Finish(); }
    }
}
