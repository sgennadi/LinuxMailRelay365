using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private void ClearSidecarRestoreReview()
    {
        reviewedSidecarRestoreSha = null;
        reviewedSidecarRestoreId = null;
        reviewedSidecarRestoreIdentity = null;
    }

    private void ClearArchiveSelections()
    {
        postfixBackupListIdentity = null;
        sidecarBackupListIdentity = null;
        foreignBackupListContext = null;
        sidecarBackupTotal = 0;
        archiveDetailsExpanded = false;
        ClearSidecarRestoreReview();
        backupSelector.Items.Clear();
        foreignBackupSelector.Items.Clear();
        sidecarBackupSelector.Items.Clear();
    }

    private SshEndpoint RequireSameArchiveConnection(SshEndpoint initial, bool allowFirstPin = false)
    {
        var current = Endpoint();
        if (!SameRollbackConnection(initial, current) ||
            (initial.HostKeySha256 != current.HostKeySha256 &&
             !(allowFirstPin && initial.HostKeySha256.Length == 0 && current.HostKeySha256.Length > 0)) ||
            (current.Password.Length > 0 && current.HostKeySha256.Length == 0))
            throw new InvalidOperationException("SSH connection or trusted host key changed during archive operation.");
        return current;
    }

    private static string RequireArchiveSelection(ComboBox selector, string? listIdentity, SshEndpoint endpoint)
    {
        if (listIdentity != SecurityOptionsStore.Identity(endpoint) || selector.SelectedItem is not string id ||
            !VerifiedArchiveListing.ValidId(id))
            throw new InvalidOperationException("List verified archives on this server and explicitly select one.");
        return id;
    }

    private async Task VerifySelectedPostfixArchiveAsync()
    {
        RequirePostfixBackup();
        var endpoint = Endpoint();
        string id = RequireArchiveSelection(backupSelector, postfixBackupListIdentity, endpoint);
        var result = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildRecoveryBundle("--verify", id), TimeSpan.FromMinutes(3));
        result.EnsureSuccess();
        var current = RequireSameArchiveConnection(endpoint);
        RequirePostfixBackup();
        if (RequireArchiveSelection(backupSelector, postfixBackupListIdentity, current) != id ||
            result.StdOut.Replace("\r\n", "\n").Split('\n').Count(x => x == "BACKUP_STATUS=verified") != 1)
            throw new InvalidDataException("Postfix archive verification or selection could not be confirmed.");
        WriteLine("Selected Postfix archive verified on current host: " + id + ". No Restore authorized.");
    }

    private void ShowArchiveChoice(TableLayoutPanel page, ComboBox selector, bool currentList, int total)
    {
        if (!currentList)
        {
            AddLine(page, UiTheme.Text(T("Сначала получите список архивов для этого сервера.",
                "List verified archives for this server first.", "תחילה יש להציג גיבויים בשרת זה.")));
            return;
        }
        if (selector.Items.Count == 0)
        {
            AddLine(page, UiTheme.Text(T("Проверенных архивов не найдено.",
                "No verified archives found.", "לא נמצאו גיבויים מאומתים.")));
            return;
        }
        AddLine(page, UiTheme.Text(T("Выберите архив явно (дата и время UTC)",
            "Explicitly select an archive (date and time UTC)", "בחרו גיבוי במפורש (זמן UTC)")));
        AddLine(page, selector);
        AddLine(page, UiTheme.Text(T("Показано архивов: ", "Archives listed: ", "גיבויים ברשימה: ") +
            selector.Items.Count + " / " + total));
        if (selector.SelectedItem is not string)
            AddLine(page, UiTheme.Text(T("После выбора появятся проверки и допустимые действия.",
                "Checks and available actions appear after selection.", "לאחר בחירה יופיעו הבדיקות והפעולות.")));
    }

    private void InvalidateAfterArchiveWrite()
    {
        // A failed/timeout response does not prove that no changes occurred.
        InvalidateAfterSendmailV2Write();
        ClearArchiveSelections();
        ClearNativeRecoverySample();
    }
}
