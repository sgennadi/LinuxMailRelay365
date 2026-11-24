using System.Drawing;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private SshEndpoint RequireSameSendmailReviewContext(SshEndpoint initial, string identity, string id)
    {
        var current = Endpoint();
        if (!SameRollbackConnection(initial, current) ||
            (initial.HostKeySha256.Length > 0 && initial.HostKeySha256 != current.HostKeySha256) ||
            (current.Password.Length > 0 && current.HostKeySha256.Length == 0) ||
            identity != TryCurrentIdentity() || ConfirmedForeignBackupMta(allowStopped: true) != "sendmail" ||
            foreignBackupListContext != identity + "|sendmail" ||
            foreignBackupSelector.SelectedItem is not string selected || selected != id)
            throw new InvalidOperationException("SSH connection, trusted host key, MTA or selected archive changed during Sendmail review.");
        return current;
    }

    // Return false only for a freshly verified legacy v1 archive. All v2 errors fail closed.
    private async Task<bool> TryPreviewSendmailV2Async(SshEndpoint endpoint, string identity, string id)
    {
        var verified = await SshRemote.RunRootScriptAsync(endpoint,
            EmbeddedAssets.BuildForeignMtaBackupBundle("sendmail", "verify", id), TimeSpan.FromMinutes(3));
        verified.EnsureSuccess();
        var reviewed = RequireSameSendmailReviewContext(endpoint, identity, id);
        if (!ForeignBackupReportOk(verified.StdOut, "sendmail", "verified"))
            throw new InvalidDataException("Selected Sendmail archive verification failed.");
        var hashes = Regex.Matches(verified.StdOut, @"(?m)^FOREIGN_BACKUP_ARCHIVE_SHA256=([a-f0-9]{64})\r?$");
        if (hashes.Count != 1)
            throw new InvalidDataException("Missing or duplicate Sendmail archive digest.");
        string format = ParseForeignBackupFormat(verified.StdOut, "sendmail");
        if (format == "v1_regular_files") return false;

        var result = await SshRemote.RunRootScriptAsync(reviewed,
            EmbeddedAssets.BuildSendmailV2ReviewBundle(id), TimeSpan.FromMinutes(5));
        result.EnsureSuccess();
        var plan = SendmailV2Review.Parse(result.StdOut, id, hashes[0].Groups[1].Value);
        var current = RequireSameSendmailReviewContext(reviewed, identity, id);
        if (current.HostKeySha256 != reviewed.HostKeySha256)
            throw new InvalidOperationException("SSH host key changed during Sendmail v2 review.");

        string summary = "Host: " + current.Host + ":" + current.Port + "\nSnapshot: " + id +
            "\n" + T("Файлов в архиве", "Files in archive", "קבצים בגיבוי") + ": " + plan.FileCount +
            "\n" + T("Изменённых файлов sendmail.cf / submit.cf", "Changed sendmail.cf / submit.cf", "שינויים בקובצי sendmail.cf / submit.cf") +
            ": " + plan.CompiledChanged + "/" + plan.CompiledTargets + " (2 expected)" +
            "\n" + T("Другие изменённые файлы", "Other changed files", "קבצים אחרים ששונו") + ": " + plan.OtherChanged +
            "\n" + T("Отсутствующие / лишние", "Missing / extra", "חסרים / נוספים") + ": " + plan.Missing + " / " + plan.Extra +
            "\n" + T("Изменения владельца/прав", "Owner/permission changes", "שינויי בעלות והרשאות") + ": " + plan.MetadataChanged +
            "\n" + T("Изменения каталогов/ссылок", "Directory/symlink drift", "שינויי תיקיות וקישורים") + ": " + plan.ObjectDrift +
            "\n\nService: " + plan.Service + "\nProcesses: " + plan.Processes +
            "\nQueue: " + plan.Queue + "\nListener: " + plan.Listener + "\nOffline gate: " + plan.OfflineGate +
            "\nReview gate: " + plan.Gate + "\n\nArchive SHA-256: " + plan.ArchiveSha +
            "\nManifest SHA-256: " + plan.ManifestSha + "\nPlan SHA-256: " + plan.PlanSha;
        string heading = plan.IsCandidate
            ? T("Кандидат для ручного восстановления — запись запрещена", "Manual recovery candidate — writes not authorized", "מועמד לשחזור ידני בלבד")
            : T("Восстановление заблокировано — проверьте причины", "Recovery blocked — review the evidence", "השחזור חסום — יש לבדוק את הנתונים");

        // Use a resizable, selectable report with a fixed footer; no Apply control.
        using var dialog = new Form
        {
            Text = "LinuxMailRelay365 | Sendmail v2",
            StartPosition = FormStartPosition.CenterParent,
            AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = new Size(760, 510),
            MinimumSize = new Size(430, 320),
            ShowInTaskbar = false,
            MinimizeBox = false
        };
        Rectangle area = Screen.FromControl(this).WorkingArea;
        dialog.Size = new Size(Math.Min(dialog.Width, area.Width), Math.Min(dialog.Height, area.Height));
        var header = UiTheme.Emphasis(heading, 700, warning: !plan.IsCandidate);
        header.Dock = DockStyle.Top;
        var report = new TextBox
        {
            Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
            ScrollBars = ScrollBars.Vertical, WordWrap = true, Text = summary + "\n\n" +
                T("Только чтение. Нет изменений конфигурации, очереди или службы. Не запускайте MTA на основании этого отчёта.",
                    "Read-only. No configuration, queue or service changes. This report does not authorize starting the MTA.",
                    "לקריאה בלבד; אין שינוי תצורה, תור או שירות. הדוח אינו אישור להפעלת שירות.")
        };
        var footer = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(6) };
        var close = new Button { Text = T("Закрыть", "Close", "סגור"), AutoSize = true, DialogResult = DialogResult.OK };
        footer.Controls.Add(close);
        dialog.Controls.Add(report);
        dialog.Controls.Add(footer);
        dialog.Controls.Add(header);
        dialog.AcceptButton = close;
        dialog.CancelButton = close;
        WriteLine("Sendmail v2 read-only review: " + plan.Gate + ", compiled changes=" + plan.CompiledChanged +
            ", plan SHA256=" + plan.PlanSha + ". No Apply authorized.");
        dialog.ShowDialog(this);
        return true;
    }
}
