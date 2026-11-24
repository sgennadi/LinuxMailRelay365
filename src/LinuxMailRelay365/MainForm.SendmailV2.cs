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

        ShowSendmailV2ReviewReport(current, id, plan);
        return true;
    }

    // A single read-only report is shared by Preview and a refused write.
    // It has no approval control and cannot dispatch Linux operations.
    private void ShowSendmailV2ReviewReport(SshEndpoint current, string id, SendmailV2Review plan)
    {
        var guidance = SendmailRecoveryGuidance.From(plan);
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
        string heading = guidance.Disposition switch
        {
            SendmailRecoveryDisposition.SeparateApprovalRequired => T(
                "Проверки пройдены — требуется отдельное подтверждение Restore",
                "Checks passed — separate Restore approval required", "הבדיקות עברו — נדרש אישור שחזור נפרד"),
            SendmailRecoveryDisposition.NoChanges => T(
                "Изменений для восстановления нет", "No compiled configuration changes to restore", "אין שינויי תצורה לשחזור"),
            _ => T("Восстановление заблокировано", "Restore blocked", "השחזור חסום")
        };
        string next = guidance.Disposition switch
        {
            SendmailRecoveryDisposition.SeparateApprovalRequired => T(
                "На остановленном тестовом сервере выберите отдельное действие Restore; оно заново проверит план и запросит подтверждение.",
                "On a stopped disposable test host, use the separate Restore action. It rechecks the plan and requires explicit confirmation.",
                "בשרת בדיקה עצור בחרו בפעולת שחזור נפרדת; התוכנית תיבדק מחדש ויידרש אישור."),
            SendmailRecoveryDisposition.NoChanges => T(
                "Оба файла уже совпадают с архивом. Запись не требуется.",
                "Both compiled files already match the archive. No write is necessary.",
                "שני קובצי התצורה כבר תואמים לגיבוי. אין צורך בכתיבה."),
            _ => string.Join("\r\n\r\n", guidance.Reasons.Select(reason => "• " + SendmailRecoveryReason(reason)))
        };
        var workArea = Screen.FromControl(this).WorkingArea.Size;
        using var dialog = new Form
        {
            Text = "LinuxMailRelay365 | Sendmail v2 Restore Plan",
            StartPosition = FormStartPosition.CenterParent,
            AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = PreferredDialogSize(workArea, DeviceDpi, 860, 680),
            MinimumSize = PreferredDialogSize(workArea, DeviceDpi, 480, 350),
            BackColor = UiTheme.Canvas, ForeColor = UiTheme.Navy,
            Font = new Font("Segoe UI", 10f),
            ShowInTaskbar = false, MinimizeBox = false,
            FormBorderStyle = FormBorderStyle.Sizable
        };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3,
            Padding = new Padding(12) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var header = UiTheme.Emphasis(heading, Math.Max(240, dialog.ClientSize.Width - 40),
            warning: guidance.Disposition == SendmailRecoveryDisposition.Blocked,
            success: guidance.Disposition == SendmailRecoveryDisposition.SeparateApprovalRequired);
        header.Dock = DockStyle.Fill;
        var report = new TextBox
        {
            Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
            ScrollBars = ScrollBars.Vertical, WordWrap = true,
            AccessibleName = T("План и причины восстановления", "Restore plan and reasons", "תוכנית וסיבות לשחזור"),
            Text = T("Следующие действия", "Next steps", "הצעדים הבאים") + "\r\n" + next + "\r\n\r\n" +
                T("Детали проверок", "Verification details", "פרטי הבדיקות") + "\r\n" +
                summary.Replace("\n", "\r\n") + "\r\n\r\n" + T(
                    "Только чтение. Нет изменений конфигурации, очереди или службы. Не запускайте MTA на основании этого отчёта.",
                    "Read-only. No configuration, queue or service changes. This report does not authorize starting the MTA.",
                    "לקריאה בלבד; אין שינוי תצורה, תור או שירות. הדוח אינו אישור להפעלת שירות.")
        };
        var footer = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft, WrapContents = true, Padding = new Padding(4) };
        var close = UiTheme.Action(T("Закрыть", "Close", "סגור"), false, "back");
        close.DialogResult = DialogResult.OK;
        footer.Controls.Add(close);
        layout.Controls.Add(header, 0, 0);
        layout.Controls.Add(report, 0, 1);
        layout.Controls.Add(footer, 0, 2);
        dialog.Controls.Add(layout);
        dialog.ClientSizeChanged += (_, _) =>
            header.MaximumSize = new Size(Math.Max(240, layout.ClientSize.Width - layout.Padding.Horizontal - 12), 0);
        dialog.AcceptButton = close;
        dialog.CancelButton = close;
        WriteLine("Sendmail v2 read-only review: " + plan.Gate + ", compiled changes=" + plan.CompiledChanged +
            ", reasons=" + string.Join(",", guidance.Reasons) + ", plan SHA256=" + plan.PlanSha + ". No Apply authorized.");
        dialog.ShowDialog(this);
    }

    private string SendmailRecoveryReason(string reason) => reason switch
    {
        "service_running" => T(
            "Sendmail или клиентская служба активна. Согласуйте остановку на тестовом сервере, затем повторите проверку.",
            "Sendmail or its client service is active. Arrange a controlled stop on the test host, then repeat the review.",
            "שירות Sendmail או שירות הלקוח פעיל. יש לתאם עצירה בשרת בדיקה ולבדוק שוב."),
        "service_unknown" => T(
            "Состояние службы не подтверждено. Проверьте systemctl для sendmail и sm-client; не считайте неизвестное состояние остановкой.",
            "Service state is unverified. Inspect systemctl status for sendmail and sm-client; unknown is not stopped.",
            "מצב השירות לא אומת. יש לבדוק את sendmail ו-sm-client באמצעות systemctl."),
        "process_running" => T(
            "Обнаружен процесс Sendmail. Дождитесь штатного завершения всех процессов; не выполняйте принудительное завершение из этого окна.",
            "A Sendmail process is present. Arrange a clean shutdown and recheck; this dialog does not kill processes.",
            "זוהה תהליך Sendmail. יש לבצע עצירה מסודרת ולבדוק שוב."),
        "process_unknown" => T(
            "Не удалось подтвердить отсутствие процессов. Проверьте доступность pgrep и состояние MTA.",
            "Process absence could not be verified. Check pgrep availability and the native MTA state.",
            "לא ניתן לאמת שאין תהליכים. בדקו את pgrep ואת מצב MTA."),
        "queue_nonempty" => T(
            "Почтовая очередь не пуста. Сохраните сообщения и согласуйте штатную обработку очереди; не удаляйте её для прохождения проверки.",
            "A mail queue is not empty. Preserve messages and arrange normal queue handling; never delete mail to pass this check.",
            "התור אינו ריק. יש לשמור את ההודעות ולטפל בתור באופן מסודר, ללא מחיקה."),
        "queue_unknown" => T(
            "Нельзя подтвердить обе очереди. Проверьте нативный Sendmail, разрешение полного имени сервера (FQDN), команды sendmail -bp и sendmail -Ac -bp. Тайм-аут не означает пустую очередь.",
            "Both queues could not be verified. Check the native Sendmail binary, local FQDN resolution, sendmail -bp and sendmail -Ac -bp. A timeout is not an empty queue.",
            "לא ניתן לאמת את שני התורים. בדקו את Sendmail המקורי, פתרון FQDN ואת פקודות בדיקת התור. פסק זמן אינו תור ריק."),
        "listener_running" => T(
            "Sendmail продолжает принимать соединения. Проверьте все его SMTP-порты и остановку службы.",
            "Sendmail still owns a listener. Inspect its actual SMTP ports and service shutdown.",
            "Sendmail עדיין מאזין. בדקו את יציאות SMTP ואת עצירת השירות."),
        "listener_unknown" => T(
            "Отсутствие SMTP-слушателей не подтверждено. Проверьте ss -ltnp, включая другие MTA и пользовательские порты; ничего не останавливайте автоматически.",
            "SMTP listener absence is unverified. Inspect ss -ltnp, including other MTAs and custom ports; do not automatically stop unrelated services.",
            "לא אומת שאין מאזיני SMTP. בדקו ss -ltnp, כולל שירותים אחרים ויציאות מותאמות."),
        "compiled_targets" => T(
            "Не найдены оба допустимых файла sendmail.cf и submit.cf. Не создавайте их автоматически; проверьте пакет и выбранный архив.",
            "Both supported compiled files are not present. Do not recreate them automatically; inspect the package and selected archive.",
            "שני קובצי התצורה הנדרשים אינם קיימים. בדקו את החבילה ואת הגיבוי."),
        "other_content" => T(
            "Изменились файлы за пределами допустимых двух. Сравните конфигурацию с независимым архивом; базы и другие файлы не будут перезаписаны.",
            "Other file contents differ. Review against an independent backup; databases and unrelated files will not be overwritten.",
            "תוכן קבצים אחרים השתנה. בדקו מול גיבוי עצמאי; מסדי נתונים לא יידרסו."),
        "file_set" => T(
            "Набор файлов не совпадает. Проверьте версию пакета и полный архив; автоматическое создание или удаление путей заблокировано.",
            "File inventory differs. Inspect package version and full backup; automatic path creation or deletion is blocked.",
            "רשימת הקבצים שונה. בדקו גרסת חבילה וגיבוי מלא; יצירה ומחיקה אוטומטיות חסומות."),
        "metadata" => T(
            "Права или владельцы отличаются. Проверьте их вручную; не ослабляйте разрешения ради Restore.",
            "Ownership or mode differs. Inspect manually; do not weaken permissions to make Restore eligible.",
            "בעלות או הרשאות שונות. יש לבדוק ידנית ולא להחליש הרשאות."),
        "objects" => T(
            "Изменились каталоги или символические ссылки. Проверьте структуру пакета; Restore не будет их пересоздавать.",
            "Directory or symlink inventory differs. Inspect the package layout; Restore does not recreate these objects.",
            "תיקיות או קישורים השתנו. יש לבדוק את מבנה החבילה."),
        "write_scope" => T(
            "Структура пакета не соответствует безопасной области записи. Используйте независимый архив и ручной план администратора.",
            "Package layout is outside the trusted write scope. Use an independent backup and administrator-reviewed recovery.",
            "מבנה החבילה מחוץ לתחום הכתיבה המותר. נדרש גיבוי עצמאי ושחזור ידני."),
        _ => T(
            "Не все обязательные условия подтверждены. Сохраните диагностический отчёт и повторите проверку после независимого анализа.",
            "Not all required evidence is verified. Retain this report and repeat the review after independent investigation.",
            "לא כל התנאים אומתו. שמרו את הדוח ובדקו שוב לאחר בירור עצמאי.")
    };
}
