using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private Task FlushPostfixQueueAsync(string scope)
    {
        string nonce = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        return RunQueueMaintenanceAsync(Endpoint(), scope, "flush", nonce, 0, null, this,
            () => true, () => ClearNativeRecoverySample());
    }

    private async Task RunQueueMaintenanceAsync(SshEndpoint endpoint, string scope, string action,
        string nonce, long sampledAt, QueueMessageRow? selected, IWin32Window owner,
        Func<bool> sameSelection, Action onDispatch, Action<string>? onReceipt = null)
    {
        bool dispatched = false;
        string fingerprint = selected?.Fingerprint ?? "-";
        string title = "LinuxMailRelay365 | EXPERIMENTAL " + action.ToUpperInvariant();
        try
        {
            if (!QueueScopeDiscovered(scope) || !sameSelection())
                throw new InvalidOperationException("Refresh queue discovery.");
            var initial = RequireSameArchiveConnection(endpoint);
            var reply = await SshRemote.RunRootScriptAsync(initial,
                EmbeddedAssets.BuildQueueMaintenanceBundle(scope, action, nonce, sampledAt, fingerprint),
                TimeSpan.FromMinutes(3));
            if (reply.ExitCode != 0) throw new IOException("Maintenance preview failed.");
            var reviewed = RequireSameArchiveConnection(initial);
            var plan = QueueMaintenanceReceipt.Parse(reply.StdOut, scope, action, nonce, sampledAt, selected);
            if (plan.Outcome != "candidate")
            {
                WriteLine("Queue maintenance refused: " + action + "; " + plan.Reason);
                MessageBox.Show(owner, T("Операция не разрешена: ", "Operation refused: ", "הפעולה נדחתה: ") +
                    plan.Reason, title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string details = "Host: " + reviewed.Host + ":" + reviewed.Port + "\r\n" + QueueScopeName(scope) +
                "\r\n" + T("Только тестовый сервер. План действует 60 секунд.",
                    "Disposable test host only. Plan expires in 60 seconds.", "לשרת בדיקה בלבד. התוכנית תקפה ל-60 שניות.") + "\r\n\r\n";
            if (action == "flush")
            {
                string[] counts = plan.Detail.Split('|');
                details += "Total: " + counts[0] + "  Active: " + counts[1] + "  Deferred: " + counts[2] +
                    "  Held: " + counts[3] + "\r\nIncoming: " + counts[4] + "  Maildrop: " + counts[5] +
                    "  Other: " + counts[6] + "\r\n\r\n" +
                    T("Flush запрашивает доставку всей очереди этого экземпляра (не удаление). Новые письма могут попасть в очередь после проверки. Не освобождает Hold. Частый Flush снижает производительность.",
                        "Flush requests delivery of the entire instance queue (not deletion). New messages may arrive after the check. Held mail is not released. Repeated Flush can harm performance.",
                        "Flush מבקש מסירה לכל התור, לא מחיקה. הודעות חדשות עשויות להגיע לאחר הבדיקה. הודעות מוחזקות אינן משתחררות.");
            }
            else
            {
                details += "Sample #" + selected!.Reference + "  Bytes: " + selected.Bytes +
                    "  Recipients: " + selected.RecipientCount + "\r\n\r\n" +
                    (action == "hold"
                        ? T("Hold: перевести одно отложенное письмо в удержание. Доставка приостанавливается, срок жизни не истекает в Hold.",
                            "Hold: move one deferred message to hold. Delivery attempts stop and queue lifetime does not expire while held.",
                            "Hold: העברת הודעה מושהית אחת להחזקה. ניסיונות המסירה נעצרים.")
                        : action == "release"
                            ? T("Release: вернуть одно удержанное письмо в deferred. Оно может быть доставлено или просрочено.",
                                "Release: return one held message to deferred. It may be delivered or expire.",
                                "Release: החזרת הודעה מוחזקת לתור המושהה. היא עשויה להימסר או לפוג.")
                            : T("НЕОБРАТИМОЕ УДАЛЕНИЕ одного удержанного письма со всеми получателями. " +
                                "Приложение не создаёт резервную копию письма. Если нужно сохранить письмо, отмените операцию и сделайте независимый архив.",
                                "IRREVERSIBLE deletion of one held message for all its recipients. " +
                                "The manager does not back up the message. Cancel and arrange an independent archive if preservation is required.",
                                "מחיקה בלתי הפיכה של הודעה מוחזקת אחת לכל נמעניה. אין גיבוי אוטומטי; אם דרוש שימור, בטלו את הפעולה."));
            }
            details += "\r\n\r\n" + T("Операция неатомарная; доставка и фактическое перемещение не гарантированы. При неизвестном результате проверьте очередь и журналы.",
                "Not atomic; delivery or actual movement is not guaranteed. If the outcome is unknown, inspect the queue and logs.",
                "הפעולה אינה אטומית; אין הבטחת מסירה או העברה. בדקו תור ויומנים אם התוצאה לא ידועה.") +
                "\r\nSHA-256: " + plan.PlanSha;
            if (!ConfirmDestructive(title, details, QueueMaintenanceReceipt.Confirmation(action), owner)) return;
            var confirmed = RequireSameArchiveConnection(reviewed);
            if (!QueueScopeDiscovered(scope) || !sameSelection())
                throw new InvalidOperationException("Maintenance selection changed.");
            dispatched = true;
            onDispatch();
            var result = await SshRemote.RunRootScriptAsync(confirmed,
                EmbeddedAssets.BuildQueueMaintenanceBundle(scope, action, nonce, sampledAt, fingerprint,
                    plan.PreparedAt, plan.PlanSha), TimeSpan.FromMinutes(3));
            if (result.ExitCode != 0) throw new IOException("Maintenance outcome unknown.");
            RequireSameArchiveConnection(confirmed);
            var receipt = QueueMaintenanceReceipt.Parse(result.StdOut, scope, action, nonce, sampledAt,
                selected, plan.PreparedAt, plan.PlanSha);
            onReceipt?.Invoke(receipt.Outcome);
            WriteLine("Queue maintenance " + action + ": " + receipt.Outcome + "; " + receipt.Reason +
                ". Effect/delivery unverified; refresh queue.");
            string message = receipt.Outcome switch
            {
                "command_completed" => T("Нативная команда завершилась. Фактическое состояние проверьте новым снимком.",
                    "Native command completed. Refresh the queue to verify its actual state.", "הפקודה הסתיימה. יש לבדוק את מצב התור מחדש."),
                "not_requested" => T("Команда не запущена: ", "No command issued: ", "הפקודה לא הופעלה: ") + receipt.Reason,
                _ => T("Результат неизвестен. Не повторяйте автоматически.", "Outcome unknown. Do not automatically repeat.", "תוצאה לא ידועה. אין לחזור אוטומטית.")
            };
            MessageBox.Show(owner, message, title, MessageBoxButtons.OK,
                receipt.Outcome == "command_completed" ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }
        catch (Exception)
        {
            WriteLine(dispatched ? "Queue maintenance outcome unknown; no automatic repeat." :
                "Queue maintenance preparation failed; no command dispatched.");
            MessageBox.Show(owner, dispatched
                ? T("Результат неизвестен. Проверьте очередь и журналы.", "Outcome unknown. Inspect queue and logs.", "תוצאה לא ידועה. בדקו תור ויומנים.")
                : T("Проверка не завершилась. Обновите диагностику.", "Preparation failed. Refresh diagnostics.", "ההכנה נכשלה. רעננו את האבחון."),
                title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
