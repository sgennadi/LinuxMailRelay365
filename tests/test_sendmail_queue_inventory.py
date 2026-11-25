"""Strict read-only native Sendmail normal-queue inventory."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sendmail_queue_product", str(ROOT / "linux/inspect-mail-queue.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
HEADER = "-----Q-ID----- --Size-- -----Q-Time----- ------------Sender/Recipient-----------\n"
NONCE = "a" * 64


def row(ident="3AP123AB45678", mark="", size=702, date="Wed Nov 25 06:00", reason=None):
    result = ident + mark + "   " + str(size) + " " + date + " <private@example.invalid>\n"
    if reason:
        result += " " + "8BITMIME".rjust(10) + " (" + reason + ")\n"
    return result + "                                      <recipient@example.invalid>\n"


class SendmailInventoryTests(unittest.TestCase):
    def test_two_groups_and_native_print_cap(self):
        raw = ("/var/spool/mqueue/a (2 requests, only 1 printed)\n" + HEADER +
               row(mark="*", reason="TLS certificate private@example.invalid") +
               "/var/spool/mqueue/b (1 request)\n" + HEADER +
               row(mark="X", date="Tue Nov  3 12:00") + "\nTotal requests: 3\n")
        total, groups, listed, truncated, rows = q.sendmail_rows(raw)
        self.assertEqual((total, groups, listed, truncated), (3, 2, 2, "yes"))
        self.assertEqual(rows[0], (1, 1, "processing_mark", 702, "Wed Nov 25 06:00", "tls"))
        self.assertEqual(rows[1], (2, 2, "load_limited", 702, "Tue Nov 3 12:00", "no_reason"))
        receipt = "\n".join(q.sendmail_inventory_lines("mta", NONCE, "ok", total, groups, listed, truncated, rows))
        for value in ("3AP123AB45678", "example.invalid", "/var/spool", "certificate"):
            self.assertNotIn(value, receipt)

    def test_independent_fixed_native_commands(self):
        runner = Mock(side_effect=["/var/spool/mqueue is empty\nTotal requests: 0\n",
                                   "/var/spool/clientmqueue (1 request)\n" + HEADER + row(mark="-")])
        self.assertEqual(q.sendmail_inventory("mta", NONCE, runner), ("ok", 0, 1, 0, "no", []))
        sample = q.sendmail_inventory("msp", NONCE, runner)
        self.assertEqual(sample[:5], ("ok", 1, 1, 1, "no"))
        self.assertEqual(sample[5][0][2], "too_young")
        self.assertEqual([call.args for call in runner.call_args_list],
                         [("sendmail", ["-bp"]), ("sendmail", ["-Ac", "-bp"])])
        with self.assertRaises(ValueError):
            q.sendmail_inventory("both", NONCE, runner)
        self.assertEqual(runner.call_count, 2)
        for args in (["-q"], ["-Ac", "-q"], ["-bp", "-qQ"], ["-bp", "-qL"]):
            self.assertFalse(q.allowed_args("sendmail", args))

    def test_reject_unknown_or_inconsistent_nonempty_listing(self):
        valid = "/var/spool/mqueue (1 request)\n" + HEADER + row()
        for raw in (valid.replace(HEADER, ""), valid.replace("1 request", "2 requests"),
                    valid.replace("Nov 25", "Feb 30"), valid.replace("06:00", "25:00"),
                    valid.replace("702", "-1"), valid.replace("702", str(q.MAX_MESSAGE_SIZE + 1)),
                    valid + row(), "Total requests: 1\n",
                    "/var/spool/mqueue (1 request)\n" + HEADER + "unrecognized row\n"):
            with self.subTest(raw=raw[:100]), self.assertRaises(q.Unavailable):
                q.sendmail_rows(raw)
        runner = Mock(side_effect=q.Unavailable("timeout"))
        self.assertEqual(q.sendmail_inventory("msp", NONCE, runner), ("timeout", None, None, None, "unknown", []))

    def test_native_pid_suffix_and_load_marker_are_unambiguous(self):
        # IDs have an eight-character encoded prefix and a decimal PID
        # suffix. X is permitted inside the prefix, not at the end of an ID.
        ident = "3AP123AX456789"
        raw = "Mail Queue (1 request)\n" + HEADER + row(ident=ident, mark="X")
        data = q.sendmail_rows(raw, private=True)
        self.assertEqual(data[-1][0][0], ident)
        self.assertEqual(data[-1][0][1][1], "load_limited")
        plain = raw.replace(ident + "X", ident)
        self.assertEqual(q.sendmail_rows(plain, private=True)[-1][0][0], ident)
        self.assertEqual(q.sendmail_rows(plain)[-1][0][2], "queued")
        with self.assertRaises(q.Unavailable):
            q.sendmail_rows("Mail Queue (1 request)\n" + HEADER + row(ident=ident + "X", mark="*"))

    def test_display_limit_is_not_native_limit(self):
        raw = "/var/spool/mqueue (505 requests)\n" + HEADER + "".join(
            row(ident="QUEUE%010d" % n) for n in range(505))
        total, groups, native, truncated, rows = q.sendmail_rows(raw)
        self.assertEqual((total, groups, native, truncated, len(rows)), (505, 1, 505, "no", 500))
        receipt = list(q.sendmail_inventory_lines("mta", NONCE, "ok", total, groups, native, truncated, rows))
        self.assertIn("SENDMAIL_ITEMS_NATIVE_TRUNCATED=no", receipt)
        self.assertIn("SENDMAIL_ITEMS_DISPLAY_TRUNCATED=yes", receipt)

    def test_gui_has_separate_inventory_and_confirmed_actions(self):
        src = ROOT / "src/LinuxMailRelay365"
        ui = (src / "MainForm.SendmailQueue.cs").read_text()
        for marker in ("SendmailQueueInventory.Parse", "RequireSameArchiveConnection",
                       "inventory.Filter(", "ReadOnly = true", "Retry/Flush are experimental and separately confirmed.",
                       "exact age is unknown", "Native print limit"):
            self.assertIn(marker, ui)
        for forbidden in ("BuildQueueMaintenanceBundle", "BuildQueueRetryApplyBundle"):
            self.assertNotIn(forbidden, ui)
        self.assertLess(ui.index("SendmailQueueAction.Parse(reply.StdOut"), ui.index("ConfirmDestructive("))
        self.assertLess(ui.index("ConfirmDestructive("), ui.index("attempted = true"))
        # A dispatched action invalidates the displayed sample. The dialog
        # now supports explicit read-only reload, but an unknown result
        # remains latched for the life of this dialog.
        self.assertNotIn("if (attempted) dialog.Close();", ui)
        self.assertIn("snapshotValid = false;", ui)
        self.assertIn("outcomeUncertain = true;", ui)
        self.assertIn("if (snapshotValid && !outcomeUncertain) attempted = false;", ui)
        self.assertIn("!snapshotValid || outcomeUncertain", ui)
        reload = ui.split("async Task ReloadAsync()", 1)[1].split("reload.Click +=", 1)[0]
        self.assertIn("BuildSendmailQueueInventoryBundle(queue, freshNonce", reload)
        self.assertIn("SendmailQueueInventory.Parse(reply.StdOut, queue, freshNonce", reload)
        self.assertIn("nonce = freshNonce;", reload)
        self.assertIn("groups.SelectedIndex = 0;", reload)
        self.assertNotIn("BuildSendmailQueueActionBundle", reload)
        self.assertNotIn("outcomeUncertain = false", reload)
        self.assertIn("grid.CurrentCell = null;", ui)
        main = (src / "MainForm.MailQueue.cs").read_text()
        self.assertIn('InspectSendmailQueueAsync("mta")', main)
        self.assertIn('InspectSendmailQueueAsync("msp")', main)


if __name__ == "__main__":
    unittest.main()
