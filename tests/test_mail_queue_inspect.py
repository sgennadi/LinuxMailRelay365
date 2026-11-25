"""Native queue inspection: strict scopes, limits, privacy and partial results."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("queue_sample", str(ROOT / "linux/inspect-mail-queue.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


def row(ident, queue, reason="", arrival=940):
    return json.dumps(dict(queue_id=ident, queue_name=queue, arrival_time=arrival,
                           sender="private@example.invalid", recipients=[
                               dict(address="recipient@example.invalid", delay_reason=reason)]))


class NativeQueueInspection(unittest.TestCase):
    def test_postfix_aggregates_and_privacy(self):
        raw = "\n".join([row("A", "active"), row("B", "deferred", "SASL authentication failed"),
                         row("C", "deferred", "TLS certificate rejected"),
                         row("D", "hold"), row("E", "futurequeue")])
        counts = q.postfix_counts(raw, now=1000)
        self.assertEqual((counts["total"], counts["deferred"], counts["held"], counts["other"]),
                         (5, 2, 1, 1))
        self.assertEqual((counts["auth"], counts["tls"], counts["oldest_minutes"]), (1, 1, 1))
        self.assertNotIn("example.invalid", str(counts))
        self.assertEqual(sum(counts[name] for name in q.REASONS), counts["deferred"])

    def test_malformed_or_duplicate_sample_never_looks_empty(self):
        for data in ("not JSON", row("X", "active") + "\n" + row("X", "active"),
                     '{"queue_id":"A","queue_id":"B"}', row("X", "active", arrival=True),
                     row("X", "active", arrival=9999), row("../path", "active")):
            with self.subTest(data=data[:50]), self.assertRaises(q.Unavailable):
                q.postfix_counts(data, now=1000)
        self.assertEqual(q.postfix_counts("", now=1000)["total"], 0)
        with patch.object(q, "LIMIT", 32), self.assertRaises(q.Unavailable) as error:
            q.postfix_counts(row("X", "active"), now=1000)
        self.assertEqual(error.exception.result, "output_limit")

    def test_native_counts_and_ambiguous_sendmail_output(self):
        self.assertEqual(q.exim_count("17\n"), 17)
        for raw in ("Mail queue is empty\n", "/var/spool/mqueue is empty\n"):
            self.assertEqual(q.sendmail_count(raw), 0)
        self.assertEqual(q.sendmail_count("/var/spool/mqueue (2 requests)\nprivate\nTotal requests: 2\n"), 2)
        for raw in ("", "error", "Mail queue is empty\nunexpected\n",
                    "Total requests: 0\nTotal requests: 2\n", "Total requests: 2\nunexpected"):
            with self.subTest(raw=raw), self.assertRaises(q.Unavailable):
                q.sendmail_count(raw)
        for raw in ("", "warning\n0", "-1", "1000000000"):
            with self.assertRaises(q.Unavailable):
                q.exim_count(raw)

    def test_sendmail_group_totals_and_single_queue_without_footer(self):
        self.assertEqual(q.sendmail_summary("/var/spool/mqueue (2 requests)\n-----Q-ID-----\nmessage row\n"), (2, 1, "no"))
        self.assertEqual(q.sendmail_summary("/var/spool/mqueue (4 requests, only 2 printed)\nmessage row\n"), (4, 1, "yes"))
        self.assertEqual(q.sendmail_summary("/var/spool/mqueue/a is empty\n/var/spool/mqueue/b (2 requests)\nmessage row\nTotal requests: 2\n"), (2, 2, "no"))
        self.assertEqual(q.sendmail_summary("Total requests: 4\n"), (4, "unknown", "unknown"))
        for raw in ("/var/spool/a (2 requests)\nTotal requests: 1\n",
                    "/var/spool/a is empty\n/var/spool/b is empty\n",
                    "/var/spool/a is empty\n/var/spool/a is empty\nTotal requests: 0\n",
                    "/var/spool/a (2 requests, only 3 printed)\n",
                    "/var/spool/a: unknown number of entries\n",
                    "/var/spool/a is empty\nunexpected\nTotal requests: 0\n"):
            with self.subTest(raw=raw), self.assertRaises(q.Unavailable):
                q.sendmail_summary(raw)

    def test_exim_age_frozen_and_non_atomic_counts(self):
        raw = (" 25m  2.9K 0t5C6f-0000c8-00 <private@example.invalid>\n"
               "          recipient@example.invalid\n\n"
               "  2h  300  1abcdE-00000001234-ABCD <> *** frozen ***\n"
               "          private@example.invalid\n\n")
        self.assertEqual(q.exim_details(raw, 2), (1, 120))
        self.assertEqual(q.exim_details("", 0), (0, 0))
        for data, total in ((raw, 1), (raw + raw, 4), ("unexpected\n", 0),
                            (" 5m 1K bad-id <private>\n", 1)):
            with self.subTest(total=total), self.assertRaises(q.Unavailable):
                q.exim_details(data, total)
        values = iter(["2\n", raw, "2\n"])
        report = q.sample("exim", lambda *_: next(values))
        self.assertEqual((report["total"], report["detail_result"], report["frozen"],
                          report["exim_oldest_minutes"]), (2, "ok", 1, 120))
        self.assertNotIn("example.invalid", str(report))
        values = iter(["2\n", raw, "3\n"])
        report = q.sample("exim", lambda *_: next(values))
        self.assertEqual((report["total"], report["detail_result"], report["frozen"]),
                         (2, "sample_changed", "unknown"))

    def test_sendmail_native_libexec_path_not_foreign_alternative(self):
        from types import SimpleNamespace
        import stat
        metadata = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        with patch.object(q.os.path, "realpath", return_value="/usr/libexec/sendmail/sendmail"), \
                patch.object(q, "secure_directory"), patch.object(q.os, "stat", return_value=metadata):
            self.assertEqual(q.native_binary("sendmail"), "/usr/libexec/sendmail/sendmail")
        with patch.object(q.os.path, "realpath", return_value="/usr/libexec/postfix/sendmail"), \
                patch.object(q, "secure_directory"), patch.object(q.os, "stat", return_value=metadata):
            with self.assertRaises(q.Unavailable):
                q.native_binary("sendmail")

    def test_sendmail_partial_results_independent(self):
        def runner(tool, args):
            self.assertEqual(tool, "sendmail")
            if args == ["-bp"]:
                raise q.Unavailable("timeout")
            self.assertEqual(args, ["-Ac", "-bp"])
            return "Total requests: 4\n"
        report = q.sample("sendmail", runner)
        self.assertEqual((report["result"], report["total"]), ("timeout", "unknown"))
        self.assertEqual((report["client_result"], report["client_total"]), ("ok", 4))
        self.assertEqual(report["delivery_verified"], "no")

    def test_postfix_scope_rechecked_and_no_fallback_to_primary(self):
        calls = []
        def runner(tool, args):
            calls.append((tool, args))
            return ""
        contexts = iter([(q.SIDECAR_CONFIG, q.SIDECAR_QUEUE, (1, 2)),
                         (q.SIDECAR_CONFIG, q.SIDECAR_QUEUE, (1, 3))])
        report = q.sample("sidecar", runner, lambda *_: next(contexts))
        self.assertEqual(calls, [("postqueue", ["-c", q.SIDECAR_CONFIG, "-j"])])
        self.assertEqual((report["result"], report["total"]), ("scope_unverified", "unknown"))
        def reject(*_):
            raise q.Unavailable("scope_unverified")
        self.assertEqual(q.sample("sidecar", runner, reject)["result"], "scope_unverified")
        self.assertEqual(len(calls), 1)

    def test_shared_queue_and_wrong_sidecar_queue_refused(self):
        with patch.object(q.os.path, "lexists", return_value=True):
            with patch.object(q, "configured_queue", side_effect=[
                (q.SIDECAR_QUEUE, (1, 2)), ("/var/spool/postfix", (1, 2))]):
                with self.assertRaises(q.Unavailable):
                    q.verify_postfix_scope("sidecar", None)
            with patch.object(q, "configured_queue", return_value=("/var/spool/postfix", (1, 2))):
                with self.assertRaises(q.Unavailable):
                    q.verify_postfix_scope("sidecar", None)

    def test_private_postfix_message_inventory_oldest_first(self):
        def sized(ident, state, arrival, size, reason=""):
            item = json.loads(row(ident, state, reason, arrival))
            item["message_size"] = size
            return json.dumps(item)
        raw = "\n".join([sized("NATIVESECRET1", "active", 940, 200),
                         sized("NATIVESECRET2", "deferred", 400, 100, "TLS private@example.invalid")])
        total, rows = q.postfix_inventory(raw, now=1000)
        self.assertEqual(total, 2)
        self.assertEqual(rows, [(1, "deferred", 10, 100, 1, "tls"),
                                (2, "active", 1, 200, 1, "not_applicable")])
        receipt = "\n".join(q.inventory_lines("postfix", "ok", total, rows))
        for private in ("NATIVESECRET", "example.invalid", "TLS private"):
            self.assertNotIn(private, receipt)
        self.assertIn("MAIL_ITEMS_REFERENCE_KIND=sample_ordinal_only", receipt)
        self.assertIn("MAIL_ITEMS_TRUNCATED=no", receipt)

    def test_message_inventory_validates_all_rows_even_after_display_cap(self):
        def data(i, size=1):
            value = json.loads(row("QUEUE" + str(i), "active"))
            value["message_size"] = size
            return json.dumps(value)
        raw = "\n".join(data(i) for i in range(505))
        total, rows = q.postfix_inventory(raw, now=1000)
        self.assertEqual((total, len(rows), rows[-1][0]), (505, 500, 500))
        self.assertIn("MAIL_ITEMS_TRUNCATED=yes",
                      list(q.inventory_lines("sidecar", "ok", total, rows)))
        for size in (-1, True, q.MAX_MESSAGE_SIZE + 1):
            with self.assertRaises(q.Unavailable):
                q.postfix_inventory(raw + "\n" + data(505, size), now=1000)
        with self.assertRaises(q.Unavailable):
            q.postfix_inventory(row("NOSIZE", "active"), now=1000)

    def test_message_inventory_refuses_scope_change_and_partial_results(self):
        item = json.loads(row("NATIVEPRIVATE", "active", arrival=0))
        item["message_size"] = 123
        contexts = iter([(q.CONFIG, "/var/spool/postfix", (1, 2)),
                         (q.CONFIG, "/var/spool/postfix", (1, 3))])
        result, total, rows = q.message_inventory("postfix", lambda *_: json.dumps(item),
                                                   lambda *_: next(contexts))
        self.assertEqual((result, total, rows), ("scope_unverified", None, []))
        receipt = list(q.inventory_lines("postfix", result, total, rows))
        self.assertIn("MAIL_ITEMS_TOTAL=unknown", receipt)
        self.assertIn("MAIL_ITEMS_LISTED=0", receipt)
        self.assertIn("MAIL_ITEMS_TRUNCATED=unknown", receipt)
        with self.assertRaises(ValueError):
            q.message_inventory("exim")

    def test_no_mutation_or_untrusted_configuration_commands(self):
        for tool, args in (("postqueue", ["-f"]), ("sendmail", ["-q"]),
                           ("exim", ["-Mrm", "id"]), ("postqueue", ["-c", "/tmp/evil", "-j"]),
                           ("postsuper", ["-d", "ALL"])):
            with self.subTest(tool=tool), patch.object(q, "native_binary") as binary:
                with self.assertRaises(ValueError):
                    q.run_native(tool, args)
                binary.assert_not_called()

    def test_bounded_subprocess_capture(self):
        # Use the current Python binary only in a mocked unit fixture, never
        # as a production command or on a real queue.
        import sys
        with patch.object(q, "allowed_args", return_value=True), \
                patch.object(q, "native_binary", return_value=sys.executable):
            self.assertEqual(q.run_native("exim", ["-c", "print(7)"]), "7\n")
            with self.assertRaises(q.Unavailable) as too_large:
                q.run_native("exim", ["-c", "print('x'*10000)"], limit=64)
            self.assertEqual(too_large.exception.result, "output_limit")
            with self.assertRaises(q.Unavailable) as timeout:
                q.run_native("exim", ["-c", "import time; time.sleep(3)"], timeout=0.05)
            self.assertEqual(timeout.exception.result, "timeout")


class QueueGuiContract(unittest.TestCase):
    def test_gui_uses_discovered_scope_and_strict_aggregate_receipt(self):
        cs = ROOT / "src/LinuxMailRelay365"
        ui = (cs / "MainForm.MailQueue.cs").read_text()
        for marker in ("QueueScopeDiscovered(scope)", "RequireSameArchiveConnection(initial",
                       "MailQueueSample.Parse(result.StdOut, scope)", "BuildMailQueueInspectionBundle(scope)",
                       "ReadOnly = true", "PreferredDialogSize", "discoveredIsolatedRelay == true"):
            self.assertIn(marker, ui)
        for forbidden in ("ConfirmDestructive(", " --flush ", " --delete ", "result.StdOut.Trim()"):
            self.assertNotIn(forbidden, ui)
        self.assertIn("AddMailQueueActions(page);", (cs / "MainForm.cs").read_text())
        self.assertIn("MailQueueSample.SelfTest", (cs / "Program.cs").read_text())
        self.assertIn("LinuxMailRelay365.linux.inspect-mail-queue.py",
                      (cs / "LinuxMailRelay365.csproj").read_text())

    def test_message_inventory_ui_is_read_only_and_filters_only_local_rows(self):
        cs = ROOT / "src/LinuxMailRelay365"
        ui = (cs / "MainForm.QueueMessages.cs").read_text()
        for marker in ("QueueScopeDiscovered(scope)", "RequireSameArchiveConnection(initial",
                       "QueueMessageInventory.Parse(response.StdOut, scope)", "DataGridView",
                       "ReadOnly = true", "inventory.Filter(", "sample references",
                       "messages: true", "No queue writes or retry actions"):
            self.assertIn(marker, ui)
        for forbidden in ("ConfirmDestructive(", "response.EnsureSuccess()", " --flush ", " --delete "):
            self.assertNotIn(forbidden, ui)
        self.assertIn("QueueMessageInventory.SelfTest", (cs / "Program.cs").read_text())
        self.assertIn("InspectQueueMessagesAsync(scope)", (cs / "MainForm.MailQueue.cs").read_text())


if __name__ == "__main__":
    unittest.main()
