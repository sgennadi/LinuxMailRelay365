"""Sendmail normal queue actions: unit tests never run a real delivery."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sm_action_product", str(ROOT / "linux/inspect-mail-queue.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
HEADER = "-----Q-ID----- --Size-- -----Q-Time----- ------------Sender/Recipient-----------\n"
ID = "3AP123ABC45678"


def message(ident=ID, marker="", size=123):
    return ident + marker + "   " + str(size) + " Wed Nov 25 06:00 <sender@example.invalid>\n" + \
        "                                    <recipient@example.invalid>\n"


class SendmailActions(unittest.TestCase):
    def setUp(self):
        self.nonce = "a" * 64
        self.raw = "Mail Queue (1 request)\n" + HEADER + message()
        self.runner = Mock(side_effect=lambda *_: self.raw)
        self.context = Mock(side_effect=lambda queue: ("scope", queue, "config", "boot"))
        self.execute = Mock(return_value="command_completed")

    def inventory(self, queue="msp"):
        return q.sendmail_review_inventory(queue, self.nonce, self.runner, self.context, now=1000)

    def plan(self, action, token="-", sampled=0, queue="msp"):
        return q.sm_prepare(queue, action, self.nonce, sampled, token, self.runner, self.context, clock=lambda: 1060)

    def apply(self, action, prepared, digest, token="-", sampled=0, queue="msp", **extra):
        opts = dict(runner=self.runner, context_check=self.context, executor=self.execute,
                    clock=lambda: 1070, monotonic=lambda: 1)
        opts.update(extra)
        return q.sm_apply(queue, action, self.nonce, sampled, token, prepared, digest, q.SM_ACTIONS[action], **opts)

    def test_private_selection_bound_to_explicit_mode_and_full_id(self):
        report = self.inventory()
        self.assertEqual(report[:5], ("ok", 1, 1, 1, "no"))
        token = report[5][0][-1]
        self.assertRegex(token, r"^[a-f0-9]{64}$")
        self.assertEqual(report[-2:], (1000, "verified"))
        receipt = "\n".join(q.sendmail_inventory_lines("msp", self.nonce, *report))
        self.assertNotIn(ID, receipt)
        self.assertNotIn("example.invalid", receipt)
        self.assertIn("SENDMAIL_ITEMS_VERSION=2", receipt)
        self.assertEqual(self.runner.call_args[0], ("sendmail", ["-Ac", "-bp"]))
        self.assertNotEqual(self.inventory("mta")[5][0][-1], token)
        self.assertEqual(self.runner.call_args[0], ("sendmail", ["-Am", "-bp"]))
        result, prepared, digest, count = self.plan("retry", token, 1000)
        self.assertEqual((result, count), ("candidate", 1))
        self.assertEqual(self.apply("retry", prepared, digest, token, 1000, queue="mta"),
                         ("not_requested", "sample_changed"))
        self.assertEqual(self.apply("retry", prepared, digest, token, 1000), ("command_completed", "none"))
        self.execute.assert_called_once_with("msp", "retry", ID)

    def test_substring_collision_processing_and_truncation_refused(self):
        self.raw = "Mail Queue (2 requests)\n" + HEADER + message() + message("A" + ID)
        self.assertEqual(self.inventory()[5][0][-1], "-")
        self.raw = "Mail Queue (1 request)\n" + HEADER + message(marker="*")
        self.assertEqual(self.inventory()[5][0][-1], "-")
        self.raw = "Mail Queue (2 requests, only 1 printed)\n" + HEADER + message()
        report = self.inventory()
        self.assertEqual((report[-1], report[5][0][-1]), ("unverified", "-"))
        self.assertEqual(self.plan("flush")[0], "scope_unverified")
        self.execute.assert_not_called()

    def test_flush_full_sample_expiration_and_mode_change(self):
        result, prepared, digest, count = self.plan("flush", queue="mta")
        self.assertEqual((result, count), ("candidate", 1))
        self.assertEqual(self.apply("flush", prepared, digest, queue="msp"), ("not_requested", "plan_changed"))
        self.assertEqual(self.apply("flush", prepared, digest, queue="mta", clock=lambda: 1121),
                         ("not_requested", "expired"))
        self.raw = self.raw.replace("123 Wed", "124 Wed")
        self.assertEqual(self.apply("flush", prepared, digest, queue="mta"), ("not_requested", "plan_changed"))
        self.execute.assert_not_called()
        self.raw = self.raw.replace("124 Wed", "123 Wed")
        self.assertEqual(self.apply("flush", prepared, digest, queue="mta"), ("command_completed", "none"))
        self.execute.assert_called_once_with("mta", "flush", None)

    def test_config_refusal_and_unknown_result(self):
        self.context.side_effect = q.Unavailable("scope_unverified")
        self.assertEqual(self.inventory()[-1], "unverified")
        self.assertEqual(self.plan("flush")[0], "scope_unverified")
        self.context.side_effect = lambda queue: ("scope", queue)
        _, prepared, digest, _ = self.plan("flush")
        self.execute.return_value = "outcome_unknown"
        self.assertEqual(self.apply("flush", prepared, digest), ("outcome_unknown", "native_result_unconfirmed"))
        self.execute.assert_called_once()
        q.sm_config_queue("O QueueDirectory=/var/spool/mqueue\n", "/var/spool/mqueue")
        for config in ("O QueueDirectory=/var/spool/mqueue/*", "O QueueDirectory=/tmp/queue",
                       "O QueueDirectory=/var/spool/mqueue\nQextra, P=/tmp/queue",
                       "O QueueDirectory=/var/spool/mqueue\nOQ/tmp/queue"):
            with self.assertRaises(q.Unavailable):
                q.sm_config_queue(config, "/var/spool/mqueue")

    def test_fixed_native_modes_and_no_quarantine_or_periodic_command(self):
        with patch.object(q, "native_binary", return_value="/usr/sbin/sendmail"), \
                patch.object(q.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            for queue, mode in (("mta", "-Am"), ("msp", "-Ac")):
                self.assertEqual(q.sm_execute(queue, "retry", ID), "command_completed")
                self.assertEqual(run.call_args[0][0], ["/usr/sbin/sendmail", mode, "-qf", "-qI" + ID])
                self.assertEqual(q.sm_execute(queue, "flush", None), "command_completed")
                self.assertEqual(run.call_args[0][0], ["/usr/sbin/sendmail", mode, "-qf"])
            for queue, action, ident in (("both", "flush", None), ("mta", "retry", "ALL"),
                                         ("mta", "flush", ID), ("msp", "delete", ID)):
                with self.assertRaises(ValueError):
                    q.sm_execute(queue, action, ident)
            self.assertEqual(run.call_count, 4)
            self.assertFalse(q.allowed_args("sendmail", ["-Am", "-qf"]))


if __name__ == "__main__":
    unittest.main()
