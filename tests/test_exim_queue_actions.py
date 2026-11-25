"""Native Exim queue metadata and explicitly confirmed Freeze/Thaw (mock mutations)."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("exim_queue_product", str(ROOT / "linux/inspect-mail-queue.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


class EximQueueTests(unittest.TestCase):
    def setUp(self):
        self.nonce = "a" * 64
        self.ident = "0t5C6f-0000c8-00"
        self.raw = ("25m 2.9K " + self.ident + " <sender@example.invalid>\n"
                    " D delivered@example.invalid\n   pending@example.invalid\n\n")
        self.runner = Mock(side_effect=lambda tool, args: "1\n" if args == ["-bpc"] else self.raw)
        self.context = Mock(return_value=("default-spool", 1, 2, "config", "boot"))
        self.executor = Mock(return_value="command_completed")

    def inventory(self):
        return q.exim_inventory(self.nonce, self.runner, self.context, now=1000)

    def plan(self, action, token):
        return q.exim_prepare(action, self.nonce, 1000, token, self.runner, self.context, clock=lambda: 1060)

    def apply(self, action, token, prepared, plan, **kw):
        opts = dict(runner=self.runner, context_check=self.context, executor=self.executor,
                    clock=lambda: 1070, monotonic=lambda: 1)
        opts.update(kw)
        return q.exim_apply(action, self.nonce, 1000, token, prepared, plan, q.EXIM_ACTIONS[action], **opts)

    def test_inventory_metadata_and_private_fingerprint(self):
        result, now, total, rows, context = self.inventory()
        self.assertEqual((result, now, total, context), ("ok", 1000, 1, "verified"))
        self.assertEqual(rows[0][:-1], (1, "queued", 25, "2.9K", 1, 1))
        self.assertRegex(rows[0][-1], r"^[a-f0-9]{64}$")
        output = "\n".join(q.exim_inventory_lines(self.nonce, result, now, total, rows, context))
        self.assertNotIn(self.ident, output)
        self.assertNotIn("example.invalid", output)
        self.assertIn("EXIM_ITEMS_CHANGES_APPLIED=no", output)

    def test_context_unverified_and_changed_counts(self):
        self.context.side_effect = q.Unavailable("scope_unverified")
        result, _, total, rows, context = self.inventory()
        self.assertEqual((result, total, rows[0][-1], context), ("ok", 1, "-", "unverified"))
        values = iter(["1\n", self.raw, "2\n"])
        result, _, total, rows, context = q.exim_inventory(
            self.nonce, lambda *_: next(values), lambda *_: ("scope",), now=1000)
        self.assertEqual((result, total, rows, context), ("sample_changed", None, [], "unverified"))

    def test_freeze_thaw_action_specific_and_fresh(self):
        token = self.inventory()[3][0][-1]
        result, prepared, plan = self.plan("freeze", token)
        self.assertEqual(result, "candidate")
        self.assertEqual(self.apply("freeze", token, prepared, plan, clock=lambda: 1121),
                         ("not_requested", "expired"))
        self.assertEqual(self.apply("freeze", token, prepared, "b"*64), ("not_requested", "plan_changed"))
        self.executor.assert_not_called()
        self.assertEqual(self.apply("freeze", token, prepared, plan), ("command_completed", "none"))
        self.executor.assert_called_once_with("freeze", self.ident)
        self.executor.reset_mock()
        self.raw = self.raw.replace("<sender@example.invalid>", "<sender@example.invalid> *** frozen ***")
        self.assertEqual(self.apply("freeze", token, prepared, plan), ("not_requested", "sample_changed"))
        frozen = self.inventory()[3][0][-1]
        self.assertNotEqual(token, frozen)
        result, prepared, plan = self.plan("thaw", frozen)
        self.assertEqual(result, "candidate")
        self.assertEqual(self.apply("thaw", frozen, prepared, plan), ("command_completed", "none"))
        self.executor.assert_called_once_with("thaw", self.ident)

    def test_changed_envelope_and_context_never_dispatch(self):
        token = self.inventory()[3][0][-1]
        _, prepared, plan = self.plan("freeze", token)
        self.raw = self.raw.replace("pending@", "changed@")
        self.assertEqual(self.apply("freeze", token, prepared, plan), ("not_requested", "sample_changed"))
        self.raw = self.raw.replace("changed@", "pending@")
        self.context.return_value = ("different-spool",)
        self.assertEqual(self.apply("freeze", token, prepared, plan), ("not_requested", "sample_changed"))
        self.executor.assert_not_called()

    def test_native_commands_are_single_id_only(self):
        with patch.object(q, "native_binary", return_value="/usr/sbin/exim4"), \
                patch.object(q.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            for action, flag in (("freeze", "-Mf"), ("thaw", "-Mt")):
                self.assertEqual(q.exim_execute(action, self.ident), "command_completed")
                self.assertEqual(run.call_args[0][0], ["/usr/sbin/exim4", flag, self.ident])
                self.assertFalse(q.allowed_args("exim", [flag, self.ident]))
            for action, ident in (("freeze", "ALL"), ("thaw", "-Mrm"), ("delete", self.ident)):
                with self.assertRaises(ValueError):
                    q.exim_execute(action, ident)
            self.assertEqual(run.call_count, 2)
        with patch.object(q, "native_binary", return_value="/usr/sbin/exim4"), \
                patch.object(q.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 12)) as run:
            self.assertEqual(q.exim_execute("freeze", self.ident), "outcome_unknown")
            run.assert_called_once()

    def test_gui_confirm_before_dispatch(self):
        form = (ROOT / "src/LinuxMailRelay365/MainForm.EximQueue.cs").read_text()
        self.assertIn("DataGridView", form)
        self.assertIn("ReadOnly = true", form)
        self.assertLess(form.index("EximQueueAction.Parse(reply.StdOut"), form.index("ConfirmDestructive("))
        self.assertLess(form.index("ConfirmDestructive("), form.index("attempted = true"))
        self.assertIn("if (attempted) dialog.Close();", form)


if __name__ == "__main__":
    unittest.main()
