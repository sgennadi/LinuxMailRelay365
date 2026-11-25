"""Scoped Flush/Hold/Release plans; all native mutations mocked."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("maintenance_product", str(ROOT / "linux/inspect-mail-queue.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.item = dict(queue_id="3Pt2mN2VXxznjll", queue_name="deferred", arrival_time=940,
                         message_size=123, sender="private@example.invalid",
                         recipients=[dict(address="recipient@example.invalid", delay_reason="TLS certificate")])
        self.nonce = "a" * 64
        self.before = (q.SIDECAR_CONFIG, q.SIDECAR_QUEUE, (1, 2))
        self.context = lambda *_: ("sidecar", self.before, "mail.example.invalid", "boot")
        self.runner = Mock(side_effect=lambda *_: json.dumps(self.item))
        self.options = dict(runner=self.runner, scope_check=lambda *_: self.before,
                            context_check=self.context, instance_check=self.context,
                            config_check=lambda *_: ["trusted-config"])
        self.execute = Mock(return_value="command_completed")

    def selection(self):
        _, _, rows, _, _ = q.reviewable_inventory("sidecar", self.nonce, self.runner,
            self.options["scope_check"], self.context, now=1000)
        return rows[0][-1]

    def plan(self, action, token="-", sampled=0):
        result, prepared, digest, detail = q.maintenance_prepare(action, "sidecar", self.nonce,
            sampled, token, clock=lambda: 1060, **self.options)
        self.assertEqual(result, "candidate")
        self.assertRegex(digest, r"^[a-f0-9]{64}$")
        return prepared, digest, detail

    def apply(self, action, prepared, digest, token="-", sampled=0, **extra):
        opts = dict(self.options, executor=self.execute, clock=lambda: 1070, monotonic=lambda: 1)
        opts.update(extra)
        return q.maintenance_apply(action, "sidecar", self.nonce, sampled, token,
            prepared, digest, q.MAINTENANCE_CONFIRM[action], **opts)

    def test_flush_exact_scoped_full_sample_and_privacy(self):
        prepared, digest, detail = self.plan("flush")
        self.assertEqual(detail, "1|0|1|0|0|0|0")
        self.assertEqual(self.apply("flush", prepared, digest), ("command_completed", "none"))
        self.execute.assert_called_once_with("flush", q.SIDECAR_CONFIG, None)
        receipt = "\n".join(q.maintenance_lines("flush", "sidecar", self.nonce, 0, "-",
            "apply", prepared, digest, "command_completed", "-", "none"))
        self.assertIn("MAIL_MAINT_EFFECT_VERIFIED=no", receipt)
        self.assertIn("MAIL_MAINT_DELIVERY_VERIFIED=no", receipt)
        self.assertNotIn(self.item["queue_id"], receipt)
        self.assertNotIn("example.invalid", receipt)

    def test_flush_refuses_changed_queue_config_and_expiry(self):
        prepared, digest, _ = self.plan("flush")
        self.item["message_size"] = 124
        self.assertEqual(self.apply("flush", prepared, digest), ("not_requested", "plan_changed"))
        self.item["message_size"] = 123
        self.assertEqual(self.apply("flush", prepared, digest, config_check=lambda *_: ["other"]),
                         ("not_requested", "plan_changed"))
        self.assertEqual(self.apply("flush", prepared, digest, clock=lambda: 1121),
                         ("not_requested", "expired"))
        self.item["queue_name"] = "hold"
        self.assertEqual(self.apply("flush", prepared, digest), ("not_requested", "no_deferred_messages"))
        self.execute.assert_not_called()

    def test_hold_and_release_bound_to_state_and_action(self):
        token = self.selection()
        prepared, digest, detail = self.plan("hold", token, 1000)
        self.assertEqual(detail, "deferred|123|1")
        self.assertEqual(self.apply("hold", prepared, digest, token, 1000), ("command_completed", "none"))
        self.execute.assert_called_once_with("hold", q.SIDECAR_CONFIG, self.item["queue_id"])
        self.execute.reset_mock()
        self.item["queue_name"] = "hold"
        self.assertEqual(self.apply("hold", prepared, digest, token, 1000), ("not_requested", "sample_changed"))
        held_token = self.selection()
        self.assertNotEqual(token, held_token)
        release_time, release_sha, detail = self.plan("release", held_token, 1000)
        self.assertEqual(detail, "held|123|1")
        self.assertEqual(q.retry_review("sidecar", self.nonce, 1000, held_token, self.runner,
            self.options["scope_check"], self.context, now=1060), ("sample_changed", None))
        self.assertEqual(self.apply("release", release_time, release_sha, held_token, 1000),
                         ("command_completed", "none"))
        self.execute.assert_called_once_with("release", q.SIDECAR_CONFIG, self.item["queue_id"])

    def test_fixed_commands_no_wildcards_delete_or_read_runner_writes(self):
        with patch.object(q, "native_binary", side_effect=lambda name: "/usr/sbin/" + name), \
                patch.object(q.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            for action, ident, expected in (
                    ("flush", None, ["/usr/sbin/postqueue", "-c", q.SIDECAR_CONFIG, "-f"]),
                    ("hold", self.item["queue_id"], ["/usr/sbin/postsuper", "-c", q.SIDECAR_CONFIG, "-h", self.item["queue_id"], "deferred"]),
                    ("release", self.item["queue_id"], ["/usr/sbin/postsuper", "-c", q.SIDECAR_CONFIG, "-H", self.item["queue_id"], "hold"])):
                self.assertEqual(q.execute_maintenance(action, q.SIDECAR_CONFIG, ident), "command_completed")
                self.assertEqual(run.call_args[0][0], expected)
                self.assertFalse(q.allowed_args(expected[0].split("/")[-1], expected[1:]))
            for action, ident in (("hold", "ALL"), ("release", "-"), ("flush", "ALL"), ("delete", self.item["queue_id"])):
                with self.assertRaises(ValueError):
                    q.execute_maintenance(action, q.CONFIG, ident)
            self.assertEqual(run.call_count, 3)

    def test_unknown_outcome_is_not_repeated(self):
        prepared, digest, _ = self.plan("flush")
        self.execute.return_value = "outcome_unknown"
        self.assertEqual(self.apply("flush", prepared, digest), ("outcome_unknown", "native_result_unconfirmed"))
        self.execute.assert_called_once()


class MaintenanceGuiContract(unittest.TestCase):
    def test_separate_confirmation_and_fresh_selection(self):
        src = ROOT / "src/LinuxMailRelay365"
        ui = (src / "MainForm.QueueMaintenance.cs").read_text()
        self.assertLess(ui.index("QueueMaintenanceReceipt.Parse(reply.StdOut"), ui.index("ConfirmDestructive("))
        self.assertLess(ui.index("ConfirmDestructive("), ui.index("dispatched = true"))
        self.assertLess(ui.index("dispatched = true"), ui.index("plan.PreparedAt, plan.PlanSha"))
        self.assertIn("onDispatch();", ui)
        self.assertIn("Effect/delivery unverified", ui)
        self.assertIn("FlushPostfixQueueAsync(scope)", (src / "MainForm.MailQueue.cs").read_text())
        self.assertIn("holdRelease.Click", (src / "MainForm.QueueMessages.cs").read_text())
        self.assertIn("QueueMaintenanceReceipt.SelfTest", (src / "Program.cs").read_text())


if __name__ == "__main__":
    unittest.main()
