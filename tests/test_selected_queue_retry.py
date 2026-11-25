"""Selected Retry uses a single fixed scheduling command, never actual mail in unit tests."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("retry_product", str(ROOT / "linux/inspect-mail-queue.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


class SelectedRetryTests(unittest.TestCase):
    def setUp(self):
        self.id = "3Pt2mN2VXxznjll"
        self.item = dict(queue_id=self.id, queue_name="deferred", arrival_time=940,
                         message_size=123, sender="private@example.invalid",
                         recipients=[dict(address="recipient@example.invalid", delay_reason="TLS certificate")])
        self.nonce = "a" * 64
        self.before = (q.SIDECAR_CONFIG, q.SIDECAR_QUEUE, (1, 2))
        self.scope = lambda *_: self.before
        self.context = lambda *_: ("sidecar", self.before, "mail.example.invalid", "boot")
        self.runner = Mock(side_effect=lambda *_: json.dumps(self.item))
        self.scheduler = Mock(return_value="request_accepted")
        _, _, rows, _, _ = q.reviewable_inventory("sidecar", self.nonce, self.runner,
                                                  self.scope, self.context, now=1000)
        self.token = rows[0][-1]
        result, _, self.prepared, self.approved = q.retry_prepare(
            "sidecar", self.nonce, 1000, self.token, self.runner, self.scope, self.context, now=1060)
        self.assertEqual(result, "candidate_review_only")
        self.assertRegex(self.approved, r"^[a-f0-9]{64}$")
        self.runner.reset_mock()

    def apply(self, **overrides):
        options = dict(scope="sidecar", nonce=self.nonce, sampled_at=1000, token=self.token,
                       prepared_at=self.prepared, approved=self.approved, confirm=q.RETRY_CONFIRM,
                       runner=self.runner, scope_check=self.scope, context_check=self.context,
                       scheduler=self.scheduler, clock=lambda: 1070, monotonic=lambda: 10)
        options.update(overrides)
        return q.retry_apply(**options)

    def test_two_rechecks_one_scoped_request_and_receipt_privacy(self):
        self.assertEqual(self.apply(), ("request_accepted", "none"))
        self.scheduler.assert_called_once_with(q.SIDECAR_CONFIG, self.id)
        self.assertEqual(self.runner.call_count, 2)
        for call in self.runner.call_args_list:
            self.assertEqual(call.args, ("postqueue", ["-c", q.SIDECAR_CONFIG, "-j"]))
        receipt = "\n".join(q.retry_apply_lines("sidecar", self.token, 1000, self.prepared,
                                              self.approved, "request_accepted", "none"))
        self.assertIn("MAIL_RETRY_APPLY_DELIVERY_VERIFIED=no", receipt)
        self.assertIn("MAIL_RETRY_APPLY_REQUEST_COUNT=1", receipt)
        self.assertIn("MAIL_RETRY_APPLY_ATOMIC=no", receipt)
        self.assertNotIn(self.id, receipt)
        self.assertNotIn("example.invalid", receipt)

    def test_expiration_invalid_confirmation_and_plan_never_schedule(self):
        with self.assertRaises(ValueError):
            self.apply(confirm="wrong")
        self.assertEqual(self.apply(clock=lambda: 1121), ("not_requested", "expired"))
        self.assertEqual(self.apply(clock=lambda: 1059), ("not_requested", "expired"))
        self.assertEqual(self.apply(approved="b" * 64), ("not_requested", "plan_changed"))
        self.scheduler.assert_not_called()

    def test_changed_message_instance_or_reason_refused(self):
        for key, value in (("queue_name", "active"), ("message_size", 124),
                           ("queue_id", "ABCDEF"), ("sender", "changed@example.invalid")):
            original = self.item[key]
            self.item[key] = value
            try:
                self.assertEqual(self.apply(), ("not_requested", "sample_changed"))
            finally:
                self.item[key] = original
        self.item["recipients"][0]["delay_reason"] = "connection refused"
        self.assertEqual(self.apply(), ("not_requested", "plan_changed"))
        self.scheduler.assert_not_called()

    def test_second_scan_and_clock_jump_refused(self):
        original = json.dumps(self.item)
        changed = json.dumps(dict(self.item, queue_name="active"))
        self.assertEqual(self.apply(runner=Mock(side_effect=[original, changed])),
                         ("not_requested", "sample_changed"))
        clock = iter([1070, 1070, 1070, 1080])
        self.assertEqual(self.apply(clock=lambda: next(clock)), ("not_requested", "expired"))
        self.scheduler.assert_not_called()

    def test_native_failure_never_automatically_retries(self):
        self.scheduler.return_value = "outcome_unknown"
        self.assertEqual(self.apply(), ("outcome_unknown", "native_result_unconfirmed"))
        self.scheduler.assert_called_once()
        with patch.object(q, "native_binary", return_value="/usr/sbin/postqueue"), \
                patch.object(q.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(q.schedule_selected_retry(q.CONFIG, self.id), "request_accepted")
            self.assertEqual(run.call_args[0][0], ["/usr/sbin/postqueue", "-c", q.CONFIG, "-i", self.id])
            self.assertIs(run.call_args[1]["stdout"], subprocess.DEVNULL)
            self.assertIs(run.call_args[1]["stderr"], subprocess.DEVNULL)
            with self.assertRaises(ValueError):
                q.schedule_selected_retry(q.CONFIG, "ALL")
            with self.assertRaises(ValueError):
                q.schedule_selected_retry("/tmp/evil", self.id)
            run.assert_called_once()
        self.assertFalse(q.allowed_args("postqueue", ["-c", q.CONFIG, "-i", self.id]))
        with patch.object(q, "native_binary", return_value="/usr/sbin/postqueue"), \
                patch.object(q.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 12)) as run:
            self.assertEqual(q.schedule_selected_retry(q.CONFIG, self.id), "outcome_unknown")
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
