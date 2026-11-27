import contextlib
import importlib.util
import pathlib
import re
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("selinux", ROOT / "linux/review-smtp-tls-selinux.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
GEN = "candidate-" + "a" * 64
SHA = "b" * 64


class SelinuxReviewTests(unittest.TestCase):
    def setUp(self):
        self.review = Mock()
        self.review.ROOT = pathlib.Path("/etc/postfix/lmr365-smtp-tls")
        self.review.GEN = re.compile(r"candidate-[a-f0-9]{64}")
        self.review.PENDING_PHASES = ("prepared", "switched", "rollback_required")
        self.review.active_generation.return_value = None
        self.review.recovery_journal.return_value = (None, "absent")
        self.review.digest.return_value = SHA
        self.adapter = Mock()
        self.tx = Mock()
        self.tx.deployment_lock.side_effect = lambda _: contextlib.nullcontext()

    def row(self, path, adapter, repairable):
        return {"path": str(path), "kind": "directory", "actual": "system_u:object_r:etc_t:s0",
                "expected": "system_u:object_r:postfix_etc_t:s0", "matches": not repairable,
                "repairable": repairable, "identity": [1, 2, 0, 0, 448, 1]}

    def test_enforcing_preview_never_relabels(self):
        with patch.object(M.os, "geteuid", return_value=0), \
             patch.object(M, "command", return_value="Enforcing") as cmd, \
             patch.object(M, "label_row", side_effect=self.row):
            plan = M.review_plan(GEN, self.review, self.adapter)
        self.assertTrue(plan["apply_supported"])
        self.assertEqual(plan["mode"], "enforcing")
        self.assertEqual(len(plan["changes"]), 5)
        self.assertFalse(plan["access_verified"])
        cmd.assert_called_once_with(self.adapter, "/usr/sbin/getenforce")

    def test_pending_transaction_blocks_repair(self):
        self.review.recovery_journal.return_value = ({"phase": "prepared"}, SHA)
        with patch.object(M.os, "geteuid", return_value=0), \
             patch.object(M, "command", return_value="Enforcing"), \
             patch.object(M, "label_row", side_effect=self.row):
            self.assertEqual(M.review_plan(GEN, self.review, self.adapter)["reason"], "pending_transaction")

    def test_parent_mismatch_blocks_repair(self):
        def row(path, adapter, repairable):
            return dict(self.row(path, adapter, repairable), matches=False)
        with patch.object(M.os, "geteuid", return_value=0), \
             patch.object(M, "command", return_value="Enforcing"), \
             patch.object(M, "label_row", side_effect=row):
            plan = M.review_plan(GEN, self.review, self.adapter)
        self.assertFalse(plan["apply_supported"])
        self.assertEqual(plan["reason"], "parent_or_pointer_context_requires_manual_review")

    def test_changed_sha_or_outside_path_never_relabels(self):
        with patch.object(M, "command") as cmd:
            for plan in ({"plan_sha256": "c"*64, "apply_supported": True},
                         {"plan_sha256": SHA, "apply_supported": True, "changes": ["/etc/passwd"]}):
                with self.assertRaises(ValueError):
                    M.execute(GEN, SHA, self.review, self.adapter, self.tx, lambda *args: plan)
            cmd.assert_not_called()

    def test_exact_restore_and_recheck(self):
        path = self.review.ROOT / GEN
        row = self.row(path, self.adapter, True)
        before = {"plan_sha256": SHA, "apply_supported": True, "changes": [str(path)],
                  "mode": "enforcing", "active": None, "journals": {}, "paths": [row]}
        after = dict(before, reason="contexts_match", paths=[dict(row, matches=True, actual=row["expected"])])
        with patch.object(M, "command") as cmd:
            result = M.execute(GEN, SHA, self.review, self.adapter, self.tx, Mock(side_effect=[before, after]))
        cmd.assert_called_once_with(self.adapter, "/usr/sbin/restorecon", str(path))
        self.assertEqual(result["status"], "contexts_verified")
        self.assertFalse(result["access_verified"])
        self.assertFalse(result["policy_changed"])

    def test_invalid_context_rejected(self):
        for label in ("", "unlabeled", "u:r:t:s0\nextra", "u:r:t:s0;cmd"):
            with self.assertRaises(ValueError):
                M.safe_label(label)
