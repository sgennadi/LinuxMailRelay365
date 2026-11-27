import importlib.util
import pathlib
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review_recovery", ROOT / "linux/review-smtp-tls-rotation.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
activation_spec = importlib.util.spec_from_file_location("activation", ROOT / "linux/smtp-tls-activate.py")
A = importlib.util.module_from_spec(activation_spec)
activation_spec.loader.exec_module(A)
SHA = "a" * 64


class ReviewedRecoveryTests(unittest.TestCase):
    def test_changed_review_never_recovers(self):
        with patch.object(M, "load") as load:
            with self.assertRaises(ValueError):
                M.execute_recovery(SHA, lambda pf: {"plan_sha256": "b"*64, "apply_supported": True})
            self.assertEqual(load.call_count, 1)

    def test_terminal_review_never_recovers(self):
        with patch.object(M, "load"):
            with self.assertRaises(ValueError):
                M.execute_recovery(SHA, lambda pf: {"status": "no_pending_transaction", "apply_supported": False})

    def test_recovery_checks_review_inside_lock(self):
        from contextlib import contextmanager
        events = []
        @contextmanager
        def lock(root):
            events.append("locked")
            yield
            events.append("unlocked")
        tx = Mock()
        tx.deployment_lock = lock
        def refuse():
            events.append("review")
            raise ValueError("stale review")
        gen = Mock()
        with self.assertRaises(ValueError):
            A.recover(pathlib.Path("/nonexistent"), gen, tx, Mock(), Mock(), before_recover=refuse)
        self.assertEqual(events, ["locked", "review"])
        gen.validate.assert_not_called()
        gen.switch.assert_not_called()

    def test_reviewed_rotation_recovery_callback(self):
        pf = Mock()
        activation = Mock()
        modules = {"smtp-tls-postfix": Mock(Postfix=Mock(return_value=pf)),
                   "smtp-tls-transaction": Mock(), "smtp-tls-activate": activation,
                   "smtp-tls-generation": Mock()}
        plan = Mock(return_value={"plan_sha256": SHA, "apply_supported": True, "mode": "rotation"})
        def recover(*args, **kwargs):
            kwargs["before_recover"]()
            return "restored"
        activation.recover.side_effect = recover
        with patch.object(M, "load", side_effect=lambda name: modules[name]):
            result = M.execute_recovery(SHA, plan)
        self.assertEqual(plan.call_count, 2)
        self.assertEqual(result["status"], "restored")
        self.assertFalse(result["mail_sent"])

    def test_backup_path_and_hash_refusals(self):
        for state in ({"backup": "../outside"},
                      {"backup": "initial-backup-abc", "original_sha256": SHA, "candidate_sha256": SHA}):
            with patch.object(M, "directory") as directory:
                with self.assertRaises(ValueError):
                    M.verified_backup(state)
                directory.assert_not_called()

    def test_gui_wiring_and_confirmation(self):
        src = ROOT / "src/LinuxMailRelay365"
        dialog = (src / "SmtpTlsRotationDialog.cs").read_text()
        assets = (src / "EmbeddedAssets.cs").read_text()
        self.assertIn('remote("recovery-preview", null, null, null)', dialog)
        self.assertIn('remote("recover", null, null, sha)', dialog)
        self.assertIn("MessageBoxDefaultButton.Button2", dialog)
        self.assertIn('action == "recover"', assets)
