import importlib.util
import pathlib
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review", ROOT / "linux/review-smtp-tls-rotation.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
CANDIDATE = "candidate-" + "a" * 64
PREVIOUS = "candidate-" + "b" * 64
SHA = "c" * 64


class ReviewedRotationTests(unittest.TestCase):
    def test_changed_plan_never_activates(self):
        activate = Mock()
        with patch.object(M, "load"):
            with self.assertRaises(ValueError):
                M.execute(CANDIDATE, "relay.example.org", SHA,
                    lambda *args: {"plan_sha256": "d" * 64, "apply_supported": True}, activate)
        activate.assert_not_called()

    def test_initial_preview_never_activates(self):
        activate = Mock()
        with patch.object(M, "load"):
            with self.assertRaises(ValueError):
                M.execute(CANDIDATE, "relay.example.org", SHA,
                    lambda *args: {"plan_sha256": SHA, "apply_supported": False}, activate)
        activate.assert_not_called()

    def test_revalidate_under_lock_callback(self):
        prepare = Mock(side_effect=[{"plan_sha256": SHA, "apply_supported": True},
                                    {"plan_sha256": "d" * 64, "apply_supported": True}])
        def fake_activate(root, name, gen, tx, check, reload, validate):
            validate(name)
            self.fail("changed review must not reach switch")
        with patch.object(M, "load"):
            with self.assertRaises(ValueError):
                M.execute(CANDIDATE, "relay.example.org", SHA, prepare, fake_activate)
        self.assertEqual(prepare.call_count, 2)

    def test_approved_activation_uses_transaction(self):
        prepare = Mock(return_value={"plan_sha256": SHA, "apply_supported": True})
        def fake_activate(root, name, gen, tx, check, reload, validate):
            self.assertEqual(name, CANDIDATE)
            validate(name)
            return "reloaded"
        with patch.object(M, "load"):
            result = M.execute(CANDIDATE, "relay.example.org", SHA, prepare, fake_activate)
        self.assertEqual(result["status"], "reloaded")
        self.assertFalse(result["mail_sent"])
        self.assertEqual(result["exchange_acceptance"], "unverified")

    def test_duplicate_journal_field_refused(self):
        with self.assertRaises(ValueError):
            M.strict_object([("phase", "verified"), ("phase", "prepared")])

    def test_invalid_inputs_refused_before_files(self):
        with patch.object(M, "directory") as directory:
            for candidate, domain in (("bad", "relay.example.org"),
                (CANDIDATE, "--bad.example.org"), (CANDIDATE, "relay;id.example.org")):
                with self.assertRaises(ValueError):
                    M.prepare(candidate, domain)
            directory.assert_not_called()

    def test_gui_wiring(self):
        source = ROOT / "src/LinuxMailRelay365"
        self.assertIn("review-smtp-tls-rotation.py", (source / "LinuxMailRelay365.csproj").read_text())
        self.assertIn("BuildSmtpTlsRotation", (source / "EmbeddedAssets.cs").read_text())
        self.assertIn("BuildSmtpTlsRotation", (source / "MainForm.DeliveryMiniWizard.cs").read_text())
        dialog = (source / "SmtpTlsRotationDialog.cs").read_text()
        self.assertIn("plan_sha256", dialog)
        self.assertIn("apply_supported", dialog)
        self.assertIn("MessageBoxDefaultButton.Button2", dialog)
