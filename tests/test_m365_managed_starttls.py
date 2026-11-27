import importlib.util
import pathlib
from contextlib import nullcontext
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("managed", ROOT / "linux/inspect-m365-managed-starttls.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
MX = "example-org.mail.protection.outlook.com"
GEN = "candidate-" + "a"*64


class ManagedStartTlsTests(unittest.TestCase):
    def setUp(self):
        self.review = Mock()
        self.review.ROOT = pathlib.Path("/etc/postfix/lmr365-smtp-tls")
        self.review.active_generation.return_value = GEN
        self.review.config_state.return_value = {"main_sha256": "a"*64}
        self.review.terminal_journals.return_value = {"deployment.json": "absent"}
        self.review.read_file.return_value = b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"
        self.pf = Mock()
        settings = {"relayhost": "["+MX+"]:25", "smtp_sasl_auth_enable": "no", "smtp_tls_security_level": "encrypt"}
        self.pf.run.side_effect = lambda *args: settings.get(args[-1], "")
        self.tls = Mock()
        self.tls.inspect.return_value = {"status": "diagnosis", "mail_sent": False, "exchange_connector_verified": False}

    def run_probe(self):
        with patch.object(M.os, "geteuid", return_value=0):
            return M.inspect(MX, self.tls, self.review, self.pf)

    def test_active_identity_loaded_without_claiming_presentation(self):
        result = self.run_probe()
        args, kwargs = self.tls.context.return_value.load_cert_chain.call_args
        self.assertEqual(args, (str(self.review.ROOT/GEN/"fullchain.pem"), str(self.review.ROOT/GEN/"key.pem")))
        self.assertIs(kwargs["password"], M.password_refused)
        self.assertTrue(result["client_certificate_loaded"])
        self.assertFalse(result["client_certificate_presentation_verified"])
        self.assertFalse(result["mail_sent"])
        self.assertEqual(result["client_generation"], GEN)

    def test_wrong_route_refused_before_key_load(self):
        self.pf.run.side_effect = lambda *args: "[other.mail.protection.outlook.com]:25"
        with self.assertRaises(ValueError):
            self.run_probe()
        self.tls.context.assert_not_called()
        self.tls.inspect.assert_not_called()

    def test_generation_change_refused_before_network(self):
        self.review.active_generation.side_effect = [GEN, "candidate-"+"b"*64]
        with self.assertRaises(ValueError):
            self.run_probe()
        self.tls.inspect.assert_not_called()

    def test_changed_generation_after_probe_invalidates_result(self):
        self.review.active_generation.side_effect = [GEN, GEN, "candidate-"+"b"*64]
        with self.assertRaises(ValueError):
            self.run_probe()
        self.tls.inspect.assert_called_once()

    def test_key_failure_no_fallback(self):
        self.tls.context.return_value.load_cert_chain.side_effect = ValueError("synthetic")
        with self.assertRaises(ValueError):
            self.run_probe()
        self.tls.inspect.assert_not_called()

    def test_non_root_refused(self):
        with patch.object(M.os, "geteuid", return_value=1000):
            with self.assertRaises(ValueError):
                M.inspect(MX, self.tls, self.review, self.pf)
        self.tls.context.assert_not_called()

    def test_encrypted_key_callback_refused(self):
        with self.assertRaises(ValueError):
            M.password_refused()

    def test_service_override_refused_before_network(self):
        original = self.pf.run.side_effect
        self.pf.run.side_effect = lambda *args: (
            "smtp/unix/relayhost=[other.example.org]:25" if args[-1] == "-P" else original(*args))
        with self.assertRaises(ValueError):
            self.run_probe()
        self.tls.context.assert_not_called()
        self.tls.inspect.assert_not_called()


class CandidateStartTlsTests(unittest.TestCase):
    # Reuse the setup without invoking a real SMTP server.
    def candidate_probe(self):
        with patch.object(M.os, "geteuid", return_value=0):
            return M.inspect_candidate(MX, GEN, "relay.example.org", self.tls, self.review,
                                       self.validator, lambda _: nullcontext())

    def setUp(self):
        ManagedStartTlsTests.setUp(self)
        self.review.active_generation.return_value = None
        self.validator = Mock(return_value={"status": "local_checks_passed"})

    def test_inactive_candidate_no_activation_or_presentation_claim(self):
        result = self.candidate_probe()
        self.assertEqual(result["client_identity_mode"], "inactive_candidate")
        self.assertEqual(result["client_generation"], GEN)
        self.assertEqual(result["certificate_domain"], "relay.example.org")
        self.assertTrue(result["active_generation_unchanged"])
        for flag in ("activation_attempted", "postfix_modified", "mail_sent", "client_certificate_presentation_verified", "exchange_connector_verified"):
            self.assertFalse(result[flag])
        self.assertEqual(self.review.verify_files.call_count, 3)
        self.validator.assert_called_once()
        self.tls.inspect.assert_called_once()

    def test_ineligible_candidate_never_connects(self):
        self.validator.return_value = {"status": "refused"}
        with self.assertRaises(ValueError):
            self.candidate_probe()
        self.tls.context.assert_not_called()
        self.tls.inspect.assert_not_called()

    def test_active_candidate_rejected(self):
        self.review.active_generation.return_value = GEN
        with self.assertRaises(ValueError):
            self.candidate_probe()
        self.tls.inspect.assert_not_called()

    def test_active_pointer_drift_refuses_network(self):
        self.review.active_generation.side_effect = [None, "candidate-"+"b"*64]
        with self.assertRaises(ValueError):
            self.candidate_probe()
        self.tls.inspect.assert_not_called()
