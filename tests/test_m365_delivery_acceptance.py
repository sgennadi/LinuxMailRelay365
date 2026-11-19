"""Mock-only delivery acceptance: no real SMTP, no Microsoft tenant, no TPM."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "linux" / "manage-m365-delivery-acceptance.py"
spec = importlib.util.spec_from_file_location("m365_acceptance", str(SOURCE))
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class DeliveryAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.request = {
            "internal": "internal@example.org",
            "external": "external@outside.net",
            "run_id": "a" * 32,
        }
        self.identity = {
            "mailbox": "system@example.org",
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "certificate": "/etc/linuxmailrelay365/sidecar-identity/hardware-app.crt",
            "signer": {"type": "openssl-provider", "provider": "tpm2",
                       "provider_config": "/etc/linuxmailrelay365/sidecar-identity/tpm2.cnf"},
        }
        self.identity_bytes = json.dumps(self.identity).encode("ascii")
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(M, "require_root"))
        self.stack.enter_context(mock.patch.object(M, "trusted_dir"))
        self.stack.enter_context(mock.patch.object(M.grp, "getgrnam",
                                 return_value=SimpleNamespace(gr_gid=31)))
        self.read = self.stack.enter_context(mock.patch.object(M, "checked_read",
                     side_effect=lambda p, *a, **kw:
                     self.identity_bytes if str(p).endswith("/app.json")
                     else b"# approved --acceptance-test executable"))
        self.plan = M.prepare("sidecar", self.request)

    def test_plan_secretless_readonly_and_domain_classification(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            M.print_plan(self.plan)
        status = out.getvalue()
        self.assertIn("SMTP_ACCEPTANCE_READY_FOR_APPROVED_TEST=yes", status)
        self.assertIn("SMTP_ACCEPTANCE_MAIL_SENT=no", status)
        self.assertIn("SMTP_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED=no", status)
        self.assertNotIn(self.request["internal"], status)
        self.assertNotIn(self.request["external"], status)
        self.assertEqual(self.plan["sha"], M.prepare("sidecar", self.request)["sha"])
        altered = dict(self.request, external="second@outside.net")
        self.assertNotEqual(self.plan["sha"], M.prepare("sidecar", altered)["sha"])

    def test_reject_wrong_internal_external_classification_and_nonhardware(self):
        for bad in [
            dict(self.request, internal="some@outside.net"),
            dict(self.request, external="other@example.org"),
            dict(self.request, external="internal@example.org"),
        ]:
            with self.subTest(bad=bad), self.assertRaisesRegex(M.Refused, "mismatch"):
                M.prepare("sidecar", bad)
        self.identity["private_key"] = "/tmp/key.pem"
        self.identity_bytes = json.dumps(self.identity).encode("ascii")
        with self.assertRaisesRegex(M.Refused, "active_hardware"):
            M.prepare("sidecar", self.request)

    def test_invalid_addresses_not_accepted(self):
        for recipient in ("a@localhost", "any\n@outside.net", "a;rm@outside.net",
                          "bad..@outside.net", "a@outside.net\nMAIL FROM:root"):
            self.assertFalse(bool(M.MAILBOX.fullmatch(recipient)),
                             "unexpected invalid address: " + repr(recipient))
        self.assertTrue(bool(M.MAILBOX.fullmatch("test@outside.net")))

    def test_apply_requires_correct_confirmation_before_lock_or_sends(self):
        with mock.patch.object(M, "lock") as lck:
            for approval, confirm in ((self.plan["sha"], "NO"),
                                      ("invalidsha", M.CONFIRM)):
                with self.assertRaisesRegex(M.Refused, "approved_sha_and_typed"):
                    M.apply("sidecar", self.request, approval, confirm)
            lck.assert_not_called()

    def _apply(self, response_codes=(0, 0), expect_failure=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "ledger"
            with mock.patch.object(M, "LEDGER_ROOT", root), \
                 mock.patch.object(M, "lock",
                                   side_effect=lambda: os.open(os.devnull, os.O_RDONLY)), \
                 mock.patch.object(M.shutil, "which", return_value="/usr/sbin/runuser"):
                seen = []
                def fake_runner(argv, **kwargs):
                    data = json.loads(kwargs["input"])
                    seen.append((argv, kwargs, data))
                    self.assertNotIn("--candidate-config", argv)
                    self.assertIn("--acceptance-test", argv)
                    self.assertNotIn("--recipient", argv)
                    self.assertEqual(kwargs["stdout"], M.subprocess.DEVNULL)
                    self.assertEqual(kwargs["stderr"], M.subprocess.DEVNULL)
                    self.assertEqual(kwargs["check"], False)
                    self.assertEqual(argv[-1],
                                     "/etc/linuxmailrelay365/sidecar-identity/app.json")
                    return SimpleNamespace(returncode=response_codes[len(seen)-1])
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    if expect_failure:
                        with self.assertRaisesRegex(M.Refused, expect_failure):
                            M.apply("sidecar", self.request, self.plan["sha"],
                                    M.CONFIRM, runner=fake_runner)
                    else:
                        M.apply("sidecar", self.request, self.plan["sha"],
                                M.CONFIRM, runner=fake_runner)
                ledger = root / (self.request["run_id"] + ".jsonl")
                rows = [json.loads(line) for line in ledger.read_text().splitlines()]
                self.assertNotIn(self.request["internal"], ledger.read_text())
                self.assertNotIn(self.request["external"], ledger.read_text())
                with self.assertRaises(FileExistsError):
                    M.apply("sidecar", self.request, self.plan["sha"],
                            M.CONFIRM, runner=fake_runner)
                return seen, rows, out.getvalue()

    def test_success_sends_exactly_one_to_each_address(self):
        seen, rows, status = self._apply()
        self.assertEqual([entry[2]["role"] for entry in seen], ["internal", "external"])
        self.assertEqual([entry[2]["recipient"] for entry in seen],
                         [self.request["internal"], self.request["external"]])
        self.assertEqual([row["status"] for row in rows],
                         ["reserved", "attempted", "smtp_accepted_not_inbox_verified",
                          "attempted", "smtp_accepted_not_inbox_verified",
                          "smtp_submissions_complete"])
        self.assertIn("SMTP_ACCEPTANCE_TWO_SMTP_SUBMISSIONS_ACCEPTED=yes", status)
        self.assertIn("SMTP_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED=no", status)

    def test_failed_internal_cannot_send_external(self):
        seen, rows, status = self._apply(response_codes=(75,), expect_failure="internal_smtp_not_accepted")
        self.assertEqual(len(seen), 1)
        self.assertEqual([row["stage"] for row in rows], ["run", "internal"])

    def test_failed_external_leaves_single_attempt_per_target(self):
        seen, rows, status = self._apply(response_codes=(0, 75), expect_failure="external_smtp_not_accepted")
        self.assertEqual(len(seen), 2)
        self.assertEqual(rows[-1]["status"], "attempted")
        self.assertNotIn("TWO_SMTP_SUBMISSIONS_ACCEPTED=yes", status)

    def test_no_real_smtp_or_credential_output_in_manager(self):
        code = SOURCE.read_text(encoding="utf-8")
        for forbidden in ["--recipient\",", "subprocess.Popen", "tpm2_evictcontrol",
                          "rm -rf", "apt-get install", "dnf install", "sendmail("]:
            self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
