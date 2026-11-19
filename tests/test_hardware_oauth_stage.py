"""TPM/HSM candidate generation is root-only, opt-in and no mail is sent."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "linux" / "manage-hardware-oauth-cutover.py"
SPEC = importlib.util.spec_from_file_location("cutover_stage", str(SOURCE))
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)


class HardwareStageTests(unittest.TestCase):
    def setUp(self):
        self.directory = STAGE.TARGETS["sidecar"][0]
        self.active = {
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "mailbox": "sender@example.org",
            "certificate": str(self.directory / "app.crt"),
            "private_key": str(self.directory / "app.key")}
        self.active_raw = (json.dumps(self.active) + "\n").encode()
        self.provider = "tpm2"
        self.key_ref = "handle:0x81000001"
        self.guard = contextlib.ExitStack()
        self.addCleanup(self.guard.close)
        self.guard.enter_context(mock.patch.object(STAGE, "checked_directory"))
        self.guard.enter_context(mock.patch.object(STAGE.grp, "getgrnam",
                             return_value=SimpleNamespace(gr_gid=31)))
        self.guard.enter_context(mock.patch.object(STAGE, "read_identity",
                             return_value=(self.active_raw, self.active)))
        self.guard.enter_context(mock.patch.object(STAGE, "original_preflight"))
        self.guard.enter_context(mock.patch.object(STAGE, "read_checked",
                             return_value=b"trusted-provider-bytes"))
        self.guard.enter_context(mock.patch.object(STAGE, "ensure_runtime",
                             return_value="/usr/sbin/runuser"))

    def plan(self, provider="tpm2", ref="handle:0x81000001"):
        return STAGE.stage_prepare("sidecar", provider, ref)

    def test_review_generates_a_candidate_with_same_sender_and_no_pem(self):
        plan = self.plan()
        candidate = json.loads(plan["candidate_raw"])
        self.assertNotIn("private_key", candidate)
        self.assertEqual(candidate["mailbox"], self.active["mailbox"])
        self.assertEqual(candidate["tenant_id"], self.active["tenant_id"])
        self.assertEqual(candidate["client_id"], self.active["client_id"])
        self.assertEqual(candidate["certificate"], str(self.directory / "hardware-app.crt"))
        self.assertEqual(candidate["signer"], {
            "type": "openssl-provider", "provider": "tpm2",
            "key_ref": self.key_ref, "provider_config": str(self.directory / "tpm2.cnf")})
        self.assertEqual(plan["request_source"], "reviewed_wizard_arguments")
        self.assertEqual(plan["sha"], self.plan()["sha"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            STAGE.stage_report(plan)
        self.assertIn("HARDWARE_STAGE_STAGED=no", buf.getvalue())
        self.assertIn("HARDWARE_STAGE_ROUTING_IDENTITY_UNCHANGED=yes", buf.getvalue())
        self.assertNotIn(self.active["mailbox"], buf.getvalue())

    def test_supports_pkcs11_and_rejects_secret_or_software_ref(self):
        plan = self.plan("pkcs11", "pkcs11:object=smtp;type=private")
        self.assertEqual(plan["candidate"]["signer"]["provider_config"],
                         str(self.directory / "pkcs11.cnf"))
        for bad in ("pkcs11:object=secret;pin-value=123;type=private",
                    "pkcs11:module-path=/tmp/bad;object=smtp;type=private",
                    "file:/etc/private.pem"):
            with self.subTest(ref=bad), self.assertRaises(STAGE.Refused):
                self.plan("pkcs11", bad)
        with self.assertRaises(STAGE.Refused):
            self.plan("tpm2", "/tmp/key.pem")

    def test_already_staged_never_overwritten(self):
        with mock.patch.object(STAGE.Path, "exists", return_value=True):
            with self.assertRaisesRegex(STAGE.Refused, "candidate_already_exists"):
                self.plan()

    def test_no_approval_or_sha_drift_can_stage(self):
        plan = self.plan()
        with mock.patch.object(STAGE, "ensure_root"), \
             mock.patch.object(STAGE, "lock", return_value=10), \
             mock.patch.object(STAGE.os, "close"), \
             mock.patch.object(STAGE, "stage_prepare", return_value=plan), \
             mock.patch.object(STAGE, "stage_identity") as write:
            with self.assertRaisesRegex(STAGE.Refused, "confirmation"):
                STAGE.stage_apply("sidecar", plan["sha"], "WRONG", self.provider, self.key_ref)
            with self.assertRaisesRegex(STAGE.Refused, "plan_changed"):
                STAGE.stage_apply("sidecar", "a" * 64, STAGE.CONFIRM_STAGE,
                                  self.provider, self.key_ref)
            write.assert_not_called()

    def _simulate_stage(self, fail_sign=False):
        plan = self.plan()
        refs = dict(plan["references"])
        def verified_bytes(path, *args, **kw):
            path = str(path)
            if path.endswith("/hardware-staged.json"):
                return plan["candidate_raw"]
            if path.endswith("/app.json"):
                return self.active_raw
            return b"trusted-provider-bytes"
        events = []
        def create(_plan):
            events.append("stage")
        def sign(_plan, candidate, token_check, _runner):
            events.append("signature")
            self.assertTrue(candidate)
            self.assertFalse(token_check)
            if fail_sign:
                raise STAGE.Refused("ps256_preflight_failed")
        # Only the final part of the staging operation is mocked;
        # no filesystem data, token, TPM device or SMTP is ever used.
        with mock.patch.object(STAGE, "ensure_root"), \
             mock.patch.object(STAGE, "lock", return_value=10), \
             mock.patch.object(STAGE.os, "close"), \
             mock.patch.object(STAGE, "stage_prepare", return_value=plan), \
             mock.patch.object(STAGE, "stage_identity", side_effect=create), \
             mock.patch.object(STAGE, "read_checked", side_effect=verified_bytes), \
             mock.patch.object(STAGE, "reference_hashes",
                               return_value={k: v for k, v in refs.items()
                                             if k not in ("transport", "signer_module")}), \
             mock.patch.object(STAGE, "checked_run", side_effect=sign), \
             mock.patch.object(STAGE.Path, "unlink") as unlink, \
             mock.patch.object(STAGE, "fsync_dir"), \
             contextlib.redirect_stdout(io.StringIO()) as log:
            if fail_sign:
                with self.assertRaisesRegex(STAGE.Refused,
                                            "stage_signing_failed_candidate_removed"):
                    STAGE.stage_apply("sidecar", plan["sha"], STAGE.CONFIRM_STAGE,
                                      self.provider, self.key_ref)
                unlink.assert_called_once()
            else:
                STAGE.stage_apply("sidecar", plan["sha"], STAGE.CONFIRM_STAGE,
                                  self.provider, self.key_ref)
                unlink.assert_not_called()
        return events, log.getvalue()

    def test_successful_stage_never_contacts_entra(self):
        events, report = self._simulate_stage()
        self.assertEqual(events, ["stage", "signature"])
        self.assertIn("HARDWARE_STAGE_STAGED=yes", report)
        self.assertIn("HARDWARE_STAGE_LOCAL_PS256_VERIFIED=yes", report)
        self.assertIn("HARDWARE_STAGE_ENTRA_CONTACTED=no", report)
        self.assertIn("HARDWARE_STAGE_KEY_CREATED=no", report)
        self.assertIn("HARDWARE_STAGE_PRIMARY_MTA_CHANGED=no", report)

    def test_failed_signature_removes_only_our_new_candidate(self):
        events, _ = self._simulate_stage(fail_sign=True)
        self.assertEqual(events, ["stage", "signature"])

    def test_cli_disallows_provider_and_key_on_unrelated_actions(self):
        with mock.patch.object(STAGE, "ensure_root"), \
             contextlib.redirect_stdout(io.StringIO()) as report:
            self.assertEqual(STAGE.main([
                "--target", "sidecar", "--plan", "--stage-provider", "tpm2",
                "--stage-key-ref", "handle:0x81000001"]), 2)
            self.assertIn("HARDWARE_CUTOVER_ERROR=stage_reference_arguments_invalid",
                          report.getvalue())
        with mock.patch.object(STAGE, "ensure_root"), \
             mock.patch.object(STAGE, "stage_prepare", return_value=self.plan()), \
             mock.patch.object(STAGE, "stage_report") as preview:
            self.assertEqual(STAGE.main([
                "--target", "sidecar", "--stage-plan", "--stage-provider", "tpm2",
                "--stage-key-ref", "handle:0x81000001"]), 0)
            preview.assert_called_once()

    def test_partial_publish_fsync_failure_removes_our_candidate(self):
        import errno
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            (directory / "app.json").write_text("{}")
            raw = b'{"candidate":"one"}\n'
            plan = {"directory": directory, "gid": 31,
                    "candidate_raw": raw, "candidate_sha": STAGE.digest(raw)}
            with mock.patch.object(STAGE.os, "fchown"), \
                 mock.patch.object(STAGE, "checked_file"), \
                 mock.patch.object(STAGE.os, "getxattr",
                                   side_effect=OSError(errno.ENODATA, "no label")), \
                 mock.patch.object(STAGE, "fsync_dir",
                                   side_effect=[OSError("disk flush failure"), None]), \
                 mock.patch.object(STAGE, "read_checked", return_value=raw):
                with self.assertRaisesRegex(STAGE.Refused,
                                            "stage_publish_refused_without_live_change"):
                    STAGE.stage_identity(plan)
            self.assertFalse((directory / "hardware-staged.json").exists())
            self.assertEqual(list(directory.glob(".hardware-staged-*")), [])

    def test_existing_candidate_never_replaced_on_exclusive_link_failure(self):
        import errno
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            (directory / "app.json").write_text("{}")
            existing = directory / "hardware-staged.json"
            existing.write_bytes(b"existing identity")
            raw = b'{"candidate":"new"}\n'
            plan = {"directory": directory, "gid": 31,
                    "candidate_raw": raw, "candidate_sha": STAGE.digest(raw)}
            with mock.patch.object(STAGE.os, "fchown"), \
                 mock.patch.object(STAGE, "checked_file"), \
                 mock.patch.object(STAGE.os, "getxattr",
                                   side_effect=OSError(errno.ENODATA, "no label")):
                with self.assertRaisesRegex(STAGE.Refused,
                                            "stage_publish_refused_without_live_change"):
                    STAGE.stage_identity(plan)
            self.assertEqual(existing.read_bytes(), b"existing identity")
            self.assertEqual(list(directory.glob(".hardware-staged-*")), [])

    def test_no_key_generation_or_mta_commands_in_stage_path(self):
        text = SOURCE.read_text(encoding="utf-8")
        for bad in ("tpm2_clear", "tpm2_create", "openssl genpkey",
                    "systemctl restart", "systemctl stop postfix",
                    "apt-get install", "dnf install"):
            self.assertNotIn(bad, text)


if __name__ == "__main__":
    unittest.main()
