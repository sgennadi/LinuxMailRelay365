"""No real TPM, Entra or MTA is accessed in guarded cutover tests."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "linux" / "manage-hardware-oauth-cutover.py"
SPEC = importlib.util.spec_from_file_location("manage_hardware_oauth_cutover", str(SOURCE))
CUT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CUT)


class HardwareOAuthCutoverTests(unittest.TestCase):
    def setUp(self):
        self.old = b'{"mode":"old"}\n'
        self.new = b'{"mode":"hardware"}\n'
        self.active = self.old
        self.target = "sidecar"
        self.directory = CUT.TARGETS[self.target][0]
        self.identity = {"tenant_id": "11111111-1111-1111-1111-111111111111",
                         "client_id": "22222222-2222-2222-2222-222222222222",
                         "mailbox": "app@example.org", "certificate": str(self.directory / "app.crt"),
                         "private_key": str(self.directory / "app.key")}
        self.staged = {k: v for k, v in self.identity.items() if k != "private_key"}
        self.staged["signer"] = {
            "type": "openssl-provider", "provider": "tpm2",
            "key_ref": "handle:0x81000001",
            "provider_config": str(self.directory / "tpm2.cnf")}
        self.plan = {"target": self.target, "directory": self.directory,
                     "transport": CUT.TARGETS[self.target][1],
                     "runuser": "/usr/sbin/runuser", "gid": 30,
                     "active_raw": self.old, "staged_raw": self.new,
                     "active": self.identity, "staged": self.staged,
                     "active_sha": CUT.digest(self.old), "staged_sha": CUT.digest(self.new),
                     "sha": "c" * 64}

    def test_unchanged_routing_required_and_software_fallback_denied(self):
        with mock.patch.object(CUT, "read_checked", return_value=b"mock cert/key data"):
            CUT.check_candidate(self.identity, self.staged, self.directory, 30)
            changes = dict(self.staged, mailbox="attacker@example.org")
            with self.assertRaisesRegex(CUT.Refused, "tenant_client_or_sender_change_forbidden"):
                CUT.check_candidate(self.identity, changes, self.directory, 30)
            changes = dict(self.staged, private_key=str(self.directory / "app.key"))
            with self.assertRaisesRegex(CUT.Refused, "pem_fallback"):
                CUT.check_candidate(self.identity, changes, self.directory, 30)
            changes = dict(self.staged, signer=dict(self.staged["signer"], key_ref="/tmp/key.pem"))
            with self.assertRaisesRegex(CUT.Refused, "unsupported_tpm_handle"):
                CUT.check_candidate(self.identity, changes, self.directory, 30)
            changes = dict(self.staged, certificate="/etc/other.crt")
            with self.assertRaisesRegex(CUT.Refused, "certificate_outside"):
                CUT.check_candidate(self.identity, changes, self.directory, 30)

    def test_review_plan_differs_for_active_or_staged_or_dependency_change(self):
        base = {"version": CUT.VERSION, "target": "sidecar",
                "active_sha": CUT.digest(self.old), "staged_sha": CUT.digest(self.new),
                "references": {"certificate": "a" * 64}, "identity_gid": 30}
        def hash_payload(x):
            return CUT.digest(json.dumps(x, sort_keys=True,
                                          separators=(",", ":")).encode("ascii"))
        value = hash_payload(base)
        changed = dict(base, active_sha="b" * 64)
        self.assertNotEqual(value, hash_payload(changed))
        changed = dict(base, references={"certificate": "d" * 64})
        self.assertNotEqual(value, hash_payload(changed))

    def _patch_apply(self, verifier=None, backup_id="20261119T095000Z-abcdef012345"):
        self.calls = []
        lock = mock.patch.object(CUT, "lock", return_value=9)
        close = mock.patch.object(CUT.os, "close")
        prepare = mock.patch.object(CUT, "prepare", return_value=self.plan)
        backup = mock.patch.object(CUT, "new_backup", return_value=backup_id)
        exists = mock.patch.object(CUT, "read_checked", side_effect=lambda *args, **kw: self.active)
        root = mock.patch.object(CUT, "ensure_root")
        def replace(_path, content, _gid):
            self.calls.append("replace_hardware" if content == self.new else "restore_old")
            self.active = content
        replacement = mock.patch.object(CUT, "replace_identity", side_effect=replace)
        def fake_run(_plan, candidate, token_check, _runner):
            name = ("candidate" if candidate else "active") + ("_entra" if token_check else "_sign")
            self.calls.append(name)
            if verifier:
                verifier(name)
        checked = mock.patch.object(CUT, "checked_run", side_effect=fake_run)
        return (lock, close, prepare, backup, exists, root, replacement, checked)

    def test_typed_approval_prevents_mutation(self):
        with mock.patch.object(CUT, "lock") as lock:
            with mock.patch.object(CUT, "ensure_root"):
                with self.assertRaisesRegex(CUT.Refused, "confirmation"):
                    CUT.apply("sidecar", "x" * 64, "wrong")
            lock.assert_not_called()

    def test_candidate_offline_signing_then_entra_before_any_change(self):
        with contextlib.ExitStack() as stack:
            for patch in self._patch_apply():
                stack.enter_context(patch)
            with contextlib.redirect_stdout(io.StringIO()) as log:
                CUT.apply(self.target, self.plan["sha"], CUT.CONFIRM_APPLY)
        self.assertEqual(self.calls, ["candidate_sign", "candidate_entra",
                                      "replace_hardware", "active_sign", "active_entra"])
        self.assertEqual(self.active, self.new)
        self.assertIn("HARDWARE_CUTOVER_APPLIED=yes", log.getvalue())
        self.assertIn("HARDWARE_CUTOVER_MAIL_SENT=no", log.getvalue())

    def test_entra_preflight_failure_must_not_change_live_identity(self):
        def fail(name):
            if name == "candidate_entra":
                raise CUT.Refused("token_preflight_failed")
        with contextlib.ExitStack() as stack:
            for patch in self._patch_apply(verifier=fail):
                stack.enter_context(patch)
            with self.assertRaisesRegex(CUT.Refused, "token_preflight"):
                CUT.apply(self.target, self.plan["sha"], CUT.CONFIRM_APPLY)
        self.assertEqual(self.active, self.old)
        self.assertEqual(self.calls, ["candidate_sign", "candidate_entra"])

    def test_postcheck_failure_restores_original_automatically(self):
        def fail(name):
            if name == "active_entra":
                raise CUT.Refused("token_preflight_failed")
        with contextlib.ExitStack() as stack:
            for patch in self._patch_apply(verifier=fail):
                stack.enter_context(patch)
            with self.assertRaisesRegex(CUT.Refused, "cutover_failed_original_restored"):
                CUT.apply(self.target, self.plan["sha"], CUT.CONFIRM_APPLY)
        self.assertEqual(self.active, self.old)
        self.assertEqual(self.calls, ["candidate_sign", "candidate_entra",
                                      "replace_hardware", "active_sign", "active_entra", "restore_old"])

    def test_plan_drift_refuses_change(self):
        with contextlib.ExitStack() as stack:
            for patch in self._patch_apply():
                stack.enter_context(patch)
            with self.assertRaisesRegex(CUT.Refused, "plan_changed_review_again"):
                CUT.apply(self.target, "d" * 64, CUT.CONFIRM_APPLY)
        self.assertEqual(self.active, self.old)
        self.assertEqual(self.calls, [])

    def test_rollback_requires_matching_active_sha_and_confirmation(self):
        manifest = {"applied_sha256": CUT.digest(self.new)}
        with mock.patch.object(CUT, "ensure_root"), \
             mock.patch.object(CUT, "lock", return_value=9), \
             mock.patch.object(CUT.os, "close"), \
             mock.patch.object(CUT, "read_backup", return_value=(self.old, manifest)), \
             mock.patch.object(CUT, "checked_directory"), \
             mock.patch.object(CUT.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=30)), \
             mock.patch.object(CUT, "read_identity", return_value=(self.old, self.identity)), \
             mock.patch.object(CUT, "original_preflight"), \
             mock.patch.object(CUT, "replace_identity") as replace:
            with self.assertRaisesRegex(CUT.Refused, "identity_changed"):
                CUT.rollback("sidecar", "20261119T095000Z-abcdef012345", CUT.CONFIRM_ROLLBACK)
            replace.assert_not_called()
        with mock.patch.object(CUT, "ensure_root"), mock.patch.object(CUT, "lock") as lock:
            with self.assertRaisesRegex(CUT.Refused, "typed_rollback"):
                CUT.rollback("sidecar", "20261119T095000Z-abcdef012345", "WRONG")
            lock.assert_not_called()

    def test_root_owned_permissions_reject_symlinks_and_world_writable(self):
        good = SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=0,
                               st_gid=30, st_nlink=1, st_size=128)
        for st, safe in ((good, True),
                         (SimpleNamespace(**dict(vars(good), st_uid=1000)), False),
                         (SimpleNamespace(**dict(vars(good), st_mode=stat.S_IFLNK | 0o777)), False),
                         (SimpleNamespace(**dict(vars(good), st_nlink=2)), False)):
            with self.subTest(safe=safe), mock.patch.object(CUT.Path, "lstat", return_value=st):
                if safe:
                    CUT.checked_file(Path("/etc/test"), 32768, 30)
                else:
                    with self.assertRaises(CUT.Refused):
                        CUT.checked_file(Path("/etc/test"), 32768, 30)

    def test_invalid_backup_id_never_accesses_arbitrary_path(self):
        with self.assertRaisesRegex(CUT.Refused, "invalid_backup_id"):
            CUT.read_backup("sidecar", "../etc/passwd")

    def test_existing_signer_must_be_recoverable_before_activation(self):
        previous = json.dumps(self.identity).encode("utf-8")
        with mock.patch.object(CUT, "read_checked", return_value=b"existing") as open_file:
            CUT.original_preflight(previous, self.staged, 30, self.directory)
        checked = [str(x.args[0]) for x in open_file.call_args_list]
        self.assertIn(str(self.directory / "app.key"), checked)
        self.assertIn(str(self.directory / "app.crt"), checked)
        with mock.patch.object(CUT, "read_checked",
                               side_effect=CUT.Refused("required_root_file_missing")):
            with self.assertRaisesRegex(CUT.Refused, "required_root_file_missing"):
                CUT.original_preflight(previous, self.staged, 30, self.directory)

    def test_missing_var_backups_parent_can_be_created_on_rhel(self):
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / "var" / "backups" / "linuxmailrelay365-hardware-oauth"
            backup.parent.parent.mkdir()
            with mock.patch.object(CUT, "BACKUP_ROOT", backup), \
                 mock.patch.object(CUT, "checked_directory", return_value=None):
                path = CUT.checked_backup_root("sidecar")
            self.assertEqual(path, backup / "sidecar")
            self.assertEqual(stat.S_IMODE(backup.parent.stat().st_mode), 0o700)
            self.assertTrue(path.is_dir())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_no_service_restart_or_tpm_key_generation_in_script(self):
        text = SOURCE.read_text(encoding="utf-8")
        for prohibited in ("systemctl restart", "systemctl stop", "dnf install",
                           "apt-get install", "tpm2_createprimary", "subprocess.Popen",
                           "smtp.office365.com", "rm -rf /etc"):
            self.assertNotIn(prohibited, text)


if __name__ == "__main__":
    unittest.main()
