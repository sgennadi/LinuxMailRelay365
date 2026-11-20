"""Fail-closed offline checks for primary software PEM OAuth certificate rotation."""
import importlib.util
import io
import contextlib
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "linux" / "manage-primary-oauth-rotation.py"
SPEC = importlib.util.spec_from_file_location("primary_oauth_rotation", str(SOURCE))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

ROOT = M.ROOT
TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"
STAMP = "app.rotation.20261120T205100Z-001122334455"


def identity(versioned=False):
    stem = STAMP if versioned else "app"
    return {"tenant_id": TENANT, "client_id": CLIENT,
            "mailbox": "alerts@example.org",
            "certificate": str(ROOT / (stem + ".crt")),
            "private_key": str(ROOT / (stem + ".key"))}


class PrimaryOAuthRotationTests(unittest.TestCase):
    def test_staged_identity_parsing_rejects_traversal_and_hardware_mode(self):
        import json
        good = identity(True)
        with mock.patch.object(M, "read_root_file", return_value=b"sample"):
            parsed, _, _ = M.parse_identity(json.dumps(good).encode(), 56, rotation=True)
            self.assertEqual(parsed["tenant_id"], TENANT)
            for update in (
                {"private_key": "/tmp/outside.key"},
                {"certificate": str(ROOT / "app.key")},
                {"signer": {"provider": "tpm2"}},
                {"mailbox": "hacker@example.org\ninvalid"},
                {"tenant_id": "bad-guid"}):
                modified = dict(good, **update)
                with self.subTest(update=update), self.assertRaises(M.Refused):
                    M.parse_identity(json.dumps(modified).encode(), 56, True)
            active, _, _ = M.parse_identity(json.dumps(identity()).encode(), 56)
            self.assertEqual(active["private_key"], str(ROOT / "app.key"))

    def test_plan_changes_with_active_key_and_validity(self):
        base = {"raw": b'{"identity":1}', "key_sha": "a" * 64,
                "cert_sha": "b" * 64}
        plan = M.review_plan(base, 90)
        self.assertEqual(len(plan), 64)
        self.assertNotEqual(plan, M.review_plan(base, 91))
        other = dict(base, key_sha="c" * 64)
        self.assertNotEqual(plan, M.review_plan(other, 90))
        for days in (-1, 0, 366, 999):
            with self.assertRaises(M.Refused):
                M.review_plan(base, days)

    def test_activation_requires_exact_reviewed_digest_and_consent(self):
        reviewed = "a" * 64
        M.require_sha(reviewed, reviewed, M.ACTIVATE_ACK, M.ACTIVATE_ACK)
        for hash_value, confirmation in (
            ("b" * 64, M.ACTIVATE_ACK), (reviewed, ""),
            (reviewed, M.CHECK_ACK), ("../../tmp", M.ACTIVATE_ACK)):
            with self.subTest(value=hash_value, confirmation=confirmation):
                with self.assertRaises(M.Refused):
                    M.require_sha(reviewed, hash_value, confirmation, M.ACTIVATE_ACK)

    def test_auth_preflight_uses_installed_transport_without_smtp_data(self):
        def fake_run(args, **kwargs):
            self.assertEqual(args[:4],
                             ["runuser", "-u", "m365mailer", "--"])
            self.assertEqual(args[-3:-1], ["--candidate-config", str(M.STAGED)])
            self.assertNotIn("--recipient", args)
            self.assertNotIn("--acceptance-test", args)
            self.assertIn("--smtp-auth-check", args)
            return SimpleNamespace(
                returncode=0,
                stdout=b"Microsoft 365 STARTTLS and SMTP AUTH XOAUTH2 verified; no message submitted")
        with mock.patch.object(M, "owned_dir"), \
             mock.patch.object(M, "read_root_file", return_value=b"root-owned"), \
             mock.patch.object(M.subprocess, "run", side_effect=fake_run):
            M.check_candidate_auth()
        with mock.patch.object(M, "owned_dir"), \
             mock.patch.object(M, "read_root_file", return_value=b"root-owned"), \
             mock.patch.object(M.subprocess, "run", return_value=SimpleNamespace(
                 returncode=75, stdout=b"rejected")):
            with self.assertRaises(M.Refused):
                M.check_candidate_auth()

    def test_failed_post_activation_smtp_rolls_back_exact_old_json(self):
        previous = b'{"old":"unchanged"}\n'
        staged_raw = b'{"new":"candidate"}\n'
        reviewed = {"sha": "a" * 64, "active": {"raw": previous},
                    "raw": staged_raw}
        snapshots = []
        copies = []
        with mock.patch.object(M, "write_new", side_effect=lambda *args: copies.append(args)), \
             mock.patch.object(M, "write_atomic", side_effect=lambda path, data, gid: snapshots.append(data)), \
             mock.patch.object(M, "staged_state", return_value=reviewed), \
             mock.patch.object(M, "check_candidate_auth",
                               side_effect=M.Refused("post_activation_auth_rejected")), \
             contextlib.redirect_stdout(io.StringIO()) as result:
            with self.assertRaises(M.Refused):
                M.activate(reviewed, 88)
        self.assertEqual(snapshots, [staged_raw, previous])
        self.assertEqual(len(copies), 1)
        self.assertTrue(copies[0][0].name.startswith("app.rollback."))
        self.assertIn("ROLLED_BACK=yes", result.getvalue())
        self.assertNotIn("ACTIVATED=yes", result.getvalue())

    def test_successful_activation_preserves_old_identity_backup(self):
        previous = b'{"old":"unchanged"}\n'
        staged_raw = b'{"new":"candidate"}\n'
        reviewed = {"sha": "c" * 64, "active": {"raw": previous},
                    "raw": staged_raw}
        snapshots = []
        fake_staged = mock.Mock()
        with mock.patch.object(M, "write_new") as save, \
             mock.patch.object(M, "write_atomic", side_effect=lambda p, d, g: snapshots.append(d)), \
             mock.patch.object(M, "staged_state", return_value=reviewed), \
             mock.patch.object(M, "read_root_file", return_value=staged_raw), \
             mock.patch.object(M, "check_candidate_auth") as auth, \
             mock.patch.object(M, "STAGED", fake_staged), \
             contextlib.redirect_stdout(io.StringIO()) as result:
            M.activate(reviewed, 88)
        save.assert_called_once()
        auth.assert_called_once_with(active=True)
        fake_staged.unlink.assert_called_once_with()
        self.assertEqual(snapshots, [staged_raw])
        self.assertIn("ACTIVATED=yes", result.getvalue())
        self.assertIn("OLD_KEYS_PRESERVED=yes", result.getvalue())

    def test_manager_never_sends_mail_or_modifies_postfix_service(self):
        data = SOURCE.read_text(encoding="utf-8")
        self.assertIn("os.O_EXCL", data)
        self.assertIn("os.replace", data)
        self.assertIn("STAGED.unlink()", data)
        self.assertNotIn("postfix reload", data)
        self.assertNotIn("systemctl restart", data)
        self.assertNotIn("MAIL FROM", data)
        self.assertNotIn("RCPT TO", data)
        self.assertNotIn("subprocess.Popen", data)


if __name__ == "__main__":
    unittest.main()
