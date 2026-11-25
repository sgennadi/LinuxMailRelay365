"""Source-map editor tests; all mutation is confined to synthetic temp files."""
import importlib.util
import contextlib
import io
import os
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("source_editor", str(ROOT / "linux/edit-multi-mailbox-source.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
MAIL = "alice@example.org"
BOB = "bob@example.org"


class SourceEditorTests(unittest.TestCase):
    def row(self, login, mail):
        return login, mail, mail, str(M.IDENTITIES / (login + ".json"))

    def evidence(self, login, sender, mailbox, path, gid):
        return dict(login=login, sender=sender, mailbox=mailbox,
                    tenant="11111111-1111-4111-8111-111111111111",
                    client="22222222-2222-4222-8222-222222222222",
                    identity_sha256="b"*64, certificate_sha256="c"*64,
                    signer="software", status="public_certificate_read")

    def req(self, action, rows, old="", login="", mailbox="", file=""):
        return dict(action=action, base_sha=M.I.digest(M.render(rows)) if rows else "",
                    old_mailbox=old, login=login, mailbox=mailbox, identity_file=file,
                    nonce="a"*64, approval="", confirm="")

    def test_add_edit_remove_only_selected_row(self):
        alice, bob = self.row("alice", MAIL), self.row("bob", BOB)
        rows = [alice, bob]
        with mock.patch.object(M, "read_source", side_effect=lambda: (M.render(rows), list(rows))), \
                mock.patch.object(M.I, "identity_row", side_effect=self.evidence):
            _, new, plan = M.plan(self.req("edit", rows, MAIL, "new-login", MAIL), 10)
            self.assertEqual(M.A.parse_map(new), [("new-login", MAIL, MAIL, alice[3]), bob])
            self.assertEqual(plan["identity_file"], "alice.json")
            _, new, plan = M.plan(self.req("remove", rows, MAIL), 10)
            self.assertEqual(M.A.parse_map(new), [bob])
            self.assertIsNone(plan["selected"])
            with self.assertRaises(M.A.Refused):
                M.plan(self.req("add", rows, login="alice2", mailbox=MAIL, file="alice.json"), 10)

    def test_add_first_and_refuse_last_removal(self):
        with mock.patch.object(M, "read_source", return_value=(None, [])), \
                mock.patch.object(M.I, "identity_row", side_effect=self.evidence):
            old, new, result = M.plan(self.req("add", [], login="alice", mailbox=MAIL, file="alice.json"), 10)
            self.assertIsNone(old)
            self.assertEqual(M.A.parse_map(new), [self.row("alice", MAIL)])
            self.assertEqual(result["old_count"], 0)
        rows = [self.row("alice", MAIL)]
        with mock.patch.object(M, "read_source", return_value=(M.render(rows), rows)):
            with self.assertRaisesRegex(M.Refused, "last_row_removal"):
                M.plan(self.req("remove", rows, MAIL), 10)

    def test_approval_binds_identity_evidence_and_stale_map(self):
        req = self.req("add", [], login="alice", mailbox=MAIL, file="alice.json")
        with mock.patch.object(M, "read_source", return_value=(None, [])), \
                mock.patch.object(M.I, "identity_row", side_effect=self.evidence):
            before = M.plan(req, 10)[2]
        def changed(*args):
            return dict(self.evidence(*args), certificate_sha256="d"*64)
        with mock.patch.object(M, "read_source", return_value=(None, [])), \
                mock.patch.object(M.I, "identity_row", side_effect=changed):
            self.assertNotEqual(M.plan(req, 10)[2]["plan_sha"], before["plan_sha"])
        with mock.patch.object(M, "read_source", return_value=(b"changed", [])):
            with self.assertRaisesRegex(M.Refused, "source_changed"):
                M.plan(req, 10)

    def test_request_rejects_traversal_and_approval_without_confirmation(self):
        req = self.req("add", [], login="alice", mailbox=MAIL, file="alice.json")
        self.assertEqual(M.request(M.encode(req)), req)
        for bad in (dict(req, identity_file="../private.json"), dict(req, identity_file="alice.key"),
                    dict(req, approval="a"*64), dict(req, mailbox="alice@example.org\n")):
            with self.assertRaises(M.Refused):
                M.request(M.encode(bad))

    def test_restore_request_is_separate_and_bound_to_backup_id(self):
        req = dict(self.req("add", [self.row("alice", MAIL)]), action="restore",
                   backup_id="source-abcdefgh")
        self.assertEqual(M.request(M.encode(req)), req)
        for bad in (dict(req, backup_id="../unsafe"), dict(req, base_sha=""),
                    dict(req, approval="a"*64, confirm=M.CONFIRM),
                    dict(req, login="alice")):
            with self.assertRaises(M.Refused):
                M.request(M.encode(bad))

    @unittest.skipUnless(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
                         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
                         "requires disposable root CI")
    def test_real_atomic_save_and_restore(self):
        # Exercise the real shared lock, file ownership, secure_read, fsync,
        # backup manifest and atomic replacement. Identity evidence alone is
        # synthetic; no real credentials or Postfix directories are touched.
        with tempfile.TemporaryDirectory(prefix="lmr365-source-ci-", dir="/root") as folder:
            base = Path(folder)
            source = base / "oauth-senders.tsv"
            backups = base / "oauth-source-backups"
            rows = [self.row("alice", MAIL), self.row("bob", BOB)]
            original = M.render(rows)
            M.write_new(source, original)
            with mock.patch.object(M, "BASE", base), mock.patch.object(M, "SOURCE", source), \
                    mock.patch.object(M, "BACKUPS", backups), mock.patch.object(M, "LOCK", base/"lock"), \
                    mock.patch.object(M.I, "identity_row", side_effect=self.evidence), \
                    contextlib.redirect_stderr(io.StringIO()):
                req = self.req("edit", rows, MAIL, "new-login", MAIL)
                _, changed, preview = M.plan(req, 10)
                self.assertEqual(source.read_bytes(), original)
                saved = M.apply(dict(req, approval=preview["plan_sha"], confirm=M.CONFIRM), 10)
                self.assertEqual(source.read_bytes(), changed)
                self.assertEqual((backups/saved["backup_id"]/"oauth-senders.tsv").read_bytes(), original)
                self.assertEqual(source.stat().st_mode & 0o777, 0o600)
                restore = dict(self.req("add", M.A.parse_map(changed)), action="restore",
                               backup_id=saved["backup_id"])
                _, restored, reviewed = M.plan(restore, 10)
                self.assertEqual(restored, original)
                self.assertEqual(source.read_bytes(), changed)
                with self.assertRaisesRegex(M.Refused, "plan_changed"):
                    M.apply(dict(restore, approval="f"*64, confirm=M.RESTORE_CONFIRM), 10)
                self.assertEqual(source.read_bytes(), changed)
                backup_file = backups/saved["backup_id"]/"oauth-senders.tsv"
                backup_file.write_bytes(b"tampered")
                with self.assertRaisesRegex(M.Refused, "backup_digest_mismatch"):
                    M.plan(restore, 10)
                self.assertEqual(source.read_bytes(), changed)
                backup_file.write_bytes(original)
                # Prove a concurrent writer cannot be overwritten by a
                # previously approved restore, even if the backup is valid.
                source.write_bytes(M.render([rows[1]]))
                with self.assertRaisesRegex(M.Refused, "source_changed"):
                    M.apply(dict(restore, approval=reviewed["plan_sha"], confirm=M.RESTORE_CONFIRM), 10)
                self.assertEqual(source.read_bytes(), M.render([rows[1]]))
                source.write_bytes(changed)
                result = M.apply(dict(restore, approval=reviewed["plan_sha"], confirm=M.RESTORE_CONFIRM), 10)
                self.assertEqual(source.read_bytes(), original)
                self.assertEqual(result["restored_from"], saved["backup_id"])
                self.assertEqual((backups/result["backup_id"]/"oauth-senders.tsv").read_bytes(), changed)
                self.assertNotEqual(result["backup_id"], saved["backup_id"])
                with self.assertRaisesRegex(M.Refused, "source_changed"):
                    M.plan(restore, 10)
                self.assertFalse(list(base.glob(".oauth-source-*")))

    def test_apply_never_writes_without_matching_approval(self):
        req = self.req("add", [], login="alice", mailbox=MAIL, file="alice.json")
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(M, "LOCK", Path(folder)/"lock"), \
                    mock.patch.object(M.E, "trusted_directory"), \
                    mock.patch.object(M, "plan", return_value=(None,b"new",{"plan_sha":"b"*64})), \
                    mock.patch.object(M, "backup") as backup:
                with mock.patch.object(M.os, "fstat", wraps=M.os.fstat) as st:
                    # Lock metadata requires root. Non-root test runs can
                    # still exercise the refusal, without changing ownership.
                    with self.assertRaises(M.Refused):
                        M.apply(dict(req, approval="c"*64, confirm=M.CONFIRM), 10)
                backup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
