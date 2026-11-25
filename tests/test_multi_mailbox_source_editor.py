"""Source-map editor tests; all mutation is confined to synthetic temp files."""
import importlib.util
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
