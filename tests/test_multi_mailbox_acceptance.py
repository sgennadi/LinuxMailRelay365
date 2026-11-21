"""No-network multi-mailbox live-acceptance contract, ledger and spoof tests."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1] / "linux"
spec = importlib.util.spec_from_file_location(
    "m365_multi_acceptance", str(BASE / "manage-multi-mailbox-acceptance.py"))
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
audit_spec = importlib.util.spec_from_file_location(
    "m365_multi_acceptance_audit", str(BASE / "audit-oauth-sender-map.py"))
AUDITOR = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(AUDITOR)
sender = "alice@example.org"
path = "/etc/linuxmailrelay365/oauth-identities/alice.json"
ROW = ("alice", sender, sender, path)
MAP = (AUDITOR.HEADER + "\n" + "\t".join(ROW) + "\n").encode("ascii")
IDENTITY = json.dumps({
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "client_id": "22222222-2222-2222-2222-222222222222",
    "mailbox": sender,
    "certificate": "/etc/linuxmailrelay365/oauth-identities/alice.crt",
    "signer": {"type": "openssl-provider",
               "provider": "tpm2",
               "provider_config": "/etc/linuxmailrelay365/oauth-identities/tpm2.cnf"}
}).encode("ascii")


class MultiAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        directory = Path(self.temp.name)
        installer = SimpleNamespace(
            RUNTIME=directory / "oauth-runtime-senders.tsv",
            TARGET=directory / "runtime-code")
        self.state = {
            "sha": "a" * 64, "marker": (None, b"root-owned-active-marker"),
            "review": {"version": 1, "config": {"sha": "a" * 64},
                       "proof": {"inode": 9001, "expires_at": 1000}},
            "record": {"runtime_map_sha256": M.digest(MAP), "source": {
                "m365-multi-mailbox-transport.py": "b" * 64}}
        }
        self.restorer = SimpleNamespace(
            install=installer, preview=mock.Mock(side_effect=lambda: self.state),
            locked=mock.Mock(side_effect=lambda: os.open(os.devnull, os.O_RDONLY)))
        def refresh_proof(_):
            # Simulate replacing a short-lived root receipt between the two
            # sends; it must not invalidate the immutable approved route.
            self.state["review"]["proof"] = {
                "inode": self.state["review"]["proof"]["inode"] + 1,
                "expires_at": 1100}
        self.refresh = SimpleNamespace(inspect=mock.Mock(return_value={
            "expires_at": 1010}), publish=mock.Mock(side_effect=refresh_proof))
        self.request = {"sender": sender, "internal": "review@example.org",
                        "external": "review@external.net",
                        "run_id": "c" * 32}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(M.os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(M.grp, "getgrnam",
                                  return_value=SimpleNamespace(gr_gid=4242)))
        def safe_read(p, size, mode, group):
            self.assertEqual(mode, 0o640)
            self.assertEqual(group, 4242)
            if str(p) == str(installer.RUNTIME):
                return MAP
            if str(p) == path:
                return IDENTITY
            raise AssertionError("unapproved file read")
        self.stack.enter_context(mock.patch.object(AUDITOR, "secure_read",
                                  side_effect=safe_read))
        def loader(filename, alias):
            if filename == "audit-oauth-sender-map.py":
                return AUDITOR
            if filename == "restore-multi-mailbox-postfix.py":
                return self.restorer
            if filename == "refresh-multi-mailbox-proof.py":
                return self.refresh
            raise AssertionError("unexpected dynamic import: " + filename)
        self.stack.enter_context(mock.patch.object(M, "source", side_effect=loader))
        self.plan = M.prepare(self.request)

    def _ledger(self, run_id):
        folder = Path(self.temp.name) / "ledger"
        folder.mkdir(exist_ok=True)
        try:
            return os.open(str(folder / (run_id + ".jsonl")),
                           os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise M.Refused("test_run_already_reserved_never_auto_retry")

    def _apply(self, runner, approve=None, confirm=None):
        with mock.patch.object(M.shutil, "which", return_value="/usr/sbin/runuser"):
            return M.send_reviewed(
                self.plan, approve or self.plan["sha"], confirm or M.CONFIRM,
                runner=runner, restorer=self.restorer, refresh=self.refresh,
                ledger_factory=self._ledger)

    def test_readonly_review_never_emits_recipients(self):
        p = M.prepare(self.request)
        self.assertEqual(p["sha"], self.plan["sha"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with mock.patch.object(M, "read_request", return_value=self.request):
                self.assertEqual(M.main(["--plan"]), 0)
        self.assertIn("MULTI_ACCEPTANCE_STATUS=preview_only", out.getvalue())
        self.assertIn("MULTI_ACCEPTANCE_MAIL_SENT=no", out.getvalue())
        self.assertNotIn(sender, out.getvalue())
        self.assertNotIn(self.request["internal"], out.getvalue())
        self.assertNotIn(self.request["external"], out.getvalue())
        self.refresh.inspect.assert_not_called()
        self.refresh.publish.assert_not_called()

    def test_review_bound_to_sender_recipients_active_and_identity(self):
        different = dict(self.request, external="other@external.net")
        self.assertNotEqual(self.plan["sha"], M.prepare(different)["sha"])
        different = dict(self.request, sender="bob@example.org")
        with self.assertRaises(M.Refused):
            M.prepare(different)
        self.state["review"]["config"]["sha"] = "f" * 64
        self.assertNotEqual(self.plan["sha"], M.prepare(self.request)["sha"])

    def test_invalid_roles_injection_json_duplicates_and_sender_rejected(self):
        for changes in (
            {"internal": "someone@external.net"},
            {"external": "someone@example.org"},
            {"external": "review@example.org"},
            {"internal": sender},
            {"external": "a@outside.net\nBcc:evil@outside.net"},
            {"sender": "unknown@example.org"},
            {"run_id": "bad-run"},
        ):
            with self.subTest(changes=changes), self.assertRaises(M.Refused):
                M.prepare(dict(self.request, **changes))
        with self.assertRaises(M.Refused):
            M.read_request(io.BytesIO(b'{"sender":"a","sender":"b"}'))
        with self.assertRaises(M.Refused):
            M.read_request(io.BytesIO(b'{"sender":"' + b"a" * 5000 + b'"}'))

    def test_success_sends_only_two_fixed_role_requests_and_never_retries(self):
        recorded = []
        def fake_run(argv, **kwargs):
            payload = json.loads(kwargs["input"])
            recorded.append((argv, kwargs, payload))
            self.assertIn("--acceptance-test", argv)
            self.assertIn("--expected-map-sha256", argv)
            self.assertEqual(argv[0], "/usr/sbin/runuser")
            self.assertNotIn("--recipient", argv)
            self.assertNotIn("--envelope-sender", argv)
            self.assertEqual(kwargs["stdout"], M.subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], M.subprocess.DEVNULL)
            return SimpleNamespace(returncode=0)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self._apply(fake_run)
        self.assertIn("MULTI_ACCEPTANCE_TWO_SMTP_SUBMISSIONS_ACCEPTED=yes",
                      out.getvalue())
        self.assertIn("MULTI_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED=no",
                      out.getvalue())
        self.assertEqual([x[2]["role"] for x in recorded], ["internal", "external"])
        self.assertEqual([x[2]["recipient"] for x in recorded],
                         [self.request["internal"], self.request["external"]])
        self.assertEqual([x[2]["sender"] for x in recorded], [sender, sender])
        self.assertEqual(self.refresh.inspect.call_count, 2)
        self.assertEqual(self.refresh.publish.call_count, 2)
        self.assertGreaterEqual(self.restorer.preview.call_count, 4)
        ledger = next((Path(self.temp.name) / "ledger").glob("*.jsonl"))
        rows = [json.loads(x) for x in ledger.read_text().splitlines()]
        self.assertEqual([(x["stage"], x["status"]) for x in rows],
                         [("run", "reserved"), ("internal", "attempted"),
                          ("internal", "smtp_accepted_not_inbox_verified"),
                          ("external", "attempted"),
                          ("external", "smtp_accepted_not_inbox_verified"),
                          ("run", "smtp_submissions_complete")])
        with self.assertRaisesRegex(M.Refused, "already_reserved"):
            self._apply(fake_run)
        self.assertEqual(len(recorded), 2)

    def test_partial_smtp_failure_remains_reserved_and_no_external_attempt(self):
        def failed(argv, **kwargs):
            return SimpleNamespace(returncode=75)
        with self.assertRaisesRegex(M.Refused, "internal_smtp_not_accepted"):
            self._apply(failed)
        ledger = next((Path(self.temp.name) / "ledger").glob("*.jsonl"))
        rows = [json.loads(x) for x in ledger.read_text().splitlines()]
        self.assertEqual(rows[-1]["stage"], "internal")
        self.assertEqual(rows[-1]["status"], "attempted")
        self.assertEqual(self.refresh.inspect.call_count, 1)
        with self.assertRaisesRegex(M.Refused, "already_reserved"):
            self._apply(failed)

    def test_unknown_timeout_no_auto_retry(self):
        with self.assertRaisesRegex(M.Refused, "result_unknown"):
            self._apply(lambda *args, **kwargs:
                        (_ for _ in ()).throw(M.subprocess.TimeoutExpired("smtp", 140)))
        ledger = next((Path(self.temp.name) / "ledger").glob("*.jsonl"))
        self.assertIn("attempted", ledger.read_text())
        with self.assertRaises(M.Refused):
            self._apply(lambda *args, **kwargs: SimpleNamespace(returncode=0))

    def test_approval_refuses_before_lock_and_ledger(self):
        for sha, confirm in (("a" * 64, ""), ("INVALID", M.CONFIRM)):
            with self.subTest(sha=sha, confirm=confirm), \
                 self.assertRaises(M.Refused):
                M.send_reviewed(self.plan, sha, confirm, restorer=self.restorer)
        self.restorer.locked.assert_not_called()
        self.assertFalse((Path(self.temp.name) / "ledger").exists())

    def test_readonly_ledger_status_classifies_uncertain_and_complete_runs(self):
        folder = Path(self.temp.name) / "status-ledger"
        folder.mkdir(mode=0o700)
        sequence = [
            ("run", "reserved"),
            ("internal", "attempted"),
            ("internal", "smtp_accepted_not_inbox_verified"),
            ("external", "attempted"),
            ("external", "smtp_accepted_not_inbox_verified"),
            ("run", "smtp_submissions_complete"),
        ]
        states = [
            "reserved_no_send_recorded",
            "internal_attempted_result_uncertain",
            "internal_smtp_accepted_external_not_attempted",
            "external_attempted_result_uncertain",
            "both_smtp_accepted_completion_not_recorded",
            "smtp_submissions_complete_not_inbox_verified",
        ]
        for index in range(len(sequence)):
            run_id = "{:032x}".format(index + 1)
            path = folder / (run_id + ".jsonl")
            path.write_bytes(b"".join(
                (json.dumps({"stage": stage, "status": status}) + "\n").encode()
                for stage, status in sequence[:index + 1]))
            path.chmod(0o600)
            with self.subTest(events=index + 1):
                state = M.inspect_ledger(run_id, root=folder,
                                          owner_uid=os.getuid())
                self.assertEqual(state["state"], states[index])
                self.assertEqual(state["events"], index + 1)
                self.assertEqual(state["run_id"], run_id)
        self.assertEqual(len(list(folder.glob("*.jsonl"))), 6)

    def test_status_refuses_invalid_transitions_duplicate_or_symlink(self):
        folder = Path(self.temp.name) / "status-ledger"
        folder.mkdir(mode=0o700)
        run_id = "e" * 32
        path = folder / (run_id + ".jsonl")
        invalid_records = (
            b'{"stage":"external","status":"attempted"}\n',
            b'{"stage":"run","status":"reserved","status":"reserved"}\n',
            b'{"stage":"run","status":"reserved"}',
            b'{"stage":"run","status":"reserved","recipient":"some@example.org"}\n',
        )
        for data in invalid_records:
            path.write_bytes(data)
            path.chmod(0o600)
            with self.subTest(data=data), self.assertRaises(M.Refused):
                M.inspect_ledger(run_id, root=folder, owner_uid=os.getuid())
        path.unlink()
        path.symlink_to(Path(self.temp.name) / "untrusted")
        with self.assertRaises(M.Refused):
            M.inspect_ledger(run_id, root=folder, owner_uid=os.getuid())

    def test_status_rejects_send_flags_without_reading_stdin(self):
        with mock.patch.object(M, "inspect_ledger", return_value={
            "run_id": self.request["run_id"], "state": "internal_attempted_result_uncertain",
            "events": 2}) as status, \
             mock.patch.object(M, "read_request") as req, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            result = M.main(["--status", "--run-id", self.request["run_id"]])
        self.assertEqual(result, 0)
        self.assertIn("MULTI_ACCEPTANCE_LEDGER_STATE=internal_attempted_result_uncertain",
                      out.getvalue())
        self.assertIn("MULTI_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED=no", out.getvalue())
        status.assert_called_once_with(self.request["run_id"])
        req.assert_not_called()
        with mock.patch.object(M, "inspect_ledger") as status:
            self.assertEqual(M.main(["--status", "--run-id", self.request["run_id"],
                                     "--confirm", M.CONFIRM]), 2)
            status.assert_not_called()

    def test_no_network_on_import_or_preview_no_auto_mta_changes(self):
        source = (BASE / "manage-multi-mailbox-acceptance.py").read_text()
        self.assertNotIn("systemctl restart", source)
        self.assertNotIn("postfix reload", source)
        self.assertNotIn("postqueue -f", source)
        self.assertIn("RECIPIENT_INBOX_VERIFIED=no", source)
        self.assertIn("SEND_MULTI_MAILBOX_TWO_TESTS", source)


if __name__ == "__main__":
    unittest.main()
