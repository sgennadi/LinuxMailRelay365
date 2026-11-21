"""No-network, fail-closed multi-mailbox XOAUTH2 pipe transport tests."""
import hashlib
import json
import importlib.util
import re
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "linux" / "m365-multi-mailbox-transport.py"
AUDITOR_PATH = ROOT / "linux" / "audit-oauth-sender-map.py"

spec = importlib.util.spec_from_file_location("m365_multi_dispatch", str(SOURCE))
dispatch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dispatch)
audit_spec = importlib.util.spec_from_file_location("m365_sender_audit", str(AUDITOR_PATH))
auditor = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(auditor)

MAP_HASH = "a" * 64
IDENTITY_A = "/etc/linuxmailrelay365/oauth-identities/alpha.json"
IDENTITY_B = "/etc/linuxmailrelay365/oauth-identities/beta.json"
ROWS = [
    ("alice", "alice@example.org", "alice@example.org", IDENTITY_A),
    ("bob", "bob@example.org", "bob@example.org", IDENTITY_B),
]


def mail(sender):
    return ("From: <{}>\r\nTo: destination@example.net\r\nSubject: test\r\n"
            "\r\nBody text.\r\n").format(sender).encode("ascii")


class FakeTransport:
    def __init__(self):
        self.events = []
        self.identity = {IDENTITY_A: "alice@example.org",
                         IDENTITY_B: "bob@example.org"}

    def load_config(self, path):
        self.events.append(("config", path))
        return {"mailbox": self.identity[path]}

    def acquire_token(self, config):
        self.events.append(("token", config["mailbox"]))
        return "fake-token-in-test-only"

    def send_smtp(self, config, recipient, raw, token):
        self.events.append(("send", config["mailbox"], recipient, raw))
        assert token == "fake-token-in-test-only"


class MultiMailboxTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.ingress = mock.Mock(return_value=True)
        self.map_patch = mock.patch.object(dispatch, "secure_runtime_map",
                                           return_value=list(ROWS))
        self.map_patch.start()
        self.addCleanup(self.map_patch.stop)

    def deliver(self, sender="alice@example.org", login="alice",
                auth="PLAIN", message=None, recipient="dest@example.net"):
        return dispatch.deliver(sender, recipient, login, auth, MAP_HASH,
                                mail(sender) if message is None else message,
                                auditor=auditor, ingress_checker=self.ingress,
                                transport=self.transport, gid=4242)

    def test_distinct_login_maps_to_distinct_identity(self):
        for login, sender, path in (("alice", "alice@example.org", IDENTITY_A),
                                    ("bob", "bob@example.org", IDENTITY_B)):
            self.assertTrue(self.deliver(sender=sender, login=login))
            self.assertEqual(self.transport.events[-3][0:2], ("config", path))
            self.assertEqual(self.transport.events[-2][1], sender)
            self.assertEqual(self.transport.events[-1][1], sender)
        self.assertEqual(self.ingress.call_count, 2)

    def test_sasl_login_is_mandatory_and_cannot_select_someone_else(self):
        for login, auth in (("", "PLAIN"), ("bob", "PLAIN"),
                            ("unrelated", "PLAIN"), ("alice", ""),
                            ("alice", "XOAUTH2"), ("alice", "INVALID"),
                            ("a \n", "PLAIN")):
            with self.subTest(login=login, auth=auth), self.assertRaises(dispatch.Denied):
                self.deliver(login=login, auth=auth)
        self.assertEqual(self.transport.events, [])
        self.ingress.assert_not_called()

    def test_sender_and_header_must_match_authorized_mailbox(self):
        invalid = (
            b"From: bob@example.org\r\n\r\nX",
            b"From: alice@example.org\r\nFrom: alice@example.org\r\n\r\nX",
            b"From: alice@example.org\r\nSender: bob@example.org\r\n\r\nX",
            b"From: alice@example.org\r\nReturn-Path: <alice@example.org>\r\n\r\nX",
            b"From: alice@example.org\r\nResent-From: bob@example.org\r\n\r\nX",
            b"From: Alice: alice@example.org;\r\n\r\nX",
            b"From: alice@example.org, bob@example.org\r\n\r\nX",
            b"To: x@example.net\r\n\r\nX",
            b"From: alice@example.org\r\nSubject: no delimiter",
            b"From: alice@example.org\r\nX: x\r\n\r\n" +
            b"A" * (dispatch.MAX_MAIL_BYTES + 1),
            b"From: alice@example.org\r\n\r\nembedded\x00NUL",
        )
        for body in invalid:
            with self.subTest(body=body[:70]), self.assertRaises(dispatch.Denied):
                self.deliver(message=body)
        self.assertEqual(self.transport.events, [])

    def test_zero_matching_identity_and_duplicate_identity_denied(self):
        for rows in ([], [ROWS[0], ROWS[0]], [ROWS[1]]):
            with self.subTest(rows=rows):
                with mock.patch.object(dispatch, "secure_runtime_map",
                                       return_value=rows):
                    with self.assertRaises(dispatch.Denied):
                        self.deliver()
        self.assertEqual(self.transport.events, [])

    def test_readback_failure_prevents_token(self):
        self.ingress.side_effect = dispatch.Unverified("guards_not_ready")
        with self.assertRaises(dispatch.Unverified):
            self.deliver()
        self.assertEqual(self.transport.events, [])

    def test_changed_selected_identity_cannot_request_token(self):
        self.transport.identity[IDENTITY_A] = "bob@example.org"
        with self.assertRaises(dispatch.Unverified):
            self.deliver()
        self.assertNotIn("token", [event[0] for event in self.transport.events])

    def test_secure_map_pins_sha_and_refuses_send_as(self):
        self.map_patch.stop()  # Exercise the real parser and SHA gate, not setUp's delivery fixture.
        original_map = (auditor.HEADER + "\n" + "\n".join(
            "\t".join(item) for item in ROWS) + "\n").encode("ascii")
        sha = hashlib.sha256(original_map).hexdigest()
        file_identity = (b'{"tenant_id":"11111111-1111-1111-1111-111111111111",'
                         b'"client_id":"22222222-2222-2222-2222-222222222222",'
                         b'"certificate":"/etc/linuxmailrelay365/oauth-identities/cert.pem",'
                         b'"mailbox":"alice@example.org",'
                         b'"signer":{"provider":"tpm2","key_ref":"device"}}')
        real_secure = auditor.secure_read
        def reader(path, limit, mode, group=None):
            self.assertEqual(mode, 0o640)
            self.assertEqual(group, 4242)
            return original_map if path == dispatch.RUNTIME_MAP else file_identity.replace(
                b"alice@example.org",
                b"bob@example.org" if path == IDENTITY_B else b"alice@example.org")
        with mock.patch.object(auditor, "secure_read", side_effect=reader):
            rows = dispatch.secure_runtime_map(auditor, 4242, sha)
            self.assertEqual(len(rows), 2)
            with self.assertRaises(dispatch.Unverified):
                dispatch.secure_runtime_map(auditor, 4242, "0" * 64)
            swapped = original_map.replace(
                b"bob@example.org\tbob@example.org",
                b"bob@example.org\tshared@example.org")
            with mock.patch.object(auditor, "secure_read", return_value=swapped):
                with self.assertRaises(dispatch.Unverified):
                    dispatch.secure_runtime_map(auditor, 4242, sha)

    def test_ingress_guard_requires_fresh_protected_privileged_receipt(self):
        from types import SimpleNamespace
        metadata = [1, 2, 3, 4, 5, 33188, 0, 0]
        body = (auditor.HEADER + "\n" +
                "\n".join("\t".join(r) for r in ROWS) + "\n").encode("ascii")
        stamp = 1000
        proof = {
            "version": 1,
            "map_sha256": hashlib.sha256(body).hexdigest(),
            "issued_at": stamp,
            "expires_at": stamp + dispatch.PROOF_TTL,
            "mailboxes": 2,
            "main_meta": metadata,
            "master_meta": metadata,
            "ingress": "root_static_audit_consistent_not_live_delivery"
        }
        requested = []
        def read(path, limit, mode, gid):
            requested.append((path, mode, gid))
            if path == dispatch.PROOF_FILE:
                return json.dumps(proof, sort_keys=True).encode("ascii")
            if path == dispatch.RUNTIME_MAP:
                return body
            raise AssertionError("transport must not read root:dovecot credentials")
        with mock.patch.object(auditor, "secure_read", side_effect=read), \
             mock.patch.object(dispatch.grp, "getgrnam",
                               return_value=SimpleNamespace(gr_gid=4242)), \
             mock.patch.object(dispatch, "config_metadata", return_value=metadata), \
             mock.patch.object(dispatch.time, "time", return_value=stamp):
            self.assertTrue(dispatch.ingress_ready(ROWS, auditor))
            self.assertEqual(
                {x[0] for x in requested},
                {dispatch.PROOF_FILE, dispatch.RUNTIME_MAP})
            self.assertTrue(all(gid == 4242 and mode == 0o640
                                for _, mode, gid in requested))
            proof["expires_at"] = stamp - 1
            with self.assertRaises(dispatch.Unverified):
                dispatch.ingress_ready(ROWS, auditor)
            proof["expires_at"] = stamp + dispatch.PROOF_TTL
            proof["map_sha256"] = "a" * 64
            with self.assertRaises(dispatch.Unverified):
                dispatch.ingress_ready(ROWS, auditor)
            proof["map_sha256"] = hashlib.sha256(body).hexdigest()
            proof["main_meta"] = ["wrong"]
            with self.assertRaises(dispatch.Unverified):
                dispatch.ingress_ready(ROWS, auditor)

    def test_run_never_prints_token_sender_or_message_on_refusal(self):
        with mock.patch.object(dispatch, "require_service_account", return_value=4242), \
             mock.patch.object(dispatch, "load_source", return_value=auditor), \
             mock.patch.object(dispatch, "secure_runtime_map", side_effect=dispatch.Unverified("map_changed")):
            from contextlib import redirect_stderr
            import io
            err = io.StringIO()
            with redirect_stderr(err):
                result = dispatch.main(["--expected-map-sha256", MAP_HASH,
                                        "--recipient", "secret@example.org",
                                        "--envelope-sender", "alice@example.org",
                                        "--sasl-login", "alice",
                                        "--sasl-method", "PLAIN"])
            self.assertEqual(result, dispatch.EX_TEMPFAIL)
            self.assertNotIn("secret@example.org", err.getvalue())
            self.assertNotIn("alice@example.org", err.getvalue())

    def test_self_managed_route_is_not_auto_activated(self):
        source = SOURCE.read_text(encoding="utf-8")
        for fragment in ("postconf -e", "systemctl restart", "systemctl enable",
                         "SMTP365-CLIENT-SECRET", "smtp_sasl_password_maps"):
            self.assertNotIn(fragment, source)
        self.assertIn("--sasl-login", source)
        self.assertIn("--sasl-method", source)
        self.assertIn("expected-map-sha256", source)


if __name__ == "__main__":
    unittest.main()
