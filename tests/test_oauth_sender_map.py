"""Offline, non-mutating multi-mailbox XOAUTH2 sender map review tests."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "linux" / "audit-oauth-sender-map.py"
SPEC = importlib.util.spec_from_file_location("audit_oauth_sender_map", str(SOURCE))
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)

MAP = "/etc/linuxmailrelay365/oauth-senders.tsv"
IDENTITY_A = "/etc/linuxmailrelay365/oauth-identities/employee-1.json"
IDENTITY_B = "/etc/linuxmailrelay365/oauth-identities/employee-2.json"


def records(rows):
    return (AUDIT.HEADER + "\n" + "\n".join("\t".join(row) for row in rows) + "\n").encode("utf-8")


def identity(mailbox, tenant="11111111-1111-1111-1111-111111111111",
             client="22222222-2222-2222-2222-222222222222"):
    return json.dumps({
        "tenant_id": tenant,
        "client_id": client,
        "mailbox": mailbox,
        "certificate": "/etc/linuxmailrelay365/oauth-identities/public.pem",
        "signer": {"provider": "tpm2", "key_ref": "pkcs11:dummy"}
    }).encode("utf-8")


class OAuthSenderMapTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            ("alice", "alice@example.org", "alice@example.org", IDENTITY_A),
            ("bob", "bob@example.org", "service@example.org", IDENTITY_B),
        ]

    def test_valid_two_users_and_distinct_m365_mailboxes_structural_only(self):
        blobs = {
            MAP: records(self.rows),
            IDENTITY_A: identity("alice@example.org"),
            IDENTITY_B: identity("service@example.org"),
        }
        calls = []
        def reader(path, limit, mode, group):
            calls.append((path, limit, mode, group))
            return blobs[path]
        report = AUDIT.audit(MAP, reader=reader, service_gid=333)
        self.assertEqual(report["ENTRIES"], 2)
        self.assertEqual(report["LOCAL_LOGINS"], 2)
        self.assertEqual(report["MAILBOXES"], 2)
        self.assertEqual(report["IDENTITIES"], 2)
        self.assertEqual(report["TENANTS"], 1)
        self.assertEqual(report["SENDAS_DIFFERENT_FROM"], 1)
        self.assertEqual(report["POLICY_SIMULATION_TEST_CASES"], 14)
        self.assertEqual(calls[0], (MAP, AUDIT.MAX_MAP, 0o600, None))
        self.assertEqual(calls[1], (IDENTITY_A, AUDIT.MAX_IDENTITY, 0o640, 333))
        self.assertNotIn("alice@example.org", str(report))
        self.assertNotIn("bob@example.org", str(report))

    def test_map_path_rejects_traversal_symlinks_and_other_directories(self):
        for value in ("../../tmp/auth.tsv", "/tmp/auth.tsv",
                      "/etc/linuxmailrelay365/../etc/passwd.tsv",
                      "/etc/linuxmailrelay365/./senders.tsv",
                      "/etc/linuxmailrelay365/map.json",
                      "/etc/linuxmailrelay365/path with spaces.tsv",
                      "/etc/linuxmailrelay365/bad\nname.tsv"):
            with self.subTest(path=value):
                with self.assertRaises(AUDIT.Refused):
                    AUDIT.allowed_path(value)
        for value in ("/etc/linuxmailrelay365/oauth-identities/../x.json",
                      "/etc/linuxmailrelay365/map.json",
                      "/etc/linuxmailrelay365/oauth-identities/file.pem"):
            with self.assertRaises(AUDIT.Refused):
                AUDIT.allowed_path(value, identity=True)

    def test_rejects_untrusted_map_rows(self):
        good = list(self.rows)
        samples = (
            good + [good[0]],
            [("bad login!", good[0][1], "other@example.org", IDENTITY_B)],
            [("alice\tinjected", good[0][1], good[0][2], good[0][3])],
            [("hacker", "admin@example.org", "admin@example.org",
              "/etc/linuxmailrelay365/oauth-identities/../private.json")],
            [(good[0][0], good[0][1], good[0][2], "/tmp/key.json")],
            [("x", "x@example.org", "a@example.org", IDENTITY_A),
             ("y", "y@example.org", "a@example.org", IDENTITY_B)],
        )
        for rowset in samples:
            with self.subTest(rows=rowset), self.assertRaises(AUDIT.Refused):
                AUDIT.parse_map(records(rowset))
        for raw in (b"", b"missing header\n",
                    records(self.rows).replace(b"\n", b"\r\n"),
                    records(self.rows) + b"\x00",
                    records(self.rows) + b"\xff"):
            with self.assertRaises(AUDIT.Refused):
                AUDIT.parse_map(raw)

    def test_identity_requires_exact_sender_mailbox_and_no_inline_secrets(self):
        self.assertEqual(
            AUDIT.validate_identity(identity("alice@example.org"), "alice@example.org"),
            "11111111-1111-1111-1111-111111111111")
        for blob in (
            identity("admin@example.org"),
            b"{}",
            b'{"password":"x"}',
            b'{"client_secret":"secret"}',
            b"not-json",
            b'[]',
            identity("alice@example.org").replace(b'"signer":', b'"private_key": "abc", "signer":'),
            identity("alice@example.org").replace(b'"certificate":', b'"certificate_removed":'),
        ):
            with self.subTest(blob=blob[:16]), self.assertRaises(AUDIT.Refused):
                AUDIT.validate_identity(blob, "alice@example.org")

    def test_offline_policy_checks_exact_login_envelope_mailbox_and_from(self):
        rows = AUDIT.parse_map(records(self.rows))
        from_header = (b"From: Alice <alice@example.org>\r\n"
                       b"To: synthetic@example.net\r\n\r\nBody\r\n")
        self.assertTrue(AUDIT.authorize_offline(
            rows, "alice", "alice@example.org", "alice@example.org", from_header))
        self.assertEqual(AUDIT.simulate_policy(rows), 14)
        for login, envelope, mailbox, headers in (
            ("bob", "alice@example.org", "alice@example.org", from_header),
            ("alice", "other@example.org", "alice@example.org", from_header),
            ("alice", "alice@example.org", "service@example.org", from_header),
            ("alice", "alice@example.org", "alice@example.org",
             b"From: alice@other.example\r\n\r\n"),
            ("alice", "alice@example.org", "alice@example.org",
             b"From: alice@example.org\r\n"
             b"From: alice@example.org\r\n\r\n"),
            ("alice", "alice@example.org", "alice@example.org",
             b"From: alice@example.org, hacker@example.org\r\n\r\n"),
            ("alice", "alice@example.org", "alice@example.org",
             b"From: alice@example.org\r\n"
             b"Sender: hacker@example.org\r\n\r\n"),
            ("alice", "alice@example.org", "alice@example.org",
             b"From: alice@example.org\r\n"
             b"Resent-From: hacker@example.org\r\n\r\n"),
            ("alice", "alice@example.org", "alice@example.org",
             b"From: alice@example.org\r\n"
             b"Return-Path: <hacker@example.org>\r\n\r\n"),
            ("alice", "alice@example.org", "alice@example.org",
             b"From: alice@example.org\r\n"
             b"Sender: alice@example.org\r\n"
             b"Sender: alice@example.org\r\n\r\n"),
            ("alice", "alice@example.org", "alice@example.org",
             b"From: Team: alice@example.org;\r\n\r\n"),
            ("alice", "alice@example.org", "alice@example.org",
             b"From: alice@example.org\r\n\r\n" + b"A" * (AUDIT.MAX_OFFLINE_MESSAGE + 1)),
        ):
            with self.subTest(login=login, env=envelope, mailbox=mailbox,
                              raw=headers[:65]):
                with self.assertRaises(AUDIT.Refused):
                    AUDIT.authorize_offline(rows, login, envelope, mailbox, headers)

    def test_simulation_does_not_parse_real_mail_or_contact_tenant(self):
        rows = AUDIT.parse_map(records(self.rows))
        self.assertEqual(AUDIT.simulate_policy(rows), len(rows) * 7)
        bad = list(rows)
        bad[0] = (bad[0][0], bad[0][1], bad[0][2],
                  "/etc/linuxmailrelay365/oauth-identities/not-selected.json")
        self.assertEqual(AUDIT.simulate_policy(bad), len(rows) * 7)

    def test_refuses_missing_root_without_revealing_map(self):
        with mock.patch.object(AUDIT.os, "geteuid", return_value=1000), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(AUDIT.main(["--map-path", MAP]), 2)
        self.assertIn("root_required", err.getvalue())
        self.assertNotIn("alice", err.getvalue())

    def test_cli_reports_no_activation_and_no_sent_mail(self):
        report = {"MAP_SHA256": "a" * 64, "ENTRIES": 2, "LOCAL_LOGINS": 2,
                  "MAILBOXES": 2, "IDENTITIES": 2, "TENANTS": 1,
                  "SENDAS_DIFFERENT_FROM": 1,
                  "POLICY_SIMULATION_TEST_CASES": 14}
        with mock.patch.object(AUDIT.os, "geteuid", return_value=0), \
             mock.patch.object(AUDIT, "audit", return_value=report) as audited, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(AUDIT.main(["--map-path", MAP]), 0)
        audited.assert_called_once_with(MAP)
        result = out.getvalue()
        self.assertIn("OAUTH_SENDER_MAP_RESULT=structural_review_only", result)
        self.assertIn("OAUTH_SENDER_MAP_EXCHANGE_SENDAS_VERIFIED=no", result)
        self.assertIn("OAUTH_SENDER_MAP_POLICY_SIMULATION=passed_offline_only", result)
        self.assertIn("OAUTH_SENDER_MAP_POLICY_SIMULATION_TEST_CASES=14", result)
        self.assertIn("OAUTH_SENDER_MAP_HEADER_FROM_GUARD_ACTIVE=no", result)
        self.assertIn("OAUTH_SENDER_MAP_MESSAGES_SENT=no", result)
        self.assertIn("OAUTH_SENDER_MAP_POSTFIX_CHANGED=no", result)

    def test_secure_read_refuses_symlink_without_using_contents(self):
        with tempfile.TemporaryDirectory() as temp:
            real = Path(temp) / "real"
            real.write_text("secret", encoding="utf-8")
            fake = Path(temp) / "link"
            fake.symlink_to(real)
            with self.assertRaises(AUDIT.Refused):
                AUDIT.secure_read(str(fake), 8192, 0o600)

    def test_code_cannot_send_or_modify_postfix(self):
        source = SOURCE.read_text(encoding="utf-8")
        for forbidden in ("smtplib", "urllib.request", "requests.post",
                          "subprocess.run(", "tpm2_evictcontrol",
                          "postconf -e", "systemctl restart"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
