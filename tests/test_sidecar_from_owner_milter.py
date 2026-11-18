"""Milter protocol and security tests for isolated private SMTP From ownership.

Python 3.6+ stdlib, no external sockets, no MTA/tenant, no message DATA.
"""
import importlib.util
import io
from pathlib import Path
import socket
import struct
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "linux" / "sidecar-from-owner-milter.py"
spec = importlib.util.spec_from_file_location("lmr365_from_milter", str(SCRIPT))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

OWNERS = {
    "alice@example.org": "smtp-app01",
    "billing@example.org": "smtp-app02",
    "alice+ci@example.org": "smtp-app01",
}


def start(owners=None):
    session = guard.Session(lambda: dict(OWNERS) if owners is None else owners())
    offer = struct.pack("!III", 6, 0, 0)
    assert session.handle(b"O", offer) == b"O" + struct.pack(
        "!III", 6, 0, guard.SMFIP_NOBODY)
    return session


def mail(session, sender="alice@example.org", login="smtp-app01", mechanism="PLAIN"):
    values = [
        b"auth_authen", login.encode("ascii"),
        b"auth_type", mechanism.encode("ascii"),
    ]
    macro = b"M" + b"\x00".join(values) + b"\x00"
    assert session.handle(b"D", macro) is None
    return session.handle(b"M", ("<" + sender + ">\x00").encode("ascii"))


def header(session, key, value):
    return session.handle(b"L", key.encode("ascii") + b"\x00" +
                          value.encode("utf-8") + b"\x00")


class PolicyTests(unittest.TestCase):
    def test_owner_maps_exact_and_case_normalized(self):
        raw = b"Alice@Example.org SMTP-app01\nbilling@example.org smtp-app02\n"
        self.assertEqual(guard.parse_owners(raw), {
            "alice@example.org": "smtp-app01",
            "billing@example.org": "smtp-app02",
        })

    def test_invalid_owner_files_fail_closed(self):
        invalid = [
            b"", b"alice@example.org\n", b"alice@example.org smtp-app01\n"
            b"Alice@example.org smtp-app02\n",
            b"alice@example.org *@bad\n",
            b"*@example.org smtp-app01\n",
            b"alice@example.org smtp-app01\n" * 65,
            b"alice@example.org smtp-app01\xff",
            b"alice@example.org smtp-app01\n # comment\n",
            b"alice@example.org smtp-app01 extra\n",
        ]
        for raw in invalid:
            with self.subTest(raw=repr(raw[:40])):
                with self.assertRaises(guard.PolicyError):
                    guard.parse_owners(raw)

    def test_header_parsing_accepts_single_named_or_quoted_mailbox(self):
        for value in ("alice@example.org",
                      "Alice Example <ALICE@example.org>",
                      '"Alice, Example" <alice@example.org>'):
            with self.subTest(value=value):
                self.assertEqual(guard.safe_from(value), "alice@example.org")

    def test_header_parsing_rejects_group_multiple_and_injection(self):
        examples = [
            "", "alice@example.org, billing@example.org",
            "Employees: alice@example.org;",
            "alice@example.org\r\nBcc: hidden@example.org",
            "Undisclosed recipients:;",
            "Alice <alice@example.org", "\x00alice@example.org",
            "alice@example.org; mail@example.org",
            "alice@example.org\nSender: alice@example.org",
        ]
        for value in examples:
            with self.subTest(value=repr(value)):
                self.assertIsNone(guard.safe_from(value))


class SessionTests(unittest.TestCase):
    def test_negotiation_and_bounded_frame_roundtrip(self):
        session = guard.Session(lambda: dict(OWNERS))
        self.assertEqual(session.handle(b"M", b"<alice@example.org>\x00"), b"t")
        self.assertEqual(session.handle(b"O", b"\x00"), b"t")
        session = start()
        self.assertEqual(session.handle(b"O", struct.pack("!III", 6, 0, 0)), b"t")
        self.assertEqual(session.handle(b"C", b""), b"c")
        self.assertEqual(session.handle(b"H", b"example.org\x00"), b"c")
        a,b = socket.socketpair()
        try:
            guard.send_frame(a, b"c")
            self.assertEqual(guard.read_frame(b), (b"c", b""))
            a.sendall(struct.pack("!I", 0))
            with self.assertRaises(guard.PolicyError):
                guard.read_frame(b)
        finally:
            a.close()
            b.close()

    def test_valid_from_sender_login_and_end_of_message(self):
        session = start()
        self.assertEqual(mail(session), b"c")
        self.assertEqual(session.handle(b"R", b"<recipient@example.org>\x00"), b"c")
        self.assertEqual(session.handle(b"T", b""), b"c")
        self.assertEqual(header(session, "Subject", "Unit test"), b"c")
        self.assertEqual(header(session, "From", "Alice <alice@example.org>"), b"c")
        self.assertEqual(session.handle(b"N", b""), b"c")
        self.assertEqual(session.handle(b"E", b""), b"c")
        self.assertEqual(session.from_header, None)

    def test_cross_account_from_is_rejected(self):
        session = start()
        self.assertEqual(mail(session), b"c")
        self.assertEqual(header(session, "From", "billing@example.org"), b"c")
        self.assertEqual(session.handle(b"N", b""), b"r")

    def test_cross_account_mail_from_is_rejected_even_if_header_matches(self):
        session = start()
        self.assertEqual(mail(session, sender="billing@example.org",
                              login="smtp-app01"), b"r")

    def test_missing_duplicate_ambiguous_and_resent_from_rejected(self):
        for mode in ("missing", "duplicate", "multiple", "resent", "sender"):
            with self.subTest(mode=mode):
                session = start()
                self.assertEqual(mail(session), b"c")
                if mode != "missing":
                    self.assertEqual(header(session, "From", "alice@example.org"), b"c")
                if mode == "duplicate":
                    self.assertEqual(header(session, "From", "alice@example.org"), b"r")
                elif mode == "multiple":
                    session = start()
                    self.assertEqual(mail(session), b"c")
                    self.assertEqual(header(session, "From",
                                            "alice@example.org, billing@example.org"),
                                     b"r")
                elif mode == "resent":
                    self.assertEqual(header(session, "Resent-From",
                                            "billing@example.org"), b"r")
                elif mode == "sender":
                    self.assertEqual(header(session, "Sender", "billing@example.org"),
                                     b"c")
                if mode in ("missing", "sender"):
                    self.assertEqual(session.handle(b"N", b""), b"r")

    def test_missing_auth_macros_and_bad_envelope_rejected(self):
        for login,mechanism in (("", "PLAIN"), ("smtp-app01","")):
            with self.subTest(login=login, mechanism=mechanism):
                session = start()
                self.assertEqual(mail(session, login=login, mechanism=mechanism), b"r")
        session = start()
        self.assertEqual(mail(session, sender="other@example.org"), b"r")

    def test_policy_error_tempfails_and_never_accepts(self):
        def invalid():
            raise guard.PolicyError("changed_policy_sha")
        session = start(invalid)
        self.assertEqual(mail(session), b"t")
        session = start(lambda: {})
        self.assertEqual(mail(session), b"r")

    def test_abort_resets_session_between_messages(self):
        session = start()
        self.assertEqual(mail(session), b"c")
        self.assertEqual(header(session, "From", "alice@example.org"), b"c")
        self.assertIsNone(session.handle(b"A", b""))
        self.assertEqual(mail(session, sender="billing@example.org",
                              login="smtp-app02"), b"c")
        self.assertEqual(header(session, "From", "billing@example.org"), b"c")
        self.assertEqual(session.handle(b"N", b""), b"c")
        self.assertEqual(session.handle(b"E", b""), b"c")

    def test_header_and_frame_limits_fail_closed(self):
        session = start()
        self.assertEqual(mail(session), b"c")
        for idx in range(guard.MAX_HEADERS):
            self.assertEqual(header(session, "X-Fixture", "v"), b"c")
        self.assertEqual(header(session, "From", "alice@example.org"), b"r")
        session = start()
        self.assertEqual(mail(session), b"c")
        self.assertEqual(session.handle(b"L",
            b"X-Big\x00" + b"A" * (guard.MAX_HEADER_BYTES + 1) + b"\x00"), b"r")

    def test_only_header_validation_no_body_or_message_mutation(self):
        session = start()
        self.assertEqual(mail(session), b"c")
        self.assertEqual(header(session, "From", "alice@example.org"), b"c")
        self.assertEqual(session.handle(b"N", b""), b"c")
        self.assertEqual(session.handle(b"B", b"body without inspection"), b"c")
        self.assertEqual(session.handle(b"E", b""), b"c")
        self.assertNotIn(b"a", (b"r", b"t"))
        self.assertNotIn("milter_default_action = accept", SCRIPT.read_text())

    def test_unknown_protocol_event_tempfails(self):
        session = start()
        self.assertEqual(session.handle(b"?", b""), b"t")


if __name__ == "__main__":
    unittest.main()
