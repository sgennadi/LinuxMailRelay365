"""Disabled broker IPC: real local socket framing plus mocked policy/TPM."""
import os
import pathlib
import socket
import struct
import sys
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
import m365_tpm_broker_service as B


class BrokerServiceTests(unittest.TestCase):
    def setUp(self):
        self.accounts = B.Accounts(20, 30, 40, 50)
        self.nonce = "a" * 32
        self.request = B.protocol.encode_request(self.nonce)

    def test_peer_credentials_and_context_are_bounded(self):
        conn = Mock()
        for domain in (B.MAIL_DOMAIN, B.SIGNER_DOMAIN):
            conn.getsockopt.side_effect = [
                struct.pack("=iII", 12, 20, 30),
                ("system_u:system_r:" + domain + ":s0\0").encode("ascii")]
            self.assertEqual(B.peer_identity(conn), B.Peer(12, 20, 30, domain))
            self.assertEqual(conn.getsockopt.call_args_list[-1][0][-1], 1024)
            conn.reset_mock()
        for label in (b"", b"unconfined", b"x:y:postfix_pipe_t:",
                      b"x:y:postfix_pipe_t:s0\0\0", b"x" * 1024,
                      b"x:y:postfix_pipe_t:s0\n"):
            conn.getsockopt.side_effect = [struct.pack("=iII", 12, 20, 30), label]
            with self.assertRaisesRegex(B.BrokerError, "^broker_peer_context$"):
                B.peer_identity(conn)
        conn.getsockopt.side_effect = [struct.pack("=iII", 12, 0, 30)]
        with self.assertRaisesRegex(B.BrokerError, "^broker_peer_credentials$"):
            B.peer_identity(conn)

    def test_peer_checks_both_uid_gid_and_domain(self):
        for signer, expected in ((True, B.Peer(12, 40, 50, B.SIGNER_DOMAIN)),
                                 (False, B.Peer(12, 20, 30, B.MAIL_DOMAIN))):
            with patch.object(B, "peer_identity", return_value=expected):
                self.assertEqual(B.authenticate_peer(Mock(), self.accounts, signer), expected)
            for changed in (expected._replace(uid=99), expected._replace(gid=99),
                            expected._replace(domain="unconfined_service_t"),
                            expected._replace(pid=1)):
                with patch.object(B, "peer_identity", return_value=changed):
                    with self.assertRaisesRegex(B.BrokerError, "^broker_peer_mismatch$"):
                        B.authenticate_peer(Mock(), self.accounts, signer)

    def test_unauthorized_connection_never_reads_or_signs(self):
        conn = Mock()
        window = Mock()
        with patch.object(B, "authenticate_peer", side_effect=B.BrokerError("broker_peer_mismatch")), \
                patch.object(B.identity, "issue_from_active_primary") as issue:
            self.assertFalse(B.handle_connection(conn, self.accounts, window))
            conn.recv.assert_not_called()
            conn.sendall.assert_not_called()
            window.claim.assert_not_called()
            issue.assert_not_called()

    def test_window_rejects_replay_capacity_and_rate_without_eviction(self):
        w = B.RequestWindow()
        w.claim(self.nonce, 100)
        with self.assertRaisesRegex(B.BrokerError, "^broker_repeated_nonce$"):
            w.claim(self.nonce, 101)
        with patch.object(B, "RATE_LIMIT", 1):
            with self.assertRaisesRegex(B.BrokerError, "^broker_signing_rate$"):
                w.claim("b" * 32, 102)
        with patch.object(B, "MAX_NONCES", 1):
            with self.assertRaisesRegex(B.BrokerError, "^broker_replay_capacity$"):
                w.claim("b" * 32, 161)
        w.claim(self.nonce, 760)
        with self.assertRaisesRegex(B.BrokerError, "^broker_monotonic_clock$"):
            w.claim("b" * 32, 759)
        self.assertEqual(len(w.nonces), 1)

    @unittest.skipUnless(hasattr(socket, "socketpair"), "local socketpair required")
    def test_real_socketpair_one_request_and_eof(self):
        client, server = socket.socketpair()
        with client, server:
            client.sendall(self.request[:5])
            client.sendall(self.request[5:])
            client.shutdown(socket.SHUT_WR)
            with patch.object(B, "authenticate_peer"), \
                    patch.object(B.identity, "issue_from_active_primary", return_value=b"opaque\n") as issue, \
                    patch.object(B.protocol, "decode_response") as validate:
                self.assertTrue(B.handle_connection(server, self.accounts, B.RequestWindow()))
                self.assertEqual(B.read_frame(client, 64, time.monotonic() + 2), b"opaque\n")
                issue.assert_called_once_with(self.request)
                validate.assert_called_once_with(b"opaque\n", self.nonce)

    @unittest.skipUnless(hasattr(socket, "socketpair"), "local socketpair required")
    def test_oversize_or_extra_frame_does_not_sign(self):
        for raw in (b"x" * (B.protocol.REQUEST_LIMIT + 1), self.request + self.request):
            client, server = socket.socketpair()
            with client, server:
                client.sendall(raw)
                client.shutdown(socket.SHUT_WR)
                with patch.object(B, "authenticate_peer"), \
                        patch.object(B.identity, "issue_from_active_primary") as issue:
                    self.assertFalse(B.handle_connection(server, self.accounts, B.RequestWindow()))
                    issue.assert_not_called()

    def test_deadline_prevents_read_after_expiry(self):
        conn = Mock()
        with patch.object(B.time, "monotonic", return_value=10):
            with self.assertRaisesRegex(B.BrokerError, "^broker_io_deadline$"):
                B.read_frame(conn, 20, 9)
            conn.recv.assert_not_called()

    def test_client_rejects_wrong_peer_before_sending(self):
        snapshot = Mock()
        with patch.object(B, "lookup_accounts", return_value=self.accounts), \
                patch.object(B, "require_process"), \
                patch.object(B.identity, "read_primary_snapshot", return_value=snapshot), \
                patch.object(B.socket, "socket") as factory, \
                patch.object(B, "authenticate_peer", side_effect=B.BrokerError("broker_peer_mismatch")), \
                patch.object(B.protocol, "verify_primary_response") as verify:
            conn = factory.return_value.__enter__.return_value
            with self.assertRaisesRegex(B.BrokerError, "^broker_peer_mismatch$"):
                B.request_primary_assertion()
            conn.connect.assert_called_once_with(B.SOCKET_ADDRESS)
            conn.sendall.assert_not_called()
            verify.assert_not_called()

    def test_client_rejects_rotation_after_exchange(self):
        before, after = Mock(), Mock()
        before.matches.return_value = False
        with patch.object(B, "lookup_accounts", return_value=self.accounts), \
                patch.object(B, "require_process"), \
                patch.object(B.identity, "read_primary_snapshot", side_effect=[before, after]), \
                patch.object(B.socket, "socket"), \
                patch.object(B, "authenticate_peer"), \
                patch.object(B, "send_frame"), \
                patch.object(B, "read_frame", return_value=b"opaque"), \
                patch.object(B.protocol, "verify_primary_response", return_value=("endpoint", "assertion")):
            with self.assertRaisesRegex(B.BrokerError, "^broker_identity_changed$"):
                B.request_primary_assertion()

    def test_service_requires_enforcing_before_bind(self):
        with patch.object(B, "lookup_accounts", return_value=self.accounts), \
                patch.object(B.Path, "read_bytes", return_value=b"0"), \
                patch.object(B.socket, "socket") as factory:
            with self.assertRaisesRegex(B.BrokerError, "^broker_selinux_not_enforcing$"):
                B.serve()
            factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
