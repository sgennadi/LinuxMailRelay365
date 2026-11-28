#!/usr/bin/env python3
"""Disabled primary TPM broker candidate: authenticated AF_UNIX service/client.

The service creates only the fixed primary OAuth assertion, not a general
signing oracle. No unit, user, SELinux policy, device access or production
transport is installed here. The separately validated fixture is not a
production policy. Linux/Python 3.6+; all failures are closed, no PEM fallback.
"""
import argparse
from collections import OrderedDict, deque, namedtuple
import grp
import os
from pathlib import Path
import pwd
import re
import socket
import struct
import sys
import time
import uuid

import m365_tpm_broker_identity as identity
import m365_tpm_broker_protocol as protocol

SIGNER_ACCOUNT = "lmr365-tpm-signer"
MAIL_ACCOUNT = "m365mailer"
SIGNER_DOMAIN = "lmr365_tpm_signer_t"
MAIL_DOMAIN = "postfix_pipe_t"
SOCKET_ADDRESS = "\0lmr365-primary-tpm-broker-v1"
PEERSEC_LIMIT = 1024
BACKLOG = 8
REQUEST_TIMEOUT = 3
RESPONSE_TIMEOUT = 5
CLIENT_TIMEOUT = 120
REPLAY_SECONDS = 660
MAX_NONCES = 1024
RATE_SECONDS = 60
RATE_LIMIT = 60
Accounts = namedtuple("Accounts", "mail_uid mail_gid signer_uid signer_gid")
Peer = namedtuple("Peer", "pid uid gid domain")


class BrokerError(protocol.BrokerProtocolError):
    pass


def need(condition, code):
    if not condition:
        raise BrokerError(code)


def lookup_accounts():
    try:
        mail = pwd.getpwnam(MAIL_ACCOUNT)
        signer = pwd.getpwnam(SIGNER_ACCOUNT)
        mail_gid = grp.getgrnam(MAIL_ACCOUNT).gr_gid
        signer_gid = grp.getgrnam(SIGNER_ACCOUNT).gr_gid
        result = Accounts(mail.pw_uid, mail_gid, signer.pw_uid, signer_gid)
        need(all(type(n) is int and n > 0 for n in result) and
             mail.pw_uid != signer.pw_uid and mail_gid != signer_gid and
             mail.pw_gid == mail_gid and signer.pw_gid == signer_gid and
             set(os.getgrouplist(MAIL_ACCOUNT, mail_gid)) == {mail_gid} and
             set(os.getgrouplist(SIGNER_ACCOUNT, signer_gid)) ==
             {mail_gid, signer_gid}, "broker_account_scope")
        return result
    except (KeyError, OSError, OverflowError):
        raise BrokerError("broker_account_unavailable") from None


def context_type(raw):
    need(type(raw) is bytes and 0 < len(raw) < PEERSEC_LIMIT,
         "broker_security_context")
    if raw.endswith(b"\0"):
        raw = raw[:-1]
    try:
        fields = raw.decode("ascii", "strict").split(":", 3)
    except UnicodeError:
        raise BrokerError("broker_security_context") from None
    need(len(fields) == 4 and
         all(re.fullmatch(r"[A-Za-z0-9_]+", f) for f in fields[:2]) and
         re.fullmatch(r"[A-Za-z0-9_]+_t", fields[2]) and
         re.fullmatch(r"[A-Za-z0-9_.,:-]+", fields[3]),
         "broker_security_context")
    return fields[2]


def require_process(accounts, signer):
    uid = accounts.signer_uid if signer else accounts.mail_uid
    gid = accounts.signer_gid if signer else accounts.mail_gid
    groups = {accounts.signer_gid, accounts.mail_gid} if signer else {accounts.mail_gid}
    domain = SIGNER_DOMAIN if signer else MAIL_DOMAIN
    try:
        need(Path("/sys/fs/selinux/enforce").read_bytes().strip() == b"1",
             "broker_selinux_not_enforcing")
        need(os.getresuid() == (uid,) * 3 and os.getresgid() == (gid,) * 3 and
             set(os.getgroups()) | {gid} == groups and uid > 0 and gid > 0,
             "broker_process_credentials")
        raw = Path("/proc/self/attr/current").read_bytes()
        # procfs may append a newline, unlike SO_PEERSEC.
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        need(context_type(raw) == domain, "broker_process_domain")
        if not signer:
            need(not os.path.lexists("/dev/tpmrm0") and
                 not os.path.lexists("/dev/tpm0"), "broker_mail_tpm_visible")
    except (OSError, AttributeError):
        raise BrokerError("broker_process_unverified") from None


def peer_identity(conn):
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize("=iII"))
        pid, uid, gid = struct.unpack("=iII", raw)
        need(pid > 1 and uid > 0 and gid > 0, "broker_peer_credentials")
    except (OSError, AttributeError, ValueError, struct.error):
        raise BrokerError("broker_peer_credentials") from None
    try:
        context = conn.getsockopt(socket.SOL_SOCKET,
                                  getattr(socket, "SO_PEERSEC", 31), PEERSEC_LIMIT)
        domain = context_type(context)
    except (OSError, ValueError):
        raise BrokerError("broker_peer_context") from None
    return Peer(pid, uid, gid, domain)


def authenticate_peer(conn, accounts, expect_signer):
    peer = peer_identity(conn)
    expected = ((accounts.signer_uid, accounts.signer_gid, SIGNER_DOMAIN)
                if expect_signer else
                (accounts.mail_uid, accounts.mail_gid, MAIL_DOMAIN))
    need(peer.pid > 1 and (peer.uid, peer.gid, peer.domain) == expected,
         "broker_peer_mismatch")
    return peer


def remaining(deadline):
    seconds = deadline - time.monotonic()
    need(seconds > 0, "broker_io_deadline")
    return seconds


def read_frame(conn, limit, deadline):
    """One bounded frame followed by EOF, with a total monotonic deadline."""
    data = bytearray()
    while len(data) <= limit:
        conn.settimeout(remaining(deadline))
        chunk = conn.recv(min(4096, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    need(0 < len(data) <= limit, "broker_frame_size")
    return bytes(data)


def send_frame(conn, raw, deadline):
    conn.settimeout(remaining(deadline))
    conn.sendall(raw)
    conn.shutdown(socket.SHUT_WR)


class RequestWindow:
    """Single service process: bounded replay and signing-rate state.

    This is not a persistent replay database; a daemon restart resets it.
    Every legitimate client operation creates a new random nonce and JWT jti.
    Full nonexpired storage fails closed instead of evicting live entries.
    """
    def __init__(self):
        self.nonces = OrderedDict()
        self.recent = deque()
        self.last = None

    def claim(self, nonce, now=None):
        protocol.valid_nonce(nonce)
        stamp = time.monotonic() if now is None else now
        need(self.last is None or stamp >= self.last, "broker_monotonic_clock")
        self.last = stamp
        while self.nonces:
            first = next(iter(self.nonces))
            if stamp - self.nonces[first] < REPLAY_SECONDS:
                break
            self.nonces.popitem(last=False)
        while self.recent and stamp - self.recent[0] >= RATE_SECONDS:
            self.recent.popleft()
        need(nonce not in self.nonces, "broker_repeated_nonce")
        need(len(self.nonces) < MAX_NONCES, "broker_replay_capacity")
        need(len(self.recent) < RATE_LIMIT, "broker_signing_rate")
        # Reserve before invoking hardware, including failed requests.
        self.nonces[nonce] = stamp
        self.recent.append(stamp)


def handle_connection(conn, accounts, window):
    """Authenticated before reading; one response, or silent close."""
    try:
        authenticate_peer(conn, accounts, expect_signer=False)
        raw = read_frame(conn, protocol.REQUEST_LIMIT, time.monotonic() + REQUEST_TIMEOUT)
        nonce = protocol.decode_request(raw)
        window.claim(nonce)
        response = identity.issue_from_active_primary(raw)
        # Defensive framing and nonce check before sending even a local result.
        protocol.decode_response(response, nonce)
        send_frame(conn, response, time.monotonic() + RESPONSE_TIMEOUT)
        return True
    except (protocol.BrokerProtocolError, OSError):
        # No raw request, JWT, peer label or exception text in the journal.
        return False


def serve():
    """One synchronous worker; no socket activation or filesystem artifacts.

    The future installer must provision this exact account/domain and device
    sandbox before allowing execution. An occupied abstract address is fatal;
    never connect to, replace, or unlink another endpoint.
    """
    accounts = lookup_accounts()
    require_process(accounts, signer=True)
    window = RequestWindow()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(SOCKET_ADDRESS)
        listener.listen(BACKLOG)
        listener.settimeout(1)
        print("LMR365_TPM_BROKER_READY", flush=True)
        while True:
            # Do not continue serving if Enforcing or our identity changes.
            require_process(accounts, signer=True)
            need(lookup_accounts() == accounts, "broker_account_changed")
            try:
                conn, unused = listener.accept()
            except socket.timeout:
                continue
            with conn:
                require_process(accounts, signer=True)
                need(lookup_accounts() == accounts, "broker_account_changed")
                handle_connection(conn, accounts, window)


def request_primary_assertion():
    """Candidate client; NOT wired into the current mail transport.

    Verify peer before sending; read the same active identity on both sides
    of the entire exchange, and independently validate the returned PS256.
    """
    accounts = lookup_accounts()
    require_process(accounts, signer=False)
    before = identity.read_primary_snapshot()
    nonce = uuid.uuid4().hex
    raw = protocol.encode_request(nonce)
    deadline = time.monotonic() + CLIENT_TIMEOUT
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(remaining(deadline))
            conn.connect(SOCKET_ADDRESS)
            authenticate_peer(conn, accounts, expect_signer=True)
            send_frame(conn, raw, deadline)
            response = read_frame(conn, protocol.RESPONSE_LIMIT, deadline)
        result = protocol.verify_primary_response(response, nonce, before.configuration())
        need(before.matches(identity.read_primary_snapshot()), "broker_identity_changed")
        require_process(accounts, signer=False)
        need(lookup_accounts() == accounts, "broker_account_changed")
        return result
    except OSError:
        raise BrokerError("broker_ipc_unavailable") from None


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args(argv)
    if not args.serve:
        return 2
    try:
        serve()
    except KeyboardInterrupt:
        return 0
    except Exception:
        # Unexpected errors terminate the candidate without sensitive traces.
        print("LMR365_TPM_BROKER_FAILED", file=sys.stderr, flush=True)
        return 75
    return 75


if __name__ == "__main__":
    sys.exit(main())
