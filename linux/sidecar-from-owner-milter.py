#!/usr/bin/env python3
"""Fail-closed RFC5322 From ownership Milter for isolated Postfix SMTP AUTH.

Preview / opt-in service foundation only. No package installation, primary MTA
changes, tenant access or mail sending. Python 3.6+ standard library.
Expected policy: root:postfix 0640, one 'address@domain login' per line.
The service must run under a dedicated unprivileged local account with the
postfix group and a private Unix socket. A reviewed deployer must explicitly
configure smtpd_milters; this file alone DOES NOT enable header filtering.
"""
import argparse
import email.policy
from email.parser import Parser
import grp
import hashlib
import os
from pathlib import Path
import pwd
import re
import socket
import socketserver
import stat
import struct
import sys

POLICY = Path("/etc/linuxmailrelay365/sidecar-postfix/eop-from-owners.tsv")
SOCKET = Path("/run/linuxmailrelay365-from-guard/from-guard.sock")
SERVICE_USER = "linuxmailrelay365-fromguard"
ADDRESS = re.compile(r"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\Z")
LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{2,63}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
MAX_OWNER_BYTES = 16384
MAX_FRAME_BYTES = 1024 * 1024
MAX_HEADERS = 256
MAX_HEADER_BYTES = 128 * 1024
VERSION = 6
SMFIP_NOBODY = 0x00000010


class PolicyError(Exception):
    pass


def parse_owners(raw):
    """Static owner map: no regex patterns, wildcard principals or macros."""
    if not 1 <= len(raw) <= MAX_OWNER_BYTES:
        raise PolicyError("owner_map_invalid_size")
    try:
        data = raw.decode("ascii")
    except UnicodeError:
        raise PolicyError("owner_map_non_ascii")
    result = {}
    lines = data.splitlines()
    if not 1 <= len(lines) <= 64:
        raise PolicyError("owner_map_record_count")
    for row in lines:
        parts = row.split()
        if len(parts) != 2:
            raise PolicyError("owner_map_invalid_record")
        addr, login = parts
        if not ADDRESS.fullmatch(addr) or not LOGIN.fullmatch(login):
            raise PolicyError("owner_map_invalid_identity")
        normalized = addr.lower()
        if normalized in result:
            raise PolicyError("owner_map_duplicate_address")
        result[normalized] = login.lower()
    return result


def protected_owner_file(path):
    """Permit only root:postfix readable; no symlink or user-writable policy."""
    if path != POLICY:
        raise PolicyError("unexpected_owner_map_path")
    for parent in (path.parent, path.parent.parent, path.parent.parent.parent):
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise PolicyError("unsafe_owner_map_parent")
    info = path.lstat()
    gid = grp.getgrnam("postfix").gr_gid
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != 0 or info.st_gid != gid or
            stat.S_IMODE(info.st_mode) != 0o640 or
            not 1 <= info.st_size <= MAX_OWNER_BYTES):
        raise PolicyError("unsafe_owner_map_permissions")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise PolicyError("owner_map_changed_during_read")
        data = os.read(fd, MAX_OWNER_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) != info.st_size:
        raise PolicyError("owner_map_changed_during_read")
    return data


def safe_from(value):
    """Exactly one uncomplicated RFC5322 mailbox. Reject groups and defects."""
    if not isinstance(value, str) or not 1 <= len(value) <= 8192:
        return None
    if "\r" in value or "\n" in value or "\x00" in value:
        return None
    try:
        msg = Parser(policy=email.policy.default).parsestr(
            "From: {}\n\n".format(value), headersonly=True)
        header = msg["From"]
        if header is None or header.defects or len(header.addresses) != 1:
            return None
        groups = header.groups
        if len(groups) != 1 or groups[0].display_name is not None:
            return None
        address = header.addresses[0].addr_spec
        if not ADDRESS.fullmatch(address):
            return None
        return address.lower()
    except (ValueError, TypeError, UnicodeError, AttributeError):
        return None


def parse_macro_packet(raw):
    """D stage followed by NUL-delimited macro names and values, no reply."""
    if len(raw) < 2:
        raise PolicyError("malformed_milter_macros")
    stage = raw[:1]
    pieces = raw[1:].split(b"\x00")
    if pieces[-1:] == [b""]:
        pieces.pop()
    if len(pieces) % 2 or len(pieces) > 96:
        raise PolicyError("malformed_milter_macros")
    result = {}
    for i in range(0, len(pieces), 2):
        try:
            name = pieces[i].decode("ascii").strip("{}").lower()
            value = pieces[i+1].decode("ascii")
        except UnicodeError:
            raise PolicyError("malformed_milter_macro_encoding")
        if name in result:
            raise PolicyError("duplicate_milter_macro")
        result[name] = value
    return stage, result


class Session(object):
    """Simple, strictly read-only Milter state machine; no message mutation."""
    def __init__(self, owner_loader):
        self.owner_loader = owner_loader
        self.negotiated = False
        self.pending = {}
        self.reset_message()

    def reset_message(self):
        self.login = ""
        self.envelope = ""
        self.auth_type = ""
        self.from_header = None
        self.sender_header = None
        self.headers = 0
        self.header_bytes = 0
        self.eoh = False
        self.rejected = False

    def handle(self, code, data):
        if code == b"O":
            if self.negotiated or len(data) < 12:
                return b"t"
            version, unused_actions, steps = struct.unpack("!III", data[:12])
            if version < 2 or version > 6:
                return b"t"
            self.negotiated = True
            return b"O" + struct.pack("!III", min(version, VERSION), 0, SMFIP_NOBODY)
        if not self.negotiated:
            return b"t"
        if code == b"D":
            stage, values = parse_macro_packet(data)
            if stage == b"M":
                self.pending[b"M"] = values
            return None
        if code == b"A":
            self.reset_message()
            self.pending.clear()
            return None
        if code in (b"Q", b"K"):
            return None
        if code == b"C" or code == b"H":
            return b"c"
        if code == b"M":
            self.reset_message()
            macros = self.pending.pop(b"M", {})
            self.login = macros.get("auth_authen", "").lower()
            self.auth_type = macros.get("auth_type", "")
            try:
                envelope = data.split(b"\x00", 1)[0].decode("ascii")
            except UnicodeError:
                return b"r"
            if not envelope.startswith("<") or not envelope.endswith(">"):
                return b"r"
            self.envelope = envelope[1:-1].lower()
            if not self.login or not LOGIN.fullmatch(self.login) or \
                    not ADDRESS.fullmatch(self.envelope) or \
                    not self.auth_type:
                return b"r"
            try:
                owners = self.owner_loader()
            except (OSError, PolicyError):
                return b"t"
            if owners.get(self.envelope) != self.login:
                return b"r"
            return b"c"
        if code in (b"R", b"T", b"U"):
            return b"c" if self.envelope else b"t"
        if code == b"L":
            if not self.envelope or self.eoh:
                return b"t"
            self.headers += 1
            self.header_bytes += len(data)
            if self.headers > MAX_HEADERS or self.header_bytes > MAX_HEADER_BYTES:
                return b"r"
            chunks = data.split(b"\x00")
            if len(chunks) != 3 or chunks[2] != b"":
                return b"r"
            try:
                name = chunks[0].decode("ascii").lower()
                value = chunks[1].decode("utf-8")
            except UnicodeError:
                return b"r"
            if len(name) > 128 or not re.fullmatch(r"[a-z0-9-]+", name):
                return b"r"
            if name == "from":
                if self.from_header is not None:
                    return b"r"
                self.from_header = safe_from(value)
                if self.from_header is None:
                    return b"r"
            elif name == "sender":
                if self.sender_header is not None:
                    return b"r"
                self.sender_header = safe_from(value)
                if self.sender_header is None:
                    return b"r"
            elif name in ("resent-from", "resent-sender", "return-path"):
                return b"r"
            return b"c"
        if code == b"N":
            self.eoh = True
            if self.from_header != self.envelope or \
                    (self.sender_header is not None and
                     self.sender_header != self.envelope):
                return b"r"
            return b"c"
        if code == b"B":
            return b"c" if self.eoh else b"t"
        if code == b"E":
            response = b"c" if self.eoh and self.from_header == self.envelope else b"r"
            self.reset_message()
            return response
        return b"t"


def recv_exact(stream, amount):
    data = b""
    while len(data) < amount:
        part = stream.recv(amount-len(data))
        if not part:
            raise EOFError()
        data += part
    return data


def read_frame(stream):
    size = struct.unpack("!I", recv_exact(stream, 4))[0]
    if size < 1 or size > MAX_FRAME_BYTES:
        raise PolicyError("unsafe_milter_frame_size")
    data = recv_exact(stream, size)
    return data[:1], data[1:]


def send_frame(stream, payload):
    stream.sendall(struct.pack("!I", len(payload)) + payload)


def serve(expected_sha):
    """Run under a dedicated non-privileged account in a private systemd unit."""
    identity = pwd.getpwnam(SERVICE_USER)
    postfix_group = grp.getgrnam("postfix")
    if (identity.pw_uid == 0 or os.geteuid() != identity.pw_uid or
            os.getegid() != postfix_group.gr_gid):
        raise PolicyError("milter_must_run_dedicated_unprivileged_user")
    def load():
        raw = protected_owner_file(POLICY)
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            raise PolicyError("owner_policy_changed_since_approved_deploy")
        return parse_owners(raw)
    load()
    directory = SOCKET.parent
    meta = directory.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != identity.pw_uid or \
            meta.st_gid != postfix_group.gr_gid or meta.st_mode & 0o027:
        raise PolicyError("unsafe_private_socket_directory")
    if SOCKET.exists() or SOCKET.is_symlink():
        raise PolicyError("milter_socket_already_exists")
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(12)
            session = Session(load)
            try:
                while True:
                    command, payload = read_frame(self.request)
                    reply = session.handle(command, payload)
                    if reply is not None:
                        send_frame(self.request, reply)
                    if command in (b"Q", b"K"):
                        break
            except (EOFError, OSError, PolicyError):
                # Postfix milter_default_action=tempfail; connection closure
                # fails closed, without logging message content or identities.
                return
    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
        request_queue_size = 32
        allow_reuse_address = False
    old_mask = os.umask(0o007)
    try:
        with Server(str(SOCKET), Handler) as server:
            os.chmod(str(SOCKET), 0o660)
            server.serve_forever(poll_interval=0.5)
    finally:
        os.umask(old_mask)
        if SOCKET.exists() and not SOCKET.is_symlink():
            SOCKET.unlink()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--serve", action="store_true")
    group.add_argument("--self-test", action="store_true")
    p.add_argument("--expected-map-sha256", default="")
    args = p.parse_args(argv)
    if args.self_test:
        assert safe_from("Alice <alice@example.org>") == "alice@example.org"
        assert safe_from("alice@example.org, other@example.org") is None
        assert parse_owners(b"alice@example.org smtp-app01\n") == {
            "alice@example.org": "smtp-app01"}
        print("FROM_OWNER_MILTER_SELF_TEST=pass")
        print("CHANGES_APPLIED=no")
        return 0
    if not HEX.fullmatch(args.expected_map_sha256):
        print("FROM_OWNER_MILTER_ERROR=reviewed_policy_sha256_required")
        return 2
    try:
        serve(args.expected_map_sha256)
    except (PolicyError, OSError, KeyError):
        print("FROM_OWNER_MILTER_STATUS=fail_closed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
