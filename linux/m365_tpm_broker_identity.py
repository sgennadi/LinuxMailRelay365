"""Protected active primary TPM identity for the disabled broker candidate.

Read only, Linux/Python 3.6+. No daemon, installation, changes to Postfix,
TPM allocation, or Entra access. All public entrypoints use fixed paths and
root ownership; the private directory-fd helper also supports isolated tests.
Root is trusted. A before/after snapshot detects ordinary concurrent
rotation, not an adversarial root who can replace and restore files.
"""
import grp
import hashlib
import os
import stat
from contextlib import contextmanager

import m365_tpm_broker_protocol as protocol

MAX_IDENTITY = 32768
MAX_CERTIFICATE = 65536
MAX_PROVIDER = 32768
# Exact output of manage-tpm-oauth-key.py for a native resource manager.
# Refuse arbitrary OpenSSL includes, provider modules, TCTI and PIN settings.
MANAGED_PROVIDER = b"""# Managed by LinuxMailRelay365 TPM2 provisioning.
# Hardware key is at an owner persistent handle; never a PEM private key.
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
tpm2 = tpm2_sect
[default_sect]
activate = 1
[tpm2_sect]
activate = 1
tcti = device:/dev/tpmrm0
"""
DIRECTORIES = ("etc", "postfix", "m365-oauth")
FILES = (
    ("app.json", MAX_IDENTITY, (0o640,)),
    ("hardware-app.crt", MAX_CERTIFICATE, (0o640, 0o644)),
    ("tpm2.cnf", MAX_PROVIDER, (0o640,)),
)
IDENTITY_FIELDS = {"tenant_id", "client_id", "mailbox", "certificate", "signer"}


class IdentityError(protocol.BrokerProtocolError):
    pass


def need(condition, code):
    if not condition:
        raise IdentityError(code)


def fingerprint(meta):
    # Exclude atime: reading must not invalidate an otherwise stable snapshot.
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def checked_directory(meta, owner=0):
    need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == owner and
         not meta.st_mode & 0o6022, "broker_identity_directory_unsafe")


@contextmanager
def open_identity_directory(group):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = None
    try:
        fd = os.open("/", flags)
        checked_directory(os.fstat(fd))
        for name in DIRECTORIES:
            child = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            checked_directory(os.fstat(fd))
        meta = os.fstat(fd)
        need(meta.st_gid == group and stat.S_IMODE(meta.st_mode) == 0o750,
             "broker_identity_directory_permissions")
        yield fd
    except OSError:
        raise IdentityError("broker_identity_directory_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def checked_file(meta, owner, group, modes, limit):
    need(stat.S_ISREG(meta.st_mode) and meta.st_uid == owner and
         meta.st_gid == group and meta.st_nlink == 1 and
         stat.S_IMODE(meta.st_mode) in modes and 0 < meta.st_size <= limit,
         "broker_identity_file_unsafe")


def read_file(directory_fd, name, limit, modes, group, owner):
    need(any((name, limit, modes) == item for item in FILES),
         "broker_identity_file_not_allowlisted")
    fd = None
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        checked_file(before, owner, group, modes, limit)
        # O_NONBLOCK avoids hanging on a substituted FIFO; verify the opened
        # inode before reading, even though the directory is root-managed.
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                     os.O_NONBLOCK, dir_fd=directory_fd)
        opened = os.fstat(fd)
        checked_file(opened, owner, group, modes, limit)
        stamp = fingerprint(before)
        need(fingerprint(opened) == stamp, "broker_identity_changed")
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        need(len(raw) == before.st_size and len(raw) <= limit and
             fingerprint(after) == stamp and fingerprint(current) == stamp,
             "broker_identity_changed")
        data = bytes(raw)
        return data, (name, stamp, hashlib.sha256(data).digest())
    except OSError:
        raise IdentityError("broker_identity_file_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def parse_identity(raw):
    config = protocol.json_object(raw, MAX_IDENTITY)
    need(set(config) == IDENTITY_FIELDS, "broker_active_identity_fields")
    config["_identity_path"] = str(protocol.IDENTITY)
    protocol.require_primary_identity(config)
    # The provisioning tool allocates from the owner application window.
    # Do not permit other persistent platform/owner handles in this mode.
    handle = config["signer"]["key_ref"]
    need(handle.startswith("handle:0x8101") and handle == handle.lower(),
         "broker_tpm_handle_window")
    need(len(config["mailbox"]) <= 320, "broker_identity_mailbox_size")
    return config


class IdentitySnapshot:
    __slots__ = ("_identity", "_stamp")

    def __init__(self, identity, stamp):
        self._identity = identity
        self._stamp = stamp

    def configuration(self):
        # A fresh copy for each operation; no mutable cached config exposed.
        return parse_identity(self._identity)

    def matches(self, other):
        return isinstance(other, IdentitySnapshot) and self._stamp == other._stamp

    def __repr__(self):
        return "IdentitySnapshot(<protected>)"


def snapshot_directory(fd, group, owner=0):
    before = os.fstat(fd)
    checked_directory(before, owner)
    need(before.st_gid == group and stat.S_IMODE(before.st_mode) == 0o750,
         "broker_identity_directory_permissions")
    files = {}
    stamps = []
    for name, limit, modes in FILES:
        data, stamp = read_file(fd, name, limit, modes, group, owner)
        files[name] = data
        stamps.append(stamp)
    need(fingerprint(os.fstat(fd)) == fingerprint(before),
         "broker_identity_changed")
    # Recheck every name after reading the entire set, not merely each file.
    for name, stamp, unused_digest in stamps:
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(fingerprint(current) == stamp, "broker_identity_changed")
    need(files["tpm2.cnf"] == MANAGED_PROVIDER,
         "broker_provider_not_managed_template")
    cert = files["hardware-app.crt"]
    need(cert.startswith(b"-----BEGIN CERTIFICATE-----\n") and
         cert.rstrip(b"\n").endswith(b"-----END CERTIFICATE-----") and
         cert.count(b"-----BEGIN CERTIFICATE-----") == 1 and
         cert.count(b"-----END CERTIFICATE-----") == 1,
         "broker_certificate_format")
    parse_identity(files["app.json"])
    return IdentitySnapshot(files["app.json"], (fingerprint(before), tuple(stamps)))


def read_primary_snapshot():
    try:
        group = grp.getgrnam("m365mailer").gr_gid
        need(group > 0, "broker_identity_group_invalid")
        with open_identity_directory(group) as fd:
            return snapshot_directory(fd, group)
    except KeyError:
        raise IdentityError("broker_identity_group_missing") from None
    except OSError:
        raise IdentityError("broker_identity_read_failed") from None


def issue_from_active_primary(raw):
    """Call only AFTER authenticating the peer. No result on identity drift."""
    protocol.decode_request(raw)
    before = read_primary_snapshot()
    result = protocol.issue_primary_assertion(raw, before.configuration())
    need(before.matches(read_primary_snapshot()), "broker_identity_changed")
    return result


def verify_from_active_primary(raw, nonce):
    """Return a verified assertion for the unchanged active identity only."""
    protocol.decode_response(raw, nonce)
    before = read_primary_snapshot()
    result = protocol.verify_primary_response(raw, nonce, before.configuration())
    need(before.matches(read_primary_snapshot()), "broker_identity_changed")
    return result
