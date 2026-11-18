#!/usr/bin/env python3
"""Read-only integrity and access audit for LinuxMailRelay365 SMTP AUTH recovery archives.

Checks root-only directories, required file metadata, and SHA256 of archived
Postfix configurations against saved activation fingerprints. Never prints
file names, local hostnames, usernames, password hashes, TLS keys or content.
Compatible with Python 3.6 on RHEL/Oracle/Rocky/AlmaLinux 8.
"""
import hashlib
import os
import re
import stat
from pathlib import Path

ARCHIVE_ROOT = Path("/var/lib/linuxmailrelay365-sidecar-auth-recovery")
MAX_ARCHIVES = 200
REQUIRED = (
    "main.cf.auth",
    "master.cf.auth",
    "linuxmailrelay365-smtp-auth.service",
    "smtp-auth/main.cf.before-auth",
    "smtp-auth/main.cf.auth.sha256",
    "smtp-auth/master.cf.auth.sha256",
    "smtp-auth/passwd",
    "smtp-auth/privkey.pem",
    "smtp-auth/fullchain.pem",
    "smtp-auth/dovecot.conf",
)


def file_stat(path):
    try:
        return path.lstat()
    except OSError:
        return None


def safe_dir(path, uid, root_only):
    item = file_stat(path)
    if item is None or not stat.S_ISDIR(item.st_mode) or item.st_uid != uid:
        return False
    mode = stat.S_IMODE(item.st_mode)
    if mode & 0o022:
        return False
    if root_only and mode & 0o077:
        return False
    return True


def safe_file(path, uid, max_bytes):
    item = file_stat(path)
    if item is None or not stat.S_ISREG(item.st_mode) or item.st_uid != uid:
        return False
    if item.st_mode & 0o022 or item.st_mode & 0o007:
        return False
    return 0 < item.st_size <= max_bytes


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def archive_integrity(path, uid):
    if not safe_dir(path, uid, True):
        return "insecure_archive_dir"
    if not safe_dir(path / "smtp-auth", uid, False):
        return "insecure_auth_dir"
    for name in REQUIRED:
        full = path / name
        if not safe_file(full, uid, 5 * 1024 * 1024):
            return "missing_or_unsafe_file"
    for src, fingerprint in (
        ("main.cf.auth", "smtp-auth/main.cf.auth.sha256"),
        ("master.cf.auth", "smtp-auth/master.cf.auth.sha256"),
    ):
        try:
            expected = (path / fingerprint).read_text(encoding="ascii").strip()
            if not re.fullmatch(r"[0-9a-f]{64}", expected):
                return "invalid_fingerprint"
            if sha256(path / src) != expected:
                return "fingerprint_mismatch"
        except (OSError, UnicodeError, ValueError):
            return "unreadable_fingerprint"
    return "verified"


def audit(root=ARCHIVE_ROOT, uid=0):
    result = {
        "AUTH_TLS_ARCHIVE_AUDIT_VERSION": "1",
        "AUTH_TLS_ARCHIVE_STATUS": "not_created",
        "AUTH_TLS_ARCHIVE_COUNT": "0",
        "AUTH_TLS_ARCHIVE_POLICY": "manual_retention_required",
        "AUTH_TLS_ARCHIVE_PRIVATE_CONTENT_EXPOSED": "no",
        "MICROSOFT365_DELIVERY_VERIFIED": "no",
        "CHANGES_APPLIED": "no",
    }
    if not root.exists() and not root.is_symlink():
        return result
    if not safe_dir(root, uid, True):
        result["AUTH_TLS_ARCHIVE_STATUS"] = "unsafe_root_directory"
        return result
    try:
        children = list(root.iterdir())
    except OSError:
        result["AUTH_TLS_ARCHIVE_STATUS"] = "unreadable_directory"
        return result
    if len(children) > MAX_ARCHIVES:
        result["AUTH_TLS_ARCHIVE_STATUS"] = "too_many_entries_manual_review"
        result["AUTH_TLS_ARCHIVE_COUNT"] = "over_200"
        return result
    if not children:
        result["AUTH_TLS_ARCHIVE_STATUS"] = "empty"
        return result
    valid = 0
    for child in children:
        # Only the reserved recovery.* convention is accepted, no symlinks or
        # unexpected data in a directory meant to protect secret snapshots.
        if not re.fullmatch(r"recovery\.[A-Za-z0-9]{8}", child.name):
            result["AUTH_TLS_ARCHIVE_STATUS"] = "unexpected_entry_manual_review"
            return result
        if archive_integrity(child, uid) != "verified":
            result["AUTH_TLS_ARCHIVE_STATUS"] = "incomplete_or_tampered"
            return result
        valid += 1
    result["AUTH_TLS_ARCHIVE_COUNT"] = str(valid)
    result["AUTH_TLS_ARCHIVE_STATUS"] = "verified_root_only"
    return result


def main():
    if os.geteuid() != 0:
        print("AUTH_TLS_ARCHIVE_AUDIT_VERSION=1")
        print("AUTH_TLS_ARCHIVE_STATUS=root_required")
        print("CHANGES_APPLIED=no")
        return 2
    values = audit()
    for key, value in values.items():
        print("{}={}".format(key, value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
