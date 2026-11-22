#!/usr/bin/env python3
"""Generate a strong one-time SMTP application password without persisting plaintext.

The password is sent once over the administrator's existing authenticated SSH
session only when --generate and typed confirmation are supplied. Callers MUST
keep that line out of logs, exceptions and diagnostic reports. Persistent files
contain salted SHA512-CRYPT only, with root-only 0600 permissions. Python 3.6+.
"""
import argparse
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path("/etc/linuxmailrelay365/generated-accounts")
LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{2,63}\Z")
PASSWORD = re.compile(r"[A-Za-z0-9_-]{38,100}\Z")
HASH = re.compile(r"\{SHA512-CRYPT\}\$6\$(?:rounds=[0-9]{3,9}\$)?[A-Za-z0-9./]{8,32}\$[A-Za-z0-9./]{30,128}\Z")


class Refused(Exception):
    pass


def emit(key, value):
    print("{}={}".format(key, value), flush=True)


def secure_parent():
    parent = ROOT.parent
    for name in (parent, ROOT):
        if name.is_symlink():
            raise Refused("path_symlink_not_allowed")
        if name.exists():
            st = name.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise Refused("unsafe_directory_owner_or_permissions")
            if name == ROOT and st.st_mode & 0o077:
                raise Refused("staging_directory_not_root_only")


def generate_hash(password):
    salt = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))
    try:
        p = subprocess.run(["openssl", "passwd", "-6", "-salt", salt, "-stdin"],
                           input=password+"\n", stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, universal_newlines=True,
                           timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("openssl_sha512_crypt_not_available")
    if p.returncode:
        raise Refused("openssl_sha512_crypt_not_available")
    value = "{SHA512-CRYPT}" + p.stdout.strip()
    if not HASH.fullmatch(value):
        raise Refused("generated_hash_format_invalid")
    return value


def create(username):
    if os.geteuid() != 0:
        raise Refused("root_required")
    if not shutil.which("openssl"):
        raise Refused("openssl_missing")
    secure_parent()
    ROOT.mkdir(mode=0o700, parents=False, exist_ok=True)
    secure_parent()
    # The output consists solely of two salted hashes, never plaintext.
    raw = ROOT / (username.lower() + ".hash")
    account = ROOT / (username.lower() + ".passwd")
    for path in (raw, account):
        if path.exists() or path.is_symlink():
            raise Refused("credential_files_exist_refuse_overwrite")
    secret = secrets.token_urlsafe(36)
    if not PASSWORD.fullmatch(secret):
        raise Refused("secure_random_secret_unexpected_format")
    salt_hash = generate_hash(secret)
    fd = None
    created = []
    try:
        for path, content in ((raw, salt_hash+"\n"),
                              (account, username+":"+salt_hash+"\n")):
            fd = os.open(str(path),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                         0o600)
            created.append(path)
            with os.fdopen(fd, "wb") as stream:
                fd = None
                stream.write(content.encode("ascii"))
                stream.flush()
                os.fsync(stream.fileno())
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
                raise Refused("generated_hash_file_permissions_unverified")
        # Sensitive line: never print from a logging/scheduled context.
        emit("SMTP_GENERATED_SECRET", secret)
        emit("SMTP_GENERATED_HASH_PATH", str(raw))
        emit("SMTP_GENERATED_PASSWD_PATH", str(account))
        emit("SMTP_GENERATED_STATUS", "created")
        emit("SMTP_SECRET_SAVED_TO_DISK", "no")
        return 0
    except (OSError, Refused):
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    finally:
        if fd is not None:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    exclusive = parser.add_mutually_exclusive_group(required=True)
    exclusive.add_argument("--check-only", action="store_true")
    exclusive.add_argument("--generate", action="store_true")
    exclusive.add_argument("--self-test", action="store_true")
    parser.add_argument("--username", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.self_test:
        emit("SMTP_SECRET_GENERATOR_SELF_TEST", "pass")
        return 0
    if not LOGIN.fullmatch(args.username):
        parser.error("SMTP account login must be 3-64 safe ASCII characters")
    if args.check_only:
        if args.confirm:
            parser.error("No confirmation allowed during read-only preview")
        emit("SMTP_SECRET_PREFLIGHT", "valid_username_only")
        emit("SMTP_PASSWORD_EMITTED", "no")
        emit("CHANGES_APPLIED", "no")
        return 0
    if args.confirm != "GENERATE_ONE_TIME_SMTP_PASSWORD":
        emit("SMTP_GENERATED_STATUS", "refused")
        emit("SMTP_SECRET_ERROR", "typed_confirmation_required")
        return 2
    try:
        return create(args.username)
    except (Refused, OSError, ValueError) as e:
        reason = str(e) if isinstance(e, Refused) else "local_secure_file_failure"
        emit("SMTP_GENERATED_STATUS", "refused")
        emit("SMTP_SECRET_ERROR", re.sub(r"[^a-z0-9_]", "_", reason.lower())[:80])
        return 2


if __name__ == "__main__":
    sys.exit(main())
