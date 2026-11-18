#!/usr/bin/env python3
"""Manage one app's SMTP AUTH hash in the isolated Dovecot passwd-file.

Python 3.6+, no plaintext passwords, no public socket, no changes to
Microsoft 365 sender scope or the primary Postfix. A root-only Linux file
with the salted SHA512-CRYPT output of 'doveadm pw -s SHA512-CRYPT' is used
for add/rotate. The Windows GUI sends only an approved Linux path.
--check-only is read-only, --apply requires a checked state fingerprint.
"""
import argparse
import fcntl
import hashlib
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

AUTH = Path("/etc/linuxmailrelay365/smtp-auth")
HASHES = AUTH / "passwd"
SIDECAR = Path("/etc/linuxmailrelay365/sidecar-postfix")
LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")
BACKUPS = Path("/var/lib/linuxmailrelay365-smtp-account-recovery")
UNIT = "linuxmailrelay365-smtp-auth.service"
USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{2,63}\Z")
HASH = re.compile(r"\{SHA512-CRYPT\}\$6\$(?:rounds=[0-9]{3,9}\$)?[A-Za-z0-9./]{8,32}\$[A-Za-z0-9./]{30,128}\Z")
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]{1,255}\Z")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_accounts(data):
    """Strict and deterministic parser; never echoes usernames or hashes."""
    if not data or len(data) > 32768 or b"\x00" in data or b"\r" in data:
        raise ValueError("invalid_hash_file")
    try:
        rows = data.decode("ascii").splitlines()
    except UnicodeError:
        raise ValueError("non_ascii_hash_file")
    if not 1 <= len(rows) <= 64:
        raise ValueError("account_count_outside_1_64")
    accounts = {}
    for row in rows:
        if row.count(":") != 1:
            raise ValueError("invalid_account_record")
        username, token = row.split(":", 1)
        if not USERNAME.fullmatch(username) or not HASH.fullmatch(token):
            raise ValueError("invalid_username_or_salted_hash")
        folded = username.lower()
        if folded in (name.lower() for name in accounts):
            raise ValueError("duplicate_username")
        accounts[username] = token
    return accounts


def output(accounts):
    return ("".join("{}:{}\n".format(key, accounts[key]) for key in sorted(
        accounts, key=lambda item: item.lower()))).encode("ascii")


def mutate(accounts, operation, username, newhash):
    result = dict(accounts)
    existing = next((x for x in result if x.lower() == username.lower()), None)
    if operation == "add":
        if existing is not None:
            raise ValueError("account_already_exists")
        if len(result) >= 64:
            raise ValueError("maximum_64_accounts")
        result[username] = newhash
    elif operation == "rotate":
        if existing is None:
            raise ValueError("account_not_found")
        if result[existing] == newhash:
            raise ValueError("new_hash_must_differ")
        result[existing] = newhash
    elif operation == "revoke":
        if existing is None:
            raise ValueError("account_not_found")
        if len(result) == 1:
            raise ValueError("last_account_cannot_be_revoked")
        del result[existing]
    else:
        raise ValueError("unknown_operation")
    load_accounts(output(result))
    return result


def safe_regular(path, root_uid=0, must_be_private=False, maximum=32768):
    item = path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_uid != root_uid:
        raise ValueError("file_must_be_root_owned_regular")
    if item.st_mode & 0o022 or (must_be_private and item.st_mode & 0o077):
        raise ValueError("unsafe_file_permissions")
    if item.st_size < 1 or item.st_size > maximum:
        raise ValueError("unsafe_file_size")


def root_service_state(port):
    if os.geteuid() != 0:
        raise ValueError("root_required")
    for tool in ("systemctl", "doveconf"):
        if shutil.which(tool) is None:
            raise ValueError("missing_{}".format(tool))
    if HASHES.is_symlink() or not AUTH.is_dir() or AUTH.is_symlink():
        raise ValueError("existing_auth_directory_missing_or_symlink")
    parent = AUTH.lstat()
    if parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError("unsafe_auth_directory")
    safe_regular(HASHES)
    if not (SIDECAR / "smtp-port").is_file():
        raise ValueError("sidecar_not_installed")
    if (SIDECAR / "smtp-port").read_text(encoding="ascii").strip() != str(port):
        raise ValueError("installed_custom_port_mismatch")
    for unit in (UNIT, "linuxmailrelay365-sidecar.service"):
        p = subprocess.run(["systemctl", "is-active", "--quiet", unit],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=8, check=False)
        if p.returncode:
            raise ValueError("isolated_service_not_active")
    if not (Path("/var/spool/linuxmailrelay365-sidecar/private/auth")).is_socket() if hasattr(Path, "is_socket") else False:
        raise ValueError("auth_socket_missing")
    os_id = ""
    try:
        source = Path("/etc/os-release").read_text(encoding="utf-8")
        m = re.search(r'(?m)^ID=["\']?([A-Za-z0-9_-]+)["\']?\s*$', source)
        os_id = m.group(1) if m else ""
    except OSError:
        pass
    enforcing = Path("/sys/fs/selinux/enforce")
    if enforcing.is_file():
        try:
            if enforcing.read_text().strip() == "1":
                raise ValueError("selinux_enforcing_not_integration_verified")
        except OSError:
            raise ValueError("selinux_status_unknown")
    elif os_id in ("rhel", "ol", "rocky", "almalinux", "centos"):
        raise ValueError("rhel_selinux_status_unknown")


def read_new_hash(filename):
    if not filename or not SAFE_PATH.fullmatch(filename) or ".." in filename.split("/"):
        raise ValueError("unsafe_hash_source_path")
    source = Path(filename)
    if source == HASHES or source.is_symlink():
        raise ValueError("hash_source_must_be_separate")
    safe_regular(source, must_be_private=True, maximum=512)
    text = source.read_text(encoding="ascii").strip()
    if not HASH.fullmatch(text):
        raise ValueError("require_doveadm_sha512_crypt_hash")
    return text


def restart_and_verify():
    p = subprocess.run(["systemctl", "restart", UNIT],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if p.returncode:
        raise ValueError("isolated_dovecot_restart_failed")
    sock = Path("/var/spool/linuxmailrelay365-sidecar/private/auth")
    for _ in range(40):
        q = subprocess.run(["systemctl", "is-active", "--quiet", UNIT],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
        if q.returncode == 0 and sock.exists():
            return
        time.sleep(0.2)
    raise ValueError("isolated_sasl_socket_not_ready")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--smtp-port", type=int, required=True)
    p.add_argument("--operation", choices=("status", "add", "rotate", "revoke"), default="status")
    p.add_argument("--username", default="")
    p.add_argument("--hash-file", default="")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--expected-state-sha256", default="")
    p.add_argument("--confirm", default="")
    args = p.parse_args()
    if not 1024 <= args.smtp_port <= 65535:
        p.error("Custom port must be 1024-65535")
    if args.operation != "status" and not USERNAME.fullmatch(args.username):
        p.error("Invalid SMTP username")
    if args.operation == "status" and (args.apply or args.hash_file):
        p.error("Status cannot modify accounts")
    if args.operation == "revoke" and args.hash_file:
        p.error("Revoke does not accept a hash")
    if args.operation in ("add", "rotate") and not args.hash_file:
        p.error("Add/rotate requires an existing Linux hash source file")
    if args.apply and (args.confirm != "CHANGE_PRIVATE_SMTP_ACCOUNT" or
                       not re.fullmatch(r"[a-f0-9]{64}", args.expected_state_sha256)):
        p.error("Apply requires exact state SHA256 and typed confirmation")

    state = {
        "SMTP_ACCOUNT_TOOL_VERSION": "1",
        "SMTP_CUSTOM_PORT": str(args.smtp_port),
        "SMTP_ACCOUNT_OPERATION": args.operation,
        "SMTP_ACCOUNT_CHANGED": "no",
        "SMTP_ACCOUNT_HASH_CONTENT_RETURNED": "no",
        "MICROSOFT365_DELIVERY_VERIFIED": "no",
    }
    lock_fd = None
    backup = None
    try:
        root_service_state(args.smtp_port)
        if args.apply:
            lock_fd = os.open(str(LOCK), os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (OSError, IOError):
                raise ValueError("concurrent_mail_change")
        current_bytes = HASHES.read_bytes()
        accounts = load_accounts(current_bytes)
        state["SMTP_ACCOUNT_COUNT_BEFORE"] = str(len(accounts))
        state["SMTP_ACCOUNT_CURRENT_STATE_SHA256"] = sha256(current_bytes)
        if args.operation == "status":
            if args.username:
                state["SMTP_ACCOUNT_FOUND"] = (
                    "yes" if args.username.lower() in (x.lower() for x in accounts) else "no")
            state["SMTP_ACCOUNT_RESULT"] = "read_only"
        else:
            secret = read_new_hash(args.hash_file) if args.operation in ("add", "rotate") else None
            updated = mutate(accounts, args.operation, args.username, secret)
            state["SMTP_ACCOUNT_COUNT_AFTER"] = str(len(updated))
            if not args.apply:
                state["SMTP_ACCOUNT_RESULT"] = "preview_ready"
            else:
                if state["SMTP_ACCOUNT_CURRENT_STATE_SHA256"] != args.expected_state_sha256:
                    raise ValueError("credentials_changed_since_preview")
                if BACKUPS.is_symlink():
                    raise ValueError("backup_parent_symlink")
                BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
                if BACKUPS.stat().st_uid != 0 or BACKUPS.stat().st_mode & 0o077:
                    raise ValueError("backup_parent_must_be_root_only")
                backup_dir = Path(tempfile.mkdtemp(prefix="rotation.", dir=str(BACKUPS)))
                os.chmod(str(backup_dir), 0o700)
                backup = backup_dir / "passwd.before"
                shutil.copy2(str(HASHES), str(backup))
                os.chown(str(backup), 0, 0)
                os.chmod(str(backup), 0o600)
                if sha256(backup.read_bytes()) != state["SMTP_ACCOUNT_CURRENT_STATE_SHA256"]:
                    raise ValueError("backup_hash_verification_failed")
                tmp_fd, tmp_name = tempfile.mkstemp(prefix=".passwd.", dir=str(AUTH))
                try:
                    with os.fdopen(tmp_fd, "wb") as fd:
                        fd.write(output(updated))
                        fd.flush()
                        os.fsync(fd.fileno())
                    original = HASHES.stat()
                    os.chown(tmp_name, 0, original.st_gid)
                    os.chmod(tmp_name, 0o640)
                    os.replace(tmp_name, str(HASHES))
                    try:
                        restart_and_verify()
                    except Exception:
                        os.replace(str(backup), str(HASHES))
                        try:
                            restart_and_verify()
                            raise ValueError("service_restart_failed_rolled_back")
                        except ValueError as e:
                            if str(e) == "service_restart_failed_rolled_back":
                                raise
                            raise ValueError("service_restart_failed_manual_recovery_required")
                finally:
                    if os.path.exists(tmp_name):
                        os.unlink(tmp_name)
                state["SMTP_ACCOUNT_CHANGED"] = "yes"
                state["SMTP_ACCOUNT_RESULT"] = "applied"
                state["SMTP_ACCOUNT_RECOVERY_ARCHIVE"] = "root_only_retention_required"
        for key, value in state.items():
            print("{}={}".format(key, value))
        return 0
    except (OSError, ValueError, UnicodeError) as error:
        print("SMTP_ACCOUNT_RESULT=refused")
        print("SMTP_ACCOUNT_ERROR={}".format(str(error)[:90]))
        print("SMTP_ACCOUNT_CHANGED=unknown_if_apply" if args.apply else "SMTP_ACCOUNT_CHANGED=no")
        return 2
    finally:
        if lock_fd is not None:
            os.close(lock_fd)


if __name__ == "__main__":
    sys.exit(main())
