#!/usr/bin/env python3
"""Guarded PRIMARY Postfix software-PEM OAuth certificate rotation (Python 3.6+).

The primary Postfix service, listener, queue and route are never changed.
Plan -> stage -> Graph addKey (separate GUI review) -> staged SMTP AUTH
-> approved, reverified atomic app.json switch -> active SMTP AUTH.
Old key, certificate and identity remain for manual recovery. Never send mail.
"""
import argparse
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path("/etc/postfix/m365-oauth")
ACTIVE = ROOT / "app.json"
STAGED = ROOT / "pem-rotation-staged.json"
LOCK = Path("/run/linuxmailrelay365-hardware-oauth.lock")
# Use the checked-in, root-owned preview diagnostic transport in the
# temporary bundle. Existing production /usr/local/libexec is not modified.
TRANSPORT = Path(__file__).resolve().parent / "m365_xoauth2_transport.py"
SIGNER = TRANSPORT.parent / "m365_hardware_signer.py"
GUID = re.compile(r"\A[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
MAIL = re.compile(r"\A[A-Za-z0-9._+-]+@[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]\Z")
STAMP = re.compile(r"\Aapp\.rotation\.[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\Z")
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
MAX_FILE = 32768
PREPARE_ACK = "STAGE_PRIMARY_OAUTH_CERT"
CHECK_ACK = "VERIFY_PRIMARY_OAUTH_CANDIDATE"
ACTIVATE_ACK = "ACTIVATE_PRIMARY_OAUTH_CERT"


class Refused(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def say(name, value):
    print("PRIMARY_OAUTH_ROTATION_{}={}".format(name, value))


def owned_dir(directory):
    path = Path(directory)
    while True:
        try:
            info = path.lstat()
        except OSError:
            raise Refused("required_trusted_directory_missing")
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or \
                (info.st_mode & 0o022):
            if path == Path("/tmp") and info.st_uid == 0 and \
                    stat.S_ISDIR(info.st_mode) and (info.st_mode & 0o1000):
                pass  # Only a root-owned, non-writable child directory is used.
            else:
                raise Refused("unsafe_directory_ownership_or_mode")
        if path == path.parent:
            return
        path = path.parent


def read_root_file(path, max_size, modes, gid=None):
    path = Path(path)
    try:
        first = path.lstat()
        if not stat.S_ISREG(first.st_mode) or first.st_uid != 0 or \
                first.st_nlink != 1 or stat.S_IMODE(first.st_mode) not in modes or \
                not 0 < first.st_size <= max_size or \
                (gid is not None and first.st_gid != gid):
            raise Refused("unsafe_identity_file")
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as file:
            again = os.fstat(file.fileno())
            if (again.st_ino, again.st_dev, again.st_mode, again.st_uid,
                again.st_gid, again.st_nlink, again.st_size) != (
                first.st_ino, first.st_dev, first.st_mode, first.st_uid,
                first.st_gid, first.st_nlink, first.st_size):
                raise Refused("identity_changed_while_reading")
            content = file.read(max_size + 1)
        if len(content) != first.st_size:
            raise Refused("identity_changed_while_reading")
        return content
    except OSError:
        raise Refused("root_identity_file_unavailable")


def parse_identity(raw, group, rotation=False):
    try:
        item = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise Refused("invalid_oauth_json")
    if not isinstance(item, dict) or set(item) != {
            "tenant_id", "client_id", "mailbox", "certificate", "private_key"}:
        raise Refused("software_pem_identity_required")
    if not GUID.fullmatch(item["tenant_id"]) or \
            not GUID.fullmatch(item["client_id"]) or \
            not MAIL.fullmatch(item["mailbox"]):
        raise Refused("invalid_installed_oauth_identity")
    cert = Path(item["certificate"])
    key = Path(item["private_key"])
    if cert.parent != ROOT or key.parent != ROOT or \
            not cert.is_absolute() or not key.is_absolute():
        raise Refused("identity_paths_outside_fixed_root")
    if rotation:
        if not STAMP.fullmatch(cert.stem) or \
                key.name != cert.stem + ".key":
            raise Refused("candidate_must_use_unique_versioned_pair")
    elif not ((cert.name == "app.crt" and key.name == "app.key") or
              (STAMP.fullmatch(cert.stem) and key.name == cert.stem + ".key")):
        raise Refused("unsupported_active_pem_pair")
    # Key and cert may be referenced only from this fixed trusted directory.
    key_bytes = read_root_file(key, MAX_FILE, (0o640,), group)
    cert_bytes = read_root_file(cert, MAX_FILE, (0o640, 0o644))
    return item, key_bytes, cert_bytes


def openssl(args, timeout=20):
    try:
        result = subprocess.run(["/usr/bin/openssl"] + args,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False,
                                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin",
                                     "HOME": "/nonexistent"})
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("openssl_unavailable_or_timeout")
    if result.returncode:
        raise Refused("certificate_or_private_key_validation_failed")
    return result.stdout


def verify_pair(identity, min_valid_seconds=0):
    pub_cert = openssl(["x509", "-pubkey", "-noout", "-in",
                        identity["certificate"]]).strip()
    pub_key = openssl(["pkey", "-pubout", "-in",
                       identity["private_key"]]).strip()
    if not pub_cert or pub_cert != pub_key:
        raise Refused("certificate_private_key_mismatch")
    openssl(["x509", "-in", identity["certificate"],
             "-noout", "-checkend", str(min_valid_seconds)])


def current(group):
    owned_dir(ROOT)
    raw = read_root_file(ACTIVE, MAX_FILE, (0o640,), group)
    identity, key_bytes, certificate = parse_identity(raw, group)
    verify_pair(identity)
    return {"raw": raw, "identity": identity, "key_sha": sha(key_bytes),
            "cert_sha": sha(certificate)}


def review_plan(active, days):
    if not isinstance(days, int) or days < 1 or days > 365:
        raise Refused("certificate_days_outside_1_365")
    return sha(json.dumps({"v": 1, "mode": "primary_software_pem",
         "active_sha": sha(active["raw"]), "key_sha": active["key_sha"],
         "cert_sha": active["cert_sha"], "days": days},
         sort_keys=True, separators=(",", ":")).encode("ascii"))


def staged_state(group):
    active = current(group)
    raw = read_root_file(STAGED, MAX_FILE, (0o640,), group)
    identity, key_bytes, certificate = parse_identity(raw, group, True)
    if any(identity[k] != active["identity"][k] for k in (
            "tenant_id", "client_id", "mailbox")):
        raise Refused("candidate_identity_mismatch")
    if identity["certificate"] == active["identity"]["certificate"]:
        raise Refused("candidate_must_differ_from_active")
    verify_pair(identity)
    proof = {"v": 1, "active_sha": sha(active["raw"]),
             "active_key_sha": active["key_sha"],
             "active_cert_sha": active["cert_sha"], "candidate_sha": sha(raw),
             "candidate_key_sha": sha(key_bytes), "candidate_cert_sha": sha(certificate)}
    return {"sha": sha(json.dumps(proof, sort_keys=True, separators=(",", ":")).encode("ascii")),
            "active": active, "raw": raw, "candidate": identity}


def write_new(path, content, group, mode=0o640):
    # Caller controls fixed paths only. Never follow existing links or overwrite.
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.fchown(fd, 0, group)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
    except BaseException:
        try:
            os.unlink(str(path))
        except OSError:
            pass
        raise


def write_atomic(path, content, group):
    tmp = path.parent / (".app-rotation-" + secrets.token_hex(12))
    try:
        write_new(tmp, content, group)
        os.replace(str(tmp), str(path))
        fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if tmp.exists():
            tmp.unlink()


def lock():
    owned_dir(LOCK.parent)
    fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or \
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(fd)
        raise Refused("unsafe_cross_workflow_lock")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        os.close(fd)
        raise Refused("oauth_operation_already_running")
    return fd


def require_sha(candidate, expected, confirmation, required):
    if not SHA.fullmatch(expected or "") or candidate != expected or \
            confirmation != required:
        raise Refused("reviewed_sha_or_typed_confirmation_did_not_match")


def prepare(active, group, days):
    if STAGED.exists() or STAGED.is_symlink():
        raise Refused("pending_pem_rotation_requires_review")
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(6)
    stem = "app.rotation." + stamp
    newkey = ROOT / (stem + ".key")
    newcert = ROOT / (stem + ".crt")
    if newkey.exists() or newcert.exists():
        raise Refused("unexpected_rotation_filename_collision")
    try:
        openssl(["req", "-x509", "-newkey", "rsa:3072", "-sha256",
                 "-nodes", "-days", str(days),
                 "-subj", "/CN=LinuxMailRelay365-OAuth-rotation",
                 "-keyout", str(newkey), "-out", str(newcert)], timeout=45)
        os.chown(str(newkey), 0, group)
        os.chmod(str(newkey), 0o640)
        os.chown(str(newcert), 0, group)
        os.chmod(str(newcert), 0o644)
        candidate = dict(active["identity"])
        candidate["private_key"] = str(newkey)
        candidate["certificate"] = str(newcert)
        raw = (json.dumps(candidate, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        parse_identity(raw, group, True)
        verify_pair(candidate, min_valid_seconds=3600)
        write_new(STAGED, raw, group)
        staged = staged_state(group)
        say("STAGED", "yes")
        say("STAGE_SHA256", staged["sha"])
        say("ACTIVE_OAUTH_CHANGED", "no")
        say("SMTP_SUBMITTED", "no")
    except BaseException:
        if STAGED.exists() and not STAGED.is_symlink():
            STAGED.unlink()
        for path in (newkey, newcert):
            if path.exists() and not path.is_symlink():
                path.unlink()
        raise


def check_candidate_auth(active=False):
    # Bundled transport is read-only for diagnostic mode. No MAIL/RCPT/DATA.
    owned_dir(TRANSPORT.parent)
    read_root_file(TRANSPORT, 1048576, (0o644, 0o755))
    read_root_file(SIGNER, 1048576, (0o644, 0o755))
    command = ["runuser", "-u", "m365mailer", "--", "/usr/bin/python3",
               str(TRANSPORT)]
    if active:
        command.extend(["--config", str(ACTIVE)])
    else:
        command.extend(["--candidate-config", str(STAGED)])
    command.append("--smtp-auth-check")
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=100,
                                check=False, env={"PATH": "/usr/sbin:/usr/bin:/bin",
                                                 "LC_ALL": "C", "HOME": "/nonexistent"})
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("oauth_smtp_auth_check_unavailable_or_timeout")
    if result.returncode != 0 or \
            b"Microsoft 365 STARTTLS and SMTP AUTH XOAUTH2 verified; no message submitted" not in result.stdout:
        raise Refused("candidate_or_active_smtp_auth_not_verified")


def activate(staged, group):
    original = staged["active"]["raw"]
    runid = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(6)
    backup = ROOT / ("app.rollback." + runid + ".json")
    write_new(backup, original, group, 0o600)
    applied = False
    try:
        # All files referenced by the candidate already exist. One atomic JSON
        # pointer switch avoids a transient private-key/certificate mismatch.
        if staged_state(group)["sha"] != staged["sha"]:
            raise Refused("rotation_changed_before_activation")
        write_atomic(ACTIVE, staged["raw"], group)
        applied = True
        check_candidate_auth(active=True)
        if sha(read_root_file(ACTIVE, MAX_FILE, (0o640,), group)) != sha(staged["raw"]):
            raise Refused("active_identity_changed_during_postcheck")
        STAGED.unlink()
        say("ACTIVATED", "yes")
        say("OLD_IDENTITY_BACKUP_ID", runid)
        say("OLD_KEYS_PRESERVED", "yes")
        say("POST_ACTIVATION_SMTP_AUTH", "verified_no_message")
        say("ROUTING_CHANGED", "no")
    except BaseException:
        if applied:
            write_atomic(ACTIVE, original, group)
            say("ROLLED_BACK", "yes")
        # Never delete the backup or the staged key/cert after a failure.
        raise


def main(argv=None):
    os.umask(0o077)
    ap = argparse.ArgumentParser(description=__doc__)
    actions = ap.add_mutually_exclusive_group(required=True)
    for action in ("plan", "stage", "status", "preflight", "activate"):
        actions.add_argument("--" + action, action="store_true")
    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--expect-sha256", default="")
    ap.add_argument("--confirm", default="")
    args = ap.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Refused("root_required")
        if args.days < 1 or args.days > 365:
            raise Refused("invalid_certificate_days")
        if (args.plan or args.status) and (args.expect_sha256 or args.confirm):
            raise Refused("read_only_mode_rejects_approval_options")
        if (args.preflight or args.activate) and args.days != 365:
            raise Refused("days_option_is_only_for_prepare")
        group = grp.getgrnam("m365mailer").gr_gid
        descriptor = lock()
        try:
            active = current(group)
            if args.plan or args.stage:
                code = review_plan(active, args.days)
                if args.plan:
                    say("PLAN_SHA256", code)
                    say("READY_FOR_STAGE", "no" if STAGED.exists() or STAGED.is_symlink() else "yes")
                    say("ACTIVE_OAUTH_CHANGED", "no")
                    return 0
                require_sha(code, args.expect_sha256, args.confirm, PREPARE_ACK)
                prepare(active, group, args.days)
                return 0
            stage = staged_state(group)
            say("STAGE_SHA256", stage["sha"])
            if args.status:
                say("READY_FOR_PREFLIGHT", "yes")
                say("ACTIVE_OAUTH_CHANGED", "no")
                return 0
            required = CHECK_ACK if args.preflight else ACTIVATE_ACK
            require_sha(stage["sha"], args.expect_sha256, args.confirm, required)
            check_candidate_auth()
            if staged_state(group)["sha"] != stage["sha"]:
                raise Refused("rotation_changed_during_smtp_check")
            say("CANDIDATE_SMTP_AUTH", "verified_no_message")
            if args.preflight:
                say("ACTIVE_OAUTH_CHANGED", "no")
                return 0
            activate(stage, group)
            return 0
        finally:
            os.close(descriptor)
    except (Refused, KeyError, ValueError, TypeError) as error:
        say("ERROR", str(error) if isinstance(error, Refused) else "invalid_primary_oauth_state")
        return 2
    except (OSError, subprocess.SubprocessError):
        say("ERROR", "primary_oauth_operation_failed_inspect_state")
        return 2


if __name__ == "__main__":
    sys.exit(main())
