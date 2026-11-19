#!/usr/bin/env python3
"""Guarded staged hardware OAuth cutover; Python 3.6+.

This tool NEVER generates keys, registers certs, sends email, changes Postfix,
restarts a service or changes the tenant. Activating an already staged hardware
identity is allowed only after local PS256 signing AND an Entra token check,
then repeated against the active identity. Failed postcheck attempts rollback.
Original PEM key/certificate files must remain available for recovery.
"""
import argparse
import datetime
import errno
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys

VERSION = "1"
CONFIRM_APPLY = "ACTIVATE_HARDWARE_OAUTH"
CONFIRM_ROLLBACK = "ROLLBACK_HARDWARE_OAUTH"
BACKUP_ROOT = Path("/var/backups/linuxmailrelay365-hardware-oauth")
LOCK_FILE = Path("/run/linuxmailrelay365-hardware-oauth.lock")
TRANSPORT_DIR = Path("/usr/local/libexec")
TARGETS = {
    "sidecar": (Path("/etc/linuxmailrelay365/sidecar-identity"),
                TRANSPORT_DIR / "linuxmailrelay365-sidecar-transport.py"),
    "primary": (Path("/etc/postfix/m365-oauth"),
                TRANSPORT_DIR / "m365_xoauth2_transport.py"),
}
HELPER = TRANSPORT_DIR / "m365_hardware_signer.py"
ID = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\Z")
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
PKCS11_URI = re.compile(r"\Apkcs11:[A-Za-z0-9%._+;=:@-]{5,230}\Z")
HANDLE = re.compile(r"\Ahandle:0x81[a-fA-F0-9]{6}\Z")
ALLOWED_IDENTITY_KEYS = {"tenant_id", "client_id", "mailbox",
                         "certificate", "private_key", "signer"}
MAX_IDENTITY = 32768
MAX_REF = 1048576


class Refused(Exception):
    pass


def say(key, value):
    print("HARDWARE_CUTOVER_{}={}".format(key, value))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ensure_root():
    if os.geteuid() != 0:
        raise Refused("root_required")


def checked_directory(path, private=False):
    try:
        info = Path(path).lstat()
    except OSError:
        raise Refused("required_directory_missing")
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Refused("untrusted_directory")
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused("backup_directory_permissions")
    return info


def checked_file(path, max_size, group=None, modes=(0o640,)):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        raise Refused("required_root_file_missing")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in modes or
            (group is not None and info.st_gid != group) or
            not 0 < info.st_size <= max_size):
        raise Refused("unsafe_root_file")
    return info


def read_checked(path, size, group=None, modes=(0o640,)):
    before = checked_file(path, size, group, modes)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_ino != before.st_ino or opened.st_dev != before.st_dev or
                    opened.st_size != before.st_size or
                    not stat.S_ISREG(opened.st_mode)):
                raise Refused("root_file_changed")
            data = stream.read(size + 1)
    except OSError:
        raise Refused("root_file_read_failed")
    if len(data) != before.st_size:
        raise Refused("root_file_changed")
    return data


def read_identity(path, group):
    raw = read_checked(path, MAX_IDENTITY, group)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise Refused("invalid_identity_json")
    if not isinstance(data, dict) or not {"tenant_id", "client_id", "mailbox",
                                         "certificate"}.issubset(data):
        raise Refused("invalid_identity_fields")
    if set(data) - ALLOWED_IDENTITY_KEYS:
        raise Refused("unexpected_identity_fields")
    if any(not isinstance(data[x], str) or not data[x] or len(data[x]) > 320
           for x in ("tenant_id", "client_id", "mailbox", "certificate")):
        raise Refused("invalid_identity_values")
    return raw, data


def same_routing(active, staged):
    return all(active[k] == staged[k] for k in
               ("tenant_id", "client_id", "mailbox"))


def check_candidate(active, staged, directory, group):
    if not same_routing(active, staged):
        raise Refused("tenant_client_or_sender_change_forbidden")
    if "private_key" in staged:
        raise Refused("candidate_pem_fallback_forbidden")
    signer = staged.get("signer")
    if not isinstance(signer, dict) or set(signer) != {
            "type", "provider", "key_ref", "provider_config"}:
        raise Refused("invalid_hardware_signer")
    if signer["type"] != "openssl-provider" or signer["provider"] not in ("tpm2", "pkcs11"):
        raise Refused("unsupported_hardware_signer")
    if not isinstance(signer["provider_config"], str) or \
            Path(signer["provider_config"]).parent != directory:
        raise Refused("provider_config_outside_identity")
    read_checked(signer["provider_config"], MAX_REF, group)
    reference = signer["key_ref"]
    if not isinstance(reference, str):
        raise Refused("invalid_key_reference")
    if signer["provider"] == "tpm2":
        if reference == str(directory / "tpm2-app.key"):
            raw = read_checked(reference, MAX_REF, group)
            if b"-----BEGIN TSS2 PRIVATE KEY-----" not in raw[:96]:
                raise Refused("invalid_tss2_wrapped_key")
        elif not HANDLE.fullmatch(reference):
            raise Refused("unsupported_tpm_handle")
    elif (not PKCS11_URI.fullmatch(reference) or
          re.search("pin|module-path|module-name", reference, re.I) or
          not ("object=" in reference or "id=" in reference) or
          "type=private" not in reference):
        raise Refused("unsafe_pkcs11_key_reference")
    if Path(staged["certificate"]).parent != directory:
        raise Refused("certificate_outside_identity")
    read_checked(staged["certificate"], MAX_REF, modes=(0o644, 0o640))
    return signer


def reference_hashes(staged, directory, group):
    spec = staged["signer"]
    paths = {"certificate": staged["certificate"],
             "provider_config": spec["provider_config"]}
    if spec["provider"] == "tpm2" and spec["key_ref"] == str(directory / "tpm2-app.key"):
        paths["tpm2_blob"] = spec["key_ref"]
    result = {}
    for name, path in paths.items():
        result[name] = digest(read_checked(path, MAX_REF,
            group if name != "certificate" else None,
            (0o640, 0o644) if name == "certificate" else (0o640,)))
    return result


def ensure_runtime(transport):
    checked_directory(TRANSPORT_DIR)
    for item in (transport, HELPER):
        read_checked(item, MAX_REF, modes=(0o644, 0o755))
    if not Path("/usr/bin/python3").is_file():
        raise Refused("python3_runtime_missing")
    runuser = shutil.which("runuser")
    if not runuser:
        raise Refused("service_user_runner_missing")
    return runuser


def prepare(target):
    directory, transport = TARGETS[target]
    checked_directory(directory)
    try:
        group = grp.getgrnam("m365mailer").gr_gid
    except KeyError:
        raise Refused("m365mailer_group_missing")
    active_path = directory / "app.json"
    staged_path = directory / "hardware-staged.json"
    active_raw, active = read_identity(active_path, group)
    staged_raw, staged = read_identity(staged_path, group)
    check_candidate(active, staged, directory, group)
    runuser = ensure_runtime(transport)
    dependencies = reference_hashes(staged, directory, group)
    dependencies["transport"] = digest(read_checked(transport, MAX_REF,
                                                     modes=(0o644, 0o755)))
    dependencies["signer_module"] = digest(read_checked(HELPER, MAX_REF,
                                                        modes=(0o644, 0o755)))
    evidence = {"version": VERSION, "target": target,
                "active_sha": digest(active_raw),
                "staged_sha": digest(staged_raw),
                "references": dependencies,
                "identity_gid": group}
    plan_sha = digest(json.dumps(evidence, sort_keys=True,
                                 separators=(",", ":")).encode("ascii"))
    return {"target": target, "directory": directory, "transport": transport,
            "runuser": runuser, "gid": group, "active_raw": active_raw,
            "staged_raw": staged_raw, "active": active, "staged": staged,
            "active_sha": evidence["active_sha"], "staged_sha": evidence["staged_sha"],
            "sha": plan_sha}


def report_plan(plan):
    say("VERSION", VERSION)
    say("TARGET", plan["target"])
    say("PLAN_SHA256", plan["sha"])
    say("ACTIVE_SHA256", plan["active_sha"])
    say("STAGED_SHA256", plan["staged_sha"])
    say("PROVIDER", plan["staged"]["signer"]["provider"])
    say("ROUTING_IDENTITY_UNCHANGED", "yes")
    say("LOCAL_SIGNING_VERIFIED", "not_yet")
    say("ENTRA_TOKEN_VERIFIED", "not_yet")
    say("READY_FOR_APPROVED_CUTOVER", "requires_live_entra_check")
    say("PRIMARY_MTA_CHANGES", "no")
    say("MAIL_SENT", "no")
    say("APPLIED", "no")


def checked_run(plan, candidate, token_check, runner=subprocess.run):
    if candidate:
        opt, path = "--candidate-config", str(plan["directory"] / "hardware-staged.json")
    else:
        opt, path = "--config", str(plan["directory"] / "app.json")
    command = [plan["runuser"], "-u", "m365mailer", "--", "/usr/bin/python3",
               str(plan["transport"]),
               "--token-check" if token_check else "--signing-check", opt, path]
    try:
        result = runner(command, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, check=False,
                        timeout=80 if token_check else 90)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("token_preflight_failed" if token_check else "ps256_preflight_failed")
    if result.returncode:
        raise Refused("token_preflight_failed" if token_check else "ps256_preflight_failed")


def lock():
    checked_directory(LOCK_FILE.parent)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(LOCK_FILE), flags, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            os.close(fd)
            raise Refused("unsafe_cutover_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        raise Refused("another_hardware_cutover_in_progress")
    return fd


def checked_backup_root(target):
    checked_directory(BACKUP_ROOT.parent)
    for item in (BACKUP_ROOT, BACKUP_ROOT / target):
        if not item.exists() and not item.is_symlink():
            item.mkdir(mode=0o700)
        checked_directory(item, private=True)
    return BACKUP_ROOT / target


def fsync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_secret(path, data):
    with os.fdopen(os.open(str(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def new_backup(plan):
    root = checked_backup_root(plan["target"])
    backup_id = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(6)
    where = root / backup_id
    where.mkdir(mode=0o700)
    # Write original identity before attempting an active configuration swap.
    write_secret(where / "previous.json", plan["active_raw"])
    manifest = {"version": VERSION, "target": plan["target"],
                "backup_id": backup_id,
                "previous_sha256": plan["active_sha"],
                "applied_sha256": plan["staged_sha"],
                "plan_sha256": plan["sha"]}
    write_secret(where / "manifest.json",
                 (json.dumps(manifest, sort_keys=True) + "\n").encode("ascii"))
    fsync_dir(where)
    fsync_dir(root)
    return backup_id


def read_backup(target, backup_id):
    if not ID.fullmatch(backup_id):
        raise Refused("invalid_backup_id")
    where = BACKUP_ROOT / target / backup_id
    checked_directory(BACKUP_ROOT, private=True)
    checked_directory(BACKUP_ROOT / target, private=True)
    checked_directory(where, private=True)
    raw = read_checked(where / "previous.json", MAX_IDENTITY, modes=(0o600,))
    data = read_checked(where / "manifest.json", 4096, modes=(0o600,))
    try:
        manifest = json.loads(data.decode("ascii"))
    except (ValueError, UnicodeError):
        raise Refused("invalid_backup_manifest")
    if not isinstance(manifest, dict) or set(manifest) != {
            "version", "target", "backup_id", "previous_sha256",
            "applied_sha256", "plan_sha256"} or \
            manifest["version"] != VERSION or manifest["target"] != target or \
            manifest["backup_id"] != backup_id or \
            any(not isinstance(manifest[x], str) or not SHA.fullmatch(manifest[x])
                for x in ("previous_sha256", "applied_sha256", "plan_sha256")) or \
            digest(raw) != manifest["previous_sha256"]:
        raise Refused("backup_integrity_failed")
    return raw, manifest


def original_preflight(previous, current, group):
    # Restore to the same tenant/client/mailbox; never cross-account.
    try:
        data = json.loads(previous.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise Refused("backup_identity_invalid")
    if not isinstance(data, dict) or not same_routing(data, current):
        raise Refused("backup_routing_identity_changed")
    if "private_key" in data:
        key = data["private_key"]
        if (not isinstance(key, str) or Path(key).parent not in
                [item[0] for item in TARGETS.values()]):
            raise Refused("previous_key_outside_identity")
        read_checked(key, MAX_REF, group)
    elif "signer" not in data:
        raise Refused("previous_signer_missing")
    cert = data.get("certificate")
    if (not isinstance(cert, str) or Path(cert).parent not in
            [item[0] for item in TARGETS.values()]):
        raise Refused("previous_cert_outside_identity")
    read_checked(cert, MAX_REF, modes=(0o640, 0o644))


def replace_identity(path, raw, group):
    # Preserve current SELinux label when present. Failure to relabel aborts
    # BEFORE changing the live identity; never silently downgrade policy.
    tmp = path.parent / (".app.json.hw-" + secrets.token_hex(8))
    descriptor = None
    try:
        descriptor = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchown(descriptor, 0, group)
        os.fchmod(descriptor, 0o640)
        try:
            label = os.getxattr(str(path), "security.selinux",
                                follow_symlinks=False)
        except OSError as exc:
            if exc.errno in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
                label = None
            else:
                raise Refused("selinux_context_read_failed")
        if label is not None:
            try:
                os.setxattr(str(tmp), "security.selinux", label,
                            follow_symlinks=False)
            except OSError:
                raise Refused("selinux_context_preservation_failed")
        with os.fdopen(descriptor, "wb") as writer:
            descriptor = None
            writer.write(raw)
            writer.flush()
            os.fsync(writer.fileno())
        checked_file(tmp, MAX_IDENTITY, group)
        os.replace(str(tmp), str(path))
        fsync_dir(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if tmp.exists() or tmp.is_symlink():
            tmp.unlink()


def apply(target, approved_sha, confirmation, runner=subprocess.run):
    ensure_root()
    if confirmation != CONFIRM_APPLY or not SHA.fullmatch(approved_sha):
        raise Refused("typed_confirmation_or_plan_sha_missing")
    fd = lock()
    try:
        plan = prepare(target)
        if approved_sha != plan["sha"]:
            raise Refused("plan_changed_review_again")
        # Explicitly check the staged provider against the staged certificate
        # and obtain an Entra token, without SMTP. This must succeed before
        # the first active identity byte is changed.
        checked_run(plan, True, False, runner)
        checked_run(plan, True, True, runner)
        if plan["sha"] != prepare(target)["sha"]:
            raise Refused("plan_changed_during_live_preflight")
        backup_id = new_backup(plan)
        active = plan["directory"] / "app.json"
        # Atomic replace: Postfix pipe jobs see either the original or the
        # staged identity, never a half-written JSON document.
        replace_identity(active, plan["staged_raw"], plan["gid"])
        try:
            checked_run(plan, False, False, runner)
            checked_run(plan, False, True, runner)
        except Refused:
            try:
                replace_identity(active, plan["active_raw"], plan["gid"])
                if digest(read_checked(active, MAX_IDENTITY, plan["gid"])) != plan["active_sha"]:
                    raise Refused("automatic_rollback_integrity_failed")
            except (Refused, OSError):
                raise Refused("critical_manual_rollback_from_backup_required")
            raise Refused("postcheck_failed_original_restored")
        say("BACKUP_ID", backup_id)
        say("APPLIED", "yes")
        say("LOCAL_SIGNING_VERIFIED", "yes")
        say("ENTRA_TOKEN_VERIFIED", "yes")
        say("MAIL_SENT", "no")
        say("PRIMARY_MTA_CHANGES", "no")
        say("RESTART_REQUIRED", "no")
    finally:
        os.close(fd)


def rollback(target, backup_id, confirmation):
    ensure_root()
    if confirmation != CONFIRM_ROLLBACK:
        raise Refused("typed_rollback_confirmation_required")
    fd = lock()
    try:
        previous, manifest = read_backup(target, backup_id)
        directory, transport = TARGETS[target]
        checked_directory(directory)
        gid = grp.getgrnam("m365mailer").gr_gid
        current_raw, current = read_identity(directory / "app.json", gid)
        if digest(current_raw) != manifest["applied_sha256"]:
            raise Refused("active_identity_changed_rollback_refused")
        # Validate that key files needed by the previous identity still exist
        # before overwriting the active configuration.
        original_preflight(previous, current, gid)
        replace_identity(directory / "app.json", previous, gid)
        say("ROLLBACK_ID", backup_id)
        say("RESTORED_PREVIOUS_IDENTITY", "yes")
        say("ENTRA_TOKEN_VERIFIED", "no")
        say("MAIL_SENT", "no")
        say("PRIMARY_MTA_CHANGES", "no")
    except KeyError:
        raise Refused("m365mailer_group_missing")
    finally:
        os.close(fd)


def list_backups(target):
    ensure_root()
    parent = BACKUP_ROOT / target
    if not parent.exists() and not parent.is_symlink():
        say("BACKUP_COUNT", "0")
        return
    checked_directory(parent, private=True)
    ids = []
    for folder in parent.iterdir():
        if ID.fullmatch(folder.name):
            try:
                read_backup(target, folder.name)
                ids.append(folder.name)
            except Refused:
                continue
    for item in sorted(ids, reverse=True)[:30]:
        say("BACKUP_ID", item)
    say("BACKUP_COUNT", str(len(ids)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--rollback", metavar="BACKUP_ID")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--approve-sha256", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    try:
        ensure_root()
        if sum((args.plan, args.apply, bool(args.rollback), args.list)) != 1:
            raise Refused("select_exactly_one_operation")
        if not args.apply and not args.rollback and (args.confirm or args.approve_sha256):
            raise Refused("approval_not_allowed_in_readonly_mode")
        if args.plan:
            report_plan(prepare(args.target))
        elif args.apply:
            apply(args.target, args.approve_sha256, args.confirm)
        elif args.rollback:
            if args.approve_sha256:
                raise Refused("approval_sha_not_used_for_rollback")
            rollback(args.target, args.rollback, args.confirm)
        else:
            list_backups(args.target)
        return 0
    except Refused as exc:
        say("ERROR", str(exc))
        return 2
    except (OSError, ValueError, TypeError):
        say("ERROR", "operation_failed_check_local_recovery")
        return 2


if __name__ == "__main__":
    sys.exit(main())
