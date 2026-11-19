#!/usr/bin/env python3
"""Reviewed two-recipient Microsoft 365 OAuth SMTP acceptance (Python 3.6+).

No mail is sent during --plan. --apply requires same SHA256, typed consent
and exactly one fresh run ID. Two fixed short messages are submitted using
the installed ACTIVE hardware XOAUTH2 transport, never staged credentials.
Each attempt is written to a root-only append-only ledger BEFORE the send:
a partial or timed-out run must be inspected and can never auto-retry.
Only hashes of recipients are output, never mailbox addresses/tokens/PIN.
Exchange SMTP submission acceptance is NOT proof of recipient inbox arrival.
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
import shutil
import stat
import subprocess
import sys

VERSION = "1"
CONFIRM = "SEND_TWO_ACCEPTANCE_TESTS"
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
RUN_ID = re.compile(r"\A[a-f0-9]{32}\Z")
MAILBOX = re.compile(
    r"\A(?![^@]*\.\.)(?:[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9_+-])?)@[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")
ROOTS = {
    "sidecar": (Path("/etc/linuxmailrelay365/sidecar-identity"),
                Path("/usr/local/libexec/linuxmailrelay365-sidecar-transport.py")),
    "primary": (Path("/etc/postfix/m365-oauth"),
                Path("/usr/local/libexec/m365_xoauth2_transport.py")),
}
LOCK = Path("/run/linuxmailrelay365-hardware-oauth.lock")
LEDGER_ROOT = Path("/var/lib/linuxmailrelay365-acceptance")
MAX_SOURCE = 1048576


class Refused(Exception):
    pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def report(key, value):
    print("SMTP_ACCEPTANCE_{}={}".format(key, value))


def require_root():
    if os.geteuid() != 0:
        raise Refused("root_required")


def trusted_dir(path):
    p = Path(path)
    while True:
        try:
            st = p.lstat()
        except OSError:
            raise Refused("root_directory_missing")
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused("untrusted_directory")
        if p == p.parent:
            break
        p = p.parent


def checked_read(path, max_bytes, gid=None, modes=(0o640,)):
    p = Path(path)
    try:
        st = p.lstat()
    except OSError:
        raise Refused("required_root_file_missing")
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
            st.st_nlink != 1 or stat.S_IMODE(st.st_mode) not in modes or
            (gid is not None and st.st_gid != gid) or
            not 0 < st.st_size <= max_bytes):
        raise Refused("untrusted_root_file")
    try:
        fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            current = os.fstat(source.fileno())
            if (current.st_dev != st.st_dev or current.st_ino != st.st_ino or
                    current.st_size != st.st_size or current.st_uid != st.st_uid or
                    current.st_gid != st.st_gid or current.st_nlink != 1 or
                    stat.S_IMODE(current.st_mode) != stat.S_IMODE(st.st_mode)):
                raise Refused("reviewed_file_changed")
            raw = source.read(max_bytes + 1)
    except OSError:
        raise Refused("reviewed_file_read_failed")
    if len(raw) != st.st_size:
        raise Refused("reviewed_file_changed")
    return raw


def read_request():
    raw = sys.stdin.buffer.read(4097)
    if not raw or len(raw) > 4096:
        raise Refused("bounded_delivery_request_required")
    try:
        request = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise Refused("invalid_delivery_request")
    if not isinstance(request, dict) or set(request) != {
            "internal", "external", "run_id"}:
        raise Refused("invalid_delivery_request_fields")
    for name in ("internal", "external"):
        value = request[name]
        if not isinstance(value, str) or not 6 <= len(value) <= 254 or \
                not MAILBOX.fullmatch(value):
            raise Refused("invalid_reviewed_recipient")
    if (request["internal"].lower() == request["external"].lower() or
            not isinstance(request["run_id"], str) or
            not RUN_ID.fullmatch(request["run_id"])):
        raise Refused("duplicate_recipient_or_invalid_run_id")
    return request


def prepare(target, request):
    require_root()
    if target not in ROOTS:
        raise Refused("invalid_target")
    directory, transport = ROOTS[target]
    trusted_dir(directory)
    trusted_dir(transport.parent)
    try:
        gid = grp.getgrnam("m365mailer").gr_gid
    except KeyError:
        raise Refused("service_group_missing")
    identity_raw = checked_read(directory / "app.json", 32768, gid)
    code = checked_read(transport, MAX_SOURCE, modes=(0o644, 0o755))
    if b"--acceptance-test" not in code:
        raise Refused("installed_transport_lacks_acceptance_contract")
    try:
        identity = json.loads(identity_raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise Refused("invalid_installed_identity")
    if not isinstance(identity, dict):
        raise Refused("invalid_installed_identity")
    sender = identity.get("mailbox")
    signer = identity.get("signer")
    if (not isinstance(sender, str) or not MAILBOX.fullmatch(sender) or
            not isinstance(signer, dict) or
            signer.get("type") != "openssl-provider" or
            signer.get("provider") not in ("tpm2", "pkcs11") or
            "private_key" in identity):
        raise Refused("active_hardware_oauth_identity_required")
    domain = sender.rsplit("@", 1)[1].lower()
    internal_domain = request["internal"].rsplit("@", 1)[1].lower()
    external_domain = request["external"].rsplit("@", 1)[1].lower()
    if internal_domain != domain or external_domain == domain:
        raise Refused("internal_external_test_domain_mismatch")
    # Domain comparison is only a convenience; another accepted domain of
    # the tenant would need separate recipient-role proof and explicit review.
    evidence = {"version": VERSION, "target": target,
                "identity_sha": digest(identity_raw),
                "transport_sha": digest(code), "run_id": request["run_id"],
                "internal_sha": digest(request["internal"].lower().encode("ascii")),
                "external_sha": digest(request["external"].lower().encode("ascii"))}
    plan_sha = digest(json.dumps(evidence, sort_keys=True,
                     separators=(",", ":")).encode("ascii"))
    return {"sha": plan_sha, "target": target, "directory": directory,
            "transport": transport, "request": request, "evidence": evidence}


def print_plan(plan):
    report("VERSION", VERSION)
    report("TARGET", plan["target"])
    report("RUN_ID", plan["request"]["run_id"])
    report("PLAN_SHA256", plan["sha"])
    report("INTERNAL_RECIPIENT_SHA256", plan["evidence"]["internal_sha"])
    report("EXTERNAL_RECIPIENT_SHA256", plan["evidence"]["external_sha"])
    report("ACTIVE_HARDWARE_IDENTITY", "yes")
    report("RECIPIENT_DOMAIN_CLASSIFIED", "yes")
    report("EXCHANGE_SUBMISSIONS_ATTEMPTED", "no")
    report("MAIL_SENT", "no")
    report("RECIPIENT_INBOX_VERIFIED", "no")
    report("READY_FOR_APPROVED_TEST", "yes")


def lock():
    trusted_dir(LOCK.parent)
    try:
        fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600):
            raise Refused("untrusted_oauth_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except (OSError, BlockingIOError):
        raise Refused("oauth_or_delivery_operation_in_progress")


def ledger_path(run_id):
    trusted_dir(Path("/var/lib"))
    if not LEDGER_ROOT.exists() and not LEDGER_ROOT.is_symlink():
        LEDGER_ROOT.mkdir(mode=0o700)
    trusted_dir(LEDGER_ROOT)
    if stat.S_IMODE(LEDGER_ROOT.lstat().st_mode) != 0o700:
        raise Refused("unsafe_acceptance_ledger_permissions")
    return LEDGER_ROOT / (run_id + ".jsonl")


def record(fd, stage, value):
    entry = json.dumps({"stage": stage, "status": value},
                       sort_keys=True, separators=(",", ":")) + "\n"
    os.write(fd, entry.encode("ascii"))
    os.fsync(fd)


def apply(target, request, approved_sha, confirm, runner=subprocess.run):
    require_root()
    if (confirm != CONFIRM or not isinstance(approved_sha, str) or
            not SHA.fullmatch(approved_sha)):
        raise Refused("approved_sha_and_typed_consent_required")
    lock_fd = lock()
    fd = None
    try:
        plan = prepare(target, request)
        if plan["sha"] != approved_sha:
            raise Refused("delivery_plan_changed_reapprove")
        path = ledger_path(request["run_id"])
        # Never re-send the same trace ID, even after crash, timeout, partial
        # delivery or lost SSH connection. A fresh operator review is required.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(fd, 0o600)
        record(fd, "run", "reserved")
        runuser = shutil.which("runuser")
        if not runuser:
            raise Refused("runuser_missing_no_delivery_attempted")
        for role in ("internal", "external"):
            if prepare(target, request)["sha"] != approved_sha:
                raise Refused("delivery_dependencies_changed_before_" + role)
            payload = json.dumps({"role": role, "run_id": request["run_id"],
                                  "recipient": request[role]},
                                 separators=(",", ":")).encode("ascii")
            command = [runuser, "-u", "m365mailer", "--",
                       "/usr/bin/python3", str(plan["transport"]),
                       "--acceptance-test", "--config",
                       str(plan["directory"] / "app.json")]
            # Reserve before network I/O; never auto-retry a send with unknown
            # result. Capture no SMTP output, errors, tokens or addresses.
            record(fd, role, "attempted")
            try:
                result = runner(command, input=payload,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=140,
                                check=False)
            except (OSError, subprocess.TimeoutExpired):
                raise Refused(role + "_smtp_result_unknown_check_recipient")
            if result.returncode:
                raise Refused(role + "_smtp_not_accepted_check_recipient")
            record(fd, role, "smtp_accepted_not_inbox_verified")
            report(role.upper() + "_SMTP_SUBMITTED", "yes")
        record(fd, "run", "smtp_submissions_complete")
        report("VERSION", VERSION)
        report("RUN_ID", request["run_id"])
        report("TWO_SMTP_SUBMISSIONS_ACCEPTED", "yes")
        report("RECIPIENT_INBOX_VERIFIED", "no")
        report("PRIMARY_MTA_CHANGED", "no")
        report("TOKEN_PRINTED", "no")
        report("AUTOMATIC_RETRY", "no")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(lock_fd)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", choices=sorted(ROOTS), required=True)
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--approve-sha256", default="")
    ap.add_argument("--confirm", default="")
    args = ap.parse_args(argv)
    try:
        if args.plan == args.apply:
            raise Refused("select_plan_or_apply")
        if args.plan and (args.approve_sha256 or args.confirm):
            raise Refused("approval_not_permitted_in_preview")
        request = read_request()
        if args.plan:
            print_plan(prepare(args.target, request))
        else:
            apply(args.target, request, args.approve_sha256, args.confirm)
        return 0
    except Refused as exc:
        report("ERROR", str(exc))
        return 2
    except (OSError, ValueError, TypeError):
        report("ERROR", "delivery_operation_failed_inspect_ledger")
        return 2


if __name__ == "__main__":
    sys.exit(main())
