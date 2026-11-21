#!/usr/bin/env python3
"""Reviewed two-recipient Multi-mailbox XOAUTH2 acceptance; Python 3.6+.

The plan performs NO SMTP or cloud calls. Apply requires exact plan SHA-256,
typed consent and a fresh unique run ID. The selected sender must be in the
protected *active* Postfix sender map and own its mailbox. Each recipient
receives only a fixed short test message. A root-owned append-only run ledger
is reserved before any network call; no automatic retries after uncertainty.

Submission via this direct diagnostic does NOT prove inbound Postfix SMTP AUTH,
Exchange message trace, or recipient inbox delivery. Nothing changes MTA
configuration, services or queues.
"""
import argparse
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path("/var/lib/linuxmailrelay365-multi-acceptance")
CONFIRM = "SEND_MULTI_MAILBOX_TWO_TESTS"
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
RUN = re.compile(r"\A[a-f0-9]{32}\Z")
VERSION = 1
MAX_REQUEST = 4096


class Refused(Exception):
    pass


def source(filename, name):
    path = HERE / filename
    if path.is_symlink() or not path.is_file():
        raise Refused("required_runtime_module_unavailable")
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise Refused("runtime_module_not_loadable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("duplicate_request_key")
        result[key] = value
    return result


def validate_request(request, auditor):
    if not isinstance(request, dict) or set(request) != {
            "sender", "internal", "external", "run_id"}:
        raise Refused("invalid_multi_test_request")
    values = (request.get("sender"), request.get("internal"),
              request.get("external"))
    if any(not isinstance(v, str) or len(v) > 254 or
           not auditor.EMAIL.fullmatch(v) for v in values):
        raise Refused("invalid_reviewed_sender_or_recipient")
    if not isinstance(request["run_id"], str) or not RUN.fullmatch(request["run_id"]):
        raise Refused("invalid_unique_multi_test_id")
    sender, internal, external = (v.casefold() for v in values)
    domain = sender.rsplit("@", 1)[1]
    if (sender in (internal, external) or internal == external or
            internal.rsplit("@", 1)[1] != domain or
            external.rsplit("@", 1)[1] == domain):
        raise Refused("reviewed_internal_external_roles_not_distinct")
    return {"sender": sender, "internal": internal,
            "external": external, "run_id": request["run_id"]}


def read_request(stdin=None):
    stream = stdin or sys.stdin.buffer
    raw = stream.read(MAX_REQUEST + 1)
    if not raw or len(raw) > MAX_REQUEST:
        raise Refused("bounded_test_request_required")
    try:
        request = json.loads(raw.decode("ascii"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError, TypeError):
        raise Refused("invalid_test_request_json")
    return request


def prepare(request, auditor=None, restorer=None):
    if os.geteuid() != 0:
        raise Refused("root_required")
    auditor = auditor or source("audit-oauth-sender-map.py", "multi_acceptance_audit")
    restorer = restorer or source("restore-multi-mailbox-postfix.py",
                                  "multi_acceptance_restore")
    verified = validate_request(request, auditor)
    state = restorer.preview()
    installer = restorer.install
    gid = grp.getgrnam("m365mailer").gr_gid
    map_bytes = auditor.secure_read(str(installer.RUNTIME), auditor.MAX_MAP,
                                    0o640, gid)
    rows = auditor.parse_map(map_bytes)
    if digest(map_bytes) != state["record"]["runtime_map_sha256"]:
        raise Refused("active_route_map_changed")
    selected = [r for r in rows if r[1] == verified["sender"] and
                r[2] == verified["sender"]]
    if len(selected) != 1:
        raise Refused("selected_sender_not_owned_by_active_mailbox")
    path = selected[0][3]
    identity = auditor.secure_read(path, auditor.MAX_IDENTITY, 0o640, gid)
    auditor.validate_identity(identity, verified["sender"])
    evidence = {
        "version": VERSION,
        "run_id": verified["run_id"],
        "active_route_sha256": state["sha"],
        "active_marker_sha256": digest(state["marker"][1]),
        "runtime_map_sha256": digest(map_bytes),
        "selected_identity_sha256": digest(identity),
        "transport_sha256": state["record"]["source"]["m365-multi-mailbox-transport.py"],
        "recipient_internal_sha256": digest(verified["internal"].encode("ascii")),
        "recipient_external_sha256": digest(verified["external"].encode("ascii")),
        "sender_sha256": digest(verified["sender"].encode("ascii"))
    }
    approved = digest(json.dumps(evidence, sort_keys=True,
                                 separators=(",", ":")).encode("ascii"))
    return {"sha": approved, "request": verified, "evidence": evidence,
            "route": state, "installer": installer, "auditor": auditor}


def private_ledger(run_id, root=ROOT):
    parent = root.parent
    if parent.is_symlink() or parent.lstat().st_uid != 0 or \
            parent.lstat().st_mode & 0o022:
        raise Refused("untrusted_ledger_parent")
    if not root.exists() and not root.is_symlink():
        root.mkdir(mode=0o700)
    st = root.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or \
            stat.S_IMODE(st.st_mode) != 0o700:
        raise Refused("unsafe_acceptance_ledger")
    path = root / (run_id + ".jsonl")
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise Refused("test_run_already_reserved_never_auto_retry")
    os.fchmod(fd, 0o600)
    return fd


def event(fd, stage, status):
    allowed = {
        "run": ("reserved", "smtp_submissions_complete"),
        "internal": ("attempted", "smtp_accepted_not_inbox_verified"),
        "external": ("attempted", "smtp_accepted_not_inbox_verified")
    }
    if stage not in allowed or status not in allowed[stage]:
        raise Refused("unrecognized_ledger_stage")
    line = json.dumps({"stage": stage, "status": status},
                      sort_keys=True, separators=(",", ":")) + "\n"
    os.write(fd, line.encode("ascii"))
    os.fsync(fd)


def send_reviewed(plan, approved_sha, confirm, runner=subprocess.run,
                  restorer=None, refresh=None, ledger_factory=private_ledger):
    if (confirm != CONFIRM or not isinstance(approved_sha, str) or
            not SHA.fullmatch(approved_sha)):
        raise Refused("sha_and_typed_delivery_consent_required")
    if os.geteuid() != 0:
        raise Refused("root_required")
    restorer = restorer or source("restore-multi-mailbox-postfix.py",
                                  "multi_send_restore")
    refresh = refresh or source("refresh-multi-mailbox-proof.py",
                                "multi_send_root_proof")
    lock_fd = restorer.locked()  # same lock as EOP/route Apply/Restore
    ledger_fd = None
    try:
        request = plan["request"]
        # Bind the preview to ALL active sources, sender/recipient hashes and
        # the selected protected OAuth identity again under the exclusive lock.
        current = prepare(request, restorer=restorer)
        if current["sha"] != approved_sha or plan["sha"] != approved_sha:
            raise Refused("multi_delivery_plan_changed_reapprove")
        ledger_fd = ledger_factory(request["run_id"])
        event(ledger_fd, "run", "reserved")
        executable = shutil.which("runuser")
        if executable not in ("/usr/sbin/runuser", "/usr/bin/runuser"):
            raise Refused("trusted_runuser_unavailable")
        for role in ("internal", "external"):
            current = prepare(request, restorer=restorer)
            if current["sha"] != approved_sha:
                raise Refused("multi_delivery_dependencies_changed_before_" + role)
            # Root checks actual running security components and m365multi
            # transport before EACH recipient. Each proof expires in 120 sec.
            map_sha = current["evidence"]["runtime_map_sha256"]
            proof = refresh.inspect(map_sha)
            refresh.publish(proof)
            submission = {"sender": request["sender"],
                          "recipient": request[role],
                          "role": role, "run_id": request["run_id"]}
            encoded = json.dumps(submission, sort_keys=True,
                                 separators=(",", ":")).encode("ascii")
            cmd = [executable, "-u", "m365mailer", "--", "/usr/bin/python3",
                   str(current["installer"].TARGET /
                       "m365-multi-mailbox-transport.py"),
                   "--acceptance-test", "--expected-map-sha256", map_sha]
            event(ledger_fd, role, "attempted")
            try:
                result = runner(cmd, input=encoded, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=140,
                                check=False)
            except (OSError, subprocess.TimeoutExpired):
                raise Refused(role + "_smtp_result_unknown_check_inbox_and_trace")
            if result.returncode != 0:
                raise Refused(role + "_smtp_not_accepted_check_inbox_and_trace")
            event(ledger_fd, role, "smtp_accepted_not_inbox_verified")
            print("MULTI_ACCEPTANCE_" + role.upper() + "_SMTP_SUBMITTED=yes")
        event(ledger_fd, "run", "smtp_submissions_complete")
        print("MULTI_ACCEPTANCE_TWO_SMTP_SUBMISSIONS_ACCEPTED=yes")
        print("MULTI_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED=no")
        print("MULTI_ACCEPTANCE_EXCHANGE_TRACE_VERIFIED=no")
        print("MULTI_ACCEPTANCE_AUTOMATIC_RETRY=no")
        print("MULTI_ACCEPTANCE_QUEUE_OR_SERVICE_CHANGED=no")
    finally:
        if ledger_fd is not None:
            os.close(ledger_fd)
        os.close(lock_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", action="store_true")
    group.add_argument("--apply", action="store_true")
    parser.add_argument("--approve-sha256", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    try:
        if args.plan and (args.approve_sha256 or args.confirm):
            raise Refused("approval_not_allowed_during_review")
        request = read_request()
        selected = prepare(request)
        if args.plan:
            print("MULTI_ACCEPTANCE_STATUS=preview_only")
            print("MULTI_ACCEPTANCE_PLAN_SHA256=" + selected["sha"])
            print("MULTI_ACCEPTANCE_RUN_ID=" + selected["request"]["run_id"])
            print("MULTI_ACCEPTANCE_INTERNAL_SHA256=" +
                  selected["evidence"]["recipient_internal_sha256"])
            print("MULTI_ACCEPTANCE_EXTERNAL_SHA256=" +
                  selected["evidence"]["recipient_external_sha256"])
            print("MULTI_ACCEPTANCE_SENDER_SHA256=" +
                  selected["evidence"]["sender_sha256"])
            print("MULTI_ACCEPTANCE_MAIL_SENT=no")
            print("MULTI_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED=no")
        else:
            send_reviewed(selected, args.approve_sha256, args.confirm)
        return 0
    except Refused as exc:
        # Only fixed error codes; never echo addresses, OAuth identities,
        # SMTP transcripts, credentials, or the request JSON.
        print("MULTI_ACCEPTANCE_ERROR=" + str(exc), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
        print("MULTI_ACCEPTANCE_ERROR=host_or_delivery_operation_failed",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
