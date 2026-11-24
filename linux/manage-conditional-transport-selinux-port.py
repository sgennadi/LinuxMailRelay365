#!/usr/bin/env python3
"""Experimental, explicit SELinux outbound SMTP port-label transaction.

One custom TCP port per revision. Full and local port tables are retained,
not a full SELinux policy backup. Only a verified newly added singleton can
be removed. Exclusive administrator maintenance is required in addition to
the manager locks. No service, firewall, boolean or mail configuration edits.
"""
import argparse
import fcntl
import importlib.util
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "outbound_policy_readiness", str(pathlib.Path(__file__).with_name(
        "inspect-conditional-transport-selinux-readiness.py")))
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
L, P, M = D.L, D.P, D.M
T = P.T
BASE = "linuxmailrelay365-outbound-selinux-port"
INTENT, APPLIED, REMOVE, RESTORED = (
    "intent.json", "applied.json", "remove-intent.json", "restored.json")
NAMES = (INTENT, APPLIED, REMOVE, RESTORED)
LOCKS = ("linuxmailrelay365-postfix-route.lock", "linuxmailrelay365-sidecar-auth.lock")
ADD = "ADD_REVIEWED_OUTBOUND_SMTP_PORT"
ROLLBACK = "REMOVE_REVIEWED_OUTBOUND_SMTP_PORT"
MAINTENANCE = "EXCLUSIVE_SELINUX_PORT_POLICY_MAINTENANCE"
MAX_JOURNAL = 2 * 1024 * 1024
MAX_ROWS = 8192
PROTOCOLS = ("tcp", "udp", "sctp", "dccp")
TYPE = re.compile(r"[A-Za-z0-9_]{1,128}\Z")


class Refused(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def sha(value):
    return M.digest(M.canonical(value))


def valid_sha(value):
    return type(value) is str and M.HEX.fullmatch(value) is not None


def rows(raw, local=False):
    """Preserve native interval boundaries; never expand or overwrite a range."""
    need(type(raw) is str and len(raw) <= 131072, "port_table_unverified")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines and local:
        # Some versions print nothing for an empty successful -C listing.
        return []
    need(lines and lines[0].split() ==
         ["SELinux", "Port", "Type", "Proto", "Port", "Number"],
         "port_table_header_unverified")
    result = []
    for line in lines[1:]:
        match = re.fullmatch(r"([A-Za-z0-9_]{1,128})\s+(tcp|udp|sctp|dccp)\s+(.+)", line)
        need(match is not None, "port_table_row_unverified")
        kind, proto, values = match.groups()
        for value in values.split(","):
            interval = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?", value.strip())
            need(interval is not None, "port_table_interval_unverified")
            low, high = int(interval.group(1)), int(interval.group(2) or interval.group(1))
            result.append([kind, proto, low, high])
            need(len(result) <= MAX_ROWS, "port_table_oversized")
    result.sort()
    validate_rows(result)
    return result


def validate_rows(table):
    need(type(table) is list and len(table) <= MAX_ROWS, "invalid_port_table")
    for row in table:
        need(type(row) is list and len(row) == 4 and type(row[0]) is str and
             TYPE.fullmatch(row[0]) is not None and row[1] in PROTOCOLS and
             type(row[2]) is int and type(row[3]) is int and
             0 <= row[2] <= row[3] <= 65535, "invalid_port_row")
    need(table == sorted(table) and len({tuple(row) for row in table}) == len(table),
         "noncanonical_port_table")


def validate_policy(policy):
    need(type(policy) is dict and set(policy) == {"mode", "full", "local"} and
         policy["mode"] in D.ACTIVE, "active_selinux_required")
    full, local = policy["full"], policy["local"]
    validate_rows(full)
    validate_rows(local)
    need(any(row[:2] == ["smtp_port_t", "tcp"] for row in full),
         "smtp_policy_unverified")
    # Deliberately conservative. Ambiguous native grouping requires review.
    need({tuple(row) for row in local} <= {tuple(row) for row in full},
         "local_policy_not_exactly_observed")


def classify(policy, port):
    validate_policy(policy)
    need(type(port) is int and 1 <= port <= 65535, "invalid_port")
    matching = lambda row: row[1] == "tcp" and row[2] <= port <= row[3]
    specific = {row[0] for row in policy["full"] if matching(row) and
                row[0] not in D.GENERIC}
    if specific == {"smtp_port_t"}:
        return "existing_smtp"
    if specific or any(matching(row) for row in policy["local"]):
        return "conflict"
    # Well-known ports are diagnostic only; never create a new binding.
    return "candidate" if port >= 1024 else "restricted_port"


def validate_intent(intent):
    need(type(intent) is dict and set(intent) ==
         {"version", "revision", "port", "before"} and
         type(intent["version"]) is int and intent["version"] == 1 and
         valid_sha(intent["revision"]) and classify(intent["before"], intent["port"]) == "candidate",
         "invalid_port_intent")


def expected_after(intent):
    validate_intent(intent)
    before = intent["before"]
    row = ["smtp_port_t", "tcp", intent["port"], intent["port"]]
    result = {"mode": before["mode"], "full": sorted(before["full"] + [row]),
              "local": sorted(before["local"] + [row])}
    validate_policy(result)
    return result


def add_receipt(intent):
    return {"intent": sha(intent), "after": sha(expected_after(intent)), "result": "applied"}


def remove_intent(intent):
    return {"intent": sha(intent), "after": sha(expected_after(intent)), "action": "rollback"}


def restored_receipt(intent):
    return {"intent": sha(intent), "before": sha(intent["before"]), "result": "restored"}


class Host:
    def snapshot(self):
        mode = L.selinux_mode()

        def read():
            value = {"mode": mode,
                     "full": rows(P.system_command("semanage", ["port", "-l"])),
                     "local": rows(P.system_command("semanage", ["port", "-l", "-C"]), local=True)}
            validate_policy(value)
            return value

        need(mode in D.ACTIVE, "active_selinux_required")
        first = read()
        need(read() == first and L.selinux_mode() == mode, "port_policy_changed")
        return first

    def busy(self, port):
        # All TCP socket states, not merely listeners. This is a sampled
        # observation in the current network namespace, not dependency proof.
        need(type(port) is int and 1 <= port <= 65535, "invalid_port")
        return bool(P.system_command("ss", ["-H", "-tan",
                    "( sport = :{} or dport = :{} )".format(port, port)]).strip())

    def change(self, action, port):
        need(action in ("add", "remove") and type(port) is int and
             1024 <= port <= 65535, "invalid_port_mutation")
        argv = [P.trusted_tool("semanage"), "port"]
        argv += ["-a", "-t", "smtp_port_t"] if action == "add" else ["-d"]
        argv += ["-p", "tcp", str(port)]
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=P.SYSTEM_ENV, timeout=120, check=False)
        need(result.returncode == 0, "port_mutation_unverified")


class Store:
    """Root-only append-only revision; no generic policy restore or file removal."""
    def __init__(self, parent, revision, uid, create=False):
        need(valid_sha(revision), "invalid_port_revision")
        self.parent, self.revision, self.uid = parent, revision, uid
        self.base = M.open_base(parent, uid, create=create, name=BASE)
        self.fd = None
        try:
            if create:
                os.mkdir(revision, 0o700, dir_fd=self.base)
                os.fsync(self.base)
            self.fd = os.open(revision, M.DIR_FLAGS, dir_fd=self.base)
            self.guard()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.base is not None:
            os.close(self.base)
            self.base = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def guard(self):
        M.check_directory(self.parent, self.uid)
        for fd, parent, name in ((self.base, self.parent, BASE),
                                 (self.fd, self.base, self.revision)):
            M.check_directory(fd, self.uid, True)
            # Only the native SELinux xattr is accepted; ACLs and unknown
            # metadata require review. No existing path is ever relabeled.
            T.file_label(fd)
            current = os.fstat(fd)
            bound = os.stat(name, dir_fd=parent, follow_symlinks=False)
            need((current.st_dev, current.st_ino) == (bound.st_dev, bound.st_ino),
                 "private_port_store_replaced")

    def entries(self):
        self.guard()
        return set(os.listdir(self.fd))

    def read(self, name):
        need(name in NAMES, "invalid_port_record_name")
        self.guard()
        raw, meta = T.config_file(self.fd, name, self.uid, MAX_JOURNAL)
        need(meta["mode"] == 0o600, "unsafe_port_record")
        value = json.loads(raw.decode("ascii"), object_pairs_hook=M.unique_object)
        need(M.canonical(value) == raw, "noncanonical_port_record")
        self.guard()
        return value

    def write(self, name, value):
        need(name in NAMES, "invalid_port_record_name")
        self.guard()
        raw = M.canonical(value)
        need(0 < len(raw) <= MAX_JOURNAL, "port_record_oversized")
        M.write_file(self.fd, name, raw)
        os.fsync(self.fd)
        need(self.read(name) == value, "port_record_publication_unverified")


def load(store):
    entries = store.entries()
    need(any(entries == set(NAMES[:i]) for i in range(1, len(NAMES) + 1)),
         "incomplete_or_foreign_port_revision")
    intent = store.read(INTENT)
    validate_intent(intent)
    need(intent["revision"] == store.revision, "port_revision_mismatch")
    expected = {APPLIED: add_receipt(intent), REMOVE: remove_intent(intent),
                RESTORED: restored_receipt(intent)}
    for name in entries - {INTENT}:
        need(store.read(name) == expected[name], "port_record_changed")
    need(store.entries() == entries and store.read(INTENT) == intent,
         "port_revision_changed")
    return intent, entries


def review_add(host, port, revision):
    need(valid_sha(revision), "invalid_port_revision")
    policy = host.snapshot()
    state = classify(policy, port)
    if state == "candidate" and host.busy(port):
        state = "port_in_use"
    need(host.snapshot() == policy, "port_policy_changed")
    return state, {"version": 1, "revision": revision, "port": port, "before": policy}


def apply(host, store, intent, approval):
    validate_intent(intent)
    need(store.revision == intent["revision"] and approval == sha(intent) and
         not store.entries(), "port_add_approval_changed")
    before = intent["before"]
    port = intent["port"]
    need(host.snapshot() == before and not host.busy(port), "port_add_context_changed")
    # Durable backup and intent precede the first possible mutation.
    store.write(INTENT, intent)
    need(load(store) == (intent, {INTENT}) and host.snapshot() == before and
         not host.busy(port), "port_add_context_changed")
    host.change("add", port)
    after = expected_after(intent)
    need(host.snapshot() == after and load(store) == (intent, {INTENT}),
         "port_add_outcome_unverified")
    store.write(APPLIED, add_receipt(intent))
    need(load(store) == (intent, {INTENT, APPLIED}) and host.snapshot() == after,
         "port_add_outcome_unverified")
    return store.revision


def status(host, store):
    intent, entries = load(store)
    current = host.snapshot()
    before, after = intent["before"], expected_after(intent)
    if RESTORED in entries:
        phase = "restored" if current == before else "restored_policy_changed"
    elif REMOVE in entries:
        phase = "rollback_outcome_unconfirmed"
    elif APPLIED in entries:
        phase = "managed" if current == after else "managed_policy_changed"
    else:
        phase = ("add_not_confirmed_original" if current == before else
                 "add_outcome_unconfirmed")
    need(load(store) == (intent, entries) and host.snapshot() == current,
         "port_revision_observation_changed")
    return phase, intent, entries, current


def review_rollback(host, store):
    phase, intent, entries, current = status(host, store)
    need(phase == "managed" and entries == {INTENT, APPLIED} and
         current == expected_after(intent) and not host.busy(intent["port"]),
         "port_rollback_not_verified")
    need(status(host, store) == (phase, intent, entries, current),
         "port_rollback_context_changed")
    return intent, sha(remove_intent(intent))


def rollback(host, store, approval):
    intent, token = review_rollback(host, store)
    need(approval == token, "port_rollback_approval_changed")
    port = intent["port"]
    # The before/after comparison proves only the exact singleton created
    # by this verified transaction. Never remove a range or existing port.
    store.write(REMOVE, remove_intent(intent))
    need(load(store) == (intent, {INTENT, APPLIED, REMOVE}) and
         host.snapshot() == expected_after(intent) and not host.busy(port),
         "port_rollback_context_changed")
    host.change("remove", port)
    need(host.snapshot() == intent["before"] and
         load(store) == (intent, {INTENT, APPLIED, REMOVE}),
         "port_rollback_outcome_unverified")
    store.write(RESTORED, restored_receipt(intent))
    need(load(store) == (intent, set(NAMES)) and host.snapshot() == intent["before"],
         "port_rollback_outcome_unverified")
    return store.revision


def locks():
    """Share both existing manager lock names; never trust symlinks."""
    directory = P.open_directory("/run")
    held = []
    try:
        for name in LOCKS:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                         os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=directory)
            held.append(fd)
            meta = os.fstat(fd)
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
                 meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o600,
                 "untrusted_port_lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return held
    except BaseException:
        for fd in reversed(held):
            os.close(fd)
        raise
    finally:
        os.close(directory)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--review", type=int, metavar="PORT")
    actions.add_argument("--apply", type=int, metavar="PORT")
    actions.add_argument("--status", metavar="REVISION")
    actions.add_argument("--review-rollback", metavar="REVISION")
    actions.add_argument("--rollback", metavar="REVISION")
    parser.add_argument("--revision")
    parser.add_argument("--approve-review-sha256")
    parser.add_argument("--confirm")
    parser.add_argument("--maintenance-confirmation")
    return parser.parse_args(argv)


def validate_args(args):
    writing = args.apply is not None or args.rollback is not None
    if writing:
        need(args.maintenance_confirmation == MAINTENANCE and
             args.confirm == (ADD if args.apply is not None else ROLLBACK) and
             valid_sha(args.approve_review_sha256), "explicit_port_approval_required")
    else:
        need(args.confirm is None and args.approve_review_sha256 is None and
             args.maintenance_confirmation is None, "unexpected_port_approval")
    need(valid_sha(args.revision) if args.apply is not None else args.revision is None,
         "invalid_port_revision_argument")
    for revision in (args.status, args.review_rollback, args.rollback):
        need(revision is None or valid_sha(revision), "invalid_port_revision")
    for port in (args.review, args.apply):
        need(port is None or 1 <= port <= 65535, "invalid_port")
    if args.apply is not None:
        need(args.apply >= 1024, "restricted_port")
    return writing


def output(state, **fields):
    print("OUTBOUND_PORT_STATUS=" + state)
    for key, value in fields.items():
        print("OUTBOUND_PORT_" + key.upper() + "=" + str(value))
    print("OUTBOUND_PORT_RUNTIME_VERIFIED=no")
    print("OUTBOUND_PORT_MAIL_SENT=no")


def main(argv=None):
    args = arguments(argv)
    held, parent = [], None
    writing = False
    try:
        need(os.geteuid() == 0, "root_required")
        writing = validate_args(args)
        os.umask(0o077)
        host = Host()
        if args.review is not None:
            state, intent = review_add(host, args.review, secrets.token_hex(32))
            output(state, revision=intent["revision"], port=intent["port"],
                   mode=intent["before"]["mode"],
                   review_sha256=sha(intent) if state == "candidate" else "none",
                   changes_applied="no")
            return 0
        if writing:
            held = locks()
        parent = P.open_directory("/var/lib")
        if args.apply is not None:
            state, intent = review_add(host, args.apply, args.revision)
            need(state == "candidate" and sha(intent) == args.approve_review_sha256,
                 "port_add_approval_changed")
            with Store(parent, args.revision, 0, create=True) as store:
                apply(host, store, intent, args.approve_review_sha256)
            output("applied", revision=args.revision, port=args.apply,
                   changes_applied="selinux_port_label_only")
        else:
            revision = args.status or args.review_rollback or args.rollback
            with Store(parent, revision, 0) as store:
                if args.rollback is not None:
                    rollback(host, store, args.approve_review_sha256)
                    output("restored", revision=revision, changes_applied="selinux_port_label_only")
                elif args.review_rollback is not None:
                    intent, token = review_rollback(host, store)
                    output("rollback_reviewed", revision=revision, port=intent["port"],
                           review_sha256=token, changes_applied="no")
                else:
                    phase, intent, _, current = status(host, store)
                    output(phase, revision=revision, port=intent["port"],
                           mode=current["mode"], changes_applied="no")
        return 0
    except Exception:
        # Never emit raw policy tables, native errors or private journal data.
        output("refused_or_unverified", changes_applied="inspect_revision" if writing else "no")
        return 2
    finally:
        if parent is not None:
            os.close(parent)
        for fd in reversed(held):
            os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
