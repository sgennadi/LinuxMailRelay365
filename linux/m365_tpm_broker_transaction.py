"""Disabled primary TPM broker transaction engine (Linux/Python 3.6+).

No production installer or CLI. The future privileged backend must supply
exclusive maintenance, a reviewed exact plan, and native stage-specific
inspection/mutation callbacks. This module journals intent before changing
anything, fsyncs state, and refuses unknown/foreign states. A backend may
only be retried after proving its exact before/after state; partial stages
need manual recovery. No arbitrary commands or paths are read from a journal.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid

STAGES = ("account", "runtime", "policy", "udev_rule", "device", "unit")
STATE = "transaction.json"
LOCK = "transaction.lock"
MAX_STATE = 32768
SHA = re.compile(r"\A[0-9a-f]{64}\Z")
TXID = re.compile(r"\A[0-9a-f]{32}\Z")
APPLY = "APPLY_PRIMARY_TPM_BROKER"
ROLLBACK = "ROLLBACK_PRIMARY_TPM_BROKER"


class Refused(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def sha(value):
    return type(value) is str and SHA.fullmatch(value) is not None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "broker_transaction_duplicate_field")
        result[key] = value
    return result


def validate_plan(plan):
    need(type(plan) is dict and set(plan) == {"preview", "stages"} and
         sha(plan["preview"]) and type(plan["stages"]) is list and
         len(plan["stages"]) == len(STAGES), "broker_transaction_invalid_plan")
    for name, stage in zip(STAGES, plan["stages"]):
        need(type(stage) is dict and set(stage) == {"name", "before", "after"} and
             stage["name"] == name and sha(stage["before"]) and sha(stage["after"]) and
             stage["before"] != stage["after"], "broker_transaction_invalid_stage")
    return plan


def validate_state(value):
    need(type(value) is dict and set(value) == {
        "schema", "id", "plan", "approval", "completed", "pending", "phase", "revision"
    } and type(value["schema"]) is int and value["schema"] == 1 and
         type(value["id"]) is str and TXID.fullmatch(value["id"]) and
         type(value["revision"]) is int and 0 <= value["revision"] <= 10000,
         "broker_transaction_invalid_state")
    plan = validate_plan(value["plan"])
    need(sha(value["approval"]) and value["approval"] == digest(plan),
         "broker_transaction_approval_mismatch")
    count = value["completed"]
    pending = value["pending"]
    phase = value["phase"]
    need(type(count) is int and 0 <= count <= len(STAGES) and
         phase in ("install", "rollback", "installed", "rolled_back"),
         "broker_transaction_invalid_progress")
    if pending is not None:
        need(type(pending) is dict and set(pending) == {"name", "direction"} and
             ((phase == "install" and count < len(STAGES) and
               pending == {"name": STAGES[count], "direction": "install"}) or
              (phase == "rollback" and count > 0 and
               pending == {"name": STAGES[count - 1], "direction": "rollback"})),
             "broker_transaction_invalid_intent")
    if phase == "installed":
        need(count == len(STAGES) and pending is None, "broker_transaction_invalid_final")
    if phase == "rolled_back":
        need(count == 0 and pending is None, "broker_transaction_invalid_final")
    return value


def metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def checked_private(info, owner):
    need(stat.S_ISREG(info.st_mode) and info.st_uid == owner and
         stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
         "broker_transaction_unsafe_file")


class Journal:
    """Caller supplies an already-opened private directory; root in production.

    The fixed state file is replaced atomically under an exclusive flock.
    Directory fsync makes intent durable across process and host failure.
    The lock cannot defend against a privileged adversary; root is trusted.
    """
    def __init__(self, fd, owner=0):
        self.fd = fd
        self.owner = owner
        self.anchor = self.check_directory()
        self.locked = False

    def check_directory(self):
        info = os.fstat(self.fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == self.owner and
             stat.S_IMODE(info.st_mode) == 0o700,
             "broker_transaction_unsafe_directory")
        return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)

    def check(self):
        need(self.locked and self.check_directory() == self.anchor,
             "broker_transaction_lock_or_directory_changed")

    @contextmanager
    def exclusive(self):
        need(not self.locked, "broker_transaction_nested_lock")
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        fd = os.open(LOCK, flags, 0o600, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            checked_private(info, self.owner)
            need(info.st_size == 0, "broker_transaction_lock_not_empty")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused("broker_transaction_busy") from None
            named = os.stat(LOCK, dir_fd=self.fd, follow_symlinks=False)
            need(metadata(named) == metadata(info), "broker_transaction_lock_replaced")
            os.fsync(fd)
            os.fsync(self.fd)
            self.locked = True
            self.check()
            yield self
        finally:
            self.locked = False
            os.close(fd)

    def read(self):
        self.check()
        try:
            before = os.stat(STATE, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        checked_private(before, self.owner)
        need(0 < before.st_size <= MAX_STATE, "broker_transaction_state_size")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        fd = os.open(STATE, flags, dir_fd=self.fd)
        with os.fdopen(fd, "rb") as stream:
            checked_private(os.fstat(stream.fileno()), self.owner)
            need(metadata(os.fstat(stream.fileno())) == metadata(before),
                 "broker_transaction_state_changed")
            raw = stream.read(MAX_STATE + 1)
            need(len(raw) == before.st_size and
                 metadata(os.fstat(stream.fileno())) == metadata(before) and
                 metadata(os.stat(STATE, dir_fd=self.fd, follow_symlinks=False)) ==
                 metadata(before), "broker_transaction_state_changed")
        try:
            value = json.loads(raw.decode("ascii"), object_pairs_hook=unique)
        except (ValueError, UnicodeError, RecursionError):
            raise Refused("broker_transaction_state_invalid") from None
        validate_state(value)
        need(raw == canonical(value), "broker_transaction_noncanonical_state")
        return value

    def save(self, previous, value):
        self.check()
        validate_state(value)
        need(self.read() == previous, "broker_transaction_stale_state")
        if previous is None:
            need(value["revision"] == 0, "broker_transaction_revision")
        else:
            need(value["revision"] == previous["revision"] + 1 and
                 value["id"] == previous["id"] and value["approval"] == previous["approval"],
                 "broker_transaction_revision")
        raw = canonical(value)
        need(len(raw) <= MAX_STATE, "broker_transaction_state_size")
        temp = ".transaction-" + uuid.uuid4().hex
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(temp, flags, 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                checked_private(os.fstat(stream.fileno()), self.owner)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self.check()
            need(self.read() == previous, "broker_transaction_stale_state")
            os.replace(temp, STATE, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temp, dir_fd=self.fd)
            except FileNotFoundError:
                pass
        need(self.read() == value, "broker_transaction_commit_unverified")
        return value


def begin(journal, plan, approved, confirmation, guard, probe):
    """No host mutation; caller must separately prove the preview is fresh."""
    validate_plan(plan)
    need(confirmation == APPLY and sha(approved) and approved == digest(plan),
         "broker_transaction_apply_not_approved")
    need(journal.read() is None, "broker_transaction_existing_state")
    guard()
    for stage in plan["stages"]:
        need(probe(stage["name"]) == stage["before"], "broker_transaction_baseline_changed")
    guard()
    value = {"schema": 1, "id": uuid.uuid4().hex, "plan": plan,
             "approval": approved, "completed": 0, "pending": None,
             "phase": "install", "revision": 0}
    return journal.save(None, value)


def update(journal, state, **changes):
    value = dict(state, revision=state["revision"] + 1, **changes)
    return journal.save(state, value)


def observe(stage, probe):
    actual = probe(stage["name"])
    need(sha(actual) and actual in (stage["before"], stage["after"]),
         "broker_transaction_foreign_or_partial_stage")
    return actual


def check_completed(state, guard, probe):
    """Verify all other stages, not just the one about to change."""
    guard()
    count = state["completed"]
    pending = state["pending"]
    for index, stage in enumerate(state["plan"]["stages"]):
        actual = observe(stage, probe)
        if pending and stage["name"] == pending["name"]:
            continue
        expected = stage["after"] if index < count else stage["before"]
        need(actual == expected, "broker_transaction_unexpected_stage_state")
    guard()


def finish_pending(journal, state, guard, probe, mutate):
    pending = state["pending"]
    need(pending is not None, "broker_transaction_no_intent")
    check_completed(state, guard, probe)
    install = pending["direction"] == "install"
    index = state["completed"] if install else state["completed"] - 1
    stage = state["plan"]["stages"][index]
    old = stage["before"] if install else stage["after"]
    new = stage["after"] if install else stage["before"]
    actual = observe(stage, probe)
    if actual == old:
        guard()
        need(observe(stage, probe) == old, "broker_transaction_stage_changed")
        # Only fixed stage/direction, never arbitrary data from the journal.
        mutate(stage["name"], pending["direction"])
    guard()
    need(observe(stage, probe) == new, "broker_transaction_stage_not_verified")
    result = update(journal, state, completed=state["completed"] + (1 if install else -1),
                    pending=None)
    check_completed(result, guard, probe)
    return result


def resume_install(journal, approved, confirmation, guard, probe, mutate):
    need(confirmation == APPLY, "broker_transaction_apply_not_approved")
    state = journal.read()
    need(state is not None and state["approval"] == approved and
         state["phase"] in ("install", "installed"), "broker_transaction_resume_refused")
    check_completed(state, guard, probe)
    if state["phase"] == "installed":
        return state
    while state["completed"] < len(STAGES):
        if state["pending"] is None:
            state = update(journal, state, pending={
                "name": STAGES[state["completed"]], "direction": "install"})
        state = finish_pending(journal, state, guard, probe, mutate)
    return update(journal, state, phase="installed")


def rollback(journal, approved, confirmation, guard, probe, mutate):
    need(confirmation == ROLLBACK, "broker_transaction_rollback_not_approved")
    state = journal.read()
    need(state is not None and state["approval"] == approved,
         "broker_transaction_rollback_refused")
    check_completed(state, guard, probe)
    if state["phase"] == "rolled_back":
        return state
    if state["phase"] == "install" and state["pending"] is not None:
        # Do not finish an interrupted install just to undo it. Only exact
        # before/after evidence may resolve the outstanding forward intent.
        stage = state["plan"]["stages"][state["completed"]]
        actual = observe(stage, probe)
        state = update(journal, state, pending=None,
                       completed=state["completed"] + (1 if actual == stage["after"] else 0))
    if state["phase"] != "rollback":
        state = update(journal, state, phase="rollback")
    while state["completed"]:
        if state["pending"] is None:
            state = update(journal, state, pending={
                "name": STAGES[state["completed"] - 1], "direction": "rollback"})
        state = finish_pending(journal, state, guard, probe, mutate)
    check_completed(state, guard, probe)
    return update(journal, state, phase="rolled_back")
