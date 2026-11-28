"""Candidate native file stages for the primary TPM broker transaction.

Linux/Python 3.6+. No CLI or automatic installation. Runtime, udev rule and
unit file only: no account/policy/device changes, daemon-reload, udev
trigger, start or enable. The privileged coordinator must hold the journal
lock, exclusive maintenance, and prove the service/udev/policy lifecycle
is safe for each operation. Root and the reviewed package are trusted.
SELinux context belongs to the separate policy stage, not file hashes.
"""
from contextlib import contextmanager
import ctypes
import hashlib
import os
from pathlib import Path
import stat

import m365_tpm_broker_bootstrap as bootstrap
import m365_tpm_broker_transaction as tx

UNIT = "linuxmailrelay365-primary-tpm-broker.service"
RULE = "99-lmr365-primary-tpm-broker.rules"
PARENTS = {"runtime": Path("/usr/local/libexec"),
           "udev_rule": Path("/etc/udev/rules.d"),
           "unit": Path("/etc/systemd/system")}
TARGETS = {"runtime": bootstrap.RUNTIME.name, "udev_rule": RULE, "unit": UNIT}
MODES = {"runtime": dict((name, 0o644) for name in bootstrap.MODULES),
         "udev_rule": {RULE: 0o644}, "unit": {UNIT: 0o644}}
MODES["runtime"]["python3"] = 0o755
SOURCES = {
    "bootstrap.py": "m365_tpm_broker_bootstrap.py",
    "m365_hardware_signer.py": "m365_hardware_signer.py",
    "m365_xoauth2_transport.py": "m365_xoauth2_transport.py",
    "m365_tpm_broker_protocol.py": "m365_tpm_broker_protocol.py",
    "m365_tpm_broker_identity.py": "m365_tpm_broker_identity.py",
    "m365_tpm_broker_service.py": "m365_tpm_broker_service.py",
}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
MAX_PYTHON = bootstrap.MAX_EXECUTABLE
MAX_FILE = bootstrap.MAX_MODULE
Refused = tx.Refused
need = tx.need


def directory_id(fd, owner, group=None, mode=None):
    info = os.fstat(fd)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and
         not info.st_mode & 0o6022 and
         (group is None or info.st_gid == group) and
         (mode is None or stat.S_IMODE(info.st_mode) == mode),
         "broker_files_directory_unsafe")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


@contextmanager
def open_trusted_directory(path):
    need(isinstance(path, Path) and path.is_absolute(),
         "broker_files_directory_not_absolute")
    fd = os.open("/", DIR_FLAGS)
    try:
        directory_id(fd, 0)
        for part in path.parts[1:]:
            need(part not in ("", ".", ".."), "broker_files_directory_component")
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            directory_id(fd, 0)
        yield fd
    finally:
        os.close(fd)


def limit(name):
    return MAX_PYTHON if name == "python3" else MAX_FILE


def check_regular(info, owner, group, mode, maximum):
    need(stat.S_ISREG(info.st_mode) and info.st_uid == owner and
         info.st_gid == group and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= maximum,
         "broker_files_unsafe_metadata")


def read_regular(fd, name, owner, group, mode, maximum):
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    check_regular(before, owner, group, mode, maximum)
    handle = os.open(name, READ_FLAGS, dir_fd=fd)
    with os.fdopen(handle, "rb") as stream:
        stamp = tx.metadata(before)
        need(tx.metadata(os.fstat(stream.fileno())) == stamp,
             "broker_files_changed")
        data = stream.read(maximum + 1)
        need(len(data) == before.st_size and len(data) <= maximum and
             tx.metadata(os.fstat(stream.fileno())) == stamp and
             tx.metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)) == stamp,
             "broker_files_changed")
    return data


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def file_manifest(stage, files, owner, group):
    return tx.digest({"stage": stage, "state": "installed",
                      "owner": owner, "group": group,
                      "directory_mode": 0o755 if stage == "runtime" else None,
                      "files": {name: {"mode": MODES[stage][name], "sha256": sha_bytes(raw)}
                                for name, raw in files.items()}})


def absent_manifest(stage):
    return tx.digest({"stage": stage, "state": "absent"})


def rename_exclusive(fd, old, new):
    """Atomic same-directory publish without overwrite; no unsafe fallback."""
    libc = ctypes.CDLL(None, use_errno=True)
    func = getattr(libc, "renameat2", None)
    need(func is not None, "broker_files_rename_noreplace_unavailable")
    func.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                     ctypes.c_char_p, ctypes.c_uint]
    func.restype = ctypes.c_int
    if func(fd, os.fsencode(old), fd, os.fsencode(new), 1) != 0:
        raise OSError(ctypes.get_errno(), "broker_files_exclusive_rename_failed")


def exists(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def write_regular(fd, name, raw, owner, group, mode):
    handle = os.open(name, WRITE_FLAGS, 0o600, dir_fd=fd)
    with os.fdopen(handle, "wb") as stream:
        os.fchown(stream.fileno(), owner, group)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
        check_regular(os.fstat(stream.fileno()), owner, group, mode, limit(name))
    need(read_regular(fd, name, owner, group, mode, limit(name)) == raw,
         "broker_files_write_unverified")


class FileStages:
    """Three concrete transaction stage callbacks on fixed anchored directories.

    Internal constructor accepts directory FDs for disposable tests. Production
    callers must use open_candidate_files with a stage-specific native guard.
    Scratch names bind to the transaction ID. Any leftover scratch object is
    an ambiguous partial stage and blocks further automatic work; it is never
    blindly deleted or accepted as installed/absent.
    """
    def __init__(self, parents, payloads, transaction_id, guard, verify_parent,
                 owner=0, group=0):
        need(type(transaction_id) is str and tx.TXID.fullmatch(transaction_id) and
             set(parents) == set(TARGETS) and set(payloads) == set(TARGETS) and
             callable(guard) and callable(verify_parent),
             "broker_files_invalid_backend")
        self._id = transaction_id
        self._parents = dict(parents)
        self._owner, self._group = owner, group
        self._guard, self._verify_parent = guard, verify_parent
        self._anchors = {stage: directory_id(fd, owner, group)
                         for stage, fd in self._parents.items()}
        self._payloads = {}
        for stage, files in payloads.items():
            need(type(files) is dict and set(files) == set(MODES[stage]),
                 "broker_files_payload_inventory")
            need(all(type(raw) is bytes and 0 < len(raw) <= limit(name)
                     for name, raw in files.items()), "broker_files_payload_size")
            self._payloads[stage] = dict(files)

    def _parent(self, stage):
        need(stage in TARGETS, "broker_files_unknown_stage")
        fd = self._parents[stage]
        need(directory_id(fd, self._owner, self._group) == self._anchors[stage],
             "broker_files_parent_changed")
        self._verify_parent(stage, self._anchors[stage])
        return fd

    def _scratch(self, stage):
        return ".lmr365-tpm-" + self._id + "-" + stage

    def stage_plan(self, stage):
        need(stage in TARGETS, "broker_files_unknown_stage")
        return {"name": stage, "before": absent_manifest(stage),
                "after": file_manifest(stage, self._payloads[stage], self._owner, self._group)}

    def _read_target(self, parent, stage, name):
        if stage != "runtime":
            filename = TARGETS[stage]
            return {filename: read_regular(parent, name, self._owner, self._group,
                                          MODES[stage][filename], MAX_FILE)}
        fd = os.open(name, DIR_FLAGS, dir_fd=parent)
        try:
            anchor = directory_id(fd, self._owner, self._group, 0o755)
            need(set(os.listdir(fd)) == set(MODES[stage]), "broker_files_runtime_inventory")
            files = {filename: read_regular(fd, filename, self._owner, self._group,
                                           mode, limit(filename))
                     for filename, mode in MODES[stage].items()}
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            need(directory_id(fd, self._owner, self._group, 0o755) == anchor and
                 (current.st_dev, current.st_ino, current.st_mode, current.st_uid,
                  current.st_gid) == anchor and set(os.listdir(fd)) == set(files),
                 "broker_files_runtime_changed")
            return files
        finally:
            os.close(fd)

    def probe(self, stage):
        fd = self._parent(stage)
        need(not exists(fd, self._scratch(stage)), "broker_files_partial_stage_requires_review")
        target = TARGETS[stage]
        if not exists(fd, target):
            return absent_manifest(stage)
        files = self._read_target(fd, stage, target)
        return file_manifest(stage, files, self._owner, self._group)

    def mutate(self, stage, direction):
        need(stage in TARGETS and direction in ("install", "rollback"),
             "broker_files_invalid_operation")
        plan = self.stage_plan(stage)
        old, new = ((plan["before"], plan["after"]) if direction == "install"
                    else (plan["after"], plan["before"]))
        self._guard(stage, direction)
        need(self.probe(stage) == old, "broker_files_stage_not_expected")
        fd = self._parent(stage)
        target, scratch = TARGETS[stage], self._scratch(stage)
        if direction == "install":
            self._install(fd, stage, scratch)
            need(self._read_target(fd, stage, scratch) == self._payloads[stage],
                 "broker_files_staging_unverified")
            self._guard(stage, direction)
            self._parent(stage)
            rename_exclusive(fd, scratch, target)
            os.fsync(fd)
        else:
            # Detach only the exact reviewed destination, then remove the
            # exact inventory. Crash during cleanup leaves a visible conflict.
            self._guard(stage, direction)
            need(self.probe(stage) == old, "broker_files_stage_not_expected")
            rename_exclusive(fd, target, scratch)
            os.fsync(fd)
            need(self._read_target(fd, stage, scratch) == self._payloads[stage],
                 "broker_files_detached_unverified")
            self._remove(fd, stage, scratch)
            os.fsync(fd)
        self._guard(stage, direction)
        need(self.probe(stage) == new, "broker_files_mutation_unverified")

    def _install(self, fd, stage, scratch):
        if stage != "runtime":
            filename = TARGETS[stage]
            write_regular(fd, scratch, self._payloads[stage][filename],
                          self._owner, self._group, MODES[stage][filename])
            os.fsync(fd)
            return
        os.mkdir(scratch, 0o700, dir_fd=fd)
        os.fsync(fd)
        child = os.open(scratch, DIR_FLAGS, dir_fd=fd)
        try:
            os.fchown(child, self._owner, self._group)
            os.fchmod(child, 0o700)
            directory_id(child, self._owner, self._group, 0o700)
            for name, mode in sorted(MODES[stage].items()):
                write_regular(child, name, self._payloads[stage][name],
                              self._owner, self._group, mode)
            os.fchmod(child, 0o755)
            os.fsync(child)
        finally:
            os.close(child)
        os.fsync(fd)

    def _remove(self, fd, stage, scratch):
        if stage != "runtime":
            os.unlink(scratch, dir_fd=fd)
            return
        child = os.open(scratch, DIR_FLAGS, dir_fd=fd)
        try:
            directory_id(child, self._owner, self._group, 0o755)
            need(set(os.listdir(child)) == set(MODES[stage]),
                 "broker_files_runtime_inventory")
            for name, mode in sorted(MODES[stage].items()):
                need(read_regular(child, name, self._owner, self._group,
                                  mode, limit(name)) == self._payloads[stage][name],
                     "broker_files_remove_changed")
                os.unlink(name, dir_fd=child)
                os.fsync(child)
            need(not os.listdir(child), "broker_files_remove_unexpected_entries")
        finally:
            os.close(child)
        os.rmdir(scratch, dir_fd=fd)


def reviewed_payloads(package, hashes):
    """Read only the fixed artifacts from the exact approved package hashes."""
    need(isinstance(package, Path) and package.is_absolute() and type(hashes) is dict,
         "broker_files_invalid_package")
    result = dict((stage, {}) for stage in TARGETS)
    def load(path, name, mode, key):
        need(tx.sha(hashes.get(key)), "broker_files_unapproved_source")
        with open_trusted_directory(path.parent) as fd:
            raw = read_regular(fd, path.name, 0, 0, mode, limit(name))
        need(sha_bytes(raw) == hashes[key], "broker_files_source_changed")
        return raw
    for name, relative in SOURCES.items():
        result["runtime"][name] = load(package / relative, name, 0o644, "runtime/" + name)
    native = bootstrap.NATIVE_PYTHON.resolve(strict=True)
    result["runtime"]["python3"] = load(native, "python3", 0o755, "runtime/python3")
    result["unit"][UNIT] = load(package / "systemd" / UNIT, UNIT, 0o644, "systemd/" + UNIT)
    result["udev_rule"][RULE] = load(package / "udev" / RULE, RULE, 0o644, "udev/" + RULE)
    return result


@contextmanager
def open_candidate_files(package, approved_hashes, transaction_id, guard):
    """Privileged coordinator only; does not itself mutate or start services."""
    need(os.geteuid() == 0 and callable(guard), "broker_files_root_guard_required")
    payloads = reviewed_payloads(package, approved_hashes)
    with open_trusted_directory(PARENTS["runtime"]) as runtime, \
         open_trusted_directory(PARENTS["udev_rule"]) as udev, \
         open_trusted_directory(PARENTS["unit"]) as unit:
        def verify_parent(stage, anchor):
            with open_trusted_directory(PARENTS[stage]) as current:
                need(directory_id(current, 0, 0) == anchor, "broker_files_parent_replaced")
        yield FileStages({"runtime": runtime, "udev_rule": udev, "unit": unit},
                         payloads, transaction_id, guard, verify_parent)
