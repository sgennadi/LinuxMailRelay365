"""Native TPM resource-manager DAC stage for the disabled primary broker.

No installer/CLI. Only /dev/tpmrm0 ownership and permissions are changed,
never /dev/tpm0, ACLs, labels, persistent TPM keys or another device. The
reviewed baseline is bound to the SAME boot, char-device inode and sysfs
identity. Reboot/hotplug changes are refused by this transaction adapter:
a separate recovery/udev acceptance path must prove a new device instance.
The coordinator must hold exclusive maintenance, verify no other TPM users,
stop the broker/Postfix, and quiesce competing udev events before mutation.
"""
from collections import namedtuple
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import re
import stat
import uuid

import m365_tpm_broker_files as files
import m365_tpm_broker_policy as policy
import m365_tpm_broker_service as service
import m365_tpm_broker_transaction as tx

DEVICE = Path("/dev/tpmrm0")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
TPM_MAJOR = Path("/sys/class/tpm/tpm0/tpm_version_major")
Evidence = namedtuple("DeviceEvidence", "boot fsdev inode rdev sysfs label uid gid mode")
Spec = namedtuple("DeviceSpec", "baseline signer_uid signer_gid")
Refused = tx.Refused
need = tx.need


def validate_evidence(value):
    need(isinstance(value, Evidence) and type(value.boot) is str and
         all(type(v) is int and v >= 0 for v in
             (value.fsdev, value.inode, value.rdev, value.uid, value.gid, value.mode)) and
         value.inode > 0 and value.rdev > 0 and value.uid == 0 and
         value.mode in (0o600, 0o660) and type(value.sysfs) is str and
         value.sysfs.startswith("/sys/devices/") and
         Path(value.sysfs).name == "tpmrm0" and
         all(part not in (".", "..") for part in Path(value.sysfs).parts) and
         type(value.label) is str and re.fullmatch(
             r"[A-Za-z0-9_]+:object_r:tpm_device_t:[A-Za-z0-9_.,:-]+", value.label),
         "broker_device_invalid_evidence")
    try:
        need(str(uuid.UUID(value.boot)) == value.boot, "broker_device_invalid_boot")
    except (ValueError, AttributeError, TypeError):
        raise Refused("broker_device_invalid_boot") from None
    return value


def validate(spec):
    need(isinstance(spec, Spec), "broker_device_invalid_spec")
    validate_evidence(spec.baseline)
    need(type(spec.signer_uid) is int and type(spec.signer_gid) is int and
         201 <= spec.signer_uid <= 999 and 201 <= spec.signer_gid <= 999 and
         spec.signer_gid != spec.baseline.gid, "broker_device_signer_id_unverified")
    return spec


def node_identity(meta):
    return meta.st_dev, meta.st_ino, meta.st_rdev


def check_node(meta):
    need(stat.S_ISCHR(meta.st_mode) and meta.st_uid == 0 and
         stat.S_IMODE(meta.st_mode) in (0o600, 0o660),
         "broker_device_native_node_unverified")


@contextmanager
def pinned_node():
    """O_PATH pins the character node without opening a TPM session."""
    policy.enforcing()
    with files.open_trusted_directory(DEVICE.parent) as directory:
        before = os.stat(DEVICE.name, dir_fd=directory, follow_symlinks=False)
        check_node(before)
        fd = os.open(DEVICE.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory)
        try:
            node = os.fstat(fd)
            check_node(node)
            need(tx.metadata(before) == tx.metadata(node),
                 "broker_device_node_changed")
            yield directory, fd
        finally:
            os.close(fd)


def check_pinned(directory, fd):
    node = os.fstat(fd)
    named = os.stat(DEVICE.name, dir_fd=directory, follow_symlinks=False)
    check_node(node)
    check_node(named)
    proc = "/proc/self/fd/{}".format(fd)
    need(os.readlink(proc) == str(DEVICE) and
         tx.metadata(node) == tx.metadata(named) == tx.metadata(os.stat(proc)),
         "broker_device_node_changed")
    return node, proc


def sysfs_identity(rdev):
    number = "{}:{}".format(os.major(rdev), os.minor(rdev))
    node = (Path("/sys/dev/char") / number).resolve(strict=True)
    need(node.name == "tpmrm0" and str(node).startswith("/sys/devices/") and
         (node / "subsystem").resolve(strict=True).name == "tpmrm" and
         (node / "dev").read_text(encoding="ascii").strip() == number and
         TPM_MAJOR.read_text(encoding="ascii").strip() == "2",
         "broker_device_sysfs_unverified")
    return str(node)


def node_label_and_acl(proc):
    raw = os.getxattr(proc, "security.selinux")
    label = policy.label_value(raw)
    need(label.split(":")[2] == "tpm_device_t", "broker_device_label_unverified")
    try:
        os.getxattr(proc, "system.posix_acl_access")
    except OSError as exc:
        need(exc.errno in (errno.ENODATA, errno.EOPNOTSUPP),
             "broker_device_acl_unverified")
    else:
        raise Refused("broker_device_existing_acl")
    return label


def observe_pinned(directory, fd):
    before, proc = check_pinned(directory, fd)
    boot = BOOT_ID.read_text(encoding="ascii").strip()
    sysfs = sysfs_identity(before.st_rdev)
    label = node_label_and_acl(proc)
    after, unused = check_pinned(directory, fd)
    need(tx.metadata(before) == tx.metadata(after) and
         BOOT_ID.read_text(encoding="ascii").strip() == boot and
         sysfs_identity(after.st_rdev) == sysfs, "broker_device_evidence_changed")
    return validate_evidence(Evidence(
        boot, before.st_dev, before.st_ino, before.st_rdev, sysfs, label,
        before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)))


def observe_native():
    try:
        with pinned_node() as (directory, fd):
            value = observe_pinned(directory, fd)
            need(observe_pinned(directory, fd) == value,
                 "broker_device_evidence_changed")
            policy.enforcing()
            return value
    except (OSError, UnicodeError, AttributeError, OverflowError):
        raise Refused("broker_device_native_inspection_failed") from None


def prepare_spec(signer_uid, signer_gid, observe=observe_native):
    before = observe()
    need(observe() == before, "broker_device_evidence_changed")
    return validate(Spec(before, signer_uid, signer_gid))


def verify_account(spec):
    accounts = service.lookup_accounts()
    need((accounts.signer_uid, accounts.signer_gid) ==
         (spec.signer_uid, spec.signer_gid) and
         accounts.mail_gid != spec.signer_gid, "broker_device_signer_account_changed")


def change_native(before, after):
    """Change only a pinned, still named, exactly reviewed character node."""
    validate_evidence(before)
    validate_evidence(after)
    need(before[:7] == after[:7] and before != after,
         "broker_device_change_scope")
    try:
        with pinned_node() as (directory, fd):
            need(observe_pinned(directory, fd) == before,
                 "broker_device_before_state_changed")
            node, proc = check_pinned(directory, fd)
            # Follow only the kernel's self/fd reference to the pinned inode,
            # not a re-resolved /dev path. O_PATH never opens the TPM.
            if before.gid != after.gid:
                os.chown(proc, 0, after.gid)
            intermediate = before._replace(gid=after.gid)
            need(observe_pinned(directory, fd) == intermediate,
                 "broker_device_group_change_unverified")
            if before.mode != after.mode:
                os.chmod(proc, after.mode)
            need(observe_pinned(directory, fd) == after,
                 "broker_device_permissions_change_unverified")
        policy.enforcing()
    except (OSError, UnicodeError, AttributeError, OverflowError):
        raise Refused("broker_device_native_change_failed") from None


class DeviceStage:
    def __init__(self, spec, guard, observe=observe_native,
                 change=change_native, account=verify_account):
        self.spec = validate(spec)
        need(all(callable(fn) for fn in (guard, observe, change, account)),
             "broker_device_guard_required")
        self.guard, self.observe, self.change, self.account = guard, observe, change, account
        self.before = spec.baseline
        self.after = self.before._replace(gid=spec.signer_gid, mode=0o660)

    def fingerprint(self, state):
        return tx.digest({"stage": "device", "state": state._asdict(),
                          "signer_uid": self.spec.signer_uid,
                          "signer_gid": self.spec.signer_gid})

    def stage_plan(self):
        return {"name": "device", "before": self.fingerprint(self.before),
                "after": self.fingerprint(self.after)}

    def probe(self):
        actual = self.observe()
        need(actual in (self.before, self.after),
             "broker_device_foreign_or_partial_state")
        return self.fingerprint(actual)

    def mutate(self, direction):
        need(direction in ("install", "rollback"), "broker_device_operation_refused")
        old, new = ((self.before, self.after) if direction == "install"
                    else (self.after, self.before))
        self.guard("device", direction)
        self.account(self.spec)
        need(self.observe() == old, "broker_device_before_state_changed")
        self.guard("device", direction)
        self.account(self.spec)
        need(self.observe() == old, "broker_device_before_state_changed")
        self.change(old, new)
        self.guard("device", direction)
        self.account(self.spec)
        need(self.observe() == new, "broker_device_after_state_unverified")
