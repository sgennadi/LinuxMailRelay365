#!/usr/bin/env python3
"""Disposable Rocky 9.9 KVM-only two-file Sendmail recovery failure drill.

Never exposed as application Restore. Requires root, CI sentinel bound to this
boot, SELinux Enforcing, stopped MTAs, no SMTP listeners and empty queues.
Controlled append comments are installed in /etc/mail/sendmail.cf and
/etc/mail/submit.cf, then restored from the verified v2 backup. One phase
deliberately fails mid-restore to prove known-state rollback of both files.
No messages, cloud operations, package changes or production service actions.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

HERE = Path(__file__).resolve().parent
SINGLE = HERE / "rocky_vm_sendmail_stopped_config_restore.py"
spec = importlib.util.spec_from_file_location("lmr365_kvm_single_restore", str(SINGLE))
single = importlib.util.module_from_spec(spec)
spec.loader.exec_module(single)

TARGET_NAMES = ("etc/mail/sendmail.cf", "etc/mail/submit.cf")
MARKER = b"\n# LinuxMail365Relay dual-config disposable KVM test only\n"


def refuse(code):
    raise RuntimeError("LMR365_SENDMAIL_VM_DUAL_" + code)


class InjectedFailure(Exception):
    pass


def selected_path(name):
    if type(name) is not str or name not in TARGET_NAMES:
        refuse("TARGET_NOT_ALLOWLISTED")
    return Path("/") / name


def state_class(contents, original):
    if contents == original:
        return "restored"
    if contents == original + MARKER:
        return "controlled_edit"
    refuse("UNKNOWN_CONCURRENT_CHANGE")


def load_records(backup, snapshot_id):
    if not backup.ID.fullmatch(snapshot_id):
        refuse("INVALID_SNAPSHOT_ID")
    directory = backup.BASE / "sendmail" / snapshot_id
    accepted = backup.verify(directory, "sendmail", 0)
    if accepted["format"] != "v2_package_metadata":
        refuse("V2_REQUIRED")
    if backup.recovery_preview("sendmail", snapshot_id)["current"] != "identical":
        refuse("BASELINE_DRIFT")
    manifest = json.loads(backup.stable_file(directory / "manifest.json", 0)[1])
    records = []
    with tarfile.open(str(directory / "config.tar.gz"), "r:gz") as tar:
        for name in TARGET_NAMES:
            destination = selected_path(name)
            entry = manifest["files"].get(name)
            if (not isinstance(entry, dict) or
                    set(entry) != {"size", "sha256", "uid", "gid", "mode"} or
                    entry["uid"] != 0 or entry["size"] > 16 * 1024 * 1024):
                refuse("UNSUPPORTED_TARGET_ARCHIVE_METADATA")
            member = tar.getmember(name)
            if (not member.isreg() or member.size != entry["size"] or
                    (member.uid, member.gid, member.mode) !=
                    (entry["uid"], entry["gid"], entry["mode"])):
                refuse("TARGET_ARCHIVE_MEMBER_CHANGED")
            reader = tar.extractfile(member)
            if reader is None:
                refuse("TARGET_ARCHIVE_UNREADABLE")
            payload = reader.read(member.size + 1)
            if (len(payload) != entry["size"] or
                    hashlib.sha256(payload).hexdigest() != entry["sha256"]):
                refuse("TARGET_ARCHIVE_SHA_MISMATCH")
            meta, before = backup.stable_file(destination, 0)
            if (before != payload or meta.st_uid != entry["uid"] or
                    meta.st_gid != entry["gid"] or
                    stat.S_IMODE(meta.st_mode) != entry["mode"] or
                    meta.st_nlink != 1):
                refuse("TARGET_NOT_EQUAL_TO_INSTALLED_CONFIG")
            try:
                label = os.getxattr(str(destination), "security.selinux",
                                    follow_symlinks=False)
            except OSError:
                refuse("TARGET_SELINUX_LABEL_UNREADABLE")
            if not label:
                refuse("TARGET_SELINUX_LABEL_MISSING")
            records.append({"path": destination, "meta": meta,
                            "original": before, "context": label})
    return records, accepted["sha256"]


def check_current(record):
    meta, contents = single.file_state_without_backup(record["path"])
    before = record["meta"]
    if ((meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode)) !=
            (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) or
            meta.st_nlink != 1):
        refuse("CURRENT_METADATA_CHANGED")
    try:
        label = os.getxattr(str(record["path"]), "security.selinux",
                            follow_symlinks=False)
    except OSError:
        refuse("CURRENT_LABEL_UNREADABLE")
    if label != record["context"]:
        refuse("CURRENT_LABEL_CHANGED")
    return state_class(contents, record["original"])


def change(record, restore=False):
    original = record["original"]
    current = original + MARKER if restore else original
    target = original if restore else original + MARKER
    single.atomic_write(target, current, record["meta"],
                        record["context"], destination=record["path"])


def recover_known_states(records):
    """No blind overwrite: only the exact injected marker may be undone."""
    single.verify_disposable()
    for record in records:
        status = check_current(record)
        if status == "controlled_edit":
            change(record, restore=True)
        if check_current(record) != "restored":
            refuse("ROLLBACK_NOT_RESTORED")


def verify_recovered(backup, snapshot_id, records, sha):
    single.verify_disposable()
    for record in records:
        if check_current(record) != "restored":
            refuse("FINAL_CONFIG_NOT_RESTORED")
    if backup.recovery_preview("sendmail", snapshot_id)["current"] != "identical":
        refuse("FINAL_SNAPSHOT_METADATA_DRIFT")
    if backup.verify(backup.BASE / "sendmail" / snapshot_id,
                     "sendmail", 0)["sha256"] != sha:
        refuse("SNAPSHOT_CHANGED_DURING_DRILL")


def drill(backup, snapshot_id, records, sha, inject):
    raised_injected = False
    try:
        for record in records:
            change(record)
        if backup.recovery_preview("sendmail", snapshot_id)["current"] != "different":
            refuse("CONTROLLED_DRIFT_NOT_DETECTED")
        if inject:
            # The first config is restored; the second remains changed when
            # the simulated interruption occurs. Cleanup must repair only it.
            change(records[0], restore=True)
            if (check_current(records[0]) != "restored" or
                    check_current(records[1]) != "controlled_edit"):
                refuse("INJECTED_PARTIAL_RESTORE_UNVERIFIED")
            raise InjectedFailure("intentional_after_first_file")
        for record in records:
            change(record, restore=True)
    except InjectedFailure:
        if not inject:
            refuse("UNEXPECTED_INJECTED_FAILURE")
        raised_injected = True
    finally:
        # An unknown third-party mutation is NOT replaced automatically.
        # The VM is disposable, and a failure aborts service restart.
        recover_known_states(records)
    verify_recovered(backup, snapshot_id, records, sha)
    if inject and not raised_injected:
        refuse("MISSING_INJECTED_FAILURE")
    return True


def main(snapshot_id):
    single.verify_disposable()
    backup = single.load_backup()
    records, sha = load_records(backup, snapshot_id)
    if len(records) != len(TARGET_NAMES):
        refuse("INCOMPLETE_TWO_FILE_SELECTION")
    drill(backup, snapshot_id, records, sha, inject=True)
    print("LMR365_SENDMAIL_VM_DUAL_FAULT_INJECTION=known_state_rollback_passed")
    drill(backup, snapshot_id, records, sha, inject=False)
    print("LMR365_SENDMAIL_VM_DUAL_CONFIG_RESTORE=verified_two_files")
    print("LMR365_SENDMAIL_VM_DUAL_CONFIG_SELINUX=unchanged")
    print("LMR365_SENDMAIL_VM_DUAL_CONFIG_PRIMARY_MTA_RESTORE_ENABLED=no")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        refuse("EXPECTED_SNAPSHOT_ID")
    main(sys.argv[1])
