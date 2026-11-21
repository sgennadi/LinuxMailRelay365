#!/usr/bin/env python3
"""KVM-only Sendmail file recovery acceptance: NOT a production Restore API.

In a disposable Rocky 9.9 VM, while both MTAs are stopped and queues empty,
restore ONLY /etc/mail/sendmail.cf after appending a harmless comment.
A verified Sendmail v2 snapshot supplies the original bytes and metadata.
The tool cannot be used outside the per-boot attested CI VM, and never
starts services, sends SMTP data, or enables any production recovery.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile

CI_MARKER = Path("/run/lmr365-disposable-sendmail-vm")
CONFIG = Path("/etc/mail/sendmail.cf")
BACKUP_MODULE = Path(__file__).with_name("foreign-mta-config-backup.py")
RESTORE_MARKER = b"\n# LinuxMail365Relay disposable KVM recovery test only\n"


def refuse(reason):
    raise RuntimeError("LMR365_SENDMAIL_VM_RECOVERY_" + reason)


def verify_disposable():
    if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        refuse("CI_ROOT_ONLY")
    distro = {}
    for row in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if row.startswith(("ID=", "VERSION_ID=")):
            key, value = row.split("=", 1)
            if key in distro:
                refuse("DUPLICATE_OS_RELEASE_ID")
            distro[key] = value.strip().strip('"').strip("'")
    if distro.get("ID") != "rocky" or distro.get("VERSION_ID") != "9.9":
        refuse("UNEXPECTED_ROCKY_GUEST_VERSION")
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        refuse("NOT_SYSTEMD_GUEST")
    if socket.gethostname().split(".")[0] != "rocky-selinux-ci":
        refuse("UNEXPECTED_CI_GUEST_HOSTNAME")
    if Path("/sys/fs/selinux/enforce").read_text().strip() != "1":
        refuse("SELINUX_NOT_ENFORCING")
    st = CI_MARKER.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
            or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600
            or CI_MARKER.read_text().strip() !=
            Path("/proc/sys/kernel/random/boot_id").read_text().strip()):
        refuse("BOOT_ATTESTATION_FAILED")
    for service in ("sendmail.service", "sm-client.service", "postfix.service"):
        check = subprocess.run(
            ["systemctl", "is-active", "--quiet", service], check=False)
        if check.returncode == 0:
            refuse("ACTIVE_MTA_" + service.replace(".", "_"))
    for process in ("sendmail", "postfix", "master"):
        p = subprocess.run(["pgrep", "-x", process],
                           capture_output=True, check=False)
        if p.returncode == 0:
            refuse("MTA_PROCESS_RUNNING_" + process)
    ss = subprocess.run(["ss", "-H", "-ltn"], text=True, check=True,
                        capture_output=True, timeout=12)
    for line in ss.stdout.splitlines():
        cols = line.split()
        if len(cols) < 5:
            refuse("UNPARSEABLE_TCP_LISTENER")
        port = cols[3].rpartition(":")[-1]
        if port.isdigit() and int(port) in (25, 465, 587, 2525, 2526):
            refuse("UNEXPECTED_SMTP_LISTENER")
    for directory in (Path("/var/spool/mqueue"), Path("/var/spool/clientmqueue")):
        if directory.is_dir() and any(
                f.is_file() and f.name.startswith(("qf", "df", "tf", "xf"))
                for f in directory.iterdir()):
            refuse("SENDMAIL_QUEUE_NOT_EMPTY")


def load_backup():
    spec = importlib.util.spec_from_file_location(
        "lmr365_kvm_native_snapshot", str(BACKUP_MODULE))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def file_state(backup):
    state, data = backup.stable_file(CONFIG, 0)
    if state.st_nlink != 1 or state.st_uid != 0:
        refuse("UNTRUSTED_PRIMARY_CONFIG")
    return state, data


def atomic_write(payload, expected_current, meta, old_context):
    # This is a direct write ONLY in an attested, disposable VM. No library
    # product command uses this function, and it is not a general restore.
    if (not isinstance(payload, bytes) or len(payload) > 16 * 1024 * 1024 or
            not isinstance(expected_current, bytes) or
            len(expected_current) > 16 * 1024 * 1024):
        refuse("BAD_RESTORATION_BYTES")
    fd, name = tempfile.mkstemp(prefix=".lmr365-kvm-restore-", dir="/etc/mail")
    try:
        with os.fdopen(fd, "wb") as writer:
            writer.write(payload)
            writer.flush()
            os.fsync(writer.fileno())
        os.chown(name, meta.st_uid, meta.st_gid, follow_symlinks=False)
        os.chmod(name, stat.S_IMODE(meta.st_mode))
        subprocess.run(["restorecon", "-F", name], check=True, timeout=20,
                       capture_output=True)
        # Renaming a temporary file into sendmail.cf retains its own SELinux
        # label. Ensure it has exactly the previous target label.
        os.setxattr(name, "security.selinux", old_context, follow_symlinks=False)
        current, current_bytes = file_state_without_backup(CONFIG)
        if (current_bytes != expected_current or
                current.st_uid != meta.st_uid or
                current.st_gid != meta.st_gid or
                stat.S_IMODE(current.st_mode) != stat.S_IMODE(meta.st_mode) or
                os.getxattr(CONFIG, "security.selinux") != old_context):
            refuse("SOURCE_CHANGED_BEFORE_ATOMIC_REPLACE")
        os.replace(name, str(CONFIG))
        name = None
        directory_fd = os.open("/etc/mail", os.O_RDONLY | os.O_DIRECTORY |
                               getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if name and os.path.lexists(name):
            os.unlink(name)


def file_state_without_backup(path):
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
            st.st_nlink != 1 or st.st_mode & 0o022):
        refuse("UNSAFE_PRIMARY_CONFIG_FILE")
    return st, path.read_bytes()


def restore_from_archive(backup, snapshot_id):
    approved = backup.verify(
        backup.BASE / "sendmail" / snapshot_id, "sendmail", 0)
    if approved["format"] != "v2_package_metadata":
        refuse("SNAPSHOT_FORMAT_NOT_V2")
    manifest_path = backup.BASE / "sendmail" / snapshot_id / "manifest.json"
    manifest = json.loads(backup.stable_file(manifest_path, 0)[1])
    entry = manifest["files"].get("etc/mail/sendmail.cf")
    if not isinstance(entry, dict) or entry.get("uid") != 0:
        refuse("ROOT_CONFIG_NOT_IN_ARCHIVE")
    archive_path = backup.BASE / "sendmail" / snapshot_id / "config.tar.gz"
    with tarfile.open(str(archive_path), "r:gz") as archive:
        member = archive.getmember("etc/mail/sendmail.cf")
        if not member.isreg() or member.size != entry["size"]:
            refuse("UNEXPECTED_ARCHIVE_MEMBER")
        stream = archive.extractfile(member)
        if stream is None:
            refuse("CANNOT_READ_ARCHIVE_MEMBER")
        original = stream.read(member.size + 1)
    if (len(original) != entry["size"] or
            hashlib.sha256(original).hexdigest() != entry["sha256"]):
        refuse("ARCHIVE_MEMBER_DIGEST_MISMATCH")
    return original, entry


def main(snapshot_id):
    verify_disposable()
    backup = load_backup()
    if not backup.ID.fullmatch(snapshot_id):
        refuse("INVALID_BACKUP_ID")
    approved = backup.verify(
        backup.BASE / "sendmail" / snapshot_id, "sendmail", 0)
    if approved["format"] != "v2_package_metadata":
        refuse("WRONG_SNAPSHOT_FORMAT")
    preview = backup.recovery_preview("sendmail", snapshot_id)
    if preview["current"] != "identical":
        refuse("BASELINE_ALREADY_DRIFTED")
    meta, before = file_state(backup)
    target, declared = restore_from_archive(backup, snapshot_id)
    if target != before or (meta.st_uid, meta.st_gid,
                           stat.S_IMODE(meta.st_mode)) != (
                           declared["uid"], declared["gid"], declared["mode"]):
        refuse("ARCHIVE_NOT_EQUAL_TO_INSTALLED_CONFIG")
    try:
        context = os.getxattr(CONFIG, "security.selinux")
    except OSError:
        refuse("SELINUX_CONTEXT_UNREADABLE")
    if not context:
        refuse("SELINUX_CONTEXT_EMPTY")

    altered = False
    try:
        altered = True  # Cover an error that occurs after os.replace().
        atomic_write(before + RESTORE_MARKER, before, meta, context)
        if hashlib.sha256(CONFIG.read_bytes()).hexdigest() == declared["sha256"]:
            refuse("CONTROLLED_EDIT_NOT_DETECTED")
        if backup.recovery_preview("sendmail", snapshot_id)["current"] != "different":
            refuse("ARCHIVE_DRIFT_NOT_DETECTED")
        # All v2 package-owned files, symlinks and directories are unchanged.
        # Only the single controlled root-owned .cf file is restored.
        atomic_write(target, before + RESTORE_MARKER, meta, context)
        final, data = file_state(backup)
        if (data != before or hashlib.sha256(data).hexdigest() != declared["sha256"]
                or os.getxattr(CONFIG, "security.selinux") != context
                or (final.st_uid, final.st_gid, stat.S_IMODE(final.st_mode)) !=
                (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode))):
            refuse("RESTORED_CONFIG_OR_CONTEXT_MISMATCH")
        if backup.recovery_preview("sendmail", snapshot_id)["current"] != "identical":
            refuse("POST_RESTORE_METADATA_DRIFT")
        altered = False  # Only after all hashes, labels and metadata match.
        print("LMR365_SENDMAIL_VM_CONFIG_RESTORE=verified_single_file")
        print("LMR365_SENDMAIL_VM_CONFIG_SELINUX=unchanged")
        print("LMR365_SENDMAIL_VM_SNAPSHOT_DRIFT=detected_then_cleared")
        print("LMR365_SENDMAIL_VM_MAIL_QUEUE_CHANGED=no")
        print("LMR365_SENDMAIL_VM_LIVE_RESTORE_ENABLED=no")
    finally:
        # Even if a simulated edit or validation fails, prefer returning the
        # exact pre-test bytes before the outer VM cleanup restores Postfix.
        if altered:
            try:
                current_meta, current_bytes = file_state_without_backup(CONFIG)
                if current_bytes == before:
                    if (current_meta.st_uid != meta.st_uid or
                            current_meta.st_gid != meta.st_gid or
                            stat.S_IMODE(current_meta.st_mode) !=
                            stat.S_IMODE(meta.st_mode) or
                            os.getxattr(CONFIG, "security.selinux") != context):
                        refuse("RESTORE_METADATA_NOT_RECOVERED")
                elif current_bytes == before + RESTORE_MARKER:
                    atomic_write(before, current_bytes, meta, context)
                    if file_state(backup)[1] != before:
                        refuse("ROLLBACK_BYTES_NOT_RECOVERED")
                else:
                    # Refuse to overwrite any unexpected concurrent content.
                    refuse("UNKNOWN_CHANGE_REQUIRES_MANUAL_RECOVERY")
            except Exception as exc:
                print("LMR365_SENDMAIL_VM_CRITICAL_RECOVERY_CLEANUP_FAILED",
                      type(exc).__name__, file=sys.stderr)
                raise


if __name__ == "__main__":
    if len(sys.argv) != 2:
        refuse("EXPECTED_SNAPSHOT_ID")
    main(sys.argv[1])
