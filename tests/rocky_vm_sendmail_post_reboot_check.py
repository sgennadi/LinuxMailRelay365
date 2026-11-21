#!/usr/bin/env python3
"""Read-only boot-continuity evidence for disposable Rocky Sendmail v2 recovery.

Called twice by the KVM harness: just after restoring the original primary
Postfix and after a REAL guest reboot. No test email, no configuration edits,
no service restart and no Microsoft 365 access. Both reports must be identical.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import socket
import stat
import subprocess

INSTALL = Path(__file__).resolve().parent
ID_FILE = INSTALL / "sendmail-v2-kvm-snapshot-id"
BACKUP = INSTALL / "foreign-mta-config-backup.py"
CONFIG = Path("/etc/mail/sendmail.cf")


def refuse(reason):
    raise RuntimeError("LMR365_VM_REBOOT_" + reason)


def verify_guest():
    if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        refuse("ROOT_DISPOSABLE_CI_REQUIRED")
    lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    values = {}
    for line in lines:
        if line.startswith(("ID=", "VERSION_ID=")):
            key, val = line.split("=", 1)
            if key in values:
                refuse("AMBIGUOUS_OS_RELEASE")
            values[key] = val.strip().strip('"').strip("'")
    if values.get("ID") != "rocky" or values.get("VERSION_ID") != "9.9":
        refuse("UNEXPECTED_OS")
    if (Path("/proc/1/comm").read_text().strip() != "systemd" or
            socket.gethostname().split(".")[0] != "rocky-selinux-ci" or
            Path("/sys/fs/selinux/enforce").read_text().strip() != "1"):
        refuse("NOT_CI_KVM_SELINUX_ENFORCING")
    for service, expected_active in (
            ("postfix.service", True),
            ("sendmail.service", False),
            ("sm-client.service", False)):
        status = subprocess.run(
            ["systemctl", "is-active", "--quiet", service],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False)
        if (status.returncode == 0) != expected_active:
            refuse("SERVICE_STATE_" + service.replace(".", "_"))
    queue = subprocess.run(
        ["postqueue", "-j"], capture_output=True, check=True, timeout=15)
    if queue.stdout.strip():
        refuse("POSTFIX_QUEUE_NOT_EMPTY")
    for location in (Path("/var/spool/mqueue"), Path("/var/spool/clientmqueue")):
        if location.is_dir() and any(
                p.is_file() and p.name.startswith(("qf", "df", "tf", "xf"))
                for p in location.iterdir()):
            refuse("SENDMAIL_QUEUE_NOT_EMPTY")


def snapshot_id_from_root_file(module):
    s = ID_FILE.lstat()
    if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1 or
            stat.S_IMODE(s.st_mode) != 0o600 or s.st_size > 96):
        refuse("SNAPSHOT_ID_NOT_ROOT_PRIVATE")
    value = ID_FILE.read_text(encoding="ascii").strip()
    if not module.ID.fullmatch(value):
        refuse("SNAPSHOT_ID_INVALID")
    return value


def run():
    verify_guest()
    spec = importlib.util.spec_from_file_location("sendmail_v2_reboot_backup", BACKUP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    snapshot_id = snapshot_id_from_root_file(module)
    accepted = module.verify(module.BASE / "sendmail" / snapshot_id,
                             "sendmail", 0)
    if (accepted["format"] != "v2_package_metadata" or
            module.recovery_preview(
                "sendmail", snapshot_id, root=Path("/"),
                base=module.BASE, owner_uid=0)["current"] != "identical"):
        refuse("SNAPSHOT_DRIFT_OR_INVALID_V2_FORMAT")
    info, content = module.stable_file(CONFIG, 0)
    label = os.getxattr(str(CONFIG), "security.selinux", follow_symlinks=False)
    if not label:
        refuse("MISSING_SELINUX_LABEL")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        refuse("UNSAFE_RESTORED_FILE")
    report = {
        "ARCHIVE_SHA256": accepted["sha256"],
        "CONFIG_SHA256": hashlib.sha256(content).hexdigest(),
        "CONFIG_OWNER_MODE": ("%d_%d_%04o" %
                              (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))),
        "SELINUX_LABEL_SHA256": hashlib.sha256(label).hexdigest(),
        "SNAPSHOT_MATCH": "identical",
        "POSTFIX": "active",
        "SENDMAIL": "stopped",
        "QUEUE": "empty",
        "SELINUX": "enforcing",
        "ACTIVE_CONFIG_CHANGED": "no",
    }
    for key, value in sorted(report.items()):
        print("LMR365_VM_REBOOT_" + key + "=" + value)


if __name__ == "__main__":
    run()
