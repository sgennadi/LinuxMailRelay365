#!/usr/bin/env python3
"""Read-only boot-continuity evidence for disposable Rocky Sendmail v2 recovery.

Called twice by the KVM harness: just after restoring the original primary
Postfix and after a REAL guest reboot. No test email, no configuration edits,
no service restart and no Microsoft 365 access. Both reports must be identical.
"""
import hashlib
import importlib.util
import json
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



def fingerprint_package_selinux(manifest, root=Path("/")):
    """Read-only v2 object SELinux fingerprint, including directories and links.

    All filesystem lookups are lstat/lgetxattr (never follow final symlinks).
    The KVM-only caller rechecks the archive inventory and compares this
    fingerprint on both sides of a real reboot. No labels are written.
    """
    files = manifest.get("files")
    objects = manifest.get("objects")
    if (manifest.get("version") != 2 or manifest.get("mta") != "sendmail" or
            not isinstance(files, dict) or not isinstance(objects, dict)):
        refuse("INVALID_PACKAGE_LABEL_MANIFEST")
    names = set(files) | set(objects)
    if (set(files) & set(objects) or
            not 1 <= len(names) <= 4096 or
            not isinstance(objects.get("etc/mail"), dict) or
            objects["etc/mail"].get("kind") != "directory"):
        refuse("INVALID_PACKAGE_LABEL_OBJECT_SET")
    digest = hashlib.sha256()
    for name in sorted(names):
        if not isinstance(name, str):
            refuse("INVALID_PACKAGE_LABEL_PATH")
        parts = name.split("/")
        if (len(name.encode("utf-8")) > 512 or
                any(part in ("", ".", "..") for part in parts) or
                not (name == "etc/mail" or name.startswith("etc/mail/") or
                     name in ("etc/aliases", "etc/aliases.db"))):
            refuse("INVALID_PACKAGE_LABEL_PATH")
        entry = files[name] if name in files else objects[name]
        if not isinstance(entry, dict):
            refuse("INVALID_PACKAGE_LABEL_METADATA")
        kind = "file" if name in files else entry.get("kind")
        if kind not in ("file", "directory", "symlink"):
            refuse("INVALID_PACKAGE_LABEL_KIND")
        path = root.joinpath(*parts)
        # Refuse a symlink in *any* path component, including /etc itself,
        # before observing final-object labels. Never traverse an alias.
        parent = root
        for part in parts[:-1]:
            parent = parent / part
            try:
                parent_st = parent.lstat()
            except OSError:
                refuse("PACKAGE_LABEL_PARENT_UNAVAILABLE")
            if not stat.S_ISDIR(parent_st.st_mode):
                refuse("PACKAGE_LABEL_PARENT_NOT_DIRECTORY")
        try:
            before = path.lstat()
        except OSError:
            refuse("PACKAGE_LABEL_OBJECT_UNAVAILABLE")
        if not (
                (kind == "file" and stat.S_ISREG(before.st_mode) and
                 before.st_nlink == 1) or
                (kind == "directory" and stat.S_ISDIR(before.st_mode)) or
                (kind == "symlink" and stat.S_ISLNK(before.st_mode) and
                 before.st_nlink == 1)):
            refuse("PACKAGE_LABEL_OBJECT_TYPE_CHANGED")
        if (before.st_uid != entry.get("uid") or
                before.st_gid != entry.get("gid") or
                (kind != "symlink" and
                 stat.S_IMODE(before.st_mode) != entry.get("mode"))):
            refuse("PACKAGE_LABEL_OBJECT_METADATA_CHANGED")
        if kind == "symlink":
            try:
                if os.readlink(str(path)) != entry.get("target"):
                    refuse("PACKAGE_LABEL_LINK_CHANGED")
            except OSError:
                refuse("PACKAGE_LABEL_LINK_UNREADABLE")
        try:
            label = os.getxattr(str(path), "security.selinux",
                                follow_symlinks=False)
            after = path.lstat()
        except OSError:
            refuse("PACKAGE_LABEL_UNREADABLE")
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid,
                              s.st_mode, s.st_nlink, s.st_ctime_ns)
        if identity(before) != identity(after):
            refuse("PACKAGE_LABEL_OBJECT_CHANGED_DURING_PROBE")
        if not label or len(label) > 512:
            refuse("PACKAGE_LABEL_EMPTY_OR_OVERSIZED")
        record = b"\0".join((
            name.encode("utf-8"), kind.encode("ascii"),
            str(before.st_uid).encode("ascii"),
            str(before.st_gid).encode("ascii"),
            (str(stat.S_IMODE(before.st_mode)).encode("ascii")
             if kind != "symlink" else b"-"),
            (entry["target"].encode("utf-8") if kind == "symlink" else b"-"),
            label,
        ))
        digest.update(len(record).to_bytes(4, byteorder="big"))
        digest.update(record)
    return len(names), digest.hexdigest()


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
    manifest = json.loads(module.stable_file(
        module.BASE / "sendmail" / snapshot_id / "manifest.json", 0)[1])
    package_objects, package_labels_sha = fingerprint_package_selinux(manifest)
    if module.recovery_preview(
            "sendmail", snapshot_id, root=Path("/"),
            base=module.BASE, owner_uid=0)["current"] != "identical":
        refuse("PACKAGE_LABEL_INVENTORY_CONCURRENT_DRIFT")
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
        "PACKAGE_SELINUX_OBJECTS": str(package_objects),
        "PACKAGE_SELINUX_SHA256": package_labels_sha,
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
