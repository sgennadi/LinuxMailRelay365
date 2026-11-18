#!/usr/bin/env python3
"""Guarded, reversible SELinux *port-label preparation* for RHEL 8-10 family.

Does not install Postfix/Dovecot, alter file contexts, change booleans, disable
SELinux, open a firewall, or claim the service is verified under Enforcing.
A policy-port label is only ONE prerequisite for separate acceptance tests.
Python 3.6+ compatible.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path("/var/lib/linuxmailrelay365-selinux-port")
ACTIVE = ROOT / "active.json"
LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")
RELEASE = Path("/etc/os-release")
HEX = re.compile(r"[a-f0-9]{64}\Z")


class Refused(Exception):
    pass


def report(key, value):
    print("{}={}".format(key, value))


def run(argv, timeout=35):
    if not shutil.which(argv[0]):
        raise Refused("missing_tool_" + argv[0])
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("tool_unavailable_or_timeout")
    if result.returncode:
        raise Refused("command_failed_" + argv[0])
    return result.stdout


def os_supported(release):
    match = re.search(r'(?m)^ID=(["' + "'" + r']?)([a-z0-9_]+)\1\s*$', release)
    value = match.group(2) if match else ""
    major_match = re.search(r'(?m)^VERSION_ID=["' + "'" + r']?([0-9]+)', release)
    major = int(major_match.group(1)) if major_match else 0
    if value in ("rhel", "ol", "rocky", "almalinux") and major in (8, 9, 10):
        return True
    return (value == "centos" and major in (9, 10) and
            bool(re.search(r"(?im)^NAME=.*stream", release)))


def port_type(port, raw):
    found = set()
    for line in raw.splitlines():
        match = re.match(r"^(\S+)\s+tcp\s+(.+)$", line)
        if not match:
            continue
        for field in re.split(r"[\s,]+", match.group(2)):
            segment = re.fullmatch(r"([0-9]+)(?:-([0-9]+))?", field)
            if segment and int(segment.group(1)) <= port <= int(segment.group(2) or segment.group(1)):
                found.add(match.group(1))
    if found == {"smtp_port_t"}:
        return "smtp_port_t"
    return "other_type" if found else "unmapped"


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def environment():
    if os.geteuid() != 0:
        raise Refused("root_required")
    try:
        if not os_supported(RELEASE.read_text(encoding="utf-8")):
            raise Refused("supported_rhel_family_8_9_10_only")
    except OSError:
        raise Refused("os_release_unavailable")
    mode = run(["getenforce"]).strip().lower()
    if mode not in ("enforcing", "permissive"):
        raise Refused("selinux_must_be_active")
    return mode


def inspect(port):
    raw = run(["semanage", "port", "-l"])
    local = run(["semanage", "port", "-l", "-C"])
    return port_type(port, raw), raw, local


def port_is_busy(port):
    output = run(["ss", "-H", "-ltn", "( sport = :{} )".format(port)])
    return bool(output.strip())


def private_state_dir():
    if ROOT.exists() or ROOT.is_symlink():
        st = ROOT.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            raise Refused("unsafe_selinux_recovery_directory")
    else:
        ROOT.mkdir(parents=True, mode=0o700)
        os.chmod(str(ROOT), 0o700)


def safe_write(path, value):
    private_state_dir()
    fd, name = tempfile.mkstemp(prefix=".selinux.", dir=str(ROOT))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, str(path))
    finally:
        if os.path.exists(name):
            os.unlink(name)


def manifest():
    private_state_dir()
    if not ACTIVE.is_file() or ACTIVE.is_symlink():
        raise Refused("no_managed_selinux_port_mapping")
    st = ACTIVE.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise Refused("unsafe_selinux_port_manifest")
    try:
        data = json.loads(ACTIVE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Refused("invalid_selinux_port_manifest")
    if data.get("version") != 1 or not isinstance(data.get("port"), int):
        raise Refused("invalid_selinux_port_manifest")
    for key in ("before", "after"):
        if not isinstance(data.get(key), str) or not HEX.fullmatch(data[key]):
            raise Refused("invalid_selinux_port_manifest")
    return data


def preflight(args):
    mode = environment()
    current, raw, custom = inspect(args.smtp_port)
    report("RHEL_PORT_SELINUX_MODE", mode)
    report("RHEL_PORT_CUSTOM_SMTP", args.smtp_port)
    report("RHEL_PORT_LABEL", current)
    report("RHEL_PORT_POLICY_SHA256", digest(raw + "\0" + custom))
    if current == "smtp_port_t":
        report("RHEL_PORT_PREFLIGHT", "already_allowed")
    elif current == "other_type":
        raise Refused("port_owned_by_other_selinux_type")
    elif ACTIVE.exists() or ACTIVE.is_symlink():
        raise Refused("existing_managed_port_mapping_review_required")
    else:
        report("RHEL_PORT_PREFLIGHT", "ready")
    report("RHEL_PORT_FILE_CONTEXTS", "not_modified")
    report("RHEL_PORT_ENFORCING_RUNTIME_VERIFIED", "no")
    report("CHANGES_APPLIED", "no")
    return 0


def apply(args):
    mode = environment()
    current, before, original_local = inspect(args.smtp_port)
    if current != "unmapped":
        raise Refused("port_not_unmapped_manual_review_required")
    if ACTIVE.exists() or ACTIVE.is_symlink():
        raise Refused("mapping_already_managed")
    if digest(before + "\0" + original_local) != args.expect_policy_sha256:
        raise Refused("selinux_policy_changed_since_preview")
    if port_is_busy(args.smtp_port):
        raise Refused("smtp_port_in_use")
    private_state_dir()
    changed = False
    try:
        run(["semanage", "port", "-a", "-t", "smtp_port_t", "-p", "tcp", str(args.smtp_port)])
        changed = True
        label, after, after_local = inspect(args.smtp_port)
        if label != "smtp_port_t" or after_local == original_local:
            raise Refused("selinux_new_port_mapping_not_verified")
        safe_write(ACTIVE, {
            "version": 1, "port": args.smtp_port,
            "before": digest(before + "\0" + original_local),
            "after": digest(after + "\0" + after_local)
        })
    except (Refused, OSError):
        if changed:
            try:
                run(["semanage", "port", "-d", "-p", "tcp", str(args.smtp_port)])
                report("RHEL_PORT_ROLLBACK", "removed_new_mapping")
            except Refused:
                report("RHEL_PORT_ROLLBACK", "manual_selinux_recovery_required")
        raise
    report("RHEL_PORT_APPLIED", "smtp_port_t")
    report("RHEL_PORT_CUSTOM_SMTP", args.smtp_port)
    report("RHEL_PORT_ENFORCING_RUNTIME_VERIFIED", "no")
    report("RHEL_PORT_FILE_CONTEXTS", "not_modified")
    report("CHANGES_APPLIED", "selinux_port_label_only")
    return 0


def status(args):
    environment()
    data = manifest()
    if data["port"] != args.smtp_port:
        raise Refused("managed_port_different_from_selected")
    label, raw, custom = inspect(args.smtp_port)
    sha = digest(raw + "\0" + custom)
    if label != "smtp_port_t" or sha != data["after"]:
        raise Refused("managed_selinux_policy_modified")
    report("RHEL_PORT_STATUS", "active")
    report("RHEL_PORT_CURRENT_POLICY_SHA256", sha)
    report("RHEL_PORT_CUSTOM_SMTP", args.smtp_port)
    report("CHANGES_APPLIED", "no")
    return 0


def restore(args):
    environment()
    data = manifest()
    if data["port"] != args.smtp_port:
        raise Refused("managed_port_different_from_selected")
    label, before, local = inspect(args.smtp_port)
    sha = digest(before + "\0" + local)
    if label != "smtp_port_t" or sha != data["after"] or sha != args.expect_policy_sha256:
        raise Refused("managed_selinux_policy_changed_since_preview")
    if port_is_busy(args.smtp_port):
        raise Refused("smtp_port_still_in_use")
    run(["semanage", "port", "-d", "-p", "tcp", str(args.smtp_port)])
    restored_label, after, restored_local = inspect(args.smtp_port)
    if restored_label != "unmapped" or digest(after + "\0" + restored_local) != data["before"]:
        report("RHEL_PORT_RESTORE", "manual_policy_reconciliation_required")
        raise Refused("selinux_port_restore_fingerprint_mismatch")
    safe_write(ROOT / ("restored-{}.json".format(args.smtp_port)), data)
    ACTIVE.unlink()
    report("RHEL_PORT_RESTORED", "yes")
    report("RHEL_PORT_SNAPSHOT_RETAINED", "yes")
    report("RHEL_PORT_ENFORCING_RUNTIME_VERIFIED", "no")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    actions = p.add_mutually_exclusive_group(required=True)
    actions.add_argument("--check-only", action="store_true")
    actions.add_argument("--apply", action="store_true")
    actions.add_argument("--status", action="store_true")
    actions.add_argument("--restore", action="store_true")
    actions.add_argument("--self-test", action="store_true")
    p.add_argument("--smtp-port", type=int, default=2525)
    p.add_argument("--expect-policy-sha256", default="")
    p.add_argument("--confirm", default="")
    a = p.parse_args()
    if a.self_test:
        report("RHEL_PORT_MANAGER_PARSER", "ready")
        return 0
    if not 1024 <= a.smtp_port <= 65535:
        p.error("Custom SMTP port must be 1024-65535")
    if a.apply or a.restore:
        target = "ADD_REVIEWED_RHEL_SMTP_PORT" if a.apply else "REMOVE_MANAGED_RHEL_SMTP_PORT"
        if a.confirm != target or not HEX.fullmatch(a.expect_policy_sha256):
            report("RHEL_PORT_RESULT", "refused")
            report("RHEL_PORT_ERROR", "typed_confirmation_and_reviewed_sha_required")
            return 2
    try:
        if a.check_only:
            return preflight(a)
        if a.status:
            return status(a)
        fd = os.open(str(LOCK), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return restore(a) if a.restore else apply(a)
        finally:
            os.close(fd)
    except (Refused, OSError, ValueError) as error:
        report("RHEL_PORT_RESULT", "refused")
        report("RHEL_PORT_ERROR", re.sub(r"[^a-z0-9_]", "_", str(error).lower())[:80])
        report("CHANGES_APPLIED", "no" if a.check_only or a.status else "unknown_check_host")
        return 2


if __name__ == "__main__":
    sys.exit(main())
