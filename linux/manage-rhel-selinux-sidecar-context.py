#!/usr/bin/env python3
"""Experimental RHEL-family SELinux file-context lifecycle for an isolated Postfix.

ONLY three fixed Postfix-equivalent path prefixes are supported. This command
never installs a mail server, changes an MTA, starts services, opens ports, or
relaxes SELinux. An exact policy SHA and typed confirmation are required for
every mutation. Production sidecar installers remain Enforcing-gated.
Python 3.6+.
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

PATHS = (
    ("/etc/postfix", "/etc/linuxmailrelay365/sidecar-postfix"),
    ("/var/spool/postfix", "/var/spool/linuxmailrelay365-sidecar"),
    ("/var/lib/postfix", "/var/lib/linuxmailrelay365-sidecar"),
)
ROOT = Path("/var/lib/linuxmailrelay365-selinux-context")
ACTIVE = ROOT / "active.json"
LOCK = Path("/run/linuxmailrelay365-selinux-context.lock")
HEX = re.compile(r"[a-f0-9]{64}\Z")
GUIDE = "isolated_postfix_equivalence_only"


class Refused(Exception):
    pass


def report(key, value):
    print("{}={}".format(key, value))


def digest(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def run(argv, timeout=40):
    if not shutil.which(argv[0]):
        raise Refused("missing_tool_" + argv[0])
    try:
        result = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("tool_unavailable_or_timeout")
    if result.returncode:
        raise Refused("command_failed_" + argv[0])
    return result.stdout


def environment():
    if os.geteuid() != 0:
        raise Refused("root_required")
    try:
        release = Path("/etc/os-release").read_text(encoding="utf-8")
        values = dict(re.findall(r'(?m)^([A-Z_]+)=["\x27]?([A-Za-z0-9_. -]+)', release))
        osid = values.get("ID", "").lower()
        major = int(values.get("VERSION_ID", "0").split(".")[0])
        if osid not in ("rhel", "rocky", "almalinux", "ol", "centos") or major not in (8, 9, 10):
            raise Refused("rhel_family_8_9_10_only")
        if osid == "centos" and "Stream" not in release:
            raise Refused("centos_stream_only")
        if Path("/proc/1/comm").read_text(encoding="ascii").strip() != "systemd":
            raise Refused("real_systemd_required")
        if Path("/sys/fs/selinux/enforce").read_text(encoding="ascii").strip() != "1":
            raise Refused("real_kernel_selinux_enforcing_required")
    except (OSError, ValueError):
        raise Refused("kernel_or_os_identity_unavailable")
    if run(["getenforce"]).strip() != "Enforcing":
        raise Refused("selinux_enforcing_required")
    report("RHEL_FCONTEXT_RUNTIME", "real_enforcing_systemd")


def custom_policy():
    return run(["semanage", "fcontext", "-l", "-C"])


def equivalences(raw):
    result = {}
    for line in raw.splitlines():
        match = re.match(r"^\s*(/\S+)\s+=\s+(/\S+)\s*$", line)
        if match:
            result[match.group(1)] = match.group(2)
    return result


def unrelated_digest(raw):
    meaningful = []
    for line in raw.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned == "SELinux Local fcontext Equivalence":
            continue
        if any(cleaned.startswith(dest + " = ") for _, dest in PATHS):
            continue
        meaningful.append(cleaned)
    return digest("\n".join(sorted(meaningful)))


def verify_custom(raw, expected, unrelated):
    if unrelated_digest(raw) != unrelated:
        raise Refused("unrelated_custom_selinux_policy_changed")
    current = equivalences(raw)
    for source, dest in PATHS:
        # Includes regex fcontexts or subpath rules, not just equivalences:
        # an external override must not be adopted as our own.
        mentions = [line.strip() for line in raw.splitlines() if dest in line]
        if dest in expected:
            if mentions != [dest + " = " + source] or current.get(dest) != source:
                raise Refused("managed_equivalence_modified_or_shadowed")
        elif mentions:
            raise Refused("unmanaged_equivalence_or_context_collision")


def safe_parent():
    if ROOT.is_symlink():
        raise Refused("unsafe_journal_root_symlink")
    if ROOT.exists():
        st = ROOT.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            raise Refused("unsafe_journal_root")
    else:
        ROOT.mkdir(parents=True, mode=0o700)
        os.chmod(str(ROOT), 0o700)


def read_journal():
    if not ACTIVE.exists() and not ACTIVE.is_symlink():
        return None
    if ACTIVE.is_symlink():
        raise Refused("unsafe_journal_symlink")
    safe_parent()
    st = ACTIVE.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise Refused("unsafe_journal_permissions")
    try:
        data = json.loads(ACTIVE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Refused("invalid_journal")
    if (data.get("version") != 1 or
            data.get("phase") not in ("applying", "active", "restoring") or
            not isinstance(data.get("before_sha"), str) or
            not HEX.fullmatch(data["before_sha"]) or
            not isinstance(data.get("unrelated_sha"), str) or
            not HEX.fullmatch(data["unrelated_sha"])):
        raise Refused("invalid_journal")
    return data


def write_journal(data):
    safe_parent()
    fd, temp = tempfile.mkstemp(prefix=".fcontext-", dir=str(ROOT))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, str(ACTIVE))
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def acquire_lock():
    fd = os.open(str(LOCK), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        os.close(fd)
        raise Refused("unsafe_operation_lock")
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def checked_tree():
    """Never restorecon recursively through symlinks or unbounded trees."""
    for _, dest in PATHS:
        path = Path(dest)
        if any(parent.is_symlink() for parent in path.parents):
            raise Refused("sidecar_ancestor_symlink_not_allowed")
        if not path.is_dir() or path.is_symlink():
            raise Refused("sidecar_path_missing_or_symlink")
        if path.lstat().st_uid not in (0, _postfix_uid()):
            raise Refused("sidecar_path_untrusted_owner")
        count = 0
        for base, dirs, files in os.walk(str(path), followlinks=False):
            for name in dirs + files:
                child = os.path.join(base, name)
                if stat.S_ISLNK(os.lstat(child).st_mode):
                    raise Refused("sidecar_tree_contains_symlink")
                count += 1
                if count > 10000:
                    raise Refused("sidecar_tree_too_large_for_review")


def _postfix_uid():
    import pwd
    try:
        return pwd.getpwnam("postfix").pw_uid
    except KeyError:
        raise Refused("postfix_service_user_missing")


def check_only():
    environment()
    if read_journal():
        raise Refused("existing_managed_contexts_review_required")
    raw = custom_policy()
    verify_custom(raw, set(), unrelated_digest(raw))
    report("RHEL_FCONTEXT_POLICY_SHA256", digest(raw))
    report("RHEL_FCONTEXT_PREFLIGHT", "ready")
    report("RHEL_FCONTEXT_PATH_SCOPE", GUIDE)
    report("RHEL_FCONTEXT_CHANGES_APPLIED", "no")


def apply(expected):
    environment()
    fd = acquire_lock()
    try:
        if read_journal():
            raise Refused("existing_managed_contexts_review_required")
        before = custom_policy()
        if digest(before) != expected:
            raise Refused("selinux_policy_changed_since_review")
        unrelated = unrelated_digest(before)
        verify_custom(before, set(), unrelated)
        entry = {"version": 1, "phase": "applying",
                 "before_sha": digest(before), "unrelated_sha": unrelated}
        write_journal(entry)  # Durable intent BEFORE the first policy change.
        try:
            for source, dest in PATHS:
                run(["semanage", "fcontext", "-a", "-e", source, dest])
            after = custom_policy()
            verify_custom(after, {dest for _, dest in PATHS}, unrelated)
            entry["phase"] = "active"
            entry["after_sha"] = digest(after)
            write_journal(entry)
        except (Refused, OSError):
            try:
                current = custom_policy()
                verify_custom(current, set(equivalences(current)) &
                              {dest for _, dest in PATHS}, unrelated)
                for source, dest in reversed(PATHS):
                    if equivalences(custom_policy()).get(dest) == source:
                        run(["semanage", "fcontext", "-d", "-e", source, dest])
                if unrelated_digest(custom_policy()) == unrelated and all(
                        dest not in equivalences(custom_policy()) for _, dest in PATHS):
                    ACTIVE.unlink()
                    report("RHEL_FCONTEXT_ROLLBACK", "removed_partial_equivalences")
                else:
                    report("RHEL_FCONTEXT_ROLLBACK", "manual_recovery_required")
            except (Refused, OSError):
                report("RHEL_FCONTEXT_ROLLBACK", "manual_recovery_required")
            raise
        report("RHEL_FCONTEXT_APPLIED", "three_postfix_equivalences")
        report("RHEL_FCONTEXT_POLICY_SHA256", entry["after_sha"])
        report("RHEL_FCONTEXT_SERVICE_STARTED", "no")
        report("RHEL_FCONTEXT_CHANGES_APPLIED", "policy_only")
    finally:
        os.close(fd)


def status():
    environment()
    entry = read_journal()
    raw = custom_policy()
    report("RHEL_FCONTEXT_POLICY_SHA256", digest(raw))
    if not entry:
        report("RHEL_FCONTEXT_MANAGED", "no")
        return
    try:
        present = {dest for _, dest in PATHS if dest in equivalences(raw)}
        verify_custom(raw, present, entry["unrelated_sha"])
        if entry["phase"] == "active" and present == {dest for _, dest in PATHS}:
            report("RHEL_FCONTEXT_MANAGED", "active")
        else:
            report("RHEL_FCONTEXT_MANAGED", "recovery_required")
    except Refused:
        report("RHEL_FCONTEXT_MANAGED", "policy_drift_blocked")
    report("RHEL_FCONTEXT_RESTORE_AVAILABLE", "only_after_sidecar_cleanup")


def relabel():
    environment()
    fd = acquire_lock()
    try:
        entry = read_journal()
        if not entry or entry["phase"] != "active":
            raise Refused("no_complete_managed_contexts")
        before = custom_policy()
        if digest(before) != entry.get("after_sha"):
            raise Refused("selinux_policy_changed_since_apply")
        verify_custom(before, {dest for _, dest in PATHS}, entry["unrelated_sha"])
        unit_stopped()
        checked_tree()
        for _, dest in PATHS:
            run(["restorecon", "-RF", dest])
        if digest(custom_policy()) != digest(before):
            raise Refused("selinux_policy_changed_during_relabel")
        report("RHEL_FCONTEXT_RELABEL", "isolated_paths_only")
        report("RHEL_FCONTEXT_CHANGES_APPLIED", "file_labels_only")
    finally:
        os.close(fd)


def unit_stopped():
    # Never remove the secondary instance's policy while systemd still owns
    # a running or transitioning service. "not-found" is also safe after cleanup.
    if not shutil.which("systemctl"):
        raise Refused("systemctl_required_for_context_restore")
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "linuxmailrelay365-sidecar.service"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("sidecar_systemd_state_unavailable")
    if result.returncode not in (3, 4) or result.stdout.strip() not in (
            "inactive", "failed", "unknown"):
        raise Refused("sidecar_service_must_be_stopped_before_restore")


def restore(expected):
    environment()
    fd = acquire_lock()
    try:
        entry = read_journal()
        if not entry:
            raise Refused("no_managed_contexts")
        raw = custom_policy()
        if digest(raw) != expected:
            raise Refused("selinux_policy_changed_since_restore_review")
        present = {dest for _, dest in PATHS if dest in equivalences(raw)}
        verify_custom(raw, present, entry["unrelated_sha"])
        unit_stopped()
        # Never remove policy while a live Postfix instance could still be
        # using the secondary queue/configuration or listening socket.
        for _, dest in PATHS:
            if os.path.lexists(dest):
                raise Refused("sidecar_paths_must_be_removed_before_restore")
        entry["phase"] = "restoring"
        write_journal(entry)
        for source, dest in reversed(PATHS):
            if dest in present:
                run(["semanage", "fcontext", "-d", "-e", source, dest])
        after = custom_policy()
        verify_custom(after, set(), entry["unrelated_sha"])
        ACTIVE.unlink()
        report("RHEL_FCONTEXT_RESTORE", "managed_equivalences_removed")
        report("RHEL_FCONTEXT_CHANGES_APPLIED", "policy_only")
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-only", action="store_true")
    group.add_argument("--apply", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--relabel", action="store_true")
    group.add_argument("--restore", action="store_true")
    group.add_argument("--self-test", action="store_true")
    parser.add_argument("--expect-policy-sha256", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.self_test:
        report("RHEL_FCONTEXT_PARSER", "ready")
        return 0
    try:
        if args.check_only:
            check_only()
        elif args.status:
            status()
        elif args.apply:
            if not HEX.fullmatch(args.expect_policy_sha256) or \
                    args.confirm != "ADD_REVIEWED_RHEL_SIDECAR_CONTEXTS":
                raise Refused("sha256_review_and_add_confirmation_required")
            apply(args.expect_policy_sha256)
        elif args.relabel:
            if args.confirm != "RELABEL_REVIEWED_RHEL_SIDECAR_PATHS":
                raise Refused("explicit_relabel_confirmation_required")
            relabel()
        elif args.restore:
            if not HEX.fullmatch(args.expect_policy_sha256) or \
                    args.confirm != "REMOVE_REVIEWED_RHEL_SIDECAR_CONTEXTS":
                raise Refused("sha256_review_and_remove_confirmation_required")
            restore(args.expect_policy_sha256)
        return 0
    except (Refused, OSError, ValueError) as exc:
        report("RHEL_FCONTEXT_RESULT", "refused")
        report("RHEL_FCONTEXT_REASON",
               re.sub(r"[^a-z0-9_]", "_", str(exc).lower())[:84])
        return 3


if __name__ == "__main__":
    sys.exit(main())
