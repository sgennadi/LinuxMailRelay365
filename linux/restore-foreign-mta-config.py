#!/usr/bin/env python3
"""Guarded offline Exim/Sendmail configuration restore; Python 3.6+.

This tool never stops, starts, restarts or reloads an MTA. It does not modify
mail queues or install packages. Run on a stopped primary MTA, with a verified
root-only snapshot and explicit, fresh SHA256 approval. This cannot replace a
full VM or system backup. Never use on an actively delivering mail host.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import pwd
import grp
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

SOURCE = Path(__file__).with_name("foreign-mta-config-backup.py")
_spec = importlib.util.spec_from_file_location("foreign_mta_backup", str(SOURCE))
backup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(backup)
Refused = backup.Refused
APPROVAL = "RESTORE_STOPPED_FOREIGN_MTA_CONFIG"
LOCK = Path("/run/linuxmailrelay365-foreign-mta-restore.lock")
PENDING = ".native-restore-pending.json"
UNITS = {"exim": ("exim4.service", "exim.service"),
         "sendmail": ("sendmail.service",)}
PROCESSES = {"exim": ("exim", "exim4"), "sendmail": ("sendmail",)}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def metadata_key(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mode, st.st_uid,
            st.st_gid, st.st_nlink, st.st_mtime_ns, st.st_ctime_ns)


def label_from_fd(fd):
    """Only SELinux labels are supported; never silently drop ACLs/xattrs."""
    attrs = os.listxattr(fd)
    if any(name != "security.selinux" for name in attrs):
        raise Refused("file_extended_attributes_unsupported")
    if "security.selinux" not in attrs:
        return None
    value = os.getxattr(fd, "security.selinux")
    if not value or len(value) > 4096:
        raise Refused("invalid_selinux_label")
    return value


def checked_label(path, uid, expected):
    """Bind label reads to the same inode and metadata as the content read."""
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        if metadata_key(os.fstat(fd)) != metadata_key(expected):
            raise Refused("config_changed_before_label_read")
        label = label_from_fd(fd)
        if (metadata_key(os.fstat(fd)) != metadata_key(expected) or
                metadata_key(backup.safe_regular(path, uid)) != metadata_key(expected)):
            raise Refused("config_changed_during_label_read")
        return label
    finally:
        os.close(fd)


def read_restore_file(path, uid):
    metadata, data = backup.stable_file(path, uid)
    return metadata, data, checked_label(path, uid, metadata)


def content_from_snapshot(mta, snapshot_id, base, uid):
    if mta not in backup.ALLOWED or not backup.ID.fullmatch(snapshot_id):
        raise Refused("invalid_snapshot_selection")
    folder = base / mta / snapshot_id
    info = backup.verify(folder, mta, uid)
    manifest = json.loads(backup.stable_file(folder / "manifest.json", uid)[1])
    if manifest["version"] != 1:
        raise Refused("package_snapshot_restore_requires_manual_metadata_review")
    contents = {}
    with tarfile.open(str(folder / "config.tar.gz"), "r:gz") as archive:
        for member in archive:
            name = member.name
            parts = name.split("/")
            if (not member.isfile() or name in contents or
                    any(not p or p in (".", "..") for p in parts) or
                    name not in manifest["files"] or
                    not any(name.startswith(p + "/") or name == p
                            for p in backup.ALLOWED[mta]) or
                    (member.mode & 0o7022)):
                raise Refused("unsafe_snapshot_member")
            stream = archive.extractfile(member)
            if stream is None:
                raise Refused("unreadable_snapshot_member")
            data = stream.read(member.size + 1)
            if (len(data) != member.size or
                    digest(data) != manifest["files"][name]["sha256"]):
                raise Refused("snapshot_member_changed_after_verification")
            contents[name] = data
    if set(contents) != set(manifest["files"]) or len(contents) != info["files"]:
        raise Refused("incomplete_snapshot")
    return info, contents


def preview(mta, snapshot_id, root=backup.ROOT, base=backup.BASE, uid=0):
    info, stored = content_from_snapshot(mta, snapshot_id, base, uid)
    current = backup.selected_files(mta, root, uid)
    # Never delete newly added files or invent a path missing from /etc.
    if set(stored) != set(current):
        raise Refused("restore_file_set_mismatch")
    originals = {}
    labels = {}
    reviewed = []
    changed = 0
    for name in sorted(current):
        metadata, data, label = read_restore_file(current[name], uid)
        if metadata.st_mode & 0o7000:
            raise Refused("unsupported_special_file_permissions")
        originals[name] = (metadata, data)
        labels[name] = label
        changed += data != stored[name]
        reviewed.append({"path": name, "sha256": digest(data),
                         "size": len(data), "mode": stat.S_IMODE(metadata.st_mode),
                         "uid": metadata.st_uid, "gid": metadata.st_gid,
                         "device": metadata.st_dev, "inode": metadata.st_ino,
                         "ctime_ns": metadata.st_ctime_ns,
                         "mtime_ns": metadata.st_mtime_ns,
                         "selinux_label_sha256": None if label is None else digest(label)})
    evidence = {"version": 1, "mta": mta, "snapshot": snapshot_id,
                "snapshot_sha256": info["sha256"], "current": reviewed}
    approved_sha = digest(json.dumps(
        evidence, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return {"sha": approved_sha, "changed": changed, "files": len(reviewed),
            "original": originals, "target": stored, "labels": labels,
            "snapshot_sha256": info["sha256"]}


def stopped(mta):
    """Fresh root-only bounded native-MTA state check; never infer inactivity."""
    if mta not in UNITS:
        raise Refused("unsupported_primary_mta")
    probe = backup.read_only_probe
    state = backup.offline_service_state(mta, probe)
    workers = backup.offline_process_state(mta, probe)
    sockets = backup.offline_listener_state(mta, probe)
    if (state != "stopped_declared" or workers != "none_observed" or
            sockets != "none_observed"):
        raise Refused("primary_mta_not_proven_inactive")
    return True


def trusted_native_tool(mta):
    """Resolve only root-managed native binary paths, never inherited PATH."""
    candidates = {
        "exim": ("/usr/sbin/exim4", "/usr/sbin/exim"),
        "sendmail": ("/usr/sbin/sendmail", "/usr/lib/sendmail",
                     "/usr/libexec/sendmail/sendmail")
    }
    if mta not in candidates:
        raise Refused("unsupported_primary_mta")
    for original in candidates[mta]:
        if not os.path.lexists(original):
            continue
        resolved = os.path.realpath(original)
        trusted_root = (resolved.startswith(
            ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")) or
            resolved in ("/usr/lib/sendmail",
                         "/usr/libexec/sendmail/sendmail"))
        if not trusted_root:
            raise Refused("native_mta_binary_outside_trusted_root")
        native_name = os.path.basename(resolved)
        native_match = (
            native_name in ("exim", "exim4") or
            native_name.startswith("exim4-daemon-")
        ) if mta == "exim" else native_name in (
            "sendmail", "sendmail.sendmail")
        # A system sendmail alternative may resolve to Exim or Postfix.
        # Never trust another MTA's -bt exit code as Sendmail validation.
        if not native_match:
            raise Refused("native_mta_alternative_mismatch")
        metadata = os.stat(resolved)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or
                metadata.st_mode & 0o022 or not metadata.st_mode & 0o111):
            raise Refused("native_mta_binary_not_root_managed")
        return resolved
    raise Refused("native_mta_binary_missing")


def safe_native_sendmail_directory(directory, root, owner_uid=0):
    """Read-only syntax probe honors the native Ubuntu/Debian smmsp layout.

    This is NOT the snapshot-restore trust policy and never permits a write.
    """
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022):
        raise Refused("native_mta_config_directory_untrusted")
    if info.st_uid == owner_uid:
        return True
    # Debian packages can install /etc/mail as smmta:smmta 2755
    # (mail transfer agent), while some installations use smmsp.
    # Validate the actual registered system principal and primary group,
    # never accept an arbitrary numeric UID or nonstandard permissions.
    if owner_uid == 0 and directory == root / "etc" / "mail" and \
            stat.S_IMODE(info.st_mode) == 0o2755:
        for principal in ("smmta", "smmsp"):
            try:
                account = pwd.getpwnam(principal)
            except KeyError:
                continue
            group_ids = {account.pw_gid}
            if principal == "smmta":
                # Debian/Ubuntu package layout is smmta:smmsp 2755.
                try:
                    group_ids.add(grp.getgrnam("smmsp").gr_gid)
                except KeyError:
                    pass
            if info.st_uid == account.pw_uid and info.st_gid in group_ids:
                return True
    raise Refused("native_mta_config_directory_untrusted")


def native_static_config_check(mta, root=backup.ROOT, uid=0,
                               command_runner=None):
    """Test native config parsing only. No daemon, SMTP, queue or shell.

    Exim -bV checks the effective generated config, not necessarily source
    snippets. Sendmail -bt -C checks the selected compiled configuration.
    Both are partial checks, never evidence of working delivery.
    """
    if mta not in UNITS:
        raise Refused("unsupported_primary_mta")
    if command_runner is None:
        def command_runner(args):
            try:
                result = subprocess.run(args, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL,
                                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                             "LC_ALL": "C",
                                             "RES_OPTIONS": "attempts:1 timeout:1"},
                                        timeout=15, check=False)
            except subprocess.TimeoutExpired:
                raise Refused("native_mta_static_parser_timed_out")
            except OSError:
                raise Refused("native_mta_static_parser_unavailable")
            return result.returncode
    tool = trusted_native_tool(mta)
    if mta == "exim":
        queries = [[tool, "-bV"]]
    else:
        queries = []
        # A native syntax probe is intentionally separate from the stricter
        # file-snapshot allowlist; accept only root or packaged smmsp owner.
        for directory in (root / "etc", root / "etc" / "mail"):
            safe_native_sendmail_directory(directory, root, uid)
        for config_name in ("sendmail.cf", "submit.cf"):
            config = root / "etc" / "mail" / config_name
            if config_name == "submit.cf" and not os.path.lexists(str(config)):
                continue
            backup.safe_regular(config, uid)
            queries.append([tool, "-bt", "-C" + str(config)])
    if not queries:
        raise Refused("no_native_configuration_to_validate")
    for args in queries:
        code = command_runner(args)
        if type(code) is not int or code != 0:
            raise Refused("native_mta_static_configuration_invalid_or_unavailable")
    return True

def take_lock(path=LOCK, uid=0):
    backup.safe_dir(path.parent, uid)
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or
                metadata.st_uid != uid or metadata.st_nlink != 1 or
                stat.S_IMODE(metadata.st_mode) != 0o600):
            raise Refused("untrusted_restore_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        os.close(fd)
        raise
    return fd


def replace_one(path, content, metadata, uid, original_inode=True,
                expected_label=None):
    """Atomic single-file replacement, preserving the reviewed SELinux label."""
    current_meta, _, current_label = read_restore_file(path, uid)
    if current_label != expected_label:
        raise Refused("config_selinux_label_changed_before_replace")
    if original_inode and metadata_key(current_meta) != metadata_key(metadata):
        raise Refused("config_changed_before_atomic_replace")
    if metadata.st_mode & 0o7000:
        raise Refused("unsupported_special_file_permissions")
    handle, temporary = tempfile.mkstemp(prefix=".lmr365-restore-",
                                         dir=str(path.parent))
    try:
        current = os.fstat(handle)
        if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
            os.fchown(handle, metadata.st_uid, metadata.st_gid)
        os.fchmod(handle, stat.S_IMODE(metadata.st_mode))
        if expected_label is not None:
            os.setxattr(handle, "security.selinux", expected_label)
        if label_from_fd(handle) != expected_label:
            raise Refused("temporary_file_label_mismatch")
        with os.fdopen(handle, "wb", closefd=False) as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        # Verify the actual temporary inode's label after writing, then
        # reject even equal-content replacements of the live source inode.
        staged_meta = os.fstat(handle)
        if label_from_fd(handle) != expected_label:
            raise Refused("temporary_file_label_changed")
        os.close(handle)
        handle = -1
        new_meta, _, new_label = read_restore_file(path, uid)
        if (metadata_key(new_meta) != metadata_key(current_meta) or
                new_label != expected_label):
            raise Refused("config_changed_before_atomic_replace")
        os.replace(temporary, str(path))
        check, data, label = read_restore_file(path, uid)
        if ((check.st_dev, check.st_ino) != (staged_meta.st_dev, staged_meta.st_ino) or
                data != content or check.st_uid != metadata.st_uid or
                check.st_gid != metadata.st_gid or label != expected_label or
                stat.S_IMODE(check.st_mode) != stat.S_IMODE(metadata.st_mode)):
            raise Refused("restored_file_verification_failed")
        parent = os.open(str(path.parent), os.O_RDONLY |
                         getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if handle >= 0:
            os.close(handle)
        if os.path.lexists(temporary):
            os.unlink(temporary)


def require_offline_preflight(mta, snapshot_id, root, base, uid, inspector=None):
    """A stale GUI preview is not evidence that queues and listeners are safe."""
    check = backup.offline_recovery_preflight if inspector is None else inspector
    proof = check(mta, snapshot_id, root, base, uid)
    if (not isinstance(proof, dict) or proof.get("mta") != mta or
            proof.get("snapshot_id") != snapshot_id):
        raise Refused("offline_preflight_identity_unverified")
    expected = {"service": "stopped_declared", "processes": "none_observed",
                "queue": "empty_reported", "listener": "none_observed"}
    if (proof.get("gate") != "offline_candidate_manual_recovery_only" or
            proof.get("current") not in ("identical", "different") or
            any(proof.get(key) != val for key, val in expected.items())):
        gate = proof.get("gate")
        reason = gate if gate in ("blocked_running", "blocked_nonempty_queue",
                                 "blocked_unverified") else "blocked_unverified"
        raise Refused("offline_preflight_" + reason)
    return proof


def sync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                 getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_pending(base, uid):
    """A global durable marker; corrupt or partial markers block writes too."""
    if base == backup.BASE:
        backup.safe_dir(Path("/var"), uid)
        if not os.path.lexists("/var/backups"):
            return None
        backup.safe_dir(Path("/var/backups"), uid)
    if not os.path.lexists(str(base)):
        return None
    backup.safe_dir(base, uid)
    path = base / PENDING
    if not os.path.lexists(str(path)):
        return None
    backup.safe_regular(path, uid, mode=0o600, maximum=4096)
    metadata, raw = backup.stable_file(path, uid)
    if stat.S_IMODE(metadata.st_mode) != 0o600 or len(raw) > 4096:
        raise Refused("invalid_pending_restore_marker")
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Refused("duplicate_pending_restore_marker_field")
            value[key] = item
        return value
    try:
        record = json.loads(raw.decode("ascii"), object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError):
        raise Refused("invalid_pending_restore_marker")
    expected = {"version", "mta", "target", "safety", "safety_sha256", "plan_sha256"}
    if (not isinstance(record, dict) or type(record.get("version")) is not int or
            record["version"] not in (1, 2)):
        raise Refused("invalid_pending_restore_marker")
    digest_fields = ("safety_sha256", "plan_sha256")
    if record["version"] == 2:
        expected.add("target_sha256")
        digest_fields += ("target_sha256",)
    if (set(record) != expected or
            not isinstance(record["mta"], str) or record["mta"] not in backup.ALLOWED or
            any(not isinstance(record[key], str) or not backup.ID.fullmatch(record[key])
                for key in ("target", "safety")) or
            record["target"] == record["safety"] or
            any(not isinstance(record[key], str) or not backup.SHA.fullmatch(record[key])
                for key in digest_fields)):
        raise Refused("invalid_pending_restore_marker")
    return record


def verify_durable_safety_snapshot(mta, safety_id, state, base, uid):
    """Ensure the safety archive contains the reviewed pre-operation bytes."""
    folder = base / mta / safety_id
    # Backup's file writes are fsynced. Also persist the directory rename
    # and its ancestors before any active configuration can change.
    backup.strict_snapshot_dir(folder, uid)
    for path in (folder, folder.parent, base, base.parent):
        sync_directory(path)
    info = backup.verify(folder, mta, uid)
    manifest = json.loads(backup.stable_file(folder / "manifest.json", uid)[1])
    if (manifest["sha256"] != info["sha256"] or
            set(manifest["files"]) != set(state["original"])):
        raise Refused("safety_snapshot_inventory_mismatch")
    for name, (_, content) in state["original"].items():
        item = manifest["files"][name]
        if item["size"] != len(content) or item["sha256"] != digest(content):
            raise Refused("safety_snapshot_content_mismatch")
    return info["sha256"]


def publish_pending(base, uid, record):
    backup.safe_dir(base, uid)
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")
    # Never replace an existing marker, including a partial one left by
    # SIGKILL or a power loss. A partial marker requires manual review.
    fd = os.open(str(base / PENDING), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    sync_directory(base)
    if read_pending(base, uid) != record:
        raise Refused("pending_restore_marker_verification_failed")


def clear_verified_pending(base, uid, record):
    if read_pending(base, uid) != record:
        raise Refused("pending_restore_marker_changed")
    (base / PENDING).unlink()
    sync_directory(base)


def pending_status(base=backup.BASE, uid=0):
    record = read_pending(base, uid)
    if record is None:
        return None
    evidence = backup.verify(base / record["mta"] / record["safety"],
                             record["mta"], uid)
    if evidence["sha256"] != record["safety_sha256"]:
        raise Refused("pending_restore_safety_snapshot_changed")
    return record


def open_existing_inspection_lock(path, uid):
    """Take a shared lock if it exists, without creating or altering it."""
    backup.safe_dir(path.parent, uid)
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_nlink != 1 or
                stat.S_IMODE(st.st_mode) != 0o600):
            raise Refused("untrusted_restore_lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("restore_in_progress_inspection_refused")
        return fd
    except BaseException:
        os.close(fd)
        raise


def pending_manifest(base, mta, snapshot_id, expected_sha, uid):
    """Read the verified, bounded manifest without exposing its contents."""
    folder = base / mta / snapshot_id
    backup.strict_snapshot_dir(folder, uid)
    before = backup.stable_file(folder / "manifest.json", uid)[1]
    info = backup.verify(folder, mta, uid)
    after = backup.stable_file(folder / "manifest.json", uid)[1]
    if before != after or info["sha256"] != expected_sha:
        raise Refused("pending_restore_snapshot_changed")
    manifest = json.loads(after)
    if manifest["sha256"] != expected_sha or len(manifest["files"]) != info["files"]:
        raise Refused("pending_restore_manifest_mismatch")
    return manifest


def pending_current_evidence(mta, root, uid):
    # The existing strict inventory refuses unsafe objects, symlinks,
    # unknown permissions, and oversized trees; do not guess around refusal.
    files = backup.selected_files(mta, root, uid)
    evidence = {}
    for name in sorted(files):
        metadata, content, label = read_restore_file(files[name], uid)
        evidence[name] = (metadata_key(metadata), digest(content),
                          None if label is None else digest(label))
    return evidence


def inspect_pending(root=backup.ROOT, base=backup.BASE, uid=0, lock_path=LOCK):
    """Read-only byte comparison, not a resume, rollback or start approval."""
    lock = open_existing_inspection_lock(lock_path, uid)
    try:
        record = pending_status(base, uid)
        if record is None:
            return {"status": "clear"}
        report = {"status": "manual_recovery_required", "record": record,
                  "comparison": "unavailable_legacy_target_unbound"}
        if record["version"] == 1:
            # Old markers can still be inspected for the verified safety
            # archive, but cannot prove the approved target's identity.
            if read_pending(base, uid) != record:
                raise Refused("pending_restore_marker_changed")
            return report
        mta = record["mta"]
        safety = pending_manifest(base, mta, record["safety"], record["safety_sha256"], uid)
        target = pending_manifest(base, mta, record["target"], record["target_sha256"], uid)
        if target["version"] != 1 or set(safety["files"]) != set(target["files"]):
            raise Refused("pending_restore_snapshot_file_set_mismatch")
        first = pending_current_evidence(mta, root, uid)
        counts = {"original_only": 0, "target_only": 0, "both": 0,
                  "other": 0, "missing": 0,
                  "extra": len(set(first) - set(target["files"]))}
        for name, item in target["files"].items():
            if name not in first:
                counts["missing"] += 1
                continue
            current_sha = first[name][1]
            original_match = current_sha == safety["files"][name]["sha256"]
            target_match = current_sha == item["sha256"]
            key = ("both" if original_match and target_match else
                   "original_only" if original_match else
                   "target_only" if target_match else "other")
            counts[key] += 1
        # Recheck archives, marker and the current tree. A report is only
        # a sampled comparison; another administrator can still change it.
        if (pending_manifest(base, mta, record["safety"], record["safety_sha256"], uid) != safety or
                pending_manifest(base, mta, record["target"], record["target_sha256"], uid) != target or
                pending_current_evidence(mta, root, uid) != first or
                read_pending(base, uid) != record):
            raise Refused("pending_restore_state_changed_during_inspection")
        report.update({"comparison": "verified_sampled_content_only",
                       "files": len(target["files"]), "counts": counts})
        return report
    finally:
        if lock is not None:
            os.close(lock)


def apply(mta, snapshot_id, approved_sha, confirm,
          root=backup.ROOT, base=backup.BASE, uid=0,
          offline_check=stopped, lock_path=LOCK, preflight_check=None,
          static_check=None):
    if confirm != APPROVAL or not backup.SHA.fullmatch(approved_sha):
        raise Refused("typed_confirmation_and_reviewed_sha_required")
    if not offline_check(mta):
        raise Refused("primary_mta_not_stopped")
    lock_handle = take_lock(lock_path, uid)
    try:
        if read_pending(base, uid) is not None:
            raise Refused("pending_restore_requires_manual_recovery")
        # Backup may read the distro's smmta-owned /etc/mail directory,
        # but automatic Restore must NOT write inside a non-root-owned path.
        # A packaged Sendmail installation therefore remains read-only
        # until explicit real-host ownership and rollback acceptance exists.
        if mta == "sendmail":
            try:
                backup.safe_dir(root / "etc" / "mail", uid)
            except (Refused, OSError):
                raise Refused("sendmail_nonroot_config_directory_restore_not_approved")
        require_offline_preflight(mta, snapshot_id, root, base, uid,
                                  preflight_check)
        state = preview(mta, snapshot_id, root, base, uid)
        if state["sha"] != approved_sha:
            raise Refused("restore_plan_changed_reapprove")
        if not offline_check(mta):
            raise Refused("primary_mta_restarted")
        safety_id, _ = backup.backup(mta, root, base, uid)
        # Print the pre-operation recovery point before the first write.
        print("FOREIGN_RESTORE_SAFETY_BACKUP_ID=" + safety_id, flush=True)
        if preview(mta, snapshot_id, root, base, uid)["sha"] != approved_sha:
            raise Refused("configuration_changed_during_safety_backup")
        require_offline_preflight(mta, snapshot_id, root, base, uid,
                                  preflight_check)
        safety_sha = verify_durable_safety_snapshot(mta, safety_id, state, base, uid)
        if preview(mta, snapshot_id, root, base, uid)["sha"] != approved_sha:
            raise Refused("configuration_changed_before_pending_restore")
        record = {"version": 2, "mta": mta, "target": snapshot_id,
                  "safety": safety_id, "safety_sha256": safety_sha,
                  "target_sha256": state["snapshot_sha256"],
                  "plan_sha256": approved_sha}
        publish_pending(base, uid, record)
        changed = []
        try:
            for name in sorted(state["original"]):
                original_meta, original_data = state["original"][name]
                wanted = state["target"][name]
                if wanted == original_data:
                    continue
                if not offline_check(mta):
                    raise Refused("primary_mta_restarted_during_restore")
                if len(changed) and len(changed) % 16 == 0:
                    require_offline_preflight(mta, snapshot_id, root, base, uid,
                                              preflight_check)
                now, current_data, label = read_restore_file(root / name, uid)
                if (label != state["labels"][name] or current_data != original_data or
                        now.st_dev != original_meta.st_dev or
                        now.st_ino != original_meta.st_ino or
                        now.st_mtime_ns != original_meta.st_mtime_ns or
                        now.st_ctime_ns != original_meta.st_ctime_ns):
                    raise Refused("configuration_changed_during_restore")
                changed.append(name)
                replace_one(root / name, wanted, original_meta, uid,
                            expected_label=state["labels"][name])
            if not offline_check(mta):
                raise Refused("primary_mta_restarted_after_restore")
            require_offline_preflight(mta, snapshot_id, root, base, uid,
                                      preflight_check)
            def verify_restored_files():
                current_files = backup.selected_files(mta, root, uid)
                if set(current_files) != set(state["target"]):
                    raise Refused("post_restore_file_set_mismatch")
                for name in sorted(state["target"]):
                    metadata, observed, label = read_restore_file(root / name, uid)
                    original_meta = state["original"][name][0]
                    if (observed != state["target"][name] or
                            label != state["labels"][name] or
                            metadata.st_uid != original_meta.st_uid or
                            metadata.st_gid != original_meta.st_gid or
                            stat.S_IMODE(metadata.st_mode) !=
                            stat.S_IMODE(original_meta.st_mode)):
                        raise Refused("post_restore_content_or_metadata_mismatch")

            verify_restored_files()
            checker = native_static_config_check if static_check is None else static_check
            if checker(mta, root, uid) is not True:
                raise Refused("native_mta_static_configuration_unverified")
            # A parser pass is not proof that the MTA remained stopped or
            # that a concurrent edit did not invalidate the restored tree.
            if not offline_check(mta):
                raise Refused("primary_mta_restarted_during_static_check")
            require_offline_preflight(mta, snapshot_id, root, base, uid,
                                      preflight_check)
            verify_restored_files()
        except Exception:
            safe_rollback = True
            for name in reversed(changed):
                original_meta, original_data = state["original"][name]
                try:
                    if not offline_check(mta):
                        raise Refused("primary_mta_restarted_before_rollback")
                    observed_meta, observed, label = read_restore_file(root / name, uid)
                    if (label != state["labels"][name] or
                            observed_meta.st_uid != original_meta.st_uid or
                            observed_meta.st_gid != original_meta.st_gid or
                            stat.S_IMODE(observed_meta.st_mode) != stat.S_IMODE(original_meta.st_mode) or
                            observed not in (original_data, state["target"][name])):
                        raise Refused("concurrent_edit_prevents_rollback")
                    if observed != original_data:
                        replace_one(root / name, original_data, original_meta,
                                    uid, original_inode=False,
                                    expected_label=state["labels"][name])
                except Exception:
                    safe_rollback = False
            if safe_rollback:
                try:
                    safe_rollback = set(backup.selected_files(mta, root, uid)) == set(state["original"])
                except Exception:
                    safe_rollback = False
            if safe_rollback:
                for name, (prior_meta, prior_data) in state["original"].items():
                    try:
                        now_meta, now_data, label = read_restore_file(root / name, uid)
                        if (label != state["labels"][name] or now_data != prior_data or
                                now_meta.st_uid != prior_meta.st_uid or
                                now_meta.st_gid != prior_meta.st_gid or
                                stat.S_IMODE(now_meta.st_mode) !=
                                stat.S_IMODE(prior_meta.st_mode)):
                            safe_rollback = False
                            break
                    except Exception:
                        safe_rollback = False
                        break
            if safe_rollback:
                clear_verified_pending(base, uid, record)
            # Incomplete rollback and abrupt interruption retain the marker.
            raise Refused("restore_failed_rollback_" +
                          ("verified" if safe_rollback
                           else "incomplete_use_safety_backup"))
        clear_verified_pending(base, uid, record)
        return {"changed": len(changed), "safety_id": safety_id,
                "static_config": "passed_partial_parse_only"}
    finally:
        os.close(lock_handle)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mta", required=True, choices=("exim", "sendmail"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", metavar="SNAPSHOT_ID")
    group.add_argument("--apply", metavar="SNAPSHOT_ID")
    group.add_argument("--static-check", action="store_true")
    group.add_argument("--pending-status", action="store_true")
    group.add_argument("--pending-inspect", action="store_true")
    parser.add_argument("--approve-sha256", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("FOREIGN_RESTORE_STATUS=root_required", file=sys.stderr)
        return 2
    try:
        if args.pending_inspect:
            if args.approve_sha256 or args.confirm:
                raise Refused("approval_not_permitted_during_pending_inspection")
            report = inspect_pending()
            print("FOREIGN_PENDING_INSPECT_VERSION=1")
            print("FOREIGN_PENDING_INSPECT_STATUS=" + report["status"])
            if report["status"] != "clear":
                record = report["record"]
                print("FOREIGN_PENDING_INSPECT_MTA=" + record["mta"])
                print("FOREIGN_PENDING_INSPECT_SAFETY_ID=" + record["safety"])
                print("FOREIGN_PENDING_INSPECT_TARGET_ID=" + record["target"])
                print("FOREIGN_PENDING_INSPECT_SAFETY_SHA256=" + record["safety_sha256"])
                print("FOREIGN_PENDING_INSPECT_COMPARISON=" + report["comparison"])
                if "counts" in report:
                    print("FOREIGN_PENDING_INSPECT_TARGET_SHA256=" + record["target_sha256"])
                    print("FOREIGN_PENDING_INSPECT_FILE_COUNT=" + str(report["files"]))
                    for key, value in sorted(report["counts"].items()):
                        print("FOREIGN_PENDING_INSPECT_" + key.upper() + "=" + str(value))
            print("FOREIGN_PENDING_INSPECT_CONFIG_CHANGED=no")
            print("FOREIGN_PENDING_INSPECT_QUEUE_CHANGED=no")
            print("FOREIGN_PENDING_INSPECT_SERVICE_CHANGED=no")
            print("FOREIGN_PENDING_INSPECT_RESUME_AUTHORIZED=no")
            return 0
        if args.pending_status:
            if args.approve_sha256 or args.confirm:
                raise Refused("approval_not_permitted_during_pending_status")
            record = pending_status()
            print("FOREIGN_PENDING_VERSION=1")
            print("FOREIGN_PENDING_STATUS=" +
                  ("clear" if record is None else "manual_recovery_required"))
            if record is not None:
                for key in ("mta", "target", "safety", "safety_sha256", "plan_sha256"):
                    print("FOREIGN_PENDING_" + key.upper() + "=" + record[key])
                if record["version"] == 2:
                    print("FOREIGN_PENDING_TARGET_SHA256=" + record["target_sha256"])
            print("FOREIGN_PENDING_CONFIG_CHANGED=no")
            print("FOREIGN_PENDING_QUEUE_CHANGED=no")
            print("FOREIGN_PENDING_SERVICE_CHANGED=no")
            return 0
        if args.static_check:
            # This operation does not use a backup, change a configuration,
            # inspect mail contents, or authorize a Restore.
            if args.approve_sha256 or args.confirm:
                raise Refused("approval_not_permitted_during_static_check")
            # Static inspection does not require archive-only permissions.
            native_static_config_check(args.mta)
            print("FOREIGN_STATIC_VERSION=1")
            print("FOREIGN_STATIC_MTA=" + args.mta)
            print("FOREIGN_STATIC_CHECK=passed_partial_parse_only")
            print("FOREIGN_STATIC_CONFIG_CHANGED=no")
            print("FOREIGN_STATIC_QUEUE_CHANGED=no")
            print("FOREIGN_STATIC_SERVICE_CHANGED=no")
            print("FOREIGN_STATIC_DELIVERY_VERIFIED=no")
            return 0
        snapshot_id = args.plan or args.apply
        if args.plan:
            if args.approve_sha256 or args.confirm:
                raise Refused("approval_not_permitted_during_preview")
            review = preview(args.mta, snapshot_id)
            print("FOREIGN_RESTORE_PLAN_VERSION=1")
            print("FOREIGN_RESTORE_PLAN_MTA=" + args.mta)
            print("FOREIGN_RESTORE_PLAN_SNAPSHOT=" + snapshot_id)
            print("FOREIGN_RESTORE_PLAN_CONFIG_CHANGED=no")
            print("FOREIGN_RESTORE_PLAN_SHA256=" + review["sha"])
            print("FOREIGN_RESTORE_CHANGED_FILES=" + str(review["changed"]))
            print("FOREIGN_RESTORE_FILE_COUNT=" + str(review["files"]))
            gate = backup.offline_recovery_preflight(args.mta, snapshot_id)
            for key in ("service", "processes", "queue", "listener", "gate"):
                print("FOREIGN_RESTORE_PREFLIGHT_" + key.upper() + "=" + gate[key])
            print("FOREIGN_RESTORE_STATUS=preview_only")
        else:
            result = apply(args.mta, snapshot_id,
                           args.approve_sha256, args.confirm)
            print("FOREIGN_RESTORE_CHANGED_FILES=" + str(result["changed"]))
            print("FOREIGN_RESTORE_NATIVE_STATIC_CHECK=" + result["static_config"])
            print("FOREIGN_RESTORE_STATUS=config_replaced_service_not_started")
        print("FOREIGN_RESTORE_QUEUE_CHANGED=no")
        print("FOREIGN_RESTORE_SERVICE_CHANGED=no")
        return 0
    except (Refused, OSError, ValueError, tarfile.TarError,
            subprocess.TimeoutExpired) as exc:
        message = str(exc) if isinstance(exc, Refused) else "system_failure"
        print("FOREIGN_RESTORE_STATUS=refused_or_failed:" + message,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
