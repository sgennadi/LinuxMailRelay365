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
REVIEW_FILE = "native-restore-review.json"
MAX_REVIEW = 8 * 1024 * 1024
ROLLBACK_APPROVAL = "ROLLBACK_INTERRUPTED_EXIM_CONFIG"
SENDMAIL_V2_APPROVAL = "RESTORE_STOPPED_SENDMAIL_V2_COMPILED_CONFIG"
SENDMAIL_V2_ROLLBACK_APPROVAL = "ROLLBACK_INTERRUPTED_SENDMAIL_V2_CONFIG"
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
            "snapshot_sha256": info["sha256"], "evidence": evidence}


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
            record["version"] not in (1, 2, 3, 4)):
        raise Refused("invalid_pending_restore_marker")
    digest_fields = ("safety_sha256", "plan_sha256")
    if record["version"] >= 2:
        expected.add("target_sha256")
        digest_fields += ("target_sha256",)
    if record["version"] == 4:
        expected.update(("target_manifest_sha256", "safety_manifest_sha256"))
        digest_fields += ("target_manifest_sha256", "safety_manifest_sha256")
        if record.get("mta") != "sendmail":
            raise Refused("invalid_pending_restore_marker")
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


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def read_saved_review(base, uid, record):
    """The exact previously approved review, not reconstructed metadata."""
    folder = base / record["mta"] / record["safety"]
    backup.strict_snapshot_dir(folder, uid)
    path = folder / REVIEW_FILE
    backup.safe_regular(path, uid, mode=0o600, maximum=MAX_REVIEW)
    metadata, raw = backup.stable_file(path, uid)
    if (stat.S_IMODE(metadata.st_mode) != 0o600 or len(raw) > MAX_REVIEW or
            digest(raw) != record["plan_sha256"]):
        raise Refused("saved_restore_review_digest_mismatch")
    try:
        evidence = json.loads(raw.decode("ascii"))
    except (ValueError, UnicodeError):
        raise Refused("invalid_saved_restore_review")
    if record["version"] == 4:
        if (not isinstance(evidence, dict) or canonical_json(evidence) != raw or
                set(evidence) != {"version", "scope", "snapshot", "archive_sha256",
                                  "manifest_sha256", "current", "offline", "gate"} or
                evidence["version"] != 1 or evidence["scope"] != "sendmail_v2_compiled_files_review_only" or
                evidence["snapshot"] != record["target"] or
                evidence["archive_sha256"] != record["target_sha256"] or
                evidence["manifest_sha256"] != record["target_manifest_sha256"] or
                evidence["gate"] != "compiled_files_review_candidate_only" or
                not isinstance(evidence["current"], dict)):
            raise Refused("invalid_saved_sendmail_v2_review")
        return evidence
    if (not isinstance(evidence, dict) or canonical_json(evidence) != raw or
            set(evidence) != {"version", "mta", "snapshot", "snapshot_sha256", "current"} or
            evidence["version"] != 1 or evidence["mta"] != record["mta"] or
            evidence["snapshot"] != record["target"] or
            evidence["snapshot_sha256"] != record["target_sha256"] or
            not isinstance(evidence["current"], list) or
            not 1 <= len(evidence["current"]) <= backup.MAX_FILES):
        raise Refused("invalid_saved_restore_review")
    return evidence


def publish_saved_review(base, uid, record, evidence):
    folder = base / record["mta"] / record["safety"]
    backup.strict_snapshot_dir(folder, uid)
    raw = canonical_json(evidence)
    if len(raw) > MAX_REVIEW or digest(raw) != record["plan_sha256"]:
        raise Refused("saved_restore_review_digest_mismatch")
    fd = os.open(str(folder / REVIEW_FILE), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    sync_directory(folder)
    if canonical_json(read_saved_review(base, uid, record)) != raw:
        raise Refused("saved_restore_review_verification_failed")


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
    if record["version"] == 4:
        sendmail_v2_bound_archives(base, uid, record)
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
        if (target["version"] != (2 if record["version"] == 4 else 1) or
                (record["version"] == 4 and safety["version"] != 2) or
                set(safety["files"]) != set(target["files"])):
            raise Refused("pending_restore_snapshot_file_set_mismatch")
        def inventory():
            if record["version"] == 4:
                return sendmail_v2_current_inventory(root, uid)
            return pending_current_evidence(mta, root, uid)
        first_inventory = inventory()
        first = ({name: (row["identity"], row["sha256"], row["selinux_label_sha256"])
                  for name, row in first_inventory["files"].items()}
                 if record["version"] == 4 else first_inventory)
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
                inventory() != first_inventory or
                read_pending(base, uid) != record):
            raise Refused("pending_restore_state_changed_during_inspection")
        if record["version"] == 4:
            sendmail_v2_bound_archives(base, uid, record)
        report.update({"comparison": "verified_sampled_content_only",
                       "files": len(target["files"]), "counts": counts})
        return report
    finally:
        if lock is not None:
            os.close(lock)


def pending_rollback_state(mta, root, base, uid, offline_check, preflight_check):
    """Only a schema-3 Exim interruption has durable original metadata."""
    record = pending_status(base, uid)
    if (mta != "exim" or record is None or record["version"] != 3 or
            record["mta"] != mta):
        raise Refused("pending_rollback_requires_schema3_exim_review")
    if not offline_check(mta):
        raise Refused("primary_mta_not_stopped")
    require_offline_preflight(mta, record["safety"], root, base, uid,
                              preflight_check)
    safety = pending_manifest(base, mta, record["safety"], record["safety_sha256"], uid)
    target = pending_manifest(base, mta, record["target"], record["target_sha256"], uid)
    reviewed = read_saved_review(base, uid, record)
    if (safety["version"] != 1 or target["version"] != 1 or
            set(safety["files"]) != set(target["files"])):
        raise Refused("pending_rollback_snapshot_file_set_mismatch")
    # Preview against the safety archive obtains the original bytes and
    # a fresh, inode-bound description of the current configuration.
    state = preview(mta, record["safety"], root, base, uid)
    if state["snapshot_sha256"] != record["safety_sha256"]:
        raise Refused("pending_rollback_safety_archive_changed")
    original_rows = {}
    for row in reviewed["current"]:
        if (not isinstance(row, dict) or
                set(row) != {"path", "sha256", "size", "mode", "uid", "gid",
                             "device", "inode", "ctime_ns", "mtime_ns",
                             "selinux_label_sha256"} or
                not isinstance(row["path"], str) or row["path"] in original_rows or
                row["path"] not in safety["files"] or
                type(row["uid"]) is not int or row["uid"] != uid or
                type(row["gid"]) is not int or row["gid"] < 0 or
                type(row["mode"]) is not int or not 0 <= row["mode"] <= 0o777 or
                row["mode"] & 0o022 or
                type(row["size"]) is not int or
                row["size"] != safety["files"][row["path"]]["size"] or
                row["sha256"] != safety["files"][row["path"]]["sha256"] or
                (row["selinux_label_sha256"] is not None and
                 (not isinstance(row["selinux_label_sha256"], str) or
                  not backup.SHA.fullmatch(row["selinux_label_sha256"])))):
            raise Refused("pending_rollback_saved_metadata_invalid")
        original_rows[row["path"]] = row
    if set(original_rows) != set(safety["files"]):
        raise Refused("pending_rollback_saved_inventory_mismatch")
    for row in state["evidence"]["current"]:
        old = original_rows[row["path"]]
        if any(row[key] != old[key] for key in
               ("uid", "gid", "mode", "selinux_label_sha256")):
            raise Refused("pending_rollback_original_metadata_changed")
        if row["sha256"] not in (old["sha256"], target["files"][row["path"]]["sha256"]):
            raise Refused("pending_rollback_foreign_file_content")
    expected_current = {
        name: (metadata_key(metadata), digest(content),
               None if state["labels"][name] is None else digest(state["labels"][name]))
        for name, (metadata, content) in state["original"].items()
    }
    if (pending_manifest(base, mta, record["safety"], record["safety_sha256"], uid) != safety or
            pending_manifest(base, mta, record["target"], record["target_sha256"], uid) != target or
            read_saved_review(base, uid, record) != reviewed or
            pending_current_evidence(mta, root, uid) != expected_current or
            read_pending(base, uid) != record):
        raise Refused("pending_rollback_state_changed_during_review")
    if not offline_check(mta):
        raise Refused("primary_mta_not_stopped")
    require_offline_preflight(mta, record["safety"], root, base, uid,
                              preflight_check)
    approval = digest(canonical_json({"version": 1, "action": "rollback",
                                      "marker": record, "current_sha256": state["sha"]}))
    return {"record": record, "sha": approval, "state": state,
            "changed": state["changed"], "files": state["files"]}


def preview_pending_rollback(mta, root=backup.ROOT, base=backup.BASE, uid=0,
                             offline_check=stopped, lock_path=LOCK,
                             preflight_check=None):
    lock = open_existing_inspection_lock(lock_path, uid)
    try:
        return pending_rollback_state(mta, root, base, uid, offline_check,
                                      preflight_check)
    finally:
        if lock is not None:
            os.close(lock)


def rollback_pending(mta, approved_sha, confirm, root=backup.ROOT,
                     base=backup.BASE, uid=0, offline_check=stopped,
                     lock_path=LOCK, preflight_check=None, static_check=None):
    """Explicitly reviewed Exim byte rollback. An interruption retains the marker."""
    if confirm != ROLLBACK_APPROVAL or not backup.SHA.fullmatch(approved_sha):
        raise Refused("pending_rollback_confirmation_and_sha_required")
    lock = take_lock(lock_path, uid)
    try:
        plan = pending_rollback_state(mta, root, base, uid, offline_check,
                                      preflight_check)
        if plan["sha"] != approved_sha:
            raise Refused("pending_rollback_plan_changed_reapprove")
        record, state = plan["record"], plan["state"]
        changed = 0
        # No new files, deletions, service actions or automatic resume.
        # Both archives and the approved original review remain durable.
        for name, (metadata, content) in sorted(state["original"].items()):
            if content == state["target"][name]:
                continue
            if read_pending(base, uid) != record:
                raise Refused("pending_restore_marker_changed")
            if not offline_check(mta):
                raise Refused("primary_mta_restarted_during_pending_rollback")
            if changed % 16 == 0:
                require_offline_preflight(mta, record["safety"], root, base, uid,
                                          preflight_check)
            now, current, label = read_restore_file(root / name, uid)
            if (metadata_key(now) != metadata_key(metadata) or current != content or
                    label != state["labels"][name]):
                raise Refused("pending_rollback_file_changed_before_replace")
            replace_one(root / name, state["target"][name], metadata, uid,
                        expected_label=label)
            changed += 1
        final = pending_rollback_state(mta, root, base, uid, offline_check,
                                       preflight_check)
        if final["record"] != record or final["changed"] != 0:
            raise Refused("pending_rollback_final_verification_failed")
        checker = native_static_config_check if static_check is None else static_check
        if checker(mta, root, uid) is not True:
            raise Refused("pending_rollback_native_static_check_failed")
        final = pending_rollback_state(mta, root, base, uid, offline_check,
                                       preflight_check)
        if final["record"] != record or final["changed"] != 0:
            raise Refused("pending_rollback_post_parser_verification_failed")
        clear_verified_pending(base, uid, record)
        return {"changed": changed, "safety": record["safety"],
                "target": record["target"], "sha": approved_sha,
                "files": plan["files"]}
    finally:
        # Any error, SIGINT or interruption before verified completion leaves
        # the marker intact. A fresh plan is needed even for remaining files.
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
        record = {"version": 3 if mta == "exim" else 2,
                  "mta": mta, "target": snapshot_id,
                  "safety": safety_id, "safety_sha256": safety_sha,
                  "target_sha256": state["snapshot_sha256"],
                  "plan_sha256": approved_sha}
        if record["version"] == 3:
            publish_saved_review(base, uid, record, state["evidence"])
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
        # Keep the durable marker if recovery evidence is no longer valid.
        if pending_status(base, uid) != record:
            raise Refused("post_restore_pending_evidence_changed")
        if record["version"] == 3:
            read_saved_review(base, uid, record)
        pending_manifest(base, mta, snapshot_id, record["target_sha256"], uid)
        clear_verified_pending(base, uid, record)
        return {"changed": len(changed), "safety_id": safety_id,
                "safety_sha256": safety_sha, "target_sha256": record["target_sha256"],
                "files": state["files"], "plan_sha256": approved_sha,
                "static_config": "passed_partial_parse_only"}
    finally:
        os.close(lock_handle)


SENDMAIL_V2_TARGETS = frozenset(("etc/mail/sendmail.cf", "etc/mail/submit.cf"))


def verified_sendmail_v2_manifest(snapshot_id, base, uid):
    if not isinstance(snapshot_id, str) or not backup.ID.fullmatch(snapshot_id):
        raise Refused("invalid_sendmail_v2_snapshot_id")
    folder = base / "sendmail" / snapshot_id
    backup.safe_dir(base, uid)
    backup.safe_dir(folder.parent, uid)
    backup.strict_snapshot_dir(folder, uid)
    manifest_path = folder / "manifest.json"
    archive_path = folder / "config.tar.gz"
    archive_before = metadata_key(backup.safe_regular(
        archive_path, uid, mode=0o600, maximum=backup.MAX_BYTES + 2 * 1024 * 1024))
    meta, raw = backup.stable_file(manifest_path, uid)
    info = backup.verify(folder, "sendmail", uid)
    after, raw_after = backup.stable_file(manifest_path, uid)
    if (metadata_key(meta) != metadata_key(after) or raw != raw_after or
            metadata_key(backup.safe_regular(
                archive_path, uid, mode=0o600,
                maximum=backup.MAX_BYTES + 2 * 1024 * 1024)) != archive_before):
        raise Refused("sendmail_v2_snapshot_changed")
    if info["format"] != "v2_package_metadata":
        raise Refused("sendmail_v2_snapshot_required")
    manifest = json.loads(raw.decode("utf-8"))
    for name in list(manifest["files"]) + list(manifest["objects"]):
        if ("\\" in name or any(not part or part in (".", "..")
                                 for part in name.split("/"))):
            raise Refused("sendmail_v2_invalid_archive_path")
    return manifest, digest(raw), archive_before


def sendmail_v2_current_inventory(root, uid):
    objects = {}
    paths = backup.selected_files("sendmail", root, uid, objects)
    files = {}
    for name, path in sorted(paths.items()):
        owner = backup.snapshot_file_owner(path, "sendmail", root, uid, True)
        metadata, contents = backup.stable_file(path, owner)
        if metadata_key(path.lstat()) != metadata_key(metadata):
            raise Refused("sendmail_v2_file_changed")
        # Only the two compiled files are candidates for a later scoped
        # restore. Generated databases and other files remain evidence only.
        label = None
        if name in SENDMAIL_V2_TARGETS and owner == uid:
            label = checked_label(path, uid, metadata)
        files[name] = {
            "sha256": digest(contents), "size": len(contents),
            "uid": metadata.st_uid, "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "identity": metadata_key(metadata),
            "selinux_label_sha256": None if label is None else digest(label)
        }
    object_ids = {}
    for name, expected in sorted(objects.items()):
        path = root / name
        before = path.lstat()
        actual = (backup.checked_package_link(path, root, uid)
                  if expected["kind"] == "symlink" else
                  backup.package_directory_metadata(path))
        if actual != expected or metadata_key(path.lstat()) != metadata_key(before):
            raise Refused("sendmail_v2_object_changed")
        object_ids[name] = metadata_key(before)
    return {"files": files, "objects": objects, "object_ids": object_ids,
            "etc_identity": metadata_key(backup.safe_dir(root / "etc", uid))}


def _sendmail_v2_plan(snapshot_id, root, base, uid, preflight_check):
    """Build a fresh exact review while the caller holds the relevant lock."""
    if read_pending(base, uid) is not None:
        raise Refused("pending_restore_requires_manual_recovery")
    manifest, manifest_sha, archive_identity = verified_sendmail_v2_manifest(
        snapshot_id, base, uid)
    current = sendmail_v2_current_inventory(root, uid)
    archived = manifest["files"]
    live = current["files"]
    shared = set(archived) & set(live)
    changed = {name for name in shared if archived[name]["sha256"] != live[name]["sha256"]}
    meta_changed = {name for name in shared if any(
        archived[name][key] != live[name][key] for key in ("uid", "gid", "mode"))}
    old_objects, new_objects = manifest["objects"], current["objects"]
    object_drift = len(set(old_objects) ^ set(new_objects)) + sum(
        old_objects[name] != new_objects[name]
        for name in set(old_objects) & set(new_objects))
    counts = {
        "file_count": len(archived),
        "compiled_targets": len(SENDMAIL_V2_TARGETS & shared),
        "compiled_changed": len(changed & SENDMAIL_V2_TARGETS),
        "other_changed": len(changed - SENDMAIL_V2_TARGETS),
        "missing": len(set(archived) - set(live)),
        "extra": len(set(live) - set(archived)),
        "metadata_changed": len(meta_changed),
        "object_drift": object_drift
    }
    check = backup.offline_recovery_preflight if preflight_check is None else preflight_check
    proof = check("sendmail", snapshot_id, root, base, uid)
    if (not isinstance(proof, dict) or proof.get("mta") != "sendmail" or
            proof.get("snapshot_id") != snapshot_id or
            proof.get("archive_sha256") != manifest["sha256"]):
        raise Refused("sendmail_v2_preflight_identity_unverified")
    allowed = {"service": ("running", "stopped_declared", "unverified"),
               "processes": ("running", "none_observed", "unverified"),
               "queue": ("empty_reported", "nonempty_reported", "unverified"),
               "listener": ("running", "none_observed", "unverified"),
               "gate": ("blocked_running", "blocked_nonempty_queue",
                        "blocked_unverified", "offline_candidate_manual_recovery_only")}
    if any(proof.get(key) not in values for key, values in allowed.items()):
        raise Refused("sendmail_v2_invalid_preflight")
    offline = {key: proof[key] for key in allowed}
    offline_ok = (offline == {"service": "stopped_declared", "processes": "none_observed",
                  "queue": "empty_reported", "listener": "none_observed",
                  "gate": "offline_candidate_manual_recovery_only"} and
                  proof.get("current") in ("identical", "different"))
    if not offline_ok:
        gate = "blocked_offline_preflight"
    elif (counts["compiled_targets"] != 2 or counts["other_changed"] or
          counts["missing"] or counts["extra"] or counts["metadata_changed"] or
          counts["object_drift"]):
        gate = "blocked_inventory_drift"
    elif (new_objects["etc/mail"]["uid"] != uid or any(
            live[name]["uid"] != uid or live[name]["mode"] & 0o7022
            for name in SENDMAIL_V2_TARGETS)):
        gate = "blocked_untrusted_write_scope"
    else:
        gate = "compiled_files_review_candidate_only"
    second = sendmail_v2_current_inventory(root, uid)
    if (second != current or verified_sendmail_v2_manifest(snapshot_id, base, uid) !=
            (manifest, manifest_sha, archive_identity) or read_pending(base, uid) is not None):
        raise Refused("sendmail_v2_state_changed_during_review")
    evidence = {"version": 1, "scope": "sendmail_v2_compiled_files_review_only",
                "snapshot": snapshot_id, "archive_sha256": manifest["sha256"],
                "manifest_sha256": manifest_sha, "current": current,
                "offline": offline, "gate": gate}
    return {"snapshot": snapshot_id, "archive_sha256": manifest["sha256"],
            "manifest_sha256": manifest_sha, "plan_sha256": digest(canonical_json(evidence)),
            "counts": counts, "offline": offline, "gate": gate, "evidence": evidence}


def preview_sendmail_v2(snapshot_id, root=backup.ROOT, base=backup.BASE, uid=0,
                        lock_path=LOCK, preflight_check=None):
    """Read-only review; the report itself never authorizes Apply."""
    lock = open_existing_inspection_lock(lock_path, uid)
    try:
        plan = _sendmail_v2_plan(snapshot_id, root, base, uid, preflight_check)
        plan.pop("evidence")
        return plan
    finally:
        if lock is not None:
            os.close(lock)


def sendmail_v2_manifest_rows(inventory):
    return {name: {key: row[key] for key in ("size", "sha256", "uid", "gid", "mode")}
            for name, row in inventory["files"].items()}


def sendmail_v2_bound_archives(base, uid, record):
    """Bind both raw manifests, not just their compressed file data."""
    reviewed = read_saved_review(base, uid, record)
    safety = verified_sendmail_v2_manifest(record["safety"], base, uid)
    target = verified_sendmail_v2_manifest(record["target"], base, uid)
    for label, item in (("safety", safety), ("target", target)):
        if (item[0]["sha256"] != record[label + "_sha256"] or
                item[1] != record[label + "_manifest_sha256"]):
            raise Refused("sendmail_v2_bound_archive_changed")
    original = reviewed["current"]
    if (set(original) != {"files", "objects", "object_ids", "etc_identity"} or
            not isinstance(original["files"], dict) or not isinstance(original["objects"], dict) or
            not isinstance(original["object_ids"], dict) or
            not SENDMAIL_V2_TARGETS.issubset(original["files"]) or
            set(original["object_ids"]) != set(original["objects"])):
        raise Refused("sendmail_v2_saved_inventory_invalid")
    rows = sendmail_v2_manifest_rows(original)
    if (safety[0]["files"] != rows or safety[0]["objects"] != original["objects"] or
            target[0]["objects"] != original["objects"] or set(target[0]["files"]) != set(rows)):
        raise Refused("sendmail_v2_bound_archive_inventory_mismatch")
    for name, item in rows.items():
        destination = target[0]["files"][name]
        keys = ("uid", "gid", "mode") if name in SENDMAIL_V2_TARGETS else tuple(item)
        if any(item[key] != destination[key] for key in keys):
            raise Refused("sendmail_v2_bound_archive_scope_mismatch")
    return reviewed, safety, target


def sendmail_v2_compiled_bytes(base, uid, snapshot_id, verified):
    """Read two verified regular TAR members as bytes; never extract paths."""
    manifest, _, identity = verified
    result = {}
    path = base / "sendmail" / snapshot_id / "config.tar.gz"
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as stream:
        if metadata_key(os.fstat(stream.fileno())) != identity:
            raise Refused("sendmail_v2_archive_identity_changed")
        with tarfile.open(fileobj=stream, mode="r:gz") as archive:
            for member in archive:
                if member.name not in SENDMAIL_V2_TARGETS:
                    continue
                item = manifest["files"][member.name]
                if (not member.isfile() or member.name in result or member.size != item["size"] or
                        member.size > backup.MAX_SINGLE or
                        (member.uid, member.gid, member.mode) != (item["uid"], item["gid"], item["mode"])):
                    raise Refused("sendmail_v2_unsafe_compiled_member")
                source = archive.extractfile(member)
                if source is None:
                    raise Refused("sendmail_v2_unreadable_compiled_member")
                data = source.read(member.size + 1)
                if len(data) != member.size or digest(data) != item["sha256"]:
                    raise Refused("sendmail_v2_compiled_member_digest_changed")
                result[member.name] = data
        if metadata_key(os.fstat(stream.fileno())) != identity:
            raise Refused("sendmail_v2_archive_identity_changed")
    if set(result) != SENDMAIL_V2_TARGETS:
        raise Refused("sendmail_v2_missing_compiled_members")
    if verified_sendmail_v2_manifest(snapshot_id, base, uid) != verified:
        raise Refused("sendmail_v2_archive_changed_after_read")
    return result


def sendmail_v2_validate_live(current, original, target, uid):
    """Only the two compiled byte streams may differ after the first write."""
    if (current["objects"] != original["objects"] or
            set(current["files"]) != set(original["files"]) or
            set(current["object_ids"]) != set(original["object_ids"]) or
            list(current["etc_identity"]) != list(original["etc_identity"])):
        raise Refused("sendmail_v2_live_inventory_drift")
    for name, now in current["object_ids"].items():
        old = original["object_ids"][name]
        # Atomic replacement necessarily changes the parent directory's
        # size/timestamps. Its device/inode, ownership, mode and link count
        # must remain identical; every other object identity is exact.
        indices = (0, 1, 3, 4, 5, 6) if name == "etc/mail" else tuple(range(9))
        if any(now[i] != old[i] for i in indices):
            raise Refused("sendmail_v2_live_object_identity_drift")
    for name, row in current["files"].items():
        old = original["files"][name]
        if name not in SENDMAIL_V2_TARGETS:
            if canonical_json(row) != canonical_json(old):
                raise Refused("sendmail_v2_unrelated_file_drift")
            continue
        if (row["uid"] != uid or row["mode"] & 0o7022 or
                any(row[key] != old[key] for key in ("uid", "gid", "mode", "selinux_label_sha256")) or
                row["sha256"] not in (old["sha256"], target["files"][name]["sha256"])):
            raise Refused("sendmail_v2_compiled_file_drift")


def sendmail_v2_pending_state(root, base, uid, offline_check, preflight_check):
    record = read_pending(base, uid)
    if record is None or record["version"] != 4 or record["mta"] != "sendmail":
        raise Refused("sendmail_v2_pending_marker_required")
    if not offline_check("sendmail"):
        raise Refused("primary_mta_not_stopped")
    backup.safe_dir(root / "etc", uid)
    backup.safe_dir(root / "etc" / "mail", uid)
    reviewed, safety, target = sendmail_v2_bound_archives(base, uid, record)
    original = reviewed["current"]
    current = sendmail_v2_current_inventory(root, uid)
    sendmail_v2_validate_live(current, original, target[0], uid)
    proof = require_offline_preflight("sendmail", record["safety"], root, base, uid, preflight_check)
    if proof.get("archive_sha256") != record["safety_sha256"]:
        raise Refused("sendmail_v2_offline_archive_identity_changed")
    if (sendmail_v2_current_inventory(root, uid) != current or
            sendmail_v2_bound_archives(base, uid, record) != (reviewed, safety, target) or
            read_pending(base, uid) != record):
        raise Refused("sendmail_v2_pending_state_changed")
    changed = sum(current["files"][name]["sha256"] != original["files"][name]["sha256"]
                  for name in SENDMAIL_V2_TARGETS)
    approval = digest(canonical_json({"version": 1, "scope": "sendmail_v2_rollback",
                                      "marker": record, "current": current}))
    return {"record": record, "current": current, "safety": safety, "target": target,
            "changed": changed, "sha": approval}


def sendmail_v2_finish(root, base, uid, record, direction, approved_current, offline_check,
                       preflight_check, static_check):
    """Recheck full scope before and after parsing; retain marker on any error."""
    count = 0
    initial = sendmail_v2_pending_state(root, base, uid, offline_check, preflight_check)
    if initial["record"] != record or initial["current"] != approved_current:
        raise Refused("sendmail_v2_state_changed_after_approval")
    wanted = sendmail_v2_compiled_bytes(base, uid, record[direction], initial[direction])
    # Every single-file replacement is independently checked against the
    # exact last sampled state. No automatic writes occur on a failure.
    expected = initial["current"]
    for name in sorted(SENDMAIL_V2_TARGETS):
        state = sendmail_v2_pending_state(root, base, uid, offline_check, preflight_check)
        if state["record"] != record or state["current"] != expected:
            raise Refused("sendmail_v2_state_changed_before_replace")
        metadata, data, label = read_restore_file(root / name, uid)
        row = expected["files"][name]
        if (metadata_key(metadata) != row["identity"] or digest(data) != row["sha256"] or
                (None if label is None else digest(label)) != row["selinux_label_sha256"]):
            raise Refused("sendmail_v2_file_changed_before_replace")
        if data == wanted[name]:
            continue
        replace_one(root / name, wanted[name], metadata, uid, expected_label=label)
        count += 1
        next_state = sendmail_v2_pending_state(root, base, uid, offline_check, preflight_check)
        if next_state["record"] != record:
            raise Refused("sendmail_v2_pending_marker_changed")
        now = next_state["current"]
        if (any(now["files"][other] != expected["files"][other]
                for other in expected["files"] if other != name) or
                now["files"][name]["sha256"] != digest(wanted[name])):
            raise Refused("sendmail_v2_unexpected_concurrent_change")
        expected = now

    def verify_final():
        state = sendmail_v2_pending_state(root, base, uid, offline_check, preflight_check)
        if (state["record"] != record or state["current"] != expected or any(
                state["current"]["files"][name]["sha256"] != digest(wanted[name])
                for name in SENDMAIL_V2_TARGETS)):
            raise Refused("sendmail_v2_final_verification_failed")

    verify_final()
    checker = native_static_config_check if static_check is None else static_check
    if checker("sendmail", root, uid) is not True:
        raise Refused("sendmail_v2_native_static_check_failed")
    verify_final()
    clear_verified_pending(base, uid, record)
    return {"changed": count, "record": record}


def apply_sendmail_v2(snapshot_id, approved_sha, confirm, root=backup.ROOT,
                      base=backup.BASE, uid=0, offline_check=stopped,
                      lock_path=LOCK, preflight_check=None, static_check=None):
    """Experimental compiled-config-only Restore. Failures retain recovery evidence."""
    if confirm != SENDMAIL_V2_APPROVAL or not backup.SHA.fullmatch(approved_sha):
        raise Refused("sendmail_v2_confirmation_and_sha_required")
    lock = take_lock(lock_path, uid)
    try:
        plan = _sendmail_v2_plan(snapshot_id, root, base, uid, preflight_check)
        if plan["plan_sha256"] != approved_sha:
            raise Refused("sendmail_v2_plan_changed_reapprove")
        if plan["gate"] != "compiled_files_review_candidate_only" or not plan["counts"]["compiled_changed"]:
            raise Refused("sendmail_v2_plan_not_eligible_for_restore")
        if not offline_check("sendmail"):
            raise Refused("primary_mta_not_stopped")
        backup.safe_dir(root / "etc" / "mail", uid)
        safety_id, _ = backup.backup("sendmail", root, base, uid, package_v2=True)
        safety = verified_sendmail_v2_manifest(safety_id, base, uid)
        original = plan["evidence"]["current"]
        if (safety[0]["files"] != sendmail_v2_manifest_rows(original) or
                safety[0]["objects"] != original["objects"]):
            raise Refused("sendmail_v2_safety_snapshot_mismatch")
        folder = base / "sendmail" / safety_id
        for directory in (folder, folder.parent, base, base.parent):
            sync_directory(directory)
        if _sendmail_v2_plan(snapshot_id, root, base, uid, preflight_check) != plan:
            raise Refused("sendmail_v2_state_changed_during_safety_backup")
        record = {"version": 4, "mta": "sendmail", "target": snapshot_id, "safety": safety_id,
                  "target_sha256": plan["archive_sha256"], "safety_sha256": safety[0]["sha256"],
                  "target_manifest_sha256": plan["manifest_sha256"], "safety_manifest_sha256": safety[1],
                  "plan_sha256": approved_sha}
        publish_saved_review(base, uid, record, plan["evidence"])
        sendmail_v2_bound_archives(base, uid, record)
        if _sendmail_v2_plan(snapshot_id, root, base, uid, preflight_check) != plan:
            raise Refused("sendmail_v2_state_changed_before_pending_marker")
        publish_pending(base, uid, record)
        print("SENDMAIL_V2_RECOVERY_SAFETY_ID=" + safety_id, flush=True)
        return sendmail_v2_finish(root, base, uid, record, "target", original, offline_check,
                                  preflight_check, static_check)
    finally:
        os.close(lock)


def preview_sendmail_v2_rollback(root=backup.ROOT, base=backup.BASE, uid=0,
                                 offline_check=stopped, lock_path=LOCK, preflight_check=None):
    lock = open_existing_inspection_lock(lock_path, uid)
    try:
        return sendmail_v2_pending_state(root, base, uid, offline_check, preflight_check)
    finally:
        if lock is not None:
            os.close(lock)


def rollback_sendmail_v2(approved_sha, confirm, root=backup.ROOT, base=backup.BASE,
                         uid=0, offline_check=stopped, lock_path=LOCK,
                         preflight_check=None, static_check=None):
    if confirm != SENDMAIL_V2_ROLLBACK_APPROVAL or not backup.SHA.fullmatch(approved_sha):
        raise Refused("sendmail_v2_rollback_confirmation_and_sha_required")
    lock = take_lock(lock_path, uid)
    try:
        plan = sendmail_v2_pending_state(root, base, uid, offline_check, preflight_check)
        if plan["sha"] != approved_sha:
            raise Refused("sendmail_v2_rollback_plan_changed_reapprove")
        result = sendmail_v2_finish(root, base, uid, plan["record"], "safety",
                                    plan["current"], offline_check, preflight_check, static_check)
        result["rollback_plan_sha256"] = approved_sha
        return result
    finally:
        os.close(lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mta", required=True, choices=("exim", "sendmail"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", metavar="SNAPSHOT_ID")
    group.add_argument("--sendmail-v2-plan", metavar="SNAPSHOT_ID")
    group.add_argument("--sendmail-v2-apply", metavar="SNAPSHOT_ID")
    group.add_argument("--sendmail-v2-rollback-plan", action="store_true")
    group.add_argument("--sendmail-v2-rollback-apply", action="store_true")
    group.add_argument("--apply", metavar="SNAPSHOT_ID")
    group.add_argument("--static-check", action="store_true")
    group.add_argument("--pending-status", action="store_true")
    group.add_argument("--pending-inspect", action="store_true")
    group.add_argument("--pending-rollback-plan", action="store_true")
    group.add_argument("--pending-rollback-apply", action="store_true")
    parser.add_argument("--approve-sha256", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("FOREIGN_RESTORE_STATUS=root_required", file=sys.stderr)
        return 2
    try:
        if args.sendmail_v2_plan:
            if args.mta != "sendmail" or args.approve_sha256 or args.confirm:
                raise Refused("sendmail_v2_review_only_no_approval")
            plan = preview_sendmail_v2(args.sendmail_v2_plan)
            print("SENDMAIL_V2_PLAN_VERSION=1")
            print("SENDMAIL_V2_PLAN_STATUS=review_only")
            for key in ("snapshot", "archive_sha256", "manifest_sha256", "plan_sha256", "gate"):
                print("SENDMAIL_V2_PLAN_" + key.upper() + "=" + plan[key])
            for key, value in sorted(plan["counts"].items()):
                print("SENDMAIL_V2_PLAN_" + key.upper() + "=" + str(value))
            for key, value in sorted(plan["offline"].items()):
                print("SENDMAIL_V2_PLAN_OFFLINE_" + key.upper() + "=" + value)
            for key in ("CONFIG_CHANGED", "QUEUE_CHANGED", "SERVICE_CHANGED", "APPLY_AUTHORIZED"):
                print("SENDMAIL_V2_PLAN_" + key + "=no")
            return 0
        if args.sendmail_v2_apply or args.sendmail_v2_rollback_plan or args.sendmail_v2_rollback_apply:
            if args.mta != "sendmail":
                raise Refused("sendmail_v2_action_requires_sendmail")
            if args.sendmail_v2_rollback_plan:
                if args.approve_sha256 or args.confirm:
                    raise Refused("approval_not_permitted_during_preview")
                plan = preview_sendmail_v2_rollback()
                record = plan["record"]
                print("SENDMAIL_V2_ROLLBACK_STATUS=review_only")
                print("SENDMAIL_V2_ROLLBACK_PLAN_SHA256=" + plan["sha"])
                print("SENDMAIL_V2_ROLLBACK_CHANGED_FILES=" + str(plan["changed"]))
                print("SENDMAIL_V2_ROLLBACK_CONFIG_CHANGED=no")
            elif args.sendmail_v2_apply:
                result = apply_sendmail_v2(args.sendmail_v2_apply, args.approve_sha256, args.confirm)
                record = result["record"]
                print("SENDMAIL_V2_RECOVERY_STATUS=config_replaced_service_not_started")
                print("SENDMAIL_V2_RECOVERY_CHANGED_FILES=" + str(result["changed"]))
                print("SENDMAIL_V2_RECOVERY_NATIVE_STATIC_CHECK=passed_partial_parse_only")
                print("SENDMAIL_V2_RECOVERY_MARKER_CLEARED=yes")
            else:
                result = rollback_sendmail_v2(args.approve_sha256, args.confirm)
                record = result["record"]
                print("SENDMAIL_V2_RECOVERY_STATUS=original_verified_service_not_started")
                print("SENDMAIL_V2_ROLLBACK_APPROVED_SHA256=" + result["rollback_plan_sha256"])
                print("SENDMAIL_V2_RECOVERY_CHANGED_FILES=" + str(result["changed"]))
                print("SENDMAIL_V2_RECOVERY_NATIVE_STATIC_CHECK=passed_partial_parse_only")
                print("SENDMAIL_V2_RECOVERY_MARKER_CLEARED=yes")
            for key in ("target", "safety", "target_sha256", "safety_sha256",
                        "target_manifest_sha256", "safety_manifest_sha256", "plan_sha256"):
                print("SENDMAIL_V2_EVIDENCE_" + key.upper() + "=" + record[key])
            print("SENDMAIL_V2_QUEUE_CHANGED=no")
            print("SENDMAIL_V2_SERVICE_CHANGED=no")
            return 0
        if args.pending_rollback_plan:
            if args.approve_sha256 or args.confirm:
                raise Refused("approval_not_permitted_during_pending_rollback_plan")
            plan = preview_pending_rollback(args.mta)
            print("FOREIGN_PENDING_ROLLBACK_VERSION=1")
            print("FOREIGN_PENDING_ROLLBACK_MTA=exim")
            print("FOREIGN_PENDING_ROLLBACK_STATUS=preview_only")
            print("FOREIGN_PENDING_ROLLBACK_SAFETY_SHA256=" + plan["record"]["safety_sha256"])
            print("FOREIGN_PENDING_ROLLBACK_TARGET_SHA256=" + plan["record"]["target_sha256"])
            print("FOREIGN_PENDING_ROLLBACK_SAFETY_ID=" + plan["record"]["safety"])
            print("FOREIGN_PENDING_ROLLBACK_TARGET_ID=" + plan["record"]["target"])
            print("FOREIGN_PENDING_ROLLBACK_PLAN_SHA256=" + plan["sha"])
            print("FOREIGN_PENDING_ROLLBACK_CHANGED_FILES=" + str(plan["changed"]))
            print("FOREIGN_PENDING_ROLLBACK_FILE_COUNT=" + str(plan["files"]))
            print("FOREIGN_PENDING_ROLLBACK_CONFIG_CHANGED=no")
            print("FOREIGN_PENDING_ROLLBACK_QUEUE_CHANGED=no")
            print("FOREIGN_PENDING_ROLLBACK_SERVICE_CHANGED=no")
            return 0
        if args.pending_rollback_apply:
            result = rollback_pending(args.mta, args.approve_sha256, args.confirm)
            print("FOREIGN_PENDING_ROLLBACK_VERSION=1")
            print("FOREIGN_PENDING_ROLLBACK_MTA=exim")
            print("FOREIGN_PENDING_ROLLBACK_STATUS=original_verified_service_not_started")
            print("FOREIGN_PENDING_ROLLBACK_SAFETY_ID=" + result["safety"])
            print("FOREIGN_PENDING_ROLLBACK_TARGET_ID=" + result["target"])
            print("FOREIGN_PENDING_ROLLBACK_PLAN_SHA256=" + result["sha"])
            print("FOREIGN_PENDING_ROLLBACK_FILE_COUNT=" + str(result["files"]))
            print("FOREIGN_PENDING_ROLLBACK_CHANGED_FILES=" + str(result["changed"]))
            print("FOREIGN_PENDING_ROLLBACK_MARKER_CLEARED=yes")
            print("FOREIGN_PENDING_ROLLBACK_NATIVE_STATIC_CHECK=passed_partial_parse_only")
            print("FOREIGN_PENDING_ROLLBACK_QUEUE_CHANGED=no")
            print("FOREIGN_PENDING_ROLLBACK_SERVICE_CHANGED=no")
            return 0
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
                if record["version"] >= 2:
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
            print("FOREIGN_RESTORE_PLAN_SNAPSHOT_SHA256=" + review["snapshot_sha256"])
            print("FOREIGN_RESTORE_CHANGED_FILES=" + str(review["changed"]))
            print("FOREIGN_RESTORE_FILE_COUNT=" + str(review["files"]))
            gate = backup.offline_recovery_preflight(args.mta, snapshot_id)
            for key in ("service", "processes", "queue", "listener", "gate"):
                print("FOREIGN_RESTORE_PREFLIGHT_" + key.upper() + "=" + gate[key])
            print("FOREIGN_RESTORE_STATUS=preview_only")
        else:
            result = apply(args.mta, snapshot_id,
                           args.approve_sha256, args.confirm)
            print("FOREIGN_RESTORE_APPLY_VERSION=1")
            print("FOREIGN_RESTORE_APPLY_MTA=" + args.mta)
            print("FOREIGN_RESTORE_APPLY_SNAPSHOT=" + snapshot_id)
            print("FOREIGN_RESTORE_APPLY_PLAN_SHA256=" + result["plan_sha256"])
            print("FOREIGN_RESTORE_APPLY_SNAPSHOT_SHA256=" + result["target_sha256"])
            print("FOREIGN_RESTORE_SAFETY_SHA256=" + result["safety_sha256"])
            print("FOREIGN_RESTORE_FILE_COUNT=" + str(result["files"]))
            print("FOREIGN_RESTORE_MARKER_CLEARED=yes")
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
