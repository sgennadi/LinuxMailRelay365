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
UNITS = {"exim": ("exim4.service", "exim.service"),
         "sendmail": ("sendmail.service",)}
PROCESSES = {"exim": ("exim", "exim4"), "sendmail": ("sendmail",)}


def digest(data):
    return hashlib.sha256(data).hexdigest()


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
    reviewed = []
    changed = 0
    for name in sorted(current):
        metadata, data = backup.stable_file(current[name], uid)
        if metadata.st_mode & 0o7000:
            raise Refused("unsupported_special_file_permissions")
        originals[name] = (metadata, data)
        changed += data != stored[name]
        reviewed.append({"path": name, "sha256": digest(data),
                         "size": len(data), "mode": stat.S_IMODE(metadata.st_mode),
                         "uid": metadata.st_uid, "gid": metadata.st_gid,
                         "device": metadata.st_dev, "inode": metadata.st_ino,
                         "ctime_ns": metadata.st_ctime_ns,
                         "mtime_ns": metadata.st_mtime_ns})
    evidence = {"version": 1, "mta": mta, "snapshot": snapshot_id,
                "snapshot_sha256": info["sha256"], "current": reviewed}
    approved_sha = digest(json.dumps(
        evidence, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return {"sha": approved_sha, "changed": changed, "files": len(reviewed),
            "original": originals, "target": stored}


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


def replace_one(path, content, metadata, uid, original_inode=True):
    """Atomic single-file replacement, preserving ownership/mode/SELinux."""
    backup.safe_regular(path, uid)
    if metadata.st_mode & 0o7000:
        raise Refused("unsupported_special_file_permissions")
    handle, temporary = tempfile.mkstemp(prefix=".lmr365-restore-",
                                         dir=str(path.parent))
    try:
        current = os.fstat(handle)
        if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
            os.fchown(handle, metadata.st_uid, metadata.st_gid)
        os.fchmod(handle, stat.S_IMODE(metadata.st_mode))
        attrs = os.listxattr(str(path), follow_symlinks=False)
        if any(name != "security.selinux" for name in attrs):
            raise Refused("file_extended_attributes_unsupported")
        if "security.selinux" in attrs:
            value = os.getxattr(str(path), "security.selinux",
                                follow_symlinks=False)
            os.setxattr(temporary, "security.selinux", value)
        if any(name != "security.selinux" for name in os.listxattr(temporary)):
            raise Refused("temporary_file_inherited_unsupported_acl")
        with os.fdopen(handle, "wb", closefd=False) as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.close(handle)
        handle = -1
        new_meta, _ = backup.stable_file(path, uid)
        if original_inode and (new_meta.st_dev, new_meta.st_ino,
                               new_meta.st_ctime_ns, new_meta.st_mtime_ns) != (
                                   metadata.st_dev, metadata.st_ino,
                                   metadata.st_ctime_ns, metadata.st_mtime_ns):
            raise Refused("config_changed_before_atomic_replace")
        os.replace(temporary, str(path))
        check, data = backup.stable_file(path, uid)
        if (data != content or check.st_uid != metadata.st_uid or
                check.st_gid != metadata.st_gid or
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
                now, current_data = backup.stable_file(root / name, uid)
                if (current_data != original_data or
                        now.st_dev != original_meta.st_dev or
                        now.st_ino != original_meta.st_ino or
                        now.st_mtime_ns != original_meta.st_mtime_ns or
                        now.st_ctime_ns != original_meta.st_ctime_ns):
                    raise Refused("configuration_changed_during_restore")
                changed.append(name)
                replace_one(root / name, wanted, original_meta, uid)
            if not offline_check(mta):
                raise Refused("primary_mta_restarted_after_restore")
            require_offline_preflight(mta, snapshot_id, root, base, uid,
                                      preflight_check)
            for name in sorted(state["target"]):
                metadata, observed = backup.stable_file(root / name, uid)
                original_meta = state["original"][name][0]
                if (observed != state["target"][name] or
                        metadata.st_uid != original_meta.st_uid or
                        metadata.st_gid != original_meta.st_gid or
                        stat.S_IMODE(metadata.st_mode) !=
                        stat.S_IMODE(original_meta.st_mode)):
                    raise Refused("post_restore_content_or_metadata_mismatch")
            checker = native_static_config_check if static_check is None else static_check
            if checker(mta, root, uid) is not True:
                raise Refused("native_mta_static_configuration_unverified")
        except Exception:
            safe_rollback = True
            for name in reversed(changed):
                original_meta, original_data = state["original"][name]
                try:
                    if not offline_check(mta):
                        raise Refused("primary_mta_restarted_before_rollback")
                    _, observed = backup.stable_file(root / name, uid)
                    if observed not in (original_data, state["target"][name]):
                        raise Refused("concurrent_edit_prevents_rollback")
                    if observed != original_data:
                        replace_one(root / name, original_data, original_meta,
                                    uid, original_inode=False)
                except Exception:
                    safe_rollback = False
            if safe_rollback:
                for name, (prior_meta, prior_data) in state["original"].items():
                    try:
                        now_meta, now_data = backup.stable_file(root / name, uid)
                        if (now_data != prior_data or
                                now_meta.st_uid != prior_meta.st_uid or
                                now_meta.st_gid != prior_meta.st_gid or
                                stat.S_IMODE(now_meta.st_mode) !=
                                stat.S_IMODE(prior_meta.st_mode)):
                            safe_rollback = False
                            break
                    except Exception:
                        safe_rollback = False
                        break
            raise Refused("restore_failed_rollback_" +
                          ("verified" if safe_rollback
                           else "incomplete_use_safety_backup"))
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
    parser.add_argument("--approve-sha256", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("FOREIGN_RESTORE_STATUS=root_required", file=sys.stderr)
        return 2
    try:
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
