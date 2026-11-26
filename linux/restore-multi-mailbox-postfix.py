#!/usr/bin/env python3
"""Preview/restore ONLY an owned, offline multi-mailbox Postfix sidecar route.

Python 3.6+. No daemon stop/start/reload, no mail or queue mutation, no cloud
calls, and no primary /etc/postfix writes. An active marker recorded by the
companion offline installer and an exact verified pre-install backup are
mandatory. A successful restore quarantines runtime artifacts (never deletes
the source backup) and leaves the sidecar STOPPED for manual inspection.
"""
import argparse
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

INSTALL = Path(__file__).with_name("manage-multi-mailbox-postfix.py")
_spec = importlib.util.spec_from_file_location("multi_mailbox_install_guard", str(INSTALL))
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)
Refused = install.Refused
BACKUP_ID = re.compile(r"\Apre-multi-[A-Za-z0-9_-]{8}\Z")
CONFIRM = "RESTORE_MULTI_MAILBOX_OFFLINE"
PROOF = Path("/etc/linuxmailrelay365/oauth-ingress-proof.json")
# Route Restore must NOT strand any root-owned proof-renewal timer.
TIMER_ARTIFACTS = (
    Path("/etc/systemd/system/linuxmailrelay365-multi-proof.service"),
    Path("/etc/systemd/system/linuxmailrelay365-multi-proof.timer"),
    Path("/var/lib/linuxmailrelay365-multi-proof-timer"),
)
SAFETY_PREFIX = "pre-restore-"


def json_unique(pairs):
    parsed = {}
    for key, value in pairs:
        if key in parsed:
            raise Refused("duplicate_restore_record_key")
        parsed[key] = value
    return parsed


def load_record(raw):
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=json_unique)
    except (UnicodeError, ValueError, TypeError):
        raise Refused("invalid_restore_record")
    if not isinstance(value, dict):
        raise Refused("invalid_restore_record")
    return value


def file_evidence(meta, raw):
    return {
        "sha256": install.digest(raw),
        "size": meta.st_size,
        "inode": meta.st_ino,
        "device": meta.st_dev,
        "mode": stat.S_IMODE(meta.st_mode),
        "uid": meta.st_uid,
        "gid": meta.st_gid,
        "ctime_ns": meta.st_ctime_ns,
        "mtime_ns": meta.st_mtime_ns,
    }


def fixed_sha(value):
    return isinstance(value, str) and bool(install.SHA.fullmatch(value))


def checked_record():
    if os.geteuid() != 0:
        raise Refused("root_required")
    install.secure_dir(install.RECOVERY)
    info, raw = install.read(install.ACTIVE, 4096, (0o600,))
    record = load_record(raw)
    expected = {"version", "backup_id", "plan_sha256", "before",
                "active", "runtime_map_sha256", "source", "primary"}
    if set(record) != expected or record["version"] != 1 or \
            not isinstance(record["backup_id"], str) or \
            not BACKUP_ID.fullmatch(record["backup_id"]) or \
            not fixed_sha(record["plan_sha256"]) or \
            not fixed_sha(record["runtime_map_sha256"]):
        raise Refused("unknown_or_untrusted_multi_route_marker")
    if (not isinstance(record["before"], dict) or
            not isinstance(record["active"], dict) or
            set(record["before"]) != {"main.cf", "master.cf"} or
            set(record["active"]) != {"main.cf", "master.cf"} or
            not all(fixed_sha(v) for v in record["before"].values()) or
            not all(fixed_sha(v) for v in record["active"].values())):
        raise Refused("invalid_config_sha_in_marker")
    if (not isinstance(record["source"], dict) or
            set(record["source"]) != set(install.FILES) or
            not all(fixed_sha(v) for v in record["source"].values())):
        raise Refused("invalid_runtime_files_in_marker")
    if (not isinstance(record["primary"], list) or len(record["primary"]) != 2 or
            not all(fixed_sha(v) for v in record["primary"])):
        raise Refused("invalid_primary_reference_in_marker")
    backup_dir = install.RECOVERY / record["backup_id"]
    install.secure_dir(backup_dir)
    if stat.S_IMODE(backup_dir.lstat().st_mode) != 0o700:
        raise Refused("recovery_backup_not_private")
    manifest_info, manifest_data = install.read(backup_dir / "manifest.json", 16384, (0o600,))
    manifest = load_record(manifest_data)
    if not isinstance(manifest, dict) or manifest.get("version") != 1 or \
            manifest.get("config") != record["before"] or \
            manifest.get("source") != record["source"] or \
            manifest.get("primary") != record["primary"] or \
            manifest.get("map_sha256") != record["runtime_map_sha256"]:
        raise Refused("recovery_manifest_differs_from_marker")
    manifest_sha = install.digest(json.dumps(
        manifest, sort_keys=True, separators=(",", ":")).encode("ascii"))
    if manifest_sha != record["plan_sha256"]:
        raise Refused("backup_manifest_not_bound_to_reviewed_install")
    original = {}
    for filename in ("main.cf", "master.cf"):
        st, data = install.read(backup_dir / filename, 1048576, (0o600,))
        if install.digest(data) != record["before"][filename]:
            raise Refused("pre_install_backup_changed")
        original[filename] = (st, data)
    return info, raw, record, backup_dir, original


def require_proof_timer_absent():
    if any(path.exists() or path.is_symlink() for path in TIMER_ARTIFACTS):
        raise Refused("multi_ingress_timer_must_be_disabled_before_restore")


def preview():
    require_proof_timer_absent()
    marker_stat, marker_bytes, record, backup_dir, original = checked_record()
    current = {}
    for filename in ("main.cf", "master.cf"):
        st, data = install.read(install.CONF / filename, 1048576)
        if install.digest(data) != record["active"][filename]:
            raise Refused("installed_route_changed_since_approval")
        current[filename] = (st, data)
    primary = []
    for filename in ("main.cf", "master.cf"):
        stat_info, raw = install.read(install.PRIMARY / filename, 1048576)
        primary.append(install.digest(raw))
    if primary != record["primary"]:
        raise Refused("primary_postfix_modified_since_installation")
    gid = grp.getgrnam("m365mailer").gr_gid
    map_stat, map_bytes = install.read(install.RUNTIME, 65536, (0o640,))
    if map_stat.st_gid != gid or install.digest(map_bytes) != record["runtime_map_sha256"]:
        raise Refused("runtime_sender_map_changed")
    install.secure_dir(install.TARGET)
    source = {}
    if {part.name for part in install.TARGET.iterdir()} != set(install.FILES):
        raise Refused("installed_runtime_file_set_changed")
    for name in install.FILES:
        st, data = install.read(install.TARGET / name, 262144, (0o644,))
        if install.digest(data) != record["source"][name]:
            raise Refused("installed_runtime_source_changed")
        source[name] = file_evidence(st, data)
    proof = None
    if PROOF.exists() or PROOF.is_symlink():
        st, data = install.read(PROOF, 2048, (0o640,))
        if st.st_gid != gid:
            raise Refused("privileged_proof_metadata_changed")
        proof = (st, data)
    review = {
        "version": 1, "backup_id": record["backup_id"],
        "active_marker": file_evidence(marker_stat, marker_bytes),
        "original": {name: file_evidence(*original[name])
                     for name in ("main.cf", "master.cf")},
        "current": {name: file_evidence(*current[name])
                    for name in ("main.cf", "master.cf")},
        "source": source,
        "runtime_map": file_evidence(map_stat, map_bytes),
        "proof": file_evidence(*proof) if proof is not None else None,
        "primary": primary,
    }
    policy=install.policy_snapshot(install.route_policy_targets()+
        [(backup_dir,True),(backup_dir/"main.cf",False),(backup_dir/"master.cf",False),
         (backup_dir/"manifest.json",False)]+([(PROOF,False)] if proof is not None else []))
    review.update(install.policy_evidence(policy))
    install.require_policy(policy)
    reviewed_sha = install.digest(json.dumps(
        review, sort_keys=True, separators=(",", ":")).encode("ascii"))
    return {"sha": reviewed_sha, "backup_id": record["backup_id"],
            "record": record, "original": original, "current": current,
            "marker": (marker_stat, marker_bytes), "map": (map_stat, map_bytes),
            "proof": proof, "source": source, "review": review, "policy":policy}


def locked():
    install.secure_dir(install.LOCK.parent)
    descriptor = os.open(str(install.LOCK),
                         os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                         0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise Refused("unsafe_shared_route_lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def write_emergency(view):
    install.secure_dir(install.RECOVERY)
    folder = Path(tempfile.mkdtemp(prefix=SAFETY_PREFIX, dir=str(install.RECOVERY)))
    os.chmod(str(folder), 0o700)
    mode=view["policy"]["mode"]
    install.label_new_directory(folder,folder,mode)
    copies = {name: view["current"][name][1] for name in ("main.cf", "master.cf")}
    copies.update({"installed-marker.json": view["marker"][1],
                   "runtime-map.tsv": view["map"][1]})
    if view["proof"] is not None:
        copies["ingress-proof.json"] = view["proof"][1]
    for name, data in copies.items():
        path = folder / name
        # Keep legacy inactive fixtures and mode behavior; active mode
        # requires exact target policy and readback for each new inode.
        if mode!="inactive":
            install.write_new(path,data,mode)
        else:
            fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
            with os.fdopen(fd,"wb") as writer:
                writer.write(data)
                writer.flush()
                os.fsync(writer.fileno())
        if install.digest(install.read(path,1048576,(0o600,))[1])!=install.digest(data):
            raise Refused("emergency_restore_snapshot_not_verified")
    install.verify_backup(folder,tuple(copies),mode)
    install.sync_dir(folder)
    install.sync_dir(install.RECOVERY)
    return folder


def unchanged(path, reviewed, size=1048576, mode=None):
    modes = (mode,) if mode is not None else (0o600, 0o640, 0o644, 0o755)
    st, raw = install.read(path, size, modes)
    if file_evidence(st, raw) != file_evidence(*reviewed):
        raise Refused("configuration_changed_since_restore_review")
    return st, raw


def apply_offline(reviewed_sha, backup_id, confirm):
    if (not fixed_sha(reviewed_sha) or not isinstance(backup_id, str) or
            not BACKUP_ID.fullmatch(backup_id) or confirm != CONFIRM or
            os.geteuid() != 0):
        raise Refused("restore_sha_backup_id_and_typed_approval_required")
    descriptor = locked()
    state = None
    safety = None
    writes = []
    retired = []
    try:
        state = preview()
        if state["backup_id"] != backup_id or state["sha"] != reviewed_sha:
            raise Refused("restore_review_has_changed_reapprove")
        install.offline()  # unit stopped, queue empty, dedicated port closed
        if preview()["sha"] != reviewed_sha:
            raise Refused("restore_review_changed_while_stopping_sidecar")
        policy=state["policy"]
        install.require_policy(policy)
        # Existing quarantine uses atomic rename. Refuse cross-filesystem
        # restore BEFORE modifying main.cf/master.cf rather than copying live files.
        retirement=[install.RUNTIME,install.TARGET,install.ACTIVE]
        if state["proof"] is not None:
            retirement.append(PROOF)
        device=install.RECOVERY.stat().st_dev
        if any(path.lstat().st_dev!=device for path in retirement):
            raise Refused("quarantine_cross_filesystem_requires_manual_review")
        safety = write_emergency(state)
        print("MULTI_RESTORE_SAFETY_BACKUP=" + str(safety), flush=True)
        # Never modify files without an intact verified rescue snapshot.
        if preview()["sha"] != reviewed_sha:
            raise Refused("restore_review_changed_during_safety_backup")
        for name in ("main.cf", "master.cf"):
            install.offline()
            install.require_policy(policy)
            current = unchanged(install.CONF / name, state["current"][name])
            writes.append(name)  # rollback even if post-write verify fails
            install.replace_file(install.CONF / name, state["original"][name][1], current)
        install.offline()
        install.require_policy(policy)
        install.run(["postfix", "-c", str(install.CONF), "check"])
        install.require_policy(policy)
        for name in ("main.cf", "master.cf"):
            if install.digest(install.read(install.CONF / name, 1048576)[1]) != \
                    state["record"]["before"][name]:
                raise Refused("restored_postfix_hash_mismatch")
        for name in ("main.cf", "master.cf"):
            raw = install.read(install.PRIMARY / name, 1048576)[1]
            if install.digest(raw) != state["record"]["primary"][
                    0 if name == "main.cf" else 1]:
                raise Refused("primary_postfix_changed_during_restore")
        # Quarantine, never unlink, the protected identity map/runtime and
        # expiring proof; a later Stage must not silently inherit old identities.
        retired_paths = [(install.RUNTIME, safety / "retired-runtime-map.tsv",
                          state["map"], 65536, 0o640)]
        if state["proof"] is not None:
            retired_paths.append((PROOF, safety / "retired-ingress-proof.json",
                                  state["proof"], 2048, 0o640))
        for old, new, before, limit, mode in retired_paths:
            install.offline()
            unchanged(old, before, limit, mode)
            install.require_policy(policy)
            if install.present(new):
                raise Refused("quarantine_destination_exists")
            os.rename(str(old), str(new))
            retired.append((old, new))
            if policy["mode"]!="inactive":
                install.verify_label(new,install.reviewed_label(policy,old))
            install.sync_dir(old.parent)
            install.sync_dir(new.parent)
        install.offline()
        install.secure_dir(install.TARGET)
        for name, evidence in state["source"].items():
            actual = install.read(install.TARGET / name, 262144, (0o644,))
            if evidence != file_evidence(*actual):
                raise Refused("installed_runtime_changed_during_retirement")
        install.require_policy(policy)
        kept_code=safety/"retired-runtime-code"
        if install.present(kept_code):
            raise Refused("quarantine_destination_exists")
        os.rename(str(install.TARGET),str(kept_code))
        retired.append((install.TARGET,kept_code))
        if policy["mode"]!="inactive":
            install.verify_label(kept_code,install.reviewed_label(policy,install.TARGET),True)
            for name in install.FILES:
                install.verify_label(kept_code/name,install.reviewed_label(policy,install.TARGET/name))
        install.sync_dir(install.TARGET.parent)
        install.sync_dir(safety)
        install.offline()
        unchanged(install.ACTIVE, state["marker"], 4096, 0o600)
        install.require_policy(policy)
        kept_marker=safety/"retired-active.json"
        if install.present(kept_marker):
            raise Refused("quarantine_destination_exists")
        os.rename(str(install.ACTIVE),str(kept_marker))
        retired.append((install.ACTIVE,kept_marker))
        if policy["mode"]!="inactive":
            install.verify_label(kept_marker,install.reviewed_label(policy,install.ACTIVE))
        install.sync_dir(install.RECOVERY)
        install.sync_dir(safety)
        install.require_policy(policy)
        if any(install.present(path) for path in retirement):
            raise Refused("retirement_readback_failed")
        # The original pre-install backup is retained unchanged, along with
        # a second pre-restore emergency copy of the active configuration.
        return {"backup_id": backup_id, "safety": safety}
    except Exception:
        rollback = "unverified_manual_recovery_required"
        try:
            if writes or retired:
                install.offline()
                install.require_policy(state["policy"])
                for original, kept in reversed(retired):
                    if original.exists() or original.is_symlink() or not kept.exists():
                        raise Refused("rollback_quarantine_target_changed")
                    os.rename(str(kept), str(original))
                for name in reversed(writes):
                    path = install.CONF / name
                    current_stat, current_data = install.read(path, 1048576)
                    before_data = state["current"][name][1]
                    old_data = state["original"][name][1]
                    if current_data not in (before_data, old_data):
                        raise Refused("concurrent_file_change_blocks_rollback")
                    if current_data != before_data:
                        install.replace_file(path, before_data, (current_stat, current_data))
                for name in ("main.cf", "master.cf"):
                    if install.digest(install.read(install.CONF / name, 1048576)[1]) != \
                            state["record"]["active"][name]:
                        raise Refused("rollback_active_configuration_not_verified")
                install.require_policy(state["policy"])
            rollback = "original_active_configuration_verified"
        except Exception:
            pass
        print("MULTI_RESTORE_ROLLBACK=" + rollback, file=sys.stderr)
        raise
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_mutually_exclusive_group(required=True)
    options.add_argument("--preview", action="store_true")
    options.add_argument("--restore-offline", action="store_true")
    parser.add_argument("--backup-id", default="")
    parser.add_argument("--approve-sha256", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    try:
        if args.preview:
            if args.backup_id or args.approve_sha256 or args.confirm:
                raise Refused("preview_has_no_approval_arguments")
            state = preview()
            print("MULTI_RESTORE_BACKUP_ID=" + state["backup_id"])
            print("MULTI_RESTORE_PLAN_SHA256=" + state["sha"])
            print("MULTI_RESTORE_STATUS=preview_only")
        else:
            restored = apply_offline(args.approve_sha256, args.backup_id,
                                     args.confirm)
            print("MULTI_RESTORE_BACKUP_ID=" + restored["backup_id"])
            print("MULTI_RESTORE_STATUS=restored_offline_not_started")
        print("MULTI_RESTORE_MESSAGES_SENT=no")
        print("MULTI_RESTORE_SERVICES_STARTED=no")
        print("MULTI_RESTORE_PRIMARY_POSTFIX_CHANGED=no")
        return 0
    except (Refused, OSError, KeyError, ValueError, TypeError,
            ImportError, TimeoutError) as exc:
        status = str(exc) if isinstance(exc, Refused) else "host_or_restore_error"
        print("MULTI_RESTORE_STATUS=refused:" + status, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
