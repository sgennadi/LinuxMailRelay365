#!/usr/bin/env python3
"""Private transaction core for future offline Postfix sender activation.

NOT a production CLI. A caller must first prove a stopped primary instance,
empty queue, no concurrent submissions/edits, existing suitable TLS policy,
map precedence and destination reachability. No such proof is inferred here.
All operations use already-open directory descriptors. The mandatory guard
and verification callbacks are injected; there is no permissive default.
"""
import importlib.util
import os
import pathlib
import stat
import uuid

_spec = importlib.util.spec_from_file_location(
    "conditional_stage", str(pathlib.Path(__file__).with_name(
        "stage-conditional-postfix-maps.py")))
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)
Refused = M.Refused
BACKUP_BASE = "linuxmailrelay365-conditional-recovery"
FILES = ("main.before", "master.before", "main.after", "candidate.db")
MANIFEST = "transaction.json"
PARAMETER = "sender_dependent_relayhost_maps"
CONFIRM = "APPLY_STOPPED_POSTFIX_SENDER_MAP"
RESTORE = "RESTORE_STOPPED_POSTFIX_SENDER_MAP"
LIMIT = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise Refused(message)


def checked_name(plan, backend):
    require(type(plan) is str and M.HEX.fullmatch(plan) and
            backend in M.MAP_SUFFIX, "invalid_candidate_identity")
    return "lmr365-conditional-" + plan + "-sender", M.MAP_SUFFIX[backend]


def config_file(fd, name, uid, maximum=LIMIT):
    handle = os.open(name, M.READ_FLAGS, dir_fd=fd)
    with os.fdopen(handle, "rb") as stream:
        a = os.fstat(stream.fileno())
        require(stat.S_ISREG(a.st_mode) and a.st_uid == uid and
                a.st_nlink == 1 and not a.st_mode & 0o7022 and
                0 < a.st_size <= maximum and not os.listxattr(stream.fileno()),
                "untrusted_config_file")
        data = stream.read(maximum + 1)
        b = os.fstat(stream.fileno())
        c = os.stat(name, dir_fd=fd, follow_symlinks=False)
        def identity(x):
            return (x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_gid,
                    x.st_size, x.st_nlink, x.st_mtime_ns, x.st_ctime_ns)
        require(len(data) == a.st_size and identity(a) == identity(b) ==
                identity(c), "config_changed_during_read")
        return data, {"mode": stat.S_IMODE(a.st_mode), "gid": a.st_gid}


def exists(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def proposed(main, plan, backend):
    # Conservative initial subset: do not replace even a declared empty map.
    import re
    name, _ = checked_name(plan, backend)
    require(b"\0" not in main and b"\r" not in main and
            not re.search(rb"(?mi)^[ \t]*sender_dependent_relayhost_maps[ \t]*=",
                          main), "existing_sender_map_assignment")
    return main + (b"" if main.endswith(b"\n") else b"\n") + (
        "\n# LinuxMailRelay365 sender map " + plan + "\n" +
        PARAMETER + " = " + backend + ":/etc/postfix/" + name + "\n").encode("ascii")


def context(fd, uid):
    M.check_directory(fd, uid)
    info = os.fstat(fd)
    return [info.st_dev, info.st_ino]


def preview(config, plan, backend, stage_sha, compiled_sha, database, uid, guard):
    guard()  # caller must refuse unless maintenance evidence is fresh
    name, suffix = checked_name(plan, backend)
    require(all(type(x) is str and M.HEX.fullmatch(x)
                for x in (stage_sha, compiled_sha)) and
            type(database) is bytes and 0 < len(database) <= M.MAX_DB_BYTES,
            "invalid_compiled_candidate")
    require(not exists(config, name) and not exists(config, name + suffix),
            "managed_destination_already_exists")
    main, main_meta = config_file(config, "main.cf", uid)
    master, master_meta = config_file(config, "master.cf", uid)
    files = dict(zip(FILES, (main, master, proposed(main, plan, backend), database)))
    manifest = {
        "version": 1, "plan": plan, "backend": backend,
        "stage_sha": stage_sha, "compiled_sha": compiled_sha,
        "config_identity": context(config, uid),
        "main_meta": main_meta, "master_meta": master_meta,
        "files": {key: M.digest(value) for key, value in files.items()},
    }
    guard()
    require(config_file(config, "main.cf", uid) == (main, main_meta) and
            config_file(config, "master.cf", uid) == (master, master_meta) and
            not exists(config, name) and not exists(config, name + suffix),
            "configuration_drift")
    return M.digest(M.canonical(manifest)), manifest, files


def backup(parent, sha, info, files, uid):
    require(M.digest(M.canonical(info)) == sha and set(files) == set(FILES)
            and info["files"] == {k: M.digest(v) for k, v in files.items()},
            "invalid_backup_payload")
    base = M.open_base(parent, uid, create=True, name=BACKUP_BASE)
    try:
        os.mkdir(sha, 0o700, dir_fd=base)
        os.fsync(base)
        fd = os.open(sha, M.DIR_FLAGS, dir_fd=base)
        try:
            M.check_directory(fd, uid, True)
            for key in FILES:
                M.write_file(fd, key, files[key])
            M.write_file(fd, MANIFEST, M.canonical(info))
            os.fsync(fd)
            os.fsync(base)
        finally:
            os.close(fd)
    finally:
        os.close(base)


def load_backup(parent, sha, uid):
    require(type(sha) is str and M.HEX.fullmatch(sha), "invalid_backup_sha")
    base = M.open_base(parent, uid, name=BACKUP_BASE)
    try:
        fd = os.open(sha, M.DIR_FLAGS, dir_fd=base)
        try:
            M.check_directory(fd, uid, True)
            require(set(os.listdir(fd)) == set(FILES) | {MANIFEST},
                    "incomplete_backup")
            raw = M.read_file(fd, MANIFEST, uid)
            info = M.decode(raw)
            require(type(info) is dict and M.canonical(info) == raw and
                    M.digest(raw) == sha and info.get("version") == 1 and
                    set(info) == {"version", "plan", "backend", "stage_sha",
                                  "compiled_sha", "config_identity", "main_meta",
                                  "master_meta", "files"}, "invalid_backup_manifest")
            checked_name(info["plan"], info["backend"])
            for key in ("stage_sha", "compiled_sha"):
                require(type(info[key]) is str and M.HEX.fullmatch(info[key]),
                        "invalid_manifest_digest")
            for key in ("main_meta", "master_meta"):
                meta = info[key]
                require(type(meta) is dict and set(meta) == {"mode", "gid"} and
                        type(meta["mode"]) is int and 0 <= meta["mode"] <= 0o777 and
                        not meta["mode"] & 0o022 and type(meta["gid"]) is int and
                        meta["gid"] >= 0, "invalid_config_metadata")
            files = {k: M.read_file(fd, k, uid, M.MAX_DB_BYTES if
                                   k == "candidate.db" else LIMIT) for k in FILES}
            require(info["files"] == {k: M.digest(v) for k, v in files.items()}
                    and files["main.after"] == proposed(files["main.before"],
                        info["plan"], info["backend"]), "backup_integrity_mismatch")
            return info, files
        finally:
            os.close(fd)
    finally:
        os.close(base)


def atomic_write(fd, name, data, meta, uid, replace):
    temp = ".lmr365-txn-" + uuid.uuid4().hex
    handle = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        with os.fdopen(handle, "wb") as stream:
            os.fchown(stream.fileno(), uid, meta["gid"])
            os.fchmod(stream.fileno(), meta["mode"])
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
        else:
            os.link(temp, name, src_dir_fd=fd, dst_dir_fd=fd,
                    follow_symlinks=False)
            os.unlink(temp, dir_fd=fd)
        os.fsync(fd)
    finally:
        if exists(fd, temp):
            os.unlink(temp, dir_fd=fd)


def restore(config, parent, sha, confirmation, uid, map_gid, guard, verify):
    require(confirmation == RESTORE, "typed_restore_confirmation_required")
    info, files = load_backup(parent, sha, uid)
    require(context(config, uid) == info["config_identity"], "wrong_config_directory")
    name, suffix = checked_name(info["plan"], info["backend"])
    target = name + suffix
    guard()
    require(config_file(config, "master.cf", uid) ==
            (files["master.before"], info["master_meta"]),
            "master_drift_blocks_restore")
    current, meta = config_file(config, "main.cf", uid)
    require(meta == info["main_meta"] and current in (
            files["main.before"], files["main.after"]), "main_drift_blocks_restore")
    map_meta = {"mode": 0o640, "gid": map_gid}
    had_map = exists(config, target)
    if had_map:
        require(config_file(config, target, uid, M.MAX_DB_BYTES) ==
                (files["candidate.db"], map_meta), "map_drift_blocks_restore")
    guard()
    if current == files["main.after"]:
        atomic_write(config, "main.cf", files["main.before"], meta, uid, True)
    verify("")  # mandatory native verification by caller
    require(config_file(config, "main.cf", uid) == (files["main.before"], meta)
            and config_file(config, "master.cf", uid) ==
            (files["master.before"], info["master_meta"]), "restore_verification_failed")
    if had_map:
        guard()
        require(config_file(config, target, uid, M.MAX_DB_BYTES) ==
                (files["candidate.db"], map_meta), "map_drift_during_restore")
        os.unlink(target, dir_fd=config)
        os.fsync(config)
    return sha


class RollbackRequired(Refused):
    pass


def apply(config, parent, reviewed, confirmation, uid, map_gid, guard, verify,
          fresh_preview):
    """Testable file transaction; production entry point intentionally absent.

    fresh_preview must re-verify the actual compiled candidate, native host
    prerequisites and TLS evidence before returning the complete preview.
    """
    require(confirmation == CONFIRM, "typed_apply_confirmation_required")
    sha, info, files = fresh_preview()
    require(sha == reviewed and context(config, uid) == info["config_identity"],
            "reviewed_activation_changed")
    backup(parent, sha, info, files, uid)
    require(load_backup(parent, sha, uid) == (info, files),
            "backup_verification_failed")
    require(fresh_preview() == (sha, info, files), "drift_during_backup")
    name, suffix = checked_name(info["plan"], info["backend"])
    target = name + suffix
    map_meta = {"mode": 0o640, "gid": map_gid}
    try:
        guard()
        atomic_write(config, target, files["candidate.db"], map_meta, uid, False)
        guard()
        require(config_file(config, "main.cf", uid) ==
                (files["main.before"], info["main_meta"]) and
                config_file(config, "master.cf", uid) ==
                (files["master.before"], info["master_meta"]),
                "configuration_drift_before_write")
        atomic_write(config, "main.cf", files["main.after"],
                     info["main_meta"], uid, True)
        verify(info["backend"] + ":/etc/postfix/" + name)
        require(config_file(config, "main.cf", uid) ==
                (files["main.after"], info["main_meta"]) and
                config_file(config, "master.cf", uid) ==
                (files["master.before"], info["master_meta"]) and
                config_file(config, target, uid, M.MAX_DB_BYTES) ==
                (files["candidate.db"], map_meta), "post_apply_integrity_failed")
    except Exception:
        try:
            restore(config, parent, sha, RESTORE, uid, map_gid, guard, verify)
        except Exception:
            raise RollbackRequired("manual_recovery_required; backup=" + sha) from None
        raise
    return sha


if __name__ == "__main__":
    raise SystemExit("Transaction library only; production activation is not exposed.")
