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
import re
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
PUBLICATION = "published-map.json"
PARAMETER = "sender_dependent_relayhost_maps"
CONFIRM = "APPLY_STOPPED_POSTFIX_SENDER_MAP"
RESTORE = "RESTORE_STOPPED_POSTFIX_SENDER_MAP"
LIMIT = 2 * 1024 * 1024
SELINUX_XATTR = "security.selinux"


def require(condition, message):
    if not condition:
        raise Refused(message)


def checked_name(plan, backend):
    require(type(plan) is str and M.HEX.fullmatch(plan) and
            backend in M.MAP_SUFFIX, "invalid_candidate_identity")
    return "lmr365-conditional-" + plan + "-sender", M.MAP_SUFFIX[backend]


def checked_label(raw):
    """Bounded raw context, including an optional terminating NUL."""
    require(type(raw) is bytes and 0 < len(raw) <= 1024,
            "invalid_selinux_label")
    value = raw[:-1] if raw.endswith(b"\0") else raw
    require(re.fullmatch(rb"[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_]+:"
                         rb"[A-Za-z0-9_.,:-]+", value) is not None,
            "invalid_selinux_label")
    return raw.hex()


def label_bytes(value):
    require(type(value) is str and 0 < len(value) <= 2048 and
            re.fullmatch(r"[0-9a-f]+", value) and len(value) % 2 == 0,
            "invalid_selinux_label_encoding")
    raw = bytes.fromhex(value)
    require(checked_label(raw) == value, "invalid_selinux_label_encoding")
    return raw


def file_label(handle):
    names = set(os.listxattr(handle))
    require(names in (set(), {SELINUX_XATTR}),
            "unsupported_extended_file_metadata")
    if SELINUX_XATTR not in names:
        return None
    return checked_label(os.getxattr(handle, SELINUX_XATTR))


def valid_meta(meta, labeled):
    require(type(meta) is dict and set(meta) ==
            ({"mode", "gid", "selinux"} if labeled else {"mode", "gid"}) and
            type(meta["mode"]) is int and 0 <= meta["mode"] <= 0o777 and
            not meta["mode"] & 0o022 and type(meta["gid"]) is int and
            meta["gid"] >= 0, "invalid_config_metadata")
    if labeled:
        label_bytes(meta["selinux"])


def map_metadata(info, gid):
    meta = {"mode": 0o640, "gid": gid}
    if info.get("version") == 2:
        label_bytes(info["map_selinux"])
        meta["selinux"] = info["map_selinux"]
    return meta


def restore_file_metadata(handle, meta):
    # Only SELinux's own xattr is supported. Do not copy or remove ACLs,
    # capabilities, integrity attributes, or arbitrary extended metadata.
    existing = file_label(handle)
    expected = meta.get("selinux")
    if expected is not None:
        desired = label_bytes(expected)
        if existing != expected:
            os.setxattr(handle, SELINUX_XATTR, desired)
    require(file_label(handle) == expected, "file_label_not_preserved")


def config_file(fd, name, uid, maximum=LIMIT):
    handle = os.open(name, M.READ_FLAGS, dir_fd=fd)
    with os.fdopen(handle, "rb") as stream:
        a = os.fstat(stream.fileno())
        require(stat.S_ISREG(a.st_mode) and a.st_uid == uid and
                a.st_nlink == 1 and not a.st_mode & 0o7022 and
                0 < a.st_size <= maximum, "untrusted_config_file")
        label = file_label(stream.fileno())
        data = stream.read(maximum + 1)
        require(file_label(stream.fileno()) == label, "file_label_changed_during_read")
        b = os.fstat(stream.fileno())
        c = os.stat(name, dir_fd=fd, follow_symlinks=False)
        def identity(x):
            return (x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_gid,
                    x.st_size, x.st_nlink, x.st_mtime_ns, x.st_ctime_ns)
        require(len(data) == a.st_size and identity(a) == identity(b) ==
                identity(c), "config_changed_during_read")
        meta = {"mode": stat.S_IMODE(a.st_mode), "gid": a.st_gid}
        if label is not None:
            meta["selinux"] = label
        return data, meta


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


def preview(config, plan, backend, stage_sha, compiled_sha, database, uid, guard,
            map_selinux=None):
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
    labeled = map_selinux is not None
    valid_meta(main_meta, labeled)
    valid_meta(master_meta, labeled)
    if labeled:
        label_bytes(map_selinux)
    files = dict(zip(FILES, (main, master, proposed(main, plan, backend), database)))
    manifest = {
        "version": 2 if labeled else 1, "plan": plan, "backend": backend,
        "stage_sha": stage_sha, "compiled_sha": compiled_sha,
        "config_identity": context(config, uid),
        "main_meta": main_meta, "master_meta": master_meta,
        "files": {key: M.digest(value) for key, value in files.items()},
    }
    if labeled:
        manifest["map_selinux"] = map_selinux
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
            names = set(os.listdir(fd))
            required = set(FILES) | {MANIFEST}
            require(names == required or names == required | {PUBLICATION},
                    "incomplete_backup")
            if PUBLICATION in names:
                read_publication(fd, sha, uid)
            raw = M.read_file(fd, MANIFEST, uid)
            info = M.decode(raw)
            common = {"version", "plan", "backend", "stage_sha",
                      "compiled_sha", "config_identity", "main_meta",
                      "master_meta", "files"}
            require(type(info) is dict and M.canonical(info) == raw and
                    M.digest(raw) == sha and type(info.get("version")) is int and
                    info["version"] in (1, 2), "invalid_backup_manifest")
            labeled = info["version"] == 2
            require(set(info) == (common | {"map_selinux"} if labeled else common),
                    "invalid_backup_manifest")
            if labeled:
                label_bytes(info["map_selinux"])
            checked_name(info["plan"], info["backend"])
            for key in ("stage_sha", "compiled_sha"):
                require(type(info[key]) is str and M.HEX.fullmatch(info[key]),
                        "invalid_manifest_digest")
            for key in ("main_meta", "master_meta"):
                valid_meta(info[key], labeled)
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


def file_identity(info):
    # Exclude atime: native read-only postmap may change it. Include ctime
    # and mtime to detect replacement or modifications even with equal bytes.
    return [info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]


def read_publication(fd, sha, uid):
    raw = M.read_file(fd, PUBLICATION, uid)
    value = M.decode(raw)
    require(type(value) is dict and set(value) ==
            {"format", "transaction_sha256", "identity"} and
            value["format"] == "LMR365-PUBLISHED-MAP-V1" and
            value["transaction_sha256"] == sha and
            type(value["identity"]) is list and len(value["identity"]) == 5 and
            all(type(x) is int and x >= 0 for x in value["identity"]) and
            M.canonical(value) == raw, "invalid_map_publication_receipt")
    return value["identity"]


def publication_receipt(parent, sha, uid, identity=None):
    base = M.open_base(parent, uid, name=BACKUP_BASE)
    try:
        fd = os.open(sha, M.DIR_FLAGS, dir_fd=base)
        try:
            M.check_directory(fd, uid, True)
            if identity is not None:
                # Exclusive durable record after no-clobber publication,
                # before main.cf is modified. Never manufacture a receipt
                # during recovery from a map with matching bytes.
                M.write_file(fd, PUBLICATION, M.canonical({
                    "format": "LMR365-PUBLISHED-MAP-V1",
                    "transaction_sha256": sha, "identity": identity}))
                os.fsync(fd)
                os.fsync(base)
            if not exists(fd, PUBLICATION):
                return None
            result = read_publication(fd, sha, uid)
            require(identity is None or result == identity,
                    "publication_receipt_changed")
            return result
        finally:
            os.close(fd)
    finally:
        os.close(base)


def checked_published_map(config, target, uid, expected, meta, identity):
    require(identity is not None, "map_publication_unproven")
    before = file_identity(os.stat(target, dir_fd=config, follow_symlinks=False))
    require(before == identity and
            config_file(config, target, uid, M.MAX_DB_BYTES) == (expected, meta) and
            file_identity(os.stat(target, dir_fd=config, follow_symlinks=False)) == identity,
            "published_map_identity_or_content_changed")


def atomic_write(fd, name, data, meta, uid, replace, published=None):
    temp = ".lmr365-txn-" + uuid.uuid4().hex
    handle = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        with os.fdopen(handle, "wb") as stream:
            os.fchown(stream.fileno(), uid, meta["gid"])
            os.fchmod(stream.fileno(), meta["mode"])
            stream.write(data)
            stream.flush()
            restore_file_metadata(stream.fileno(), meta)
            os.fsync(stream.fileno())
            prepared = file_identity(os.fstat(stream.fileno()))
        if replace:
            os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
        else:
            os.link(temp, name, src_dir_fd=fd, dst_dir_fd=fd,
                    follow_symlinks=False)
            # Remember successful exclusive publication before any later
            # operation can fail. Never roll back by deleting someone else's
            # map when link() itself did not succeed.
            if published is not None:
                published(prepared[:4])
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
    require(not exists(config, name), "unexpected_managed_source_file")
    require(config_file(config, "master.cf", uid) ==
            (files["master.before"], info["master_meta"]),
            "master_drift_blocks_restore")
    current, meta = config_file(config, "main.cf", uid)
    require(meta == info["main_meta"] and current in (
            files["main.before"], files["main.after"]), "main_drift_blocks_restore")
    map_meta = map_metadata(info, map_gid)
    had_map = exists(config, target)
    publication = publication_receipt(parent, sha, uid)
    if had_map:
        checked_published_map(config, target, uid, files["candidate.db"],
                              map_meta, publication)
    guard()
    if current == files["main.after"]:
        atomic_write(config, "main.cf", files["main.before"], meta, uid, True)
    verify("")  # mandatory native verification by caller
    require(config_file(config, "main.cf", uid) == (files["main.before"], meta)
            and config_file(config, "master.cf", uid) ==
            (files["master.before"], info["master_meta"]), "restore_verification_failed")
    if had_map:
        guard()
        require(publication_receipt(parent, sha, uid) == publication,
                "publication_receipt_changed")
        checked_published_map(config, target, uid, files["candidate.db"],
                              map_meta, publication)
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
    map_meta = map_metadata(info, map_gid)
    published = [None]
    def remember_publication(identity):
        published[0] = identity
    try:
        guard()
        atomic_write(config, target, files["candidate.db"], map_meta, uid,
                     False, remember_publication)
        # Capture the inode after the temporary hard link is removed (ctime
        # changes during link/unlink). Require the same inode, size and mtime
        # that were observed on our private source before exclusive publish.
        identity = file_identity(os.stat(target, dir_fd=config, follow_symlinks=False))
        require(identity[:4] == published[0], "published_map_replaced")
        checked_published_map(config, target, uid, files["candidate.db"], map_meta, identity)
        publication_receipt(parent, sha, uid, identity)
        guard()
        checked_published_map(config, target, uid, files["candidate.db"], map_meta, identity)
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
                (files["master.before"], info["master_meta"]), "post_apply_integrity_failed")
        require(publication_receipt(parent, sha, uid) == identity,
                "publication_receipt_changed")
        checked_published_map(config, target, uid, files["candidate.db"],
                              map_meta, identity)
    except Exception:
        if published[0] is None:
            # No active configuration write was attempted; retain the
            # backup and leave any externally created map untouched.
            raise
        try:
            restore(config, parent, sha, RESTORE, uid, map_gid, guard, verify)
        except Exception as rollback_error:
            # Preserve the original and rollback failure for automated tests.
            # The CLI catches RollbackRequired and emits only fixed statuses
            # and the recovery digest, never a traceback or config values.
            raise RollbackRequired("manual_recovery_required; backup=" + sha) from rollback_error
        raise
    return sha


if __name__ == "__main__":
    raise SystemExit("Transaction library only; production activation is not exposed.")
