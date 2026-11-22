#!/usr/bin/env python3
"""Root-only, NO-RESTORE config snapshots for an existing Exim/Sendmail MTA.

Only declared /etc files are captured, never mail queues or service state.
No package changes, service restart, SMTP, token, or Exchange calls.
Archives may contain secrets and stay on Linux with mode 0600.
Python 3.6+; Linux only. Do not use as a substitute for a VM-level backup.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
import re
import subprocess
import secrets
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path

BASE = Path("/var/backups/linuxmailrelay365-foreign-mta")
ROOT = Path("/")
ID = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\Z")
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
MAX_FILES = 4096
MAX_BYTES = 128 * 1024 * 1024
MAX_SINGLE = 16 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
ALLOWED = {
    "exim": ("etc/exim4", "etc/exim"),
    "sendmail": ("etc/mail", "etc/aliases", "etc/aliases.db"),
}
MANDATORY = {"exim": ("etc/exim4", "etc/exim"),
             "sendmail": ("etc/mail",)}


class Refused(Exception):
    pass


def safe_regular(path, owner_uid=0, mode=None, maximum=MAX_SINGLE):
    """Never follow a file symlink or ignore changed content metadata."""
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != owner_uid or
            st.st_nlink != 1 or st.st_mode & 0o022 or
            st.st_size < 0 or st.st_size > maximum or
            (mode is not None and stat.S_IMODE(st.st_mode) != mode)):
        raise Refused("unsafe_snapshot_file")
    return st


def safe_dir(path, owner_uid=0):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or
            info.st_mode & 0o022):
        raise Refused("unsafe_snapshot_directory")
    return info


def safe_packaged_sendmail_dir(path, owner_uid=0, modes=(0o2755,)):
    """Only package-native /etc/mail 2755 smmta/smmsp may differ from root.

    All backup *files* and other directories still require root ownership;
    this exception cannot be used for arbitrary paths or for writes.
    """
    try:
        return safe_dir(path, owner_uid)
    except Refused:
        if owner_uid != 0:
            raise
    metadata = path.lstat()  # A symlink is never accepted.
    if (not stat.S_ISDIR(metadata.st_mode) or
            stat.S_IMODE(metadata.st_mode) not in modes or
            metadata.st_mode & 0o022):
        raise Refused("unsafe_sendmail_package_directory")
    import pwd
    import grp
    try:
        smmsp_gid = grp.getgrnam("smmsp").gr_gid
    except KeyError:
        smmsp_gid = None
    for account_name in ("smmta", "smmsp"):
        try:
            account = pwd.getpwnam(account_name)
        except KeyError:
            continue
        accepted_gids = {account.pw_gid}
        if account_name == "smmta" and smmsp_gid is not None:
            accepted_gids.add(smmsp_gid)
        if metadata.st_uid == account.pw_uid and metadata.st_gid in accepted_gids:
            return metadata
    raise Refused("untrusted_sendmail_package_directory_owner")


def safe_config_dir(directory, mta, root, owner_uid):
    # The sole exception is /etc/mail on an actual root-owned package host;
    # /etc, subdirectories and Exim remain root-only.
    if mta == "sendmail":
        mail = root / "etc" / "mail"
        if directory == mail:
            return safe_packaged_sendmail_dir(directory, owner_uid)
        # These three package-managed subdirectories may be owned by the
        # registered service account; arbitrary subdirectories never may.
        if directory.parent == mail and directory.name in ("m4", "smrsh", "tls"):
            return safe_packaged_sendmail_dir(directory, owner_uid,
                                             modes=(0o0755, 0o2755))
    return safe_dir(directory, owner_uid)


def stable_file(path, owner_uid=0):
    before = safe_regular(path, owner_uid)
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(fd)
        stat_key = lambda s: (s.st_dev, s.st_ino, s.st_size,
                              s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_uid)
        if stat_key(before) != stat_key(opened):
            raise Refused("file_changed_before_snapshot")
        parts = []
        remaining = opened.st_size
        while remaining:
            block = os.read(fd, min(65536, remaining))
            if not block:
                raise Refused("short_snapshot_read")
            parts.append(block)
            remaining -= len(block)
        if os.read(fd, 1) or stat_key(os.fstat(fd)) != stat_key(opened):
            raise Refused("file_changed_during_snapshot")
        return opened, b"".join(parts)
    finally:
        os.close(fd)


# In package-native Sendmail snapshots a few generated DBs belong to the
# registered service user. Back them up AS DATA, never execute or restore them.
PACKAGE_LINKS = frozenset((
    "etc/mail/aliases", "etc/mail/smrsh/procmail",
    "etc/mail/smrsh/mail.local",
))


def _package_principals():
    import pwd
    import grp
    accounts = {}
    for account_name in ("smmta", "smmsp"):
        try:
            account = pwd.getpwnam(account_name)
        except KeyError:
            continue
        accounts[account.pw_uid] = account.pw_gid
    try:
        smmsp = grp.getgrnam("smmsp").gr_gid
    except KeyError:
        smmsp = None
    return accounts, smmsp


def snapshot_file_owner(path, mta, root, owner_uid, package=False):
    info = path.lstat()
    if info.st_uid == owner_uid:
        safe_regular(path, owner_uid)
        return owner_uid
    if not package or mta != "sendmail" or owner_uid != 0:
        raise Refused("untrusted_package_generated_file")
    if (path.parent != root / "etc" / "mail" or
            not re.fullmatch(r"[A-Za-z0-9_-]+\.db", path.name)):
        raise Refused("nonroot_file_not_known_generated_sendmail_database")
    principals, smmsp = _package_principals()
    if info.st_uid not in principals or info.st_gid not in (
            principals[info.st_uid], smmsp):
        raise Refused("untrusted_sendmail_generated_db_owner")
    safe_regular(path, info.st_uid)
    return info.st_uid


def checked_package_link(path, root, owner_uid):
    relative = path.relative_to(root).as_posix()
    if relative not in PACKAGE_LINKS:
        raise Refused("unrecognized_sendmail_package_symlink")
    before = path.lstat()
    if (not stat.S_ISLNK(before.st_mode) or before.st_uid != owner_uid or
            before.st_nlink != 1):
        raise Refused("untrusted_sendmail_package_symlink")
    target = os.readlink(str(path))  # Never resolve, open, or follow the link.
    after = path.lstat()
    evidence = lambda info: (info.st_dev, info.st_ino, info.st_uid,
                             info.st_gid, info.st_size, info.st_ctime_ns)
    if evidence(before) != evidence(after) or not target or len(target) > 1024:
        raise Refused("sendmail_link_changed_during_inventory")
    return {"kind": "symlink", "target": target, "uid": before.st_uid,
            "gid": before.st_gid}


def package_directory_metadata(path):
    info = path.lstat()
    return {"kind": "directory", "uid": info.st_uid, "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode)}


def selected_files(mta, root=ROOT, owner_uid=0, package_metadata=None):
    """Strict allowlisted walk; package metadata only in explicit backup mode."""
    if mta not in ALLOWED:
        raise Refused("invalid_mta")
    entries = {}
    found = 0
    for name in ALLOWED[mta]:
        source = root / name
        if not source.exists() and not source.is_symlink():
            continue
        # /etc or the injected fixture /etc must itself be safe.
        safe_dir(root / "etc", owner_uid)
        st = source.lstat()
        if stat.S_ISDIR(st.st_mode):
            safe_config_dir(source, mta, root, owner_uid)
            if package_metadata is not None:
                package_metadata[name] = package_directory_metadata(source)
            found += 1 if name in MANDATORY[mta] else 0
            pending = [source]
            while pending:
                directory = pending.pop()
                safe_config_dir(directory, mta, root, owner_uid)
                for path in sorted(directory.iterdir(), key=lambda p: p.name):
                    relative = path.relative_to(root).as_posix()
                    if len(relative.encode("utf-8")) > 512:
                        raise Refused("configuration_path_too_long")
                    if path.is_symlink():
                        if package_metadata is None or mta != "sendmail":
                            raise Refused("symlink_in_existing_mta_configuration")
                        package_metadata[relative] = checked_package_link(
                            path, root, owner_uid)
                    elif path.is_dir():
                        safe_config_dir(path, mta, root, owner_uid)
                        if package_metadata is not None:
                            package_metadata[relative] = package_directory_metadata(path)
                        pending.append(path)
                    else:
                        snapshot_file_owner(path, mta, root, owner_uid,
                                            package_metadata is not None)
                        if relative in entries or (package_metadata is not None and
                                                   relative in package_metadata):
                            raise Refused("duplicate_configuration_path")
                        entries[relative] = path
        elif stat.S_ISREG(st.st_mode) and name in MANDATORY[mta]:
            # Exim/Sendmail primary configuration roots must be directories.
            # A file in their place is not a valid complete MTA snapshot.
            raise Refused("primary_mta_config_root_not_directory")
        elif stat.S_ISREG(st.st_mode):
            snapshot_file_owner(source, mta, root, owner_uid,
                                package_metadata is not None)
            entries[name] = source
        else:
            raise Refused("nonregular_configuration_object")
    if found == 0 or not entries:
        raise Refused("existing_mta_configuration_not_found")
    if len(entries) + len(package_metadata or {}) > MAX_FILES or sum(
            p.lstat().st_size for p in entries.values()) > MAX_BYTES:
        raise Refused("configuration_snapshot_limits_exceeded")
    return entries


def safe_backup_base(base, owner_uid=0):
    # In the real invocation the path is fixed, never a user-supplied option.
    if base == BASE:
        safe_dir(Path("/var"), owner_uid)
        backups_parent = Path("/var/backups")
        if not backups_parent.exists() and not backups_parent.is_symlink():
            backups_parent.mkdir(mode=0o700)
        safe_dir(backups_parent, owner_uid)
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe_dir(base, owner_uid)


def archive_folder(base, mta, owner_uid=0):
    safe_backup_base(base, owner_uid)
    directory = base / mta
    directory.mkdir(mode=0o700, exist_ok=True)
    safe_dir(directory, owner_uid)
    return directory


def strict_snapshot_dir(directory, owner_uid=0):
    safe_dir(directory, owner_uid)
    for item in ("config.tar.gz", "manifest.json"):
        safe_regular(directory / item, owner_uid, mode=0o600,
                     maximum=(MAX_BYTES + 2 * 1024 * 1024
                              if item.endswith(".gz") else MAX_MANIFEST))


def verify(directory, mta, owner_uid=0):
    """Validate digest + every tar member without extracting any content."""
    if mta not in ALLOWED:
        raise Refused("invalid_mta")
    # Archive identifiers are fixed-format, but verifying a preexisting
    # snapshot must also refuse a replaced parent path or symlink. Validate
    # both the MTA archive folder and its backing base before any file read.
    safe_dir(directory.parent.parent, owner_uid)
    safe_dir(directory.parent, owner_uid)
    strict_snapshot_dir(directory, owner_uid)
    raw = stable_file(directory / "manifest.json", owner_uid)[1]
    if len(raw) > MAX_MANIFEST:
        raise Refused("oversized_snapshot_manifest")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise Refused("bad_snapshot_manifest")
    if (not isinstance(manifest, dict) or
            manifest.get("version") not in (1, 2) or
            (manifest["version"] == 2 and mta != "sendmail") or
            manifest.get("mta") != mta or
            not isinstance(manifest.get("files"), dict) or
            not 1 <= len(manifest["files"]) <= MAX_FILES or
            not isinstance(manifest.get("sha256"), str) or
            not SHA.fullmatch(manifest["sha256"])):
        raise Refused("invalid_snapshot_manifest")
    objects = manifest.get("objects", {})
    if manifest["version"] == 1:
        if objects or "objects" in manifest:
            raise Refused("unexpected_legacy_snapshot_objects")
    else:
        if not isinstance(objects, dict) or not objects or len(objects) > MAX_FILES:
            raise Refused("invalid_package_object_manifest")
        if ("etc/mail" not in objects or
                not isinstance(objects["etc/mail"], dict) or
                objects["etc/mail"].get("kind") != "directory"):
            raise Refused("sendmail_package_root_directory_unrecorded")
        if len(objects) + len(manifest["files"]) > MAX_FILES:
            raise Refused("package_snapshot_object_limit")
        for name, metadata in objects.items():
            if (not isinstance(name, str) or not name.startswith("etc/mail/")
                    and name != "etc/mail" or len(name.encode("utf-8")) > 512
                    or ".." in name.split("/") or name in manifest["files"]
                    or not isinstance(metadata, dict)):
                raise Refused("invalid_package_object_path")
            kind = metadata.get("kind")
            if (kind not in ("directory", "symlink") or
                    type(metadata.get("uid")) is not int or
                    type(metadata.get("gid")) is not int or
                    not 0 <= metadata["uid"] <= 65535 or
                    not 0 <= metadata["gid"] <= 65535):
                raise Refused("invalid_package_object_metadata")
            if kind == "directory":
                if (type(metadata.get("mode")) is not int or
                        not 0 <= metadata["mode"] <= 0o7777 or
                        metadata["mode"] & 0o022 or
                        set(metadata) != {"kind", "uid", "gid", "mode"}):
                    raise Refused("invalid_package_directory_metadata")
            else:
                target = metadata.get("target")
                if (name not in PACKAGE_LINKS or
                        type(target) is not str or not target or
                        len(target.encode("utf-8")) > 1024 or
                        set(metadata) != {"kind", "uid", "gid", "target"}):
                    raise Refused("invalid_package_symlink_metadata")
    archive = directory / "config.tar.gz"
    digest = hashlib.sha256()
    with archive.open("rb") as reader:
        while True:
            part = reader.read(65536)
            if not part:
                break
            digest.update(part)
    if digest.hexdigest() != manifest["sha256"]:
        raise Refused("snapshot_archive_digest_mismatch")
    seen = set()
    total = 0
    try:
        with tarfile.open(str(archive), "r:gz") as tar:
            for member in tar:
                name = member.name
                # Exact relative file names; no tar extraction, symlinks or devices.
                if (name in seen or not member.isfile() or
                        len(name.encode("utf-8")) > 512 or
                        name.startswith("/") or ".." in name.split("/") or
                        not any(name.startswith(prefix + "/") or name == prefix
                                for prefix in ALLOWED[mta]) or
                        name not in manifest["files"] or member.size > MAX_SINGLE):
                    raise Refused("unsafe_snapshot_tar_member")
                seen.add(name)
                meta = manifest["files"][name]
                if (not isinstance(meta, dict) or meta.get("size") != member.size or
                        not isinstance(meta.get("sha256"), str) or
                        not SHA.fullmatch(meta["sha256"])):
                    raise Refused("invalid_snapshot_file_manifest")
                if manifest["version"] == 2 and (
                        set(meta) != {"size", "sha256", "uid", "gid", "mode"} or
                        type(meta["uid"]) is not int or
                        type(meta["gid"]) is not int or
                        type(meta["mode"]) is not int or
                        (member.uid, member.gid, member.mode) != (
                            meta["uid"], meta["gid"], meta["mode"])):
                    raise Refused("package_file_metadata_mismatch")
                total += member.size
                if total > MAX_BYTES:
                    raise Refused("snapshot_decompressed_size_exceeded")
                stream = tar.extractfile(member)
                if stream is None:
                    raise Refused("snapshot_member_unreadable")
                content = stream.read(member.size + 1)
                if (len(content) != member.size or
                        hashlib.sha256(content).hexdigest() != meta["sha256"]):
                    raise Refused("snapshot_member_digest_mismatch")
    except (OSError, EOFError, tarfile.TarError, UnicodeError):
        raise Refused("invalid_snapshot_archive")
    if seen != set(manifest["files"]):
        raise Refused("missing_snapshot_members")
    return {"files": len(seen), "bytes": total,
            "sha256": manifest["sha256"], "mta": mta,
            "format": ("v2_package_metadata" if manifest["version"] == 2
                       else "v1_regular_files")}


def backup(mta, root=ROOT, base=BASE, owner_uid=0):
    package_objects = {} if mta == "sendmail" and owner_uid == 0 else None
    files = selected_files(mta, root, owner_uid, package_objects)
    directory = archive_folder(base, mta, owner_uid)
    staging = Path(tempfile.mkdtemp(prefix=".pending-", dir=str(directory)))
    try:
        safe_dir(staging, owner_uid)
        # Package-native snapshot v2 records symlink metadata ONLY; never
        # resolves symlinks or imports their potentially external targets.
        manifest = {"version": 2 if package_objects is not None else 1,
                    "mta": mta, "files": {}}
        if package_objects is not None:
            manifest["objects"] = package_objects
        archive = staging / "config.tar.gz"
        with archive.open("xb") as output:
            os.chmod(str(archive), 0o600)
            with tarfile.open(fileobj=output, mode="w:gz") as tar:
                total = 0
                for name, path in sorted(files.items()):
                    current, content = stable_file(
                        path, snapshot_file_owner(path, mta, root, owner_uid,
                                                  package_objects is not None))
                    total += len(content)
                    if total > MAX_BYTES:
                        raise Refused("configuration_changed_or_over_limit")
                    entry = tarfile.TarInfo(name)
                    entry.type = tarfile.REGTYPE
                    entry.size = len(content)
                    entry.uid, entry.gid = current.st_uid, current.st_gid
                    entry.mode, entry.mtime = stat.S_IMODE(current.st_mode), int(current.st_mtime)
                    tar.addfile(entry, io.BytesIO(content))
                    file_info = {
                        "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                    if package_objects is not None:
                        file_info.update({"uid": current.st_uid, "gid": current.st_gid,
                                          "mode": stat.S_IMODE(current.st_mode)})
                    manifest["files"][name] = file_info
            output.flush()
            os.fsync(output.fileno())
        manifest["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        metafile = staging / "manifest.json"
        with metafile.open("x", encoding="utf-8") as output:
            os.chmod(str(metafile), 0o600)
            json.dump(manifest, output, sort_keys=True, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
        review = verify(staging, mta, owner_uid)
        if package_objects is not None:
            observed_objects = {}
            observed_files = selected_files(mta, root, owner_uid,
                                            observed_objects)
            if (observed_objects != package_objects or
                    set(observed_files) != set(files)):
                raise Refused("sendmail_package_inventory_changed_during_backup")
        backup_id = (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                     + "-" + secrets.token_hex(6))
        target = directory / backup_id
        if target.exists() or target.is_symlink():
            raise Refused("snapshot_identifier_collision")
        staging.rename(target)
        return backup_id, review
    except Exception:
        shutil.rmtree(str(staging), ignore_errors=True)
        raise



def recovery_preview(mta, snapshot_id, root=ROOT, base=BASE, owner_uid=0):
    """Summarize differences using hashes only. Never display paths or data."""
    if mta not in ALLOWED or not ID.fullmatch(snapshot_id):
        raise Refused("invalid_recovery_selection")
    directory = base / mta / snapshot_id
    verified = verify(directory, mta, owner_uid)
    manifest = json.loads(stable_file(directory / "manifest.json", owner_uid)[1])
    try:
        current_objects = {} if manifest["version"] == 2 else None
        files = selected_files(mta, root, owner_uid, current_objects)
        same = (len(files) == verified["files"] and
                (current_objects is None or current_objects == manifest["objects"]))
        if same:
            for name, path in files.items():
                expected = manifest["files"].get(name)
                if not expected:
                    same = False
                    break
                meta, contents = stable_file(
                    path, snapshot_file_owner(path, mta, root, owner_uid,
                                              current_objects is not None))
                if (meta.st_size != expected["size"] or
                        hashlib.sha256(contents).hexdigest() != expected["sha256"] or
                        (current_objects is not None and (
                            meta.st_uid != expected["uid"] or
                            meta.st_gid != expected["gid"] or
                            stat.S_IMODE(meta.st_mode) != expected["mode"]))):
                    same = False
                    break
        state = "identical" if same else "different"
    except (OSError, ValueError, Refused):
        state = "unverified"
    return {"snapshot": verified, "current": state}


def _copy_verified_snapshot_member(source, dest, owner_uid, maximum):
    """Copy a private snapshot file without following links or changing owners."""
    original = safe_regular(source, owner_uid, mode=0o600, maximum=maximum)
    identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mode,
                           st.st_uid, st.st_gid, st.st_nlink,
                           st.st_mtime_ns, st.st_ctime_ns)
    fd = os.open(str(source), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        if identity(os.fstat(fd)) != identity(original):
            raise Refused("snapshot_source_changed_before_export")
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
        out = os.open(str(dest), flags, 0o600)
        try:
            copied = 0
            with os.fdopen(out, "wb") as writer:
                while copied < original.st_size:
                    chunk = os.read(fd, min(65536, original.st_size - copied))
                    if not chunk:
                        raise Refused("snapshot_source_short_during_export")
                    writer.write(chunk)
                    copied += len(chunk)
                if os.read(fd, 1):
                    raise Refused("snapshot_source_grew_during_export")
                writer.flush()
                os.fsync(writer.fileno())
        finally:
            # fdopen closed its descriptor, even on a failed write.
            pass
        if (identity(os.fstat(fd)) != identity(original) or
                identity(source.lstat()) != identity(original)):
            raise Refused("snapshot_source_changed_during_export")
        safe_regular(dest, owner_uid, mode=0o600, maximum=maximum)
    finally:
        os.close(fd)


def _private_export_parent(target, components, owner_uid):
    """Create only private directories, never link targets or active /etc."""
    dest = target
    for part in components:
        if (not part or part in (".", "..") or len(part) > 255
                or "/" in part):
            raise Refused("unsafe_package_export_component")
        dest = dest / part
        if not dest.exists() and not dest.is_symlink():
            dest.mkdir(mode=0o700)
        safe_dir(dest, owner_uid)
    return dest


def _write_private_export_file(path, contents, owner_uid, maximum=MAX_MANIFEST):
    if not isinstance(contents, bytes) or len(contents) > maximum:
        raise Refused("invalid_or_oversized_export_payload")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())
    safe_regular(path, owner_uid, mode=0o600, maximum=maximum)


def _export_sendmail_package_v2(directory, folder, manifest, accepted, owner_uid):
    """Rehearsal-only export with inert symlink metadata, NOT active recovery.

    The original verified archive and its manifest are preserved alongside
    private 0600 data copies. Package symlinks are represented as JSON, never
    materialized; original owner/mode is recorded, never applied to files.
    """
    target = Path(tempfile.mkdtemp(prefix=".offline-recovery-", dir=str(folder)))
    try:
        safe_dir(target, owner_uid)
        _copy_verified_snapshot_member(
            directory / "manifest.json", target / "manifest.json",
            owner_uid, MAX_MANIFEST)
        _copy_verified_snapshot_member(
            directory / "config.tar.gz", target / "config.tar.gz",
            owner_uid, MAX_BYTES + 2 * 1024 * 1024)
        sealed = verify(target, "sendmail", owner_uid)
        if sealed != accepted or json.loads(stable_file(
                target / "manifest.json", owner_uid)[1]) != manifest:
            raise Refused("snapshot_changed_between_review_and_export")

        # Recreate directory layout PRIVATELY as 0700 even if original was
        # service-owned. Never apply arbitrary packaged permissions or ownership.
        for name, metadata in sorted(manifest["objects"].items()):
            parts = name.split("/")
            if metadata["kind"] == "directory":
                _private_export_parent(target, parts, owner_uid)

        seen = set()
        with tarfile.open(str(target / "config.tar.gz"), "r:gz") as tar:
            for member in tar:
                name = member.name
                parts = name.split("/")
                if (name not in manifest["files"] or member.type != tarfile.REGTYPE
                        or not parts or any(not part or part in (".", "..") or
                                            len(part) > 255 for part in parts)
                        or name in seen):
                    raise Refused("unsafe_package_export_member")
                seen.add(name)
                parent = _private_export_parent(target, parts[:-1], owner_uid)
                final = parent / parts[-1]
                stream = tar.extractfile(member)
                if stream is None:
                    raise Refused("package_export_member_unreadable")
                payload = stream.read(member.size + 1)
                evidence = manifest["files"][name]
                if (len(payload) != member.size or
                        hashlib.sha256(payload).hexdigest() != evidence["sha256"]):
                    raise Refused("package_export_digest_mismatch")
                if len(payload) > MAX_SINGLE:
                    raise Refused("package_export_member_too_large")
                _write_private_export_file(final, payload, owner_uid,
                                           maximum=MAX_SINGLE)
                # Verify the bytes BACK from the private export, not only the
                # TAR input. Never claim success after an incomplete write.
                exported_meta, exported_bytes = stable_file(final, owner_uid)
                if (stat.S_IMODE(exported_meta.st_mode) != 0o600 or
                        len(exported_bytes) != evidence["size"] or
                        hashlib.sha256(exported_bytes).hexdigest() != evidence["sha256"]):
                    raise Refused("private_export_readback_digest_mismatch")
        if seen != set(manifest["files"]):
            raise Refused("package_export_missing_regular_files")

        # Missing symlinks are deliberate: their targets may be absolute paths
        # outside /etc/mail and must NOT be opened or followed during export.
        for name, metadata in manifest["objects"].items():
            if metadata["kind"] == "symlink":
                link_path = target.joinpath(*name.split("/"))
                _private_export_parent(target, name.split("/")[:-1], owner_uid)
                if os.path.lexists(str(link_path)):
                    raise Refused("package_symlink_was_materialized_or_overlapped")

        record = {
            "format": "sendmail_v2_inert_metadata_only",
            "source_archive_sha256": sealed["sha256"],
            "files": manifest["files"],
            "objects": manifest["objects"],
            "symlinks_materialized": False,
            "original_permissions_or_owners_applied": False,
            "active_etc_modified": False,
            "automatic_live_restore_supported": False,
        }
        _write_private_export_file(
            target / "PACKAGE_RECOVERY_METADATA.json",
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            owner_uid)
        _write_private_export_file(
            target / "READ_ME_BEFORE_RECOVERY.txt",
            b"OFFLINE REVIEW ONLY. Do NOT copy this tree over /etc/mail.\n"
            b"Original owner/mode and package links are in "
            b"PACKAGE_RECOVERY_METADATA.json and manifest.json.\n"
            b"Files are private 0600, directories private 0700; links "
            b"have NOT been created. Queue, service and certificates "
            b"outside the allowlist are NOT backed up.\n",
            owner_uid)
        if verify(target, "sendmail", owner_uid) != accepted:
            raise Refused("package_export_archive_postcheck_failed")
        return str(target), sealed
    except Exception:
        shutil.rmtree(str(target), ignore_errors=True)
        raise


def extract_offline(mta, snapshot_id, base=BASE, owner_uid=0):
    """Extract ONLY into a new 0700 backup-area directory, never /etc.

    This is deliberately NOT a primary MTA configuration restore. It never
    modifies active paths, config, queues or services. Keys remain root-only.
    """
    if mta not in ALLOWED or not ID.fullmatch(snapshot_id):
        raise Refused("invalid_export_selection")
    folder = base / mta
    safe_dir(base, owner_uid)
    safe_dir(folder, owner_uid)
    directory = folder / snapshot_id
    accepted = verify(directory, mta, owner_uid)
    manifest = json.loads(stable_file(directory / "manifest.json", owner_uid)[1])
    # V2 export is explicit, private and metadata-complete, but never an
    # automatic Restore. Symlink targets are recorded as inert JSON only.
    if manifest["version"] == 2:
        return _export_sendmail_package_v2(
            directory, folder, manifest, accepted, owner_uid)
    target = Path(tempfile.mkdtemp(prefix=".offline-recovery-", dir=str(folder)))
    try:
        safe_dir(target, owner_uid)
        seen = set()
        with tarfile.open(str(directory / "config.tar.gz"), "r:gz") as tar:
            for member in tar:
                name = member.name
                parts = name.split("/")
                if (name not in manifest["files"] or
                        member.type != tarfile.REGTYPE or
                        not parts or any(not part or part in (".", "..") or
                                         len(part) > 255 for part in parts) or
                        not any(name.startswith(prefix + "/") or name == prefix
                                for prefix in ALLOWED[mta]) or
                        name in seen):
                    raise Refused("invalid_offline_export_member")
                seen.add(name)
                dest = target
                for component in parts[:-1]:
                    dest = dest / component
                    if not dest.exists() and not dest.is_symlink():
                        dest.mkdir(mode=0o700)
                    safe_dir(dest, owner_uid)
                final = dest / parts[-1]
                stream = tar.extractfile(member)
                if stream is None:
                    raise Refused("offline_export_member_unreadable")
                contents = stream.read(member.size + 1)
                item = manifest["files"][name]
                if (len(contents) != member.size or
                        hashlib.sha256(contents).hexdigest() != item["sha256"]):
                    raise Refused("offline_export_member_changed")
                flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_CLOEXEC", 0))
                fd = os.open(str(final), flags, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(contents)
                    output.flush()
                    os.fsync(output.fileno())
        if len(seen) != accepted["files"] or seen != set(manifest["files"]):
            raise Refused("incomplete_offline_export")
        return str(target), accepted
    except Exception:
        shutil.rmtree(str(target), ignore_errors=True)
        raise



def listed(mta, base=BASE, owner_uid=0):
    if mta not in ALLOWED:
        raise Refused("invalid_mta")
    if not base.exists() and not base.is_symlink():
        return []
    safe_dir(base, owner_uid)
    directory = base / mta
    if not directory.exists() and not directory.is_symlink():
        return []
    safe_dir(directory, owner_uid)
    results = []
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        if not ID.fullmatch(entry.name):
            continue
        try:
            verify(entry, mta, owner_uid)
        except (Refused, OSError, ValueError):
            continue
        results.append(entry.name)
        if len(results) > 128:
            raise Refused("too_many_snapshots")
    return results



def read_only_probe(args, timeout=8):
    """Bounded commands from a fixed allowlist; no shell or output forwarding."""
    if not args or args[0] not in ("systemctl", "pgrep", "exim", "exim4",
                                  "sendmail", "ss"):
        raise Refused("unsafe_mta_preflight_probe")
    binary = shutil.which(args[0])
    if not binary or not os.path.isabs(binary):
        return None
    # Root must not execute an attacker-supplied PATH executable, even for
    # a read-only status query. Resolve distribution-managed alternatives.
    resolved = os.path.realpath(binary)
    if not resolved.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")):
        return None
    try:
        meta = os.stat(resolved)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or                 meta.st_mode & 0o022:
            return None
        result = subprocess.run(
            [binary] + list(args[1:]), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        if len(result.stdout) > 8192:
            return None
        return result.returncode, result.stdout.decode("ascii", errors="replace")
    except (OSError, subprocess.TimeoutExpired, UnicodeError, ValueError):
        return None


def offline_service_state(mta, probe=read_only_probe):
    """Inactive is advisory, not proof no worker remains or no TCP listener."""
    units = (("exim.service", "exim4.service") if mta == "exim"
             else ("sendmail.service", "sm-client.service"))
    loaded = 0
    active = False
    for unit in units:
        result = probe(["systemctl", "show", "--property=LoadState",
                        "--property=ActiveState", unit])
        if result is None or result[0] != 0:
            return "unverified"
        values = {}
        for line in result[1].splitlines():
            if "=" not in line:
                return "unverified"
            key, value = line.split("=", 1)
            if key in values or key not in ("LoadState", "ActiveState"):
                return "unverified"
            values[key] = value
        if set(values) != {"LoadState", "ActiveState"}:
            return "unverified"
        if values["LoadState"] == "not-found":
            if values["ActiveState"] not in ("inactive", "unknown"):
                return "unverified"
            continue
        if values["LoadState"] != "loaded":
            return "unverified"
        loaded += 1
        if values["ActiveState"] in ("active", "activating", "reloading",
                                     "deactivating"):
            active = True
        elif values["ActiveState"] != "inactive":
            return "unverified"  # failed/masked/unknown need human review
    if active:
        return "running"
    return "stopped_declared" if loaded else "unverified"


def offline_process_state(mta, probe=read_only_probe):
    names = ("exim", "exim4") if mta == "exim" else ("sendmail",)
    for name in names:
        result = probe(["pgrep", "-x", name])
        if result is None:
            return "unverified"
        code, output = result
        if code == 0:
            lines = [x.strip() for x in output.splitlines()]
            if not lines or any(not re.fullmatch(r"[0-9]{1,10}", x)
                                for x in lines):
                return "unverified"
            return "running"
        if code != 1 or output.strip():
            return "unverified"
    return "none_observed"


def offline_listener_state(mta, probe=read_only_probe):
    """Bounded TCP listener/process hint; never a port ownership guarantee."""
    result = probe(["ss", "-ltnp"])
    if result is None or result[0] != 0:
        return "unverified"
    lines = result[1].splitlines()
    if not lines or len(lines) > 256 or "State" not in lines[0]:
        return "unverified"
    for line in lines[1:]:
        if not line.startswith("LISTEN "):
            return "unverified"
        columns = line.split()
        if len(columns) < 5 or ":" not in columns[3]:
            return "unverified"
        # Only parse the LOCAL address:port column. A regex lookbehind on
        # ":25" incorrectly misses ordinary IPv4 addresses ending in a
        # digit (0.0.0.0:25). Never match the peer address or process text.
        port_text = columns[3].rsplit(":", 1)[-1]
        if not re.fullmatch(r"[0-9]{1,5}", port_text):
            return "unverified"
        port = int(port_text)
        if not 1 <= port <= 65535:
            return "unverified"
        match = re.search(r'users:\(\("(exim4?|sendmail)",pid=[0-9]{1,10},fd=[0-9]{1,10}\)', line)
        if match and ((mta == "exim" and match.group(1) in ("exim", "exim4")) or
                      (mta == "sendmail" and match.group(1) == "sendmail")):
            return "running"
        # Any standard SMTP listener blocks automatic claims of a quiescent
        # host, even when owned by another daemon; it may be part of delivery.
        if port in (25, 465, 587, 2525):
            return "unverified"
    return "none_observed"


def offline_queue_state(mta, probe=read_only_probe):
    """Only a bounded *hint*; aliases, spool paths and client queue need QA."""
    if mta == "exim":
        result = probe(["exim4", "-bpc"])
        if result is None:
            result = probe(["exim", "-bpc"])
        if result is None or result[0] != 0:
            return "unverified"
        value = result[1].strip()
        if not re.fullmatch(r"[0-9]{1,9}", value):
            return "unverified"
        return "empty_reported" if int(value) == 0 else "nonempty_reported"
    states = []
    for argv in (["sendmail", "-bp"], ["sendmail", "-Ac", "-bp"]):
        result = probe(argv)
        if result is None or result[0] != 0:
            return "unverified"
        text = result[1].strip()
        if len(text) > 8192 or not text:
            return "unverified"
        if re.search(r"(?im)^(?:Mail queue is empty|/[^\r\n]+ is empty)\.?$", text):
            states.append("empty")
        elif re.search(r"(?im)^Total requests:\s*0\s*$", text):
            states.append("empty")
        elif re.search(r"(?im)^Total requests:\s*[1-9][0-9]*\s*$", text):
            states.append("nonempty")
        else:
            return "unverified"
    return "empty_reported" if states == ["empty", "empty"] else "nonempty_reported"


def offline_recovery_preflight(mta, snapshot_id, root=ROOT, base=BASE,
                               owner_uid=0, probe=read_only_probe):
    """Read-only safety report. Does NOT enable or authorize primary MTA restore."""
    if mta not in ALLOWED or not isinstance(snapshot_id, str) or \
            not ID.fullmatch(snapshot_id):
        raise Refused("invalid_mta_offline_preflight_selection")
    snapshot = base / mta / snapshot_id
    evidence = verify(snapshot, mta, owner_uid)
    comparison = recovery_preview(mta, snapshot_id, root, base, owner_uid)["current"]
    service = offline_service_state(mta, probe)
    processes = offline_process_state(mta, probe)
    queue = offline_queue_state(mta, probe)
    listener = offline_listener_state(mta, probe)
    # Even all-green preflight is not a recoverability guarantee: it doesn't
    # validate external certs, aliases, unit files, DNS or custom queue paths.
    if service == "running" or processes == "running" or listener == "running":
        gate = "blocked_running"
    elif queue == "nonempty_reported":
        gate = "blocked_nonempty_queue"
    elif service != "stopped_declared" or processes != "none_observed" or \
            queue != "empty_reported" or listener != "none_observed":
        gate = "blocked_unverified"
    elif comparison == "unverified":
        gate = "blocked_unverified"
    else:
        gate = "offline_candidate_manual_recovery_only"
    digest_data = json.dumps({
        "mta": mta, "snapshot_id": snapshot_id, "archive": evidence["sha256"],
        "current": comparison, "service": service,
        "processes": processes, "queue": queue, "listener": listener,
        "gate": gate
    }, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {
        "mta": mta, "snapshot_id": snapshot_id, "archive_sha256": evidence["sha256"],
        "preflight_sha256": hashlib.sha256(digest_data).hexdigest(),
        "current": comparison, "service": service, "processes": processes,
        "queue": queue, "listener": listener, "gate": gate
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verified root-only Exim/Sendmail config backup")
    ap.add_argument("--mta", choices=("exim", "sendmail"), required=True)
    actions = ap.add_mutually_exclusive_group(required=True)
    actions.add_argument("--backup", action="store_true")
    actions.add_argument("--list", action="store_true")
    actions.add_argument("--verify")
    actions.add_argument("--preview-recovery")
    actions.add_argument("--offline-preflight")
    actions.add_argument("--export-offline")
    actions.add_argument("--self-test", action="store_true")
    ap.add_argument("--confirm", default="")
    opts = ap.parse_args(argv)
    if opts.self_test:
        assert ID.fullmatch("20261121T005501Z-abcdef012345")
        assert not ID.fullmatch("../etc/mail")
        assert ALLOWED["sendmail"][0] == "etc/mail"
        print("FOREIGN_BACKUP_SELF_TEST=pass")
        return 0
    if opts.export_offline is not None:
        if opts.confirm != "EXTRACT_VERIFIED_FOREIGN_MTA_SNAPSHOT":
            print("FOREIGN_BACKUP_STATUS=confirmation_required", file=sys.stderr)
            return 2
    elif opts.confirm:
        print("FOREIGN_BACKUP_STATUS=unexpected_confirmation", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("FOREIGN_BACKUP_STATUS=refused_root_required", file=sys.stderr)
        return 2
    try:
        if opts.backup:
            backup_id, result = backup(opts.mta)
            print("FOREIGN_BACKUP_ID=" + backup_id)
            print("FOREIGN_BACKUP_ARCHIVE_SHA256=" + result["sha256"])
            print("FOREIGN_BACKUP_FILE_COUNT=" + str(result["files"]))
            print("FOREIGN_BACKUP_FORMAT=" + result["format"])
            print("FOREIGN_BACKUP_STATUS=verified")
        elif opts.list:
            items = listed(opts.mta)
            for backup_id in items:
                print("FOREIGN_BACKUP_ID=" + backup_id)
            print("FOREIGN_BACKUP_COUNT=" + str(len(items)))
            print("FOREIGN_BACKUP_STATUS=verified_list")
        elif opts.preview_recovery is not None:
            state = recovery_preview(opts.mta, opts.preview_recovery)
            print("FOREIGN_BACKUP_CURRENT_CONFIG_MATCH=" + state["current"])
            print("FOREIGN_BACKUP_ARCHIVE_SHA256=" + state["snapshot"]["sha256"])
            print("FOREIGN_BACKUP_FORMAT=" + state["snapshot"]["format"])
            print("FOREIGN_BACKUP_STATUS=recovery_preview_only")
        elif opts.offline_preflight is not None:
            info = offline_recovery_preflight(opts.mta, opts.offline_preflight)
            print("FOREIGN_PREFLIGHT_SERVICE=" + info["service"])
            print("FOREIGN_PREFLIGHT_PROCESSES=" + info["processes"])
            print("FOREIGN_PREFLIGHT_QUEUE=" + info["queue"])
            print("FOREIGN_PREFLIGHT_LISTENER=" + info["listener"])
            print("FOREIGN_PREFLIGHT_CONFIG_MATCH=" + info["current"])
            print("FOREIGN_PREFLIGHT_ARCHIVE_SHA256=" + info["archive_sha256"])
            print("FOREIGN_PREFLIGHT_PLAN_SHA256=" + info["preflight_sha256"])
            print("FOREIGN_PREFLIGHT_GATE=" + info["gate"])
            print("FOREIGN_PREFLIGHT_STATUS=read_only_no_restore")
        elif opts.export_offline is not None:
            path, info = extract_offline(opts.mta, opts.export_offline)
            print("FOREIGN_BACKUP_OFFLINE_DIRECTORY=" + path)
            print("FOREIGN_BACKUP_ARCHIVE_SHA256=" + info["sha256"])
            print("FOREIGN_BACKUP_FILE_COUNT=" + str(info["files"]))
            print("FOREIGN_BACKUP_FORMAT=" + info["format"])
            print("FOREIGN_BACKUP_OFFLINE_LINKS_MATERIALIZED=no")
            print("FOREIGN_BACKUP_STATUS=exported_offline_only")
        else:
            if not ID.fullmatch(opts.verify):
                raise Refused("invalid_backup_identifier")
            result = verify(BASE / opts.mta / opts.verify, opts.mta)
            print("FOREIGN_BACKUP_ARCHIVE_SHA256=" + result["sha256"])
            print("FOREIGN_BACKUP_FORMAT=" + result["format"])
            print("FOREIGN_BACKUP_STATUS=verified")
        print("FOREIGN_BACKUP_MTA=" + opts.mta)
        print("FOREIGN_BACKUP_PRIMARY_CONFIG_CHANGED=no")
        print("FOREIGN_BACKUP_MAIL_QUEUE_CHANGED=no")
        print("FOREIGN_BACKUP_SERVICE_CHANGED=no")
        print("FOREIGN_BACKUP_RESTORE_ENABLED=no")
        return 0
    except (Refused, OSError, ValueError, tarfile.TarError):
        print("FOREIGN_BACKUP_STATUS=refused_or_unverified", file=sys.stderr)
        print("FOREIGN_BACKUP_PRIMARY_CONFIG_CHANGED=no", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
