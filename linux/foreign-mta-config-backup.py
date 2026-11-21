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


def selected_files(mta, root=ROOT, owner_uid=0):
    """Strict allowlisted tree walk. A symlink anywhere is a hard refusal."""
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
            safe_dir(source, owner_uid)
            found += 1 if name in MANDATORY[mta] else 0
            pending = [source]
            while pending:
                directory = pending.pop()
                safe_dir(directory, owner_uid)
                for path in sorted(directory.iterdir(), key=lambda p: p.name):
                    if path.is_symlink():
                        raise Refused("symlink_in_existing_mta_configuration")
                    if len(str(path.relative_to(root)).encode("utf-8")) > 512:
                        raise Refused("configuration_path_too_long")
                    if path.is_dir():
                        safe_dir(path, owner_uid)
                        pending.append(path)
                    else:
                        safe_regular(path, owner_uid)
                        relative = path.relative_to(root).as_posix()
                        if relative in entries:
                            raise Refused("duplicate_configuration_path")
                        entries[relative] = path
        elif stat.S_ISREG(st.st_mode) and name in MANDATORY[mta]:
            # Exim/Sendmail primary configuration roots must be directories.
            # A file in their place is not a valid complete MTA snapshot.
            raise Refused("primary_mta_config_root_not_directory")
        elif stat.S_ISREG(st.st_mode):
            safe_regular(source, owner_uid)
            entries[name] = source
        else:
            raise Refused("nonregular_configuration_object")
    if found == 0 or not entries:
        raise Refused("existing_mta_configuration_not_found")
    if len(entries) > MAX_FILES or sum(p.lstat().st_size for p in entries.values()) > MAX_BYTES:
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
    strict_snapshot_dir(directory, owner_uid)
    raw = stable_file(directory / "manifest.json", owner_uid)[1]
    if len(raw) > MAX_MANIFEST:
        raise Refused("oversized_snapshot_manifest")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise Refused("bad_snapshot_manifest")
    if (not isinstance(manifest, dict) or manifest.get("version") != 1 or
            manifest.get("mta") != mta or
            not isinstance(manifest.get("files"), dict) or
            not 1 <= len(manifest["files"]) <= MAX_FILES or
            not isinstance(manifest.get("sha256"), str) or
            not SHA.fullmatch(manifest["sha256"])):
        raise Refused("invalid_snapshot_manifest")
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
            "sha256": manifest["sha256"], "mta": mta}


def backup(mta, root=ROOT, base=BASE, owner_uid=0):
    files = selected_files(mta, root, owner_uid)
    directory = archive_folder(base, mta, owner_uid)
    staging = Path(tempfile.mkdtemp(prefix=".pending-", dir=str(directory)))
    try:
        safe_dir(staging, owner_uid)
        manifest = {"version": 1, "mta": mta, "files": {}}
        archive = staging / "config.tar.gz"
        with archive.open("xb") as output:
            os.chmod(str(archive), 0o600)
            with tarfile.open(fileobj=output, mode="w:gz") as tar:
                total = 0
                for name, path in sorted(files.items()):
                    current, content = stable_file(path, owner_uid)
                    total += len(content)
                    if total > MAX_BYTES:
                        raise Refused("configuration_changed_or_over_limit")
                    entry = tarfile.TarInfo(name)
                    entry.type = tarfile.REGTYPE
                    entry.size = len(content)
                    entry.uid, entry.gid = current.st_uid, current.st_gid
                    entry.mode, entry.mtime = stat.S_IMODE(current.st_mode), int(current.st_mtime)
                    tar.addfile(entry, io.BytesIO(content))
                    manifest["files"][name] = {
                        "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
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
        files = selected_files(mta, root, owner_uid)
        same = len(files) == verified["files"]
        if same:
            for name, path in files.items():
                expected = manifest["files"].get(name)
                if not expected:
                    same = False
                    break
                meta, contents = stable_file(path, owner_uid)
                if (meta.st_size != expected["size"] or
                        hashlib.sha256(contents).hexdigest() != expected["sha256"]):
                    same = False
                    break
        state = "identical" if same else "different"
    except (OSError, ValueError, Refused):
        state = "unverified"
    return {"snapshot": verified, "current": state}


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


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verified root-only Exim/Sendmail config backup")
    ap.add_argument("--mta", choices=("exim", "sendmail"), required=True)
    actions = ap.add_mutually_exclusive_group(required=True)
    actions.add_argument("--backup", action="store_true")
    actions.add_argument("--list", action="store_true")
    actions.add_argument("--verify")
    actions.add_argument("--preview-recovery")
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
    if ((opts.export_offline is not None) !=
            (opts.confirm == "EXTRACT_VERIFIED_FOREIGN_MTA_SNAPSHOT")):
        print("FOREIGN_BACKUP_STATUS=confirmation_required", file=sys.stderr)
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
            print("FOREIGN_BACKUP_STATUS=recovery_preview_only")
        elif opts.export_offline is not None:
            path, info = extract_offline(opts.mta, opts.export_offline)
            print("FOREIGN_BACKUP_OFFLINE_DIRECTORY=" + path)
            print("FOREIGN_BACKUP_ARCHIVE_SHA256=" + info["sha256"])
            print("FOREIGN_BACKUP_FILE_COUNT=" + str(info["files"]))
            print("FOREIGN_BACKUP_STATUS=exported_offline_only")
        else:
            if not ID.fullmatch(opts.verify):
                raise Refused("invalid_backup_identifier")
            result = verify(BASE / opts.mta / opts.verify, opts.mta)
            print("FOREIGN_BACKUP_ARCHIVE_SHA256=" + result["sha256"])
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
