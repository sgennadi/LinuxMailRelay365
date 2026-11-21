#!/usr/bin/env python3
"""Disposable CI-only Sendmail v2 package metadata recovery rehearsal.

Reconstruct file ownership, modes and symlink texts inside a throwaway,
root-private directory under the *backup* tree, never active /etc/mail.
The original v2 export remains inert; the test materializes package links
ONLY in this fenced ephemeral rehearsal and never resolves their targets.

This is not a real mail service restore: no queues, runtime service, TLS,
Entra tenant, or active /etc files are touched.
"""
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

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "lmr365_v2_rehearsal_backup", ROOT / "linux/foreign-mta-config-backup.py")
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


def fail(reason):
    raise RuntimeError("SENDMAIL_V2_REHEARSAL_" + reason)


def relative_parts(name):
    if (not isinstance(name, str) or not name or len(name.encode("utf-8")) > 512
            or name.startswith("/") or "\\" in name):
        fail("BAD_PATH")
    parts = name.split("/")
    if any(not part or part in (".", "..") or len(part) > 255 for part in parts):
        fail("BAD_PATH")
    return parts


def safe_parents(root, parts):
    location = root
    for part in parts:
        location = location / part
        if not os.path.lexists(str(location)):
            location.mkdir(mode=0o700)
        st = location.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
            fail("UNSAFE_TEMP_PARENT")
    return location


def preserve_metadata(destination, entry, symlink=False):
    uid, gid = entry["uid"], entry["gid"]
    if (type(uid) is not int or type(gid) is not int
            or not 0 <= uid <= 65535 or not 0 <= gid <= 65535):
        fail("BAD_IDENTITY")
    os.chown(str(destination), uid, gid, follow_symlinks=False)
    if not symlink:
        mode = entry["mode"]
        if (type(mode) is not int or mode < 0 or mode > 0o7777
                or mode & 0o022):
            fail("UNSAFE_PACKAGE_MODE")
        os.chmod(str(destination), mode, follow_symlinks=False)


def check_metadata(path, entry, symlink=False):
    st = path.lstat()
    if st.st_uid != entry["uid"] or st.st_gid != entry["gid"]:
        fail("OWNER_OR_GROUP_MISMATCH")
    if symlink:
        if (not stat.S_ISLNK(st.st_mode) or
                os.readlink(str(path)) != entry["target"]):
            fail("SYMLINK_TARGET_MISMATCH")
    elif stat.S_IMODE(st.st_mode) != entry["mode"]:
        fail("PERMISSION_MISMATCH")


def rehearse(export, snapshot_id):
    if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        fail("DISPOSABLE_CI_ROOT_ONLY")
    base = backup.BASE / "sendmail"
    if (export.parent != base or
            not re.fullmatch(r"\.offline-recovery-[A-Za-z0-9_-]{8,20}", export.name)
            or not backup.ID.fullmatch(snapshot_id)):
        fail("UNTRUSTED_EXPORT_PATH")
    backup.safe_dir(backup.BASE)
    backup.safe_dir(base)
    backup.safe_dir(export)
    approved = backup.verify(base / snapshot_id, "sendmail", 0)
    if backup.verify(export, "sendmail", 0) != approved:
        fail("EXPORT_ARCHIVE_MISMATCH")
    manifest = json.loads((export / "manifest.json").read_text(encoding="utf-8"))
    record = json.loads((export / "PACKAGE_RECOVERY_METADATA.json").read_text(
        encoding="utf-8"))
    if (approved["format"] != "v2_package_metadata" or
            record.get("format") != "sendmail_v2_inert_metadata_only" or
            record.get("source_archive_sha256") != approved["sha256"] or
            record.get("objects") != manifest["objects"] or
            record.get("files") != manifest["files"] or
            record.get("symlinks_materialized") is not False or
            record.get("automatic_live_restore_supported") is not False):
        fail("UNVERIFIED_REHEARSAL_SOURCE")

    # Outer temporary dir remains owned by root and mode 0700, preventing
    # service account processes from entering even if inner directories are
    # restored to package ownership/permissions.
    with tempfile.TemporaryDirectory(prefix=".sendmail-v2-rehearsal-", dir=str(base)) as td:
        root = Path(td)
        backup.safe_dir(root)
        staged = root / "simulated-root"
        staged.mkdir(mode=0o700)
        files = manifest["files"]
        objects = manifest["objects"]
        if not files or not objects:
            fail("EMPTY_MANIFEST")

        # Prepare all directories while the tree is still private and owned
        # by root, then write verified regular files. No symlink is present
        # during either step.
        for name, item in sorted(objects.items()):
            if item["kind"] == "directory":
                safe_parents(staged, relative_parts(name))
        for name, item in sorted(files.items()):
            parts = relative_parts(name)
            parent = safe_parents(staged, parts[:-1])
            source = export.joinpath(*parts)
            backup.safe_regular(source, 0, mode=0o600)
            content = source.read_bytes()
            if (len(content) != item["size"] or
                    hashlib.sha256(content).hexdigest() != item["sha256"]):
                fail("EXPORTED_DATA_MISMATCH")
            destination = parent / parts[-1]
            with destination.open("xb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            preserve_metadata(destination, item)
            check_metadata(destination, item)
            if hashlib.sha256(destination.read_bytes()).hexdigest() != item["sha256"]:
                fail("RECREATED_DATA_HASH_MISMATCH")

        # Links are ONLY created in the isolated rehearsal after all file
        # writes, and only for the allowlisted path keys already verified.
        links = 0
        for name, item in sorted(objects.items()):
            if item["kind"] != "symlink":
                continue
            if name not in backup.PACKAGE_LINKS:
                fail("UNAPPROVED_PACKAGE_LINK")
            parts = relative_parts(name)
            destination = safe_parents(staged, parts[:-1]) / parts[-1]
            if os.path.lexists(str(destination)):
                fail("PACKAGE_LINK_COLLISION")
            os.symlink(item["target"], str(destination))
            preserve_metadata(destination, item, symlink=True)
            check_metadata(destination, item, symlink=True)
            links += 1

        # Apply exact directory metadata from leaves to root, so a root-owned
        # private parent prevents any nonroot service from reaching the tree.
        for name, item in sorted(objects.items(),
                                 key=lambda x: (-len(relative_parts(x[0])), x[0])):
            if item["kind"] == "directory":
                destination = staged.joinpath(*relative_parts(name))
                preserve_metadata(destination, item)
                check_metadata(destination, item)

        if stat.S_IMODE(root.lstat().st_mode) != 0o700:
            fail("ISOLATION_DIRECTORY_MODE")
        for name, item in files.items():
            dest = staged.joinpath(*relative_parts(name))
            check_metadata(dest, item)
            if hashlib.sha256(dest.read_bytes()).hexdigest() != item["sha256"]:
                fail("FINAL_FILE_DIGEST_MISMATCH")
        for name, item in objects.items():
            dest = staged.joinpath(*relative_parts(name))
            check_metadata(dest, item, symlink=item["kind"] == "symlink")
        if not any(item["kind"] == "directory" for item in objects.values()):
            fail("DIRECTORY_METADATA_MISSING")
        print("SENDMAIL_V2_REHEARSAL_DATA_HASHES=verified")
        print("SENDMAIL_V2_REHEARSAL_OWNER_MODE=verified")
        print("SENDMAIL_V2_REHEARSAL_PACKAGE_LINKS=verified_" + str(links))
        print("SENDMAIL_V2_REHEARSAL_SERVICES_STARTED=no")
        print("SENDMAIL_V2_REHEARSAL_ACTIVE_ETC_CHANGED=no")
    if any(base.glob(".sendmail-v2-rehearsal-*")):
        fail("TEMPORARY_TREE_NOT_CLEANED")
    print("SENDMAIL_V2_REHEARSAL_TEMP_CLEANUP=verified")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        fail("EXPECTED_EXPORT_PATH_AND_SNAPSHOT_ID")
    rehearse(Path(sys.argv[1]), sys.argv[2])
