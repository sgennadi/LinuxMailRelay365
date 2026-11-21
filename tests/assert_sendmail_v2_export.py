#!/usr/bin/env python3
"""CI-only read-only inspection of Sendmail v2 private export."""
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "sendmail_export_verifier", ROOT / "linux/foreign-mta-config-backup.py")
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("SENDMAIL_V2_EXPORT_DISPOSABLE_CI_ONLY")
    path = Path(sys.argv[1])
    backup_id = sys.argv[2]
    if not snapshot.ID.fullmatch(backup_id):
        raise SystemExit("SENDMAIL_V2_EXPORT_BAD_BACKUP_ID")
    base = snapshot.BASE / "sendmail"
    if (path.parent != base or
            not re.fullmatch(r"\.offline-recovery-[A-Za-z0-9_-]{8,20}", path.name)):
        raise SystemExit("SENDMAIL_V2_EXPORT_PATH_NOT_EXPECTED")
    snapshot.safe_dir(snapshot.BASE)
    snapshot.safe_dir(base)
    snapshot.safe_dir(path)
    if stat.S_IMODE(path.lstat().st_mode) != 0o700:
        raise SystemExit("SENDMAIL_V2_EXPORT_DIRECTORY_NOT_PRIVATE")
    for entry in path.rglob("*"):
        st = entry.lstat()
        if st.st_uid != 0 or stat.S_ISLNK(st.st_mode):
            raise SystemExit("SENDMAIL_V2_EXPORT_UNSAFE_OWNER_OR_LINK")
        mode = stat.S_IMODE(st.st_mode)
        if (stat.S_ISDIR(st.st_mode) and mode != 0o700 or
                stat.S_ISREG(st.st_mode) and mode != 0o600 or
                not stat.S_ISREG(st.st_mode) and not stat.S_ISDIR(st.st_mode)):
            raise SystemExit("SENDMAIL_V2_EXPORT_UNSAFE_FILE_MODE")

    original = snapshot.verify(base / backup_id, "sendmail", 0)
    exported = snapshot.verify(path, "sendmail", 0)
    if original != exported or original["format"] != "v2_package_metadata":
        raise SystemExit("SENDMAIL_V2_EXPORT_ARCHIVE_DIFFERS")
    manifest = json.loads((path / "manifest.json").read_text())
    metadata = json.loads((path / "PACKAGE_RECOVERY_METADATA.json").read_text())
    if (metadata.get("format") != "sendmail_v2_inert_metadata_only" or
            metadata.get("source_archive_sha256") != original["sha256"] or
            metadata.get("objects") != manifest["objects"] or
            metadata.get("files") != manifest["files"] or
            metadata.get("symlinks_materialized") is not False or
            metadata.get("original_permissions_or_owners_applied") is not False or
            metadata.get("active_etc_modified") is not False or
            metadata.get("automatic_live_restore_supported") is not False):
        raise SystemExit("SENDMAIL_V2_EXPORT_METADATA_MISMATCH")
    if not (path / "READ_ME_BEFORE_RECOVERY.txt").read_bytes().startswith(
            b"OFFLINE REVIEW ONLY."):
        raise SystemExit("SENDMAIL_V2_EXPORT_WARNING_ABSENT")
    import hashlib
    for name, evidence in manifest["files"].items():
        data = (path / name).read_bytes()
        if (len(data) != evidence["size"] or
                hashlib.sha256(data).hexdigest() != evidence["sha256"]):
            raise SystemExit("SENDMAIL_V2_EXPORT_FILE_HASH_MISMATCH")
    for name, evidence in manifest["objects"].items():
        if evidence["kind"] == "symlink" and os.path.lexists(str(path / name)):
            raise SystemExit("SENDMAIL_V2_EXPORT_LINK_MATERIALIZED")
    # A private export must be a complete and exact copy of declared data
    # plus only the non-executable review markers.
    expected = set(manifest["files"]) | {
        "manifest.json", "config.tar.gz",
        "PACKAGE_RECOVERY_METADATA.json", "READ_ME_BEFORE_RECOVERY.txt"}
    actual = {str(item.relative_to(path).as_posix())
              for item in path.rglob("*") if item.is_file()}
    if actual != expected:
        raise SystemExit("SENDMAIL_V2_EXPORT_FILE_SET_MISMATCH")
    print("SENDMAIL_V2_EXPORT_ARCHIVE=verified")
    print("SENDMAIL_V2_EXPORT_DATA_HASHES=verified")
    print("SENDMAIL_V2_EXPORT_ALL_PATHS_PRIVATE=yes")
    print("SENDMAIL_V2_EXPORT_SYMLINKS_MATERIALIZED=no")
    print("SENDMAIL_V2_EXPORT_AUTOMATIC_RESTORE_ENABLED=no")


if __name__ == "__main__":
    main()
