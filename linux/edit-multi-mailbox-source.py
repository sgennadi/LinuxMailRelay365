#!/usr/bin/env python3
"""Edit only the prepared root-only multi-mailbox TSV; never activate it.

Python 3.6+. Two-phase approval binds exact old/new map bytes and all
remaining public identity evidence. No credential creation or deletion.
"""
import fcntl
import grp
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

_spec = importlib.util.spec_from_file_location(
    "source_identity_inventory", str(Path(__file__).with_name("inspect-multi-mailbox-identities.py")))
I = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(I)
A, E = I.A, I.E
BASE, SOURCE, IDENTITIES = I.BASE, I.SOURCE, I.IDENTITIES
BACKUPS = BASE / "oauth-source-backups"
# Coordinate with the existing offline route installer.
LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")
CONFIRM = "SAVE_PLANNED_MAILBOX_MAP"
RESTORE_CONFIRM = "RESTORE_PLANNED_MAILBOX_MAP"
BACKUP_ID = re.compile(r"source-[a-z0-9_]{8}\Z")
FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.json\Z")
Refused = I.Refused
need = I.need


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def request(raw):
    need(1 <= len(raw) <= 4096, "request_size")
    obj = I.decode(raw)
    need(isinstance(obj, dict), "request_fields")
    if obj.get("action") == "list_backups":
        need(set(obj) == {"action", "base_sha", "nonce"} and
             all(isinstance(v, str) for v in obj.values()) and
             I.SHA.fullmatch(obj["base_sha"]) and I.SHA.fullmatch(obj["nonce"]),
             "backup_catalog_context")
        return obj
    fields = {"action", "base_sha", "old_mailbox", "login", "mailbox",
              "identity_file", "nonce", "approval", "confirm"}
    restoring = obj.get("action") == "restore"
    if restoring:
        fields.add("backup_id")
    need(set(obj) == fields and all(isinstance(v, str) for v in obj.values()), "request_fields")
    if restoring:
        need(I.SHA.fullmatch(obj["base_sha"]) and I.SHA.fullmatch(obj["nonce"]) and
             BACKUP_ID.fullmatch(obj["backup_id"]) and not any(obj[k] for k in
                 ("old_mailbox", "login", "mailbox", "identity_file")), "restore_context")
        need((obj["approval"] == "" and obj["confirm"] == "") or
             (I.SHA.fullmatch(obj["approval"]) and obj["confirm"] == RESTORE_CONFIRM),
             "restore_approval_context")
        return obj
    need(obj["action"] in ("add", "edit", "remove") and I.SHA.fullmatch(obj["nonce"]) and
         (obj["base_sha"] == "" or I.SHA.fullmatch(obj["base_sha"])), "request_context")
    need((obj["approval"] == "" and obj["confirm"] == "") or
         (I.SHA.fullmatch(obj["approval"]) and obj["confirm"] == CONFIRM), "approval_context")
    need((obj["action"] == "add" and obj["old_mailbox"] == "") or
         (obj["action"] != "add" and I.valid_mailbox(obj["old_mailbox"])), "selected_mailbox")
    if obj["action"] == "remove":
        need(not any(obj[k] for k in ("login", "mailbox", "identity_file")), "remove_fields")
    else:
        need(I.LOGIN.fullmatch(obj["login"]) and I.valid_mailbox(obj["mailbox"]) and
             (not obj["identity_file"] or FILE.fullmatch(obj["identity_file"])), "identity_fields")
    return obj


def render(rows):
    return (A.HEADER + "\n" + "".join("\t".join(row) + "\n" for row in rows)).encode("ascii")


def read_source():
    E.trusted_directory(BASE)
    raw = I.read_optional(SOURCE, A.MAX_MAP, (0o600,))
    if raw is None:
        return None, []
    return raw, canonical_rows(raw)


def canonical_rows(raw):
    rows = A.parse_map(raw)
    # Do not silently normalize/rewrite existing unrelated rows. An older
    # noncanonical file needs manual review before using this editor.
    need(raw == render(rows) and len(rows) <= 64 and
         all(I.LOGIN.fullmatch(r[0]) and I.valid_mailbox(r[1]) and r[1] == r[2] and
             Path(r[3]).parent == IDENTITIES and FILE.fullmatch(Path(r[3]).name)
             for r in rows), "source_requires_manual_review")
    return rows


def identity_path(req, previous, gid):
    login, mailbox = req["login"], req["mailbox"]
    if req["identity_file"]:
        return str(IDENTITIES / req["identity_file"])
    if previous is not None and previous[2] == mailbox:
        return previous[3]
    E.trusted_directory(IDENTITIES)
    # Auto-select only one exact valid existing identity. Never choose
    # between duplicate identities or enumerate an unbounded directory.
    matches = []
    with os.scandir(str(IDENTITIES)) as entries:
        for index, entry in enumerate(entries):
            need(index < 256, "identity_catalog_too_large")
            if not FILE.fullmatch(entry.name):
                continue
            candidate = str(IDENTITIES / entry.name)
            row = I.identity_row(login, mailbox, mailbox, candidate, gid)
            if row["status"] == "public_certificate_read":
                matches.append(candidate)
    need(len(matches) == 1, "exact_existing_identity_required")
    return matches[0]


def restore_backup(req):
    """Verify backup metadata and canonical bytes without reading identities."""
    need(BACKUP_ID.fullmatch(req["backup_id"]), "invalid_backup_id")
    E.trusted_directory(BACKUPS)
    folder = BACKUPS / req["backup_id"]
    E.trusted_directory(folder)
    need(stat.S_IMODE(BACKUPS.lstat().st_mode) == 0o700 and
         stat.S_IMODE(folder.lstat().st_mode) == 0o700, "backup_not_private")
    manifest_raw = E.secure_read(folder / "manifest.json", 4096, modes=(0o600,))
    manifest = I.decode(manifest_raw)
    need(isinstance(manifest, dict) and set(manifest) == {"version", "source_was_present",
         "old_sha256", "new_sha256", "plan_sha256"} and
         type(manifest["version"]) is int and manifest["version"] == 1 and
         type(manifest["source_was_present"]) is bool and
         all(isinstance(manifest[k], str) for k in
             ("old_sha256", "new_sha256", "plan_sha256")), "invalid_backup_manifest")
    # A first-map creation backup intentionally contains no previous file.
    # Restoring it would delete the only source map; require separate
    # decommission review rather than silently implementing deletion.
    need(manifest["source_was_present"], "absent_source_requires_decommission")
    need(all(I.SHA.fullmatch(manifest[k]) for k in
             ("old_sha256", "new_sha256", "plan_sha256")) and
         manifest["old_sha256"] != manifest["new_sha256"], "invalid_backup_hash")
    need(manifest["new_sha256"] == req["base_sha"], "backup_not_current_successor")
    new = E.secure_read(folder / "oauth-senders.tsv", A.MAX_MAP, modes=(0o600,))
    need(I.digest(new) == manifest["old_sha256"], "backup_digest_mismatch")
    rows = canonical_rows(new)
    return new, rows, manifest_raw


def backup_catalog(req):
    old, current = read_source()
    need(old is not None and I.digest(old) == req["base_sha"],
         "source_changed_since_inventory")
    items = []
    scanned = 0
    try:
        BACKUPS.lstat()
    except FileNotFoundError:
        pass
    else:
        E.trusted_directory(BACKUPS)
        need(stat.S_IMODE(BACKUPS.lstat().st_mode) == 0o700, "backup_root_not_private")
        with os.scandir(str(BACKUPS)) as entries:
            for entry in entries:
                scanned += 1
                need(scanned <= 256, "backup_catalog_limit")
                if not BACKUP_ID.fullmatch(entry.name):
                    continue
                try:
                    new, rows, _ = restore_backup(dict(req, backup_id=entry.name))
                except (Refused, A.Refused, E.Refused, OSError, KeyError, ValueError, TypeError, UnicodeError):
                    continue
                items.append(dict(backup_id=entry.name, map_sha=I.digest(new), row_count=len(rows)))
                need(len(items) <= 64, "backup_catalog_match_limit")
    need(read_source() == (old, current), "source_changed_during_catalog")
    return dict(version=1, action="list_backups", status="catalog", nonce=req["nonce"],
                base_sha=req["base_sha"], old_count=len(current), scanned=scanned,
                backups=sorted(items, key=lambda item: item["backup_id"]), changes=False,
                runtime_changed=False, mail_sent=False, cloud_changed=False)


def restore_plan(req, gid):
    old, current = read_source()
    need(old is not None and I.digest(old) == req["base_sha"],
         "source_changed_since_inventory")
    new, rows, manifest_raw = restore_backup(req)
    evidence = [I.identity_row(*row, gid) for row in rows]
    need(all(row["status"] == "public_certificate_read" for row in evidence),
         "restore_identity_or_certificate_unverified")
    review = dict(request={k:v for k,v in req.items() if k not in ("approval", "confirm")},
                  manifest_sha=I.digest(manifest_raw), old_sha=req["base_sha"],
                  new_sha=I.digest(new), old_count=len(current), new_count=len(rows),
                  identities=evidence)
    return old, new, dict(plan_sha=I.digest(encode(review)), base_sha=req["base_sha"],
                          new_sha=review["new_sha"], old_count=len(current),
                          new_count=len(rows), selected=None, identity_file="",
                          action="restore", nonce=req["nonce"], old_mailbox="",
                          restored_from=req["backup_id"])


def plan(req, gid):
    if req["action"] == "restore":
        return restore_plan(req, gid)
    old, rows = read_source()
    old_sha = I.digest(old) if old is not None else ""
    need(req["base_sha"] == old_sha, "source_changed_since_inventory")
    action = req["action"]
    previous = None
    if action != "add":
        positions = [n for n, row in enumerate(rows) if row[2] == req["old_mailbox"]]
        need(len(positions) == 1, "selected_source_row_missing")
        index = positions[0]
        previous = rows[index]
    selected = None
    if action == "remove":
        need(len(rows) > 1, "last_row_removal_requires_separate_decommission")
        rows.pop(index)
    else:
        path = identity_path(req, previous, gid)
        selected = (req["login"], req["mailbox"], req["mailbox"], path)
        if action == "edit":
            rows[index] = selected
        else:
            rows.append(selected)
    need(1 <= len(rows) <= 64, "source_row_limit")
    new = render(rows)
    need(new != old and A.parse_map(new) == rows, "no_change_or_ambiguous_sender")
    evidence = [I.identity_row(*row, gid) for row in rows]
    need(all(row["status"] == "public_certificate_read" for row in evidence),
         "remaining_identity_or_certificate_unverified")
    selected_evidence = evidence[rows.index(selected)] if selected is not None else None
    # Approval includes all remaining identity/cert hashes, not merely the TSV.
    review = dict(request={k:v for k,v in req.items() if k not in ("approval", "confirm")},
                  old_sha=old_sha, new_sha=I.digest(new), identities=evidence,
                  old_count=len(rows) + (1 if action == "remove" else -1 if action == "add" else 0),
                  new_count=len(rows))
    result = dict(plan_sha=I.digest(encode(review)), base_sha=old_sha, new_sha=review["new_sha"],
                  old_count=review["old_count"], new_count=len(rows),
                  selected=selected_evidence, identity_file=Path(selected[3]).name if selected else "",
                  action=action, nonce=req["nonce"], old_mailbox=req["old_mailbox"])
    return old, new, result


def sync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def backup(old, result):
    E.trusted_directory(BASE)
    BACKUPS.mkdir(mode=0o700, exist_ok=True)
    E.trusted_directory(BACKUPS)
    need(stat.S_IMODE(BACKUPS.lstat().st_mode) == 0o700, "backup_root_not_private")
    folder = Path(tempfile.mkdtemp(prefix="source-", dir=str(BACKUPS)))
    if old is not None:
        write_new(folder / "oauth-senders.tsv", old)
        need(I.digest(E.secure_read(folder / "oauth-senders.tsv", A.MAX_MAP, modes=(0o600,))) ==
             result["base_sha"], "backup_readback_mismatch")
    write_new(folder / "manifest.json", encode(dict(version=1, source_was_present=old is not None,
              old_sha256=result["base_sha"], new_sha256=result["new_sha"], plan_sha256=result["plan_sha"])))
    sync_directory(folder)
    sync_directory(BACKUPS)
    sync_directory(BASE)
    return folder.name


def source_metadata(old):
    if old is None:
        # New-file SELinux labeling requires a separate policy-aware
        # acceptance path. Do not silently create an incorrectly labeled map.
        need(not Path("/sys/fs/selinux/enforce").exists(), "new_source_selinux_requires_review")
        return None, None
    info = SOURCE.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == 0o600, "unsafe_source_metadata")
    attributes = os.listxattr(str(SOURCE), follow_symlinks=False)
    need(set(attributes) <= {"security.selinux"}, "unsupported_source_extended_attributes")
    label = os.getxattr(str(SOURCE), "security.selinux", follow_symlinks=False) if "security.selinux" in attributes else None
    need(not Path("/sys/fs/selinux/enforce").exists() or label is not None, "source_selinux_label_missing")
    return info.st_gid, label


def apply(req, gid):
    E.trusted_directory(LOCK.parent)
    fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    stage = None
    committed = False
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600, "unsafe_shared_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old, new, result = plan(req, gid)
        need(req["approval"] == result["plan_sha"], "plan_changed_since_approval")
        group, label = source_metadata(old)
        backup_id = backup(old, result)
        # Report the durable backup even if a later readback is uncertain.
        print("SOURCE_MAP_BACKUP_ID=" + backup_id, file=sys.stderr, flush=True)
        stage_fd, name = tempfile.mkstemp(prefix=".oauth-source-", dir=str(BASE))
        stage = Path(name)
        with os.fdopen(stage_fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            os.fchown(stream.fileno(), 0, group if group is not None else 0)
            if label is not None:
                os.setxattr(stream.fileno(), "security.selinux", label)
                need(os.getxattr(stream.fileno(), "security.selinux") == label, "source_label_not_preserved")
            stream.write(new)
            stream.flush()
            os.fsync(stream.fileno())
        need(E.secure_read(stage, A.MAX_MAP, modes=(0o600,)) == new, "stage_readback")
        need(plan(req, gid) == (old, new, result) and source_metadata(old) == (group, label),
             "configuration_changed_before_commit")
        # The shared lock protects cooperating installers/editors. Other root
        # administrators must not concurrently edit this map.
        if old is None:
            # Atomic no-clobber publication for the first source map.
            os.link(str(stage), str(SOURCE), follow_symlinks=False)
            committed = True
            stage.unlink()
        else:
            os.replace(str(stage), str(SOURCE))
            committed = True
        stage = None
        sync_directory(BASE)
        need(E.secure_read(SOURCE, A.MAX_MAP, modes=(0o600,)) == new, "committed_readback")
        return dict(result, backup_id=backup_id, status="saved", changes=True)
    except Exception:
        if committed:
            print("SOURCE_MAP_OUTCOME=unknown_review_backup", file=sys.stderr, flush=True)
        raise
    finally:
        try:
            if stage is not None and stage.exists():
                stage.unlink()
        finally:
            os.close(fd)


def main():
    try:
        need(os.geteuid() == 0, "root_required")
        req = request(sys.stdin.buffer.read(4097))
        if req["action"] == "list_backups":
            print(json.dumps(backup_catalog(req), sort_keys=True, separators=(",", ":")))
            return 0
        gid = grp.getgrnam("m365mailer").gr_gid
        if req["approval"]:
            result = apply(req, gid)
        else:
            first = plan(req, gid)
            need(plan(req, gid) == first, "configuration_changed_during_preview")
            result = dict(first[2], backup_id="", status="preview", changes=False)
        result.update(version=1, runtime_changed=False, mail_sent=False, cloud_changed=False)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (Refused, A.Refused, E.Refused, OSError, KeyError, ValueError, TypeError, UnicodeError):
        print("SOURCE_MAP_EDITOR=refused_or_review_required")
        return 2


if __name__ == "__main__":
    sys.exit(main())
