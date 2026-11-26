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
_policy_spec = importlib.util.spec_from_file_location(
    "source_label_policy", str(Path(__file__).with_name("prepare-multi-mailbox-identity.py")))
P = importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(P)
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


def exists(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def source_policy(req):
    """Review only fixed source/backup paths, not arbitrary request paths."""
    mode = P.selinux_mode()
    labels = {}
    if mode != "inactive":
        E.trusted_directory(BASE)
        targets = [(BASE,True), (SOURCE,False), (BACKUPS,True)]
        if req["action"] == "restore":
            need(BACKUP_ID.fullmatch(req["backup_id"]), "invalid_backup_id")
            folder = BACKUPS / req["backup_id"]
            targets += [(folder,True),(folder/"manifest.json",False),
                        (folder/"oauth-senders.tsv",False)]
        for path, directory in targets:
            expected = P.query_label(path, "dir" if directory else "file")
            if exists(path):
                if directory:
                    E.trusted_directory(path)
                P.verify_label(path, expected, directory=directory)
            else:
                need(path in (SOURCE,BACKUPS), "required_policy_path_missing")
            labels[str(path)] = expected
    need(P.selinux_mode() == mode,"selinux_mode_changed")
    return dict(mode=mode,labels=labels)


def check_backup_labels(folder):
    if P.selinux_mode() == "inactive":
        return
    for path,directory in ((BASE,True),(BACKUPS,True),(folder,True),
                           (folder/"manifest.json",False),(folder/"oauth-senders.tsv",False)):
        expected=P.query_label(path,"dir" if directory else "file")
        P.verify_label(path,expected,directory=directory)


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
    check_backup_labels(folder)
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
                except (Refused, A.Refused, E.Refused, P.Refused, P.E.Refused, OSError, KeyError, ValueError, TypeError, UnicodeError):
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
    # Preserve legacy inactive plan digests. With active SELinux, bind the
    # exact policy and mode into the reviewed plan, not just the map bytes.
    old, new, result = content_plan(req, gid)
    policy = source_policy(req)
    if policy["mode"] != "inactive":
        sha = I.digest(encode(policy))
        result.update(plan_sha=I.digest(encode(dict(content_plan=result["plan_sha"], policy=policy))),
                      selinux_mode=policy["mode"], selinux_policy_sha=sha)
    return old, new, result


def content_plan(req, gid):
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


def label_new_directory(path, mode):
    if mode == "inactive":
        return
    expected = P.query_label(path,"dir")
    fd = os.open(str(path),os.O_RDONLY|os.O_DIRECTORY|getattr(os,"O_NOFOLLOW",0))
    try:
        info, live = os.fstat(fd), path.lstat()
        need(info.st_uid == 0 and stat.S_IMODE(info.st_mode)==0o700 and
             (info.st_dev,info.st_ino)==(live.st_dev,live.st_ino),"new_backup_directory_changed")
        P.set_new_label(fd,expected)
        os.fsync(fd)
    finally:
        os.close(fd)
    P.verify_label(path,expected,directory=True)


def write_new(path, data, mode="inactive"):
    expected=P.query_label(path,"file") if mode!="inactive" else None
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        if expected is not None:
            P.set_new_label(stream.fileno(),expected)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if expected is not None:
        P.verify_label(path,expected)


def backup(old, result):
    E.trusted_directory(BASE)
    mode = result.get("selinux_mode","inactive")
    need(P.selinux_mode()==mode,"selinux_mode_changed")
    if not exists(BACKUPS):
        BACKUPS.mkdir(mode=0o700)
        label_new_directory(BACKUPS,mode)
    E.trusted_directory(BACKUPS)
    need(stat.S_IMODE(BACKUPS.lstat().st_mode) == 0o700, "backup_root_not_private")
    if mode!="inactive":
        P.verify_label(BACKUPS,P.query_label(BACKUPS,"dir"),directory=True)
    folder = Path(tempfile.mkdtemp(prefix="source-", dir=str(BACKUPS)))
    label_new_directory(folder,mode)
    if old is not None:
        write_new(folder / "oauth-senders.tsv", old, mode)
        need(I.digest(E.secure_read(folder / "oauth-senders.tsv", A.MAX_MAP, modes=(0o600,))) ==
             result["base_sha"], "backup_readback_mismatch")
    write_new(folder / "manifest.json", encode(dict(version=1, source_was_present=old is not None,
              old_sha256=result["base_sha"], new_sha256=result["new_sha"], plan_sha256=result["plan_sha"])),mode)
    if mode!="inactive":
        for path,directory in ((folder,True),(folder/"manifest.json",False)):
            P.verify_label(path,P.query_label(path,"dir" if directory else "file"),directory=directory)
        if old is not None:
            check_backup_labels(folder)
    need(P.selinux_mode()==mode,"selinux_mode_changed")
    sync_directory(folder)
    sync_directory(BACKUPS)
    sync_directory(BASE)
    return folder.name


def source_metadata(old, policy):
    active = policy["mode"] != "inactive"
    if old is None:
        return None, (policy["labels"][str(SOURCE)].encode("ascii")+b"\0") if active else None
    info = SOURCE.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == 0o600, "unsafe_source_metadata")
    attributes = os.listxattr(str(SOURCE), follow_symlinks=False)
    need(set(attributes) <= {P.LABEL_ATTR}, "unsupported_source_extended_attributes")
    label = os.getxattr(str(SOURCE), P.LABEL_ATTR, follow_symlinks=False) if P.LABEL_ATTR in attributes else None
    if active:
        need(label is not None and P.checked_context(label)==policy["labels"][str(SOURCE)],
             "source_selinux_label_mismatch")
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
        policy = source_policy(req)
        def verify_policy():
            need(source_policy(req)==policy,"selinux_policy_changed")
            need(policy["mode"]==result.get("selinux_mode","inactive") and
                 (policy["mode"]=="inactive" or I.digest(encode(policy))==result["selinux_policy_sha"]),
                 "selinux_policy_changed_since_approval")
        verify_policy()
        group, label = source_metadata(old,policy)
        backup_id = backup(old, result)
        verify_policy()
        # Report the durable backup even if a later readback is uncertain.
        print("SOURCE_MAP_BACKUP_ID=" + backup_id, file=sys.stderr, flush=True)
        stage_fd, name = tempfile.mkstemp(prefix=".oauth-source-", dir=str(BASE))
        stage = Path(name)
        with os.fdopen(stage_fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            os.fchown(stream.fileno(), 0, group if group is not None else 0)
            if policy["mode"]!="inactive":
                P.set_new_label(stream.fileno(),policy["labels"][str(SOURCE)])
            elif label is not None:
                os.setxattr(stream.fileno(), P.LABEL_ATTR, label)
                need(os.getxattr(stream.fileno(), P.LABEL_ATTR) == label, "source_label_not_preserved")
            stream.write(new)
            stream.flush()
            os.fsync(stream.fileno())
        need(E.secure_read(stage, A.MAX_MAP, modes=(0o600,)) == new, "stage_readback")
        verify_policy()
        if policy["mode"]!="inactive":
            P.verify_label(stage,policy["labels"][str(SOURCE)])
        need(plan(req, gid) == (old, new, result) and source_metadata(old,policy) == (group, label),
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
        verify_policy()
        committed_group,committed_label=source_metadata(new,policy)
        need(committed_group==(group if group is not None else 0) and
             (P.checked_context(committed_label)==policy["labels"][str(SOURCE)] if policy["mode"]!="inactive"
              else committed_label==label), "committed_source_metadata_mismatch")
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
    except (Refused, A.Refused, E.Refused, P.Refused, P.E.Refused, OSError, KeyError, ValueError, TypeError, UnicodeError):
        print("SOURCE_MAP_EDITOR=refused_or_review_required")
        return 2


if __name__ == "__main__":
    sys.exit(main())
