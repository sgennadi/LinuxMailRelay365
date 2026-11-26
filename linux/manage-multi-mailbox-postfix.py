#!/usr/bin/env python3
"""Experimental guarded OFFLINE Postfix sidecar multi-mailbox OAuth installer.

No SMTP, Microsoft 365, firewall or MTA service mutations. The administrator
must stop the isolated sidecar and drain its queue before --apply-offline.
Primary /etc/postfix is read only. Python 3.6+ compatible.
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
import subprocess
import sys
import tempfile

CONF = Path("/etc/linuxmailrelay365/sidecar-postfix")
PRIMARY = Path("/etc/postfix")
SOURCE = Path("/opt/linuxmailrelay365/multi-oauth")
TARGET = Path("/usr/local/libexec/linuxmailrelay365-multi-oauth")
MAP = Path("/etc/linuxmailrelay365/oauth-senders.tsv")
RUNTIME = Path("/etc/linuxmailrelay365/oauth-runtime-senders.tsv")
RECOVERY = Path("/var/backups/linuxmailrelay365-multi-oauth")
LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")
ACTIVE = RECOVERY / "active.json"
SELINUX = Path("/sys/fs/selinux/enforce")
LABEL_ATTR = "security.selinux"
FILES = ("audit-oauth-sender-map.py", "audit-oauth-ingress.py",
         "m365_xoauth2_transport.py", "m365_hardware_signer.py",
         "m365-multi-mailbox-transport.py",
         "refresh-multi-mailbox-proof.py",
         "manage-multi-mailbox-proof-timer.py",
         "manage-multi-mailbox-acceptance.py")
CONFIRM = "INSTALL_MULTI_MAILBOX_OFFLINE"
SHA = re.compile(r"\A[a-f0-9]{64}\Z")


class Refused(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def secure_dir(path):
    path = Path(path)
    while True:
        st = path.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid or st.st_mode & 0o022:
            raise Refused("unsafe_directory")
        if path == path.parent:
            return
        path = path.parent


def read(path, maximum, modes=(0o600, 0o640, 0o644, 0o755)):
    secure_dir(path.parent)
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid or st.st_nlink != 1 or
            stat.S_IMODE(st.st_mode) not in modes or not 0 <= st.st_size <= maximum):
        raise Refused("unsafe_file")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        fields = lambda i: (i.st_dev, i.st_ino, i.st_uid, i.st_gid, i.st_mode,
                            i.st_size, i.st_mtime_ns, i.st_ctime_ns)
        if fields(opened) != fields(st):
            raise Refused("file_changed_before_read")
        raw = b""
        while len(raw) < opened.st_size:
            part = os.read(fd, min(65536, opened.st_size - len(raw)))
            if not part:
                raise Refused("file_short_read")
            raw += part
        if os.read(fd, 1) or fields(os.fstat(fd)) != fields(st):
            raise Refused("file_changed_during_read")
        return st, raw
    finally:
        os.close(fd)


def selinux_mode():
    try:
        value = SELINUX.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return "inactive"
    if value not in ("0","1"):
        raise Refused("selinux_mode_unverified")
    return "enforcing" if value == "1" else "permissive"


def checked_context(raw):
    if raw.endswith(b"\0"):
        raw = raw[:-1]
    if len(raw) > 256 or not re.fullmatch(
            rb"[A-Za-z0-9_]+:object_r:[A-Za-z0-9_]+:s[0-9][A-Za-z0-9_:.,-]*", raw):
        raise Refused("selinux_context_invalid")
    if raw.split(b":")[2] in (b"default_t",b"unlabeled_t",b"file_t",b"tmp_t",b"user_tmp_t",b"unconfined_t"):
        raise Refused("selinux_unsafe_context_type")
    return raw.decode("ascii")


def expected_label(path, directory=False):
    for candidate in (Path("/usr/sbin/matchpathcon"),Path("/usr/bin/matchpathcon")):
        try:
            tool = candidate.resolve(strict=True)
        except FileNotFoundError:
            continue
        secure_dir(tool.parent)
        st = tool.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid or st.st_mode & 0o022 or not st.st_mode & 0o111:
            raise Refused("selinux_untrusted_policy_tool")
        reply = subprocess.run([str(tool),"-N","-n","-m","dir" if directory else "file",str(path)],
                               stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,
                               env={"LC_ALL":"C","PATH":"/usr/sbin:/usr/bin:/sbin:/bin"},check=False)
        if reply.returncode or len(reply.stdout)>512 or len(reply.stdout.splitlines())!=1:
            raise Refused("selinux_policy_lookup_failed")
        return checked_context(reply.stdout.splitlines()[0])
    raise Refused("selinux_matchpathcon_required")


def label_fd(fd):
    if set(os.listxattr(fd)) != {LABEL_ATTR}:
        raise Refused("selinux_missing_label_or_foreign_xattrs")
    return checked_context(os.getxattr(fd,LABEL_ATTR))


def verify_label(path, expected, directory=False):
    secure_dir(path if directory else path.parent)
    fd = os.open(str(path),os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|
                 (os.O_DIRECTORY if directory else os.O_NONBLOCK))
    try:
        st, live = os.fstat(fd), path.lstat()
        if (not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink==1)
                or st.st_uid or st.st_mode & 0o022 or (st.st_dev,st.st_ino)!=(live.st_dev,live.st_ino)
                or label_fd(fd)!=expected):
            raise Refused("selinux_existing_context_mismatch")
    finally:
        os.close(fd)


def set_label(fd, expected):
    if not set(os.listxattr(fd)) <= {LABEL_ATTR}:
        raise Refused("selinux_foreign_xattrs")
    os.setxattr(fd,LABEL_ATTR,expected.encode("ascii")+b"\0")
    if label_fd(fd)!=expected:
        raise Refused("selinux_new_context_not_verified")


def present(path):
    return os.path.lexists(str(path))


def policy_snapshot(targets):
    # All callers supply fixed managed paths or a verified private backup.
    mode = selinux_mode()
    labels = {}
    if mode != "inactive":
        for path,directory in targets:
            expected = expected_label(path,directory)
            if present(path):
                verify_label(path,expected,directory)
            labels[str(path)] = [directory,expected]
    if selinux_mode()!=mode:
        raise Refused("selinux_mode_changed")
    return {"mode":mode,"labels":labels}


def require_policy(policy):
    targets = [(Path(name),item[0]) for name,item in policy["labels"].items()]
    if policy_snapshot(targets)!=policy:
        raise Refused("selinux_policy_changed")


def route_policy_targets():
    return [(CONF,True),(CONF/"main.cf",False),(CONF/"master.cf",False),
            (RUNTIME.parent,True),(RUNTIME,False),(TARGET.parent,True),(TARGET,True),
            (RECOVERY.parent,True),(RECOVERY,True),(ACTIVE,False)] + \
           [(TARGET/name,False) for name in FILES]


def policy_evidence(policy):
    if policy["mode"]=="inactive":
        return {}
    return {"selinux_mode":policy["mode"],"selinux_policy_sha256":
            digest(json.dumps(policy,sort_keys=True,separators=(",",":")).encode("ascii"))}


def reviewed_label(policy,path):
    if policy["mode"]=="inactive":
        return None
    return policy["labels"][str(path)][1]


def sync_dir(path):
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY|getattr(os,"O_NOFOLLOW",0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def label_new_directory(path,destination,mode):
    if mode=="inactive":
        return
    if selinux_mode()!=mode:
        raise Refused("selinux_mode_changed")
    expected=expected_label(destination,True)
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY|getattr(os,"O_NOFOLLOW",0))
    try:
        st,live=os.fstat(fd),path.lstat()
        if st.st_uid or st.st_mode & 0o022 or (st.st_dev,st.st_ino)!=(live.st_dev,live.st_ino):
            raise Refused("unsafe_new_directory")
        set_label(fd,expected)
        os.fsync(fd)
    finally:
        os.close(fd)
    verify_label(path,expected,True)


def write_new(path,data,mode,permission=0o600,group=None,destination=None):
    # Exclusive new inode. A staged runtime file gets its final path label.
    expected=expected_label(destination or path) if mode!="inactive" else None
    if selinux_mode()!=mode:
        raise Refused("selinux_mode_changed")
    fd=os.open(str(path),os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"wb") as stream:
        if group is not None:
            os.fchown(stream.fileno(),0,group)
        if expected is not None:
            set_label(stream.fileno(),expected)
        os.fchmod(stream.fileno(),permission)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if expected is not None:
        verify_label(path,expected)
    st,actual=read(path,max(len(data),1),(permission,))
    if actual!=data or (group is not None and st.st_gid!=group):
        raise Refused("new_route_file_readback_failed")


def verify_backup(folder,names,mode):
    if mode=="inactive":
        return
    if selinux_mode()!=mode:
        raise Refused("selinux_mode_changed")
    for path,directory in [(RECOVERY,True),(folder,True)]+[(folder/name,False) for name in names]:
        verify_label(path,expected_label(path,directory),directory)


def import_checked(path, label):
    spec = importlib.util.spec_from_file_location(label, str(path))
    if spec is None or spec.loader is None:
        raise Refused("guard_source_not_found")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(args):
    allowed = {
        'postconf': ('/usr/sbin/postconf', '/usr/bin/postconf'),
        'postqueue': ('/usr/sbin/postqueue', '/usr/bin/postqueue'),
        'postfix': ('/usr/sbin/postfix', '/usr/bin/postfix'),
        'systemctl': ('/usr/bin/systemctl', '/bin/systemctl'),
        'ss': ('/usr/sbin/ss', '/usr/bin/ss', '/bin/ss'),
    }
    if not args or args[0] not in allowed or shutil.which(args[0]) not in allowed[args[0]]:
        raise Refused('untrusted_host_command')
    args = [shutil.which(args[0])] + list(args[1:])
    result = subprocess.run(args, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20,
                            universal_newlines=True, check=False)
    if result.returncode or len(result.stdout) > 65536:
        raise Refused("host_preflight_command_failed")
    return result.stdout.strip()


def postconf(key):
    return run(["postconf", "-c", str(CONF), "-h", key])


def offline():
    result = run(["systemctl", "show", "linuxmailrelay365-sidecar.service",
                  "--property=LoadState", "--property=ActiveState"])
    state = dict(line.split("=", 1) for line in result.splitlines()
                 if line.count("=") == 1)
    if state != {"LoadState": "loaded", "ActiveState": "inactive"}:
        raise Refused("sidecar_service_not_proven_stopped")
    if run(["postqueue", "-c", str(CONF), "-j"]):
        raise Refused("sidecar_queue_not_empty")
    port_raw = read(CONF / "smtp-port", 16, (0o644,))[1].strip()
    if not port_raw.isdigit() or not 1024 <= int(port_raw) <= 65535:
        raise Refused("sidecar_custom_port_unverified")
    sockets = run(["ss", "-H", "-ltn"])
    for line in sockets.splitlines():
        parts = line.split()
        if len(parts) < 4:
            raise Refused("socket_inventory_malformed")
        if parts[3].rsplit(":", 1)[-1] == port_raw.decode("ascii"):
            raise Refused("sidecar_custom_port_still_listening")
    return True


def replace_settings(raw):
    try:
        value = raw.decode("utf-8")
    except UnicodeError:
        raise Refused("unknown_main_cf_encoding")
    if "\r" in value or "\x00" in value or "\n " in value or "\n\t" in value:
        raise Refused("unsupported_main_cf_continuation")
    replacements = {
        "default_transport": "m365multi:",
        "relay_transport": "m365multi:",
        "m365multi_destination_recipient_limit": "1",
        "m365multi_destination_concurrency_limit": "2",
    }
    lines, seen = [], set()
    for line in value.splitlines():
        m = re.match(r"^([a-z][a-z0-9_]*)\s*=", line)
        if m and m.group(1) in replacements:
            key = m.group(1)
            if key in seen:
                raise Refused("duplicate_route_parameter")
            seen.add(key)
            lines.append(key + " = " + replacements[key])
        else:
            lines.append(line)
    for key, value in replacements.items():
        if key not in seen:
            lines.append(key + " = " + value)
    return ("\n".join(lines) + "\n").encode("utf-8")


def master_service(raw, map_sha):
    try:
        value = raw.decode("utf-8")
    except UnicodeError:
        raise Refused("unknown_master_cf_encoding")
    if "\x00" in value or "\r" in value or \
            re.search(r"(?m)^m365multi\s", value) or not SHA.fullmatch(map_sha):
        raise Refused("unexpected_existing_m365multi_service")
    # No shell interpretation in Postfix pipe(8). Macro values are from queue.
    dollar = "$"
    service = (
        "\nm365multi unix - n n - 2 pipe\n"
        "  flags=q user=m365mailer argv=/usr/bin/python3 " +
        str(TARGET / "m365-multi-mailbox-transport.py") +
        " --recipient " + dollar + "{recipient}" +
        " --envelope-sender " + dollar + "{sender}" +
        " --sasl-login " + dollar + "{sasl_username}" +
        " --sasl-method " + dollar + "{sasl_method}" +
        " --expected-map-sha256 " + map_sha + "\n")
    return (value.rstrip("\n") + service).encode("utf-8")


def plan():
    if os.geteuid() != 0:
        raise Refused("root_required")
    secure_dir(TARGET.parent)
    secure_dir(RUNTIME.parent)
    if ACTIVE.exists() or ACTIVE.is_symlink() or \
            TARGET.exists() or TARGET.is_symlink() or \
            RUNTIME.exists() or RUNTIME.is_symlink():
        raise Refused("multi_mailbox_route_already_present")
    # No competing route recovery manager may own this configuration.
    if Path("/var/lib/linuxmailrelay365-eop-route-recovery/active.json").exists():
        raise Refused("previous_eop_route_recovery_ownership_requires_review")
    source = {name: read(SOURCE / name, 262144, (0o644, 0o755))[1] for name in FILES}
    auditor = import_checked(SOURCE / FILES[0], "sender_map_guard")
    ingress = import_checked(SOURCE / FILES[1], "smtp_ingress_guard")
    gid = grp.getgrnam("m365mailer").gr_gid
    source_map = auditor.secure_read(str(MAP), auditor.MAX_MAP, 0o600, None)
    rows = auditor.parse_map(source_map)
    if not rows or len(rows) > 64 or any(a != b for _, a, b, _ in rows):
        raise Refused("alias_or_send_as_route_requires_separate_authorization")
    report = auditor.audit(str(MAP), service_gid=gid)
    if report.get("ENTRIES") != len(rows) or report.get("SENDAS_DIFFERENT_FROM"):
        raise Refused("sender_map_audit_not_verified")
    ingress_report = ingress.assess(rows, auditor)
    for key, expected in (
        ("AUTH_ACCOUNTS", "exact_match"),
        ("FROM_GUARD_POLICY", "exact_match"),
        ("POSTFIX_OWNER_RULES", "exact_match"),
        ("FROM_GUARD_SHA_PIN", "configured_pinned_only"),
        ("SASL_TLS_CONFIG", "configured_only"),
        ("SENDER_LOGIN_CONFIG", "configured_only"),
        ("FROM_GUARD_MILTER_CONFIG", "configured_fail_closed_only"),
        ("TRACE_HEADER_GUARD", "exact_static_reject"),
        ("MASTER_CF_SERVICE", "single_private_smtpd_no_overrides"),
    ):
        if ingress_report.get(key) != expected:
            raise Refused("smtp_ingress_guard_incomplete")
    if (not postconf("default_transport").startswith("smtp:[") or
            not postconf("relay_transport").startswith("smtp:[") or
            any(postconf(k) for k in ("transport_maps",
                                     "sender_dependent_default_transport_maps",
                                     "sender_canonical_maps"))):
        raise Refused("existing_route_or_sender_rewrite_conflict")
    originals = {n: read(CONF / n, 1048576) for n in ("main.cf", "master.cf")}
    primary = [digest(read(PRIMARY / n, 1048576)[1])
               for n in ("main.cf", "master.cf")]
    identities = []
    for _, _, mailbox, path in rows:
        raw = auditor.secure_read(path, auditor.MAX_IDENTITY, 0o640, gid)
        auditor.validate_identity(raw, mailbox)
        identities.append(digest(raw))
    evidence = {"version": 1, "map_sha256": digest(source_map),
                "source": {key: digest(raw) for key, raw in source.items()},
                "config": {key: digest(item[1]) for key, item in originals.items()},
                "identities": sorted(identities), "primary": primary,
                "mailboxes": len(set(row[2] for row in rows))}
    policy = policy_snapshot(route_policy_targets()+[(MAP,False)])
    evidence.update(policy_evidence(policy))
    require_policy(policy)
    plan_sha = digest(json.dumps(evidence, sort_keys=True,
                                 separators=(",", ":")).encode("ascii"))
    return {"sha": plan_sha, "evidence": evidence, "policy": policy, "source": source,
            "map": source_map, "originals": originals,
            "main": replace_settings(originals["main.cf"][1]),
            "master": master_service(originals["master.cf"][1],
                                     evidence["map_sha256"])}


def replace_file(path, data, original):
    metadata, _ = original
    mode=selinux_mode()
    expected=expected_label(path) if mode!="inactive" else None
    if expected is not None:
        verify_label(path,expected)
    attrs = os.listxattr(str(path), follow_symlinks=False)
    if any(x != LABEL_ATTR for x in attrs):
        raise Refused("unsupported_extended_config_attributes")
    handle, temporary = tempfile.mkstemp(prefix=".lmr365-multi-", dir=str(path.parent))
    try:
        os.fchown(handle, metadata.st_uid, metadata.st_gid)
        os.fchmod(handle, stat.S_IMODE(metadata.st_mode))
        if expected is not None:
            set_label(handle,expected)
        elif LABEL_ATTR in attrs:
            label = os.getxattr(str(path), LABEL_ATTR, follow_symlinks=False)
            os.setxattr(handle, LABEL_ATTR, label)
        with os.fdopen(handle, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if selinux_mode()!=mode:
            raise Refused("selinux_mode_changed")
        if expected is not None:
            if expected_label(path)!=expected or label_fd(handle)!=expected:
                raise Refused("selinux_policy_changed")
            verify_label(path,expected)
        current,current_data=read(path,1048576)
        if (current.st_dev,current.st_ino,current.st_ctime_ns,current.st_gid,current.st_mode,current_data)!=(
                metadata.st_dev,metadata.st_ino,metadata.st_ctime_ns,metadata.st_gid,metadata.st_mode,original[1]):
            raise Refused("config_changed_before_replace")
        os.close(handle)
        handle = -1
        os.replace(temporary, str(path))
        sync_dir(path.parent)
        if expected is not None:
            verify_label(path,expected)
        if digest(read(path, 1048576)[1]) != digest(data):
            raise Refused("config_write_verification_failed")
    finally:
        if handle >= 0:
            os.close(handle)
        if os.path.lexists(temporary):
            os.unlink(temporary)


def apply_offline(review_sha, confirm):
    if not SHA.fullmatch(review_sha) or confirm != CONFIRM or os.geteuid():
        raise Refused("root_typed_approval_and_plan_sha_required")
    secure_dir(LOCK.parent)
    fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    modified = []
    plan_data = None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise Refused("unsafe_install_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan_data = plan()
        if plan_data["sha"] != review_sha:
            raise Refused("plan_changed_since_approval")
        offline()
        if plan()["sha"] != review_sha:
            raise Refused("plan_changed_after_shutdown")
        policy=plan_data["policy"]
        mode=policy["mode"]
        require_policy(policy)
        secure_dir(RECOVERY.parent)
        if not present(RECOVERY):
            RECOVERY.mkdir(mode=0o700)
            label_new_directory(RECOVERY,RECOVERY,mode)
            sync_dir(RECOVERY.parent)
        secure_dir(RECOVERY)
        if stat.S_IMODE(RECOVERY.lstat().st_mode) != 0o700:
            raise Refused("backup_root_not_private")
        safety = Path(tempfile.mkdtemp(prefix="pre-multi-", dir=str(RECOVERY)))
        label_new_directory(safety,safety,mode)
        for name, (_, raw) in plan_data["originals"].items():
            write_new(safety/name,raw,mode)
        manifest=json.dumps(plan_data["evidence"],sort_keys=True).encode("ascii")
        write_new(safety/"manifest.json",manifest,mode)
        verify_backup(safety,("main.cf","master.cf","manifest.json"),mode)
        sync_dir(safety)
        sync_dir(RECOVERY)
        require_policy(policy)
        if plan()["sha"]!=review_sha:
            raise Refused("plan_changed_during_safety_backup")
        print("MULTI_OAUTH_SAFETY_BACKUP=" + str(safety), flush=True)
        print("MULTI_OAUTH_RESTORE_BACKUP_ID=" + safety.name, flush=True)
        staging = Path(tempfile.mkdtemp(prefix=".multi-oauth-", dir=str(TARGET.parent)))
        try:
            label_new_directory(staging,TARGET,mode)
            for name,data in plan_data["source"].items():
                write_new(staging/name,data,mode,0o644,destination=TARGET/name)
            require_policy(policy)
            if mode!="inactive":
                verify_label(staging,reviewed_label(policy,TARGET),True)
                for name in FILES:
                    verify_label(staging/name,reviewed_label(policy,TARGET/name))
            if present(TARGET):
                raise Refused("runtime_target_appeared")
            os.chmod(str(staging),0o755)
            sync_dir(staging)
            staging.rename(TARGET)
            modified.append(("target", TARGET))
            sync_dir(TARGET.parent)
            require_policy(policy)
        finally:
            if staging.exists():
                shutil.rmtree(str(staging))
        group=grp.getgrnam("m365mailer").gr_gid
        require_policy(policy)
        # Create under a private scratch name, then atomically publish without
        # clobbering any runtime map that appeared since the review.
        mapstage=Path(tempfile.mkdtemp(prefix=".multi-map-",dir=str(RUNTIME.parent)))
        try:
            write_new(mapstage/"map",plan_data["map"],mode,0o640,group,RUNTIME)
            require_policy(policy)
            if mode!="inactive":
                verify_label(mapstage/"map",reviewed_label(policy,RUNTIME))
            os.link(str(mapstage/"map"),str(RUNTIME),follow_symlinks=False)
            modified.append(("map",RUNTIME))
            (mapstage/"map").unlink()
            sync_dir(RUNTIME.parent)
        finally:
            shutil.rmtree(str(mapstage))
        require_policy(policy)
        if digest(read(RUNTIME,65536,(0o640,))[1])!=plan_data["evidence"]["map_sha256"]:
            raise Refused("runtime_map_changed")
        for name in ("main.cf", "master.cf"):
            offline()
            require_policy(policy)
            current = read(CONF / name, 1048576)
            if digest(current[1]) != plan_data["evidence"]["config"][name]:
                raise Refused("live_config_changed_during_offline_apply")
            modified.append(("config", name))
            replace_file(CONF / name, plan_data["main"] if name == "main.cf"
                         else plan_data["master"], current)
        offline()
        require_policy(policy)
        run(["postfix", "-c", str(CONF), "check"])
        require_policy(policy)
        if [digest(read(PRIMARY / x, 1048576)[1]) for x in
                ("main.cf", "master.cf")] != plan_data["evidence"]["primary"]:
            raise Refused("primary_postfix_changed")
        offline()
        # The marker is written ONLY after a verified offline Postfix check.
        # It binds Restore to the exact installed config and safety snapshot.
        if ACTIVE.exists() or ACTIVE.is_symlink():
            raise Refused("active_route_marker_created_by_other_process")
        record = {
            "version": 1, "backup_id": safety.name,
            "plan_sha256": plan_data["sha"],
            "before": plan_data["evidence"]["config"],
            "active": {"main.cf": digest(plan_data["main"]),
                       "master.cf": digest(plan_data["master"])},
            "runtime_map_sha256": plan_data["evidence"]["map_sha256"],
            "source": plan_data["evidence"]["source"],
            "primary": plan_data["evidence"]["primary"]
        }
        require_policy(policy)
        verify_backup(safety,("main.cf","master.cf","manifest.json"),mode)
        marker_bytes=(json.dumps(record,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
        markerstage=Path(tempfile.mkdtemp(prefix=".active-",dir=str(RECOVERY)))
        try:
            write_new(markerstage/"marker",marker_bytes,mode,destination=ACTIVE)
            require_policy(policy)
            if mode!="inactive":
                verify_label(markerstage/"marker",reviewed_label(policy,ACTIVE))
            os.link(str(markerstage/"marker"),str(ACTIVE),follow_symlinks=False)
            modified.append(("marker",ACTIVE))
            (markerstage/"marker").unlink()
            sync_dir(RECOVERY)
        finally:
            shutil.rmtree(str(markerstage))
        require_policy(policy)
        if read(ACTIVE,4096,(0o600,))[1]!=marker_bytes:
            raise Refused("active_route_marker_verification_failed")
        return plan_data["evidence"]
    except Exception:
        # Never rollback while the SMTP service is active: print warning and
        # leave a separate root-only safety backup for operator recovery.
        try:
            if modified:
                offline()
            if plan_data and modified:
                require_policy(plan_data["policy"])
                for kind, thing in reversed(modified):
                    if kind == "marker":
                        if ACTIVE.is_file() and not ACTIVE.is_symlink():
                            ACTIVE.unlink()
                    elif kind == "config":
                        path=CONF/thing
                        current=read(path,1048576)
                        before=plan_data["originals"][thing][1]
                        after=plan_data["main"] if thing=="main.cf" else plan_data["master"]
                        if current[1] not in (before,after):
                            raise Refused("concurrent_change_blocks_rollback")
                        if current[1]!=before:
                            replace_file(path,before,current)
                    elif kind == "map":
                        if RUNTIME.is_file() and not RUNTIME.is_symlink():
                            RUNTIME.unlink()
                    elif kind == "target":
                        if TARGET.is_dir() and not TARGET.is_symlink():
                            shutil.rmtree(str(TARGET))
                require_policy(plan_data["policy"])
        except Exception:
            print("MULTI_OAUTH_ROLLBACK=unverified_manual_recovery_required",
                  file=sys.stderr)
        raise
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply-offline", action="store_true")
    parser.add_argument("--approve-sha256", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    try:
        if args.plan:
            if args.approve_sha256 or args.confirm:
                raise Refused("approval_not_allowed_in_preview")
            review = plan()
            data = review["evidence"]
            print("MULTI_OAUTH_PLAN_SHA256=" + review["sha"])
            print("MULTI_OAUTH_MAILBOXES=" + str(data["mailboxes"]))
            print("MULTI_OAUTH_STATUS=review_only")
        else:
            result = apply_offline(args.approve_sha256, args.confirm)
            print("MULTI_OAUTH_MAILBOXES=" + str(result["mailboxes"]))
            print("MULTI_OAUTH_STATUS=offline_installed_NOT_started")
        print("MULTI_OAUTH_MESSAGES_SENT=no")
        print("MULTI_OAUTH_SERVICES_CHANGED=no")
        print("MULTI_OAUTH_PRIMARY_POSTFIX_CHANGED=no")
        return 0
    except (Refused, OSError, ValueError, KeyError,
            subprocess.TimeoutExpired) as exc:
        detail = str(exc) if isinstance(exc, Refused) else "host_operation_failed"
        print("MULTI_OAUTH_STATUS=refused:" + detail, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
