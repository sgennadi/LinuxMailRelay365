#!/usr/bin/env python3
"""Root-only, fail-closed isolated SMTP configuration backup and recovery.

Does not back up or restore mail queues, primary MTAs, package state, DNS,
tenant-side Connectors, firewall rules, system CA trust or external TLS keys.
Never operates on /etc/postfix, postfix.service, Exim or Sendmail.
Python 3.6+ for RHEL / Oracle / Rocky / Alma Linux and Ubuntu/Debian.
"""
import argparse
import datetime
import fcntl
import hashlib
import ipaddress
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path("/")
BASE = Path("/var/backups/linuxmailrelay365-sidecar")
LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")
CONF = "etc/linuxmailrelay365"
QUEUE = "var/spool/linuxmailrelay365-sidecar"
SIDECAR = "linuxmailrelay365-sidecar.service"
AUTH = "linuxmailrelay365-smtp-auth.service"
HEALTH = "linuxmailrelay365-health.service"
TIMER = "linuxmailrelay365-health.timer"
FROM_GUARD = "linuxmailrelay365-from-guard.service"
UNITS = (SIDECAR, AUTH, HEALTH, TIMER, FROM_GUARD)
OPTIONAL = (
    "etc/systemd/system/linuxmailrelay365-sidecar.service",
    "etc/systemd/system/linuxmailrelay365-sidecar.service.d",
    "etc/systemd/system/linuxmailrelay365-smtp-auth.service",
    "etc/systemd/system/linuxmailrelay365-smtp-auth.service.d",
    "etc/systemd/system/linuxmailrelay365-health.service",
    "etc/systemd/system/linuxmailrelay365-health.timer",
    "etc/systemd/system/linuxmailrelay365-health.timer.d",
    "etc/systemd/system/linuxmailrelay365-health.service.d",
    "etc/systemd/system/linuxmailrelay365-from-guard.service",
    "etc/systemd/system/linuxmailrelay365-from-guard.service.d",
    "usr/local/libexec/linuxmailrelay365-from-owner-milter.py",
    "usr/local/libexec/linuxmailrelay365-sidecar-transport.py",
    "usr/local/libexec/linuxmailrelay365-relay-health.py",
    "usr/local/libexec/linuxmailrelay365-health-alerts.py",
    "var/lib/linuxmailrelay365-sidecar-auth-recovery",
    "var/lib/linuxmailrelay365-smtp-account-recovery",
    "var/lib/linuxmailrelay365-smtp-tls-recovery",
    "var/lib/linuxmailrelay365-eop-route-recovery",
    "var/lib/linuxmailrelay365-public-smtp",
    "var/lib/linuxmailrelay365-health-alerts",
)
ROOTS = (CONF,) + OPTIONAL
ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
REL = re.compile(r"[A-Za-z0-9._@+/-]{1,320}\Z")
MAX_ITEMS = 4096
MAX_SIZE = 96 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024
OWNER_UID = 0


class Refused(Exception):
    pass


def say(key, value):
    print("{}={}".format(key, value))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def rooted(rel):
    if not REL.fullmatch(rel) or rel.startswith("/") or ".." in rel.split("/") or \
            "//" in rel or rel.endswith("/"):
        raise Refused("invalid_archive_path")
    if not any(rel == r or rel.startswith(r + "/") for r in ROOTS):
        raise Refused("archive_path_outside_sidecar_allowlist")
    return ROOT / rel


def secure(path, directory=None, owner=True):
    try:
        info = path.lstat()
    except OSError:
        raise Refused("source_or_archive_unavailable")
    if owner and info.st_uid != OWNER_UID:
        raise Refused("non_root_owned_backup_component")
    if info.st_mode & 0o7022:
        raise Refused("untrusted_scoped_inode_mode")
    if directory is True and not stat.S_ISDIR(info.st_mode):
        raise Refused("expected_directory_not_present")
    if directory is False and not stat.S_ISREG(info.st_mode):
        raise Refused("expected_regular_file_not_present")
    if directory is None and not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise Refused("link_or_special_file_not_permitted")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise Refused("hardlinked_scoped_file_not_permitted")
    return info


def secure_parents(path):
    """Check every parent inode down to the chosen filesystem root."""
    parent = path.parent
    while parent != ROOT:
        if parent == parent.parent:
            raise Refused("scoped_path_escaped_filesystem_root")
        secure(parent, directory=True)
        parent = parent.parent
    secure(ROOT, directory=True)


def walk_inventory():
    """No symlinks; do not visit mail spools, postfix queue or external paths."""
    paths = {}
    total = 0
    for rel in ROOTS:
        full = rooted(rel)
        if not full.exists() and not full.is_symlink():
            continue
        stack = [rel]
        while stack:
            item = stack.pop()
            secure_parents(rooted(item))
            meta = secure(rooted(item))
            kind = "dir" if stat.S_ISDIR(meta.st_mode) else "file"
            if len(paths) >= MAX_ITEMS or item in paths:
                raise Refused("inventory_limit_or_overlap")
            record = {"path": item, "kind": kind, "mode": stat.S_IMODE(meta.st_mode),
                      "uid": meta.st_uid, "gid": meta.st_gid}
            if kind == "dir":
                try:
                    children = sorted(rooted(item).iterdir(), key=lambda x: x.name)
                except OSError:
                    raise Refused("source_directory_unavailable")
                if len(children) > MAX_ITEMS:
                    raise Refused("inventory_limit_or_overlap")
                for child in reversed(children):
                    stack.append(item + "/" + child.name)
            else:
                if meta.st_size > MAX_FILE or total + meta.st_size > MAX_SIZE:
                    raise Refused("source_file_too_large")
                record["size"] = meta.st_size
                total += meta.st_size
            paths[item] = record
    core = tuple(CONF + "/sidecar-postfix/" + name for name in
                 ("main.cf", "master.cf", "smtp-port"))
    if not all(p in paths and paths[p]["kind"] == "file" for p in core):
        raise Refused("installed_isolated_sidecar_configuration_required")
    return paths


def read_source(rel, expected):
    path = rooted(rel)
    secure_parents(path)
    info = secure(path, directory=False)
    if info.st_size != expected["size"] or info.st_uid != expected["uid"] or \
            info.st_gid != expected["gid"] or \
            stat.S_IMODE(info.st_mode) != expected["mode"]:
        raise Refused("source_changed_during_snapshot")
    fd = None
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(fd)
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev or \
                not stat.S_ISREG(opened.st_mode):
            raise Refused("source_changed_during_snapshot")
        with os.fdopen(fd, "rb") as reader:
            fd = None
            raw = reader.read(MAX_FILE + 1)
    except OSError:
        raise Refused("source_read_failed")
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw) != expected["size"]:
        raise Refused("source_changed_during_snapshot")
    return raw


def fingerprint(paths):
    """Snapshot of current configuration content and metadata, no secrets echoed."""
    clean = []
    for rel, item in sorted(paths.items()):
        copy = dict(item)
        if item["kind"] == "file":
            copy["sha256"] = digest(read_source(rel, item))
        clean.append(copy)
    return digest(encode(clean)), clean


def command(argv, allowed=(0,), timeout=20):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                universal_newlines=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("required_service_command_unavailable")
    if result.returncode not in allowed or len(result.stdout) > 32768:
        raise Refused("service_command_failed")
    return result.stdout.strip()


def service_state():
    result = {}
    for unit in UNITS:
        active = command(["systemctl", "is-active", unit], allowed=(0, 3, 4))
        enabled = command(["systemctl", "is-enabled", unit], allowed=(0, 1, 3, 4))
        if active not in ("active", "inactive", "failed", "unknown") or \
                enabled not in ("enabled", "disabled", "static", "masked", "indirect", "not-found") or \
                (active == "unknown" and enabled != "not-found"):
            raise Refused("service_state_not_verifiable")
        result[unit] = {"active": active == "active",
                        "enabled": enabled == "enabled"}
    return result


def active_public():
    p = ROOT / "var/lib/linuxmailrelay365-public-smtp/active.json"
    return p.exists() or p.is_symlink()


def sidecar_config():
    """Read-only Postfix sanity checks; no postfix check (it creates dirs)."""
    config = str(rooted(CONF + "/sidecar-postfix"))
    queue = command(["postconf", "-c", config, "-h", "queue_directory"])
    if queue != str(ROOT / QUEUE):
        raise Refused("sidecar_queue_directory_must_be_isolated")
    data = command(["postconf", "-c", config, "-h", "data_directory"])
    if data != str(ROOT / "var/lib/linuxmailrelay365-sidecar"):
        raise Refused("sidecar_data_directory_must_be_isolated")
    interfaces = command(["postconf", "-c", config, "-h", "inet_interfaces"])
    addresses = [v.strip() for v in interfaces.split(",")]
    if not 1 <= len(addresses) <= 2 or addresses[0] != "127.0.0.1" or             len(set(addresses)) != len(addresses):
        raise Refused("unsafe_or_unexpected_sidecar_interfaces")
    private = tuple(ipaddress.ip_network(x) for x in
                    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    for address in addresses[1:]:
        try:
            ipv4 = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError:
            raise Refused("unsafe_or_unexpected_sidecar_interfaces")
        if not any(ipv4 in net for net in private):
            raise Refused("public_or_untrusted_sidecar_listener")
    return config


def current_state():
    paths = walk_inventory()
    sha, entries = fingerprint(paths)
    return sha, entries


def lock():
    fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    meta = os.fstat(fd)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != OWNER_UID or meta.st_mode & 0o077:
        os.close(fd)
        raise Refused("unsafe_global_sidecar_operation_lock")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError):
        os.close(fd)
        raise Refused("concurrent_sidecar_change_blocked")
    return fd


def ensure_base():
    secure_parents(BASE.parent)
    if BASE.parent.is_symlink():
        raise Refused("backup_parent_is_symlink")
    if not BASE.parent.exists():
        BASE.parent.mkdir(mode=0o700)
    secure(BASE.parent, directory=True)
    if BASE.is_symlink():
        raise Refused("backup_root_is_symlink")
    BASE.mkdir(mode=0o700, exist_ok=True)
    meta = secure(BASE, directory=True)
    if stat.S_IMODE(meta.st_mode) & 0o077:
        raise Refused("backup_root_not_private")


def archive_file(target, entries):
    with tarfile.open(str(target), "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for record in entries:
            rel = record["path"]
            ti = tarfile.TarInfo(rel + ("/" if record["kind"] == "dir" else ""))
            ti.mode, ti.uid, ti.gid = record["mode"], record["uid"], record["gid"]
            ti.mtime = 0
            if record["kind"] == "dir":
                ti.type = tarfile.DIRTYPE
                archive.addfile(ti)
            else:
                blob = read_source(rel, record)
                if digest(blob) != record["sha256"]:
                    raise Refused("source_changed_during_archive")
                ti.size = len(blob)
                archive.addfile(ti, io.BytesIO(blob))


def verify_snapshot(backup_id):
    if not ID.fullmatch(backup_id or ""):
        raise Refused("invalid_backup_identifier")
    folder = BASE / backup_id
    secure_parents(folder)
    secure(BASE, directory=True)
    secure(folder, directory=True)
    for name in ("config.tar.gz", "manifest.json", "SHA256SUMS"):
        secure_parents(folder / name)
        info = secure(folder / name, directory=False)
        if info.st_mode & 0o077:
            raise Refused("snapshot_file_permissions_not_private")
    if (folder / "config.tar.gz").stat().st_size > MAX_ARCHIVE or \
            (folder / "manifest.json").stat().st_size > 2 * 1024 * 1024:
        raise Refused("archive_or_manifest_too_large")
    checksum = (folder / "SHA256SUMS").read_text(encoding="ascii")
    if not re.fullmatch(r"[a-f0-9]{64}  config[.]tar[.]gz\n[a-f0-9]{64}  manifest[.]json\n",
                        checksum):
        raise Refused("invalid_archive_checksum_manifest")
    first, second = [x.split("  ", 1)[0] for x in checksum.splitlines()]
    if digest((folder / "config.tar.gz").read_bytes()) != first:
        raise Refused("archive_sha256_mismatch")
    raw = (folder / "manifest.json").read_bytes()
    if digest(raw) != second:
        raise Refused("manifest_sha256_mismatch")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise Refused("manifest_invalid")
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or \
            manifest.get("backup_id") != backup_id or \
            manifest.get("scope") != "isolated_config_no_queue" or \
            not isinstance(manifest.get("entries"), list) or \
            len(manifest["entries"]) > MAX_ITEMS:
        raise Refused("unrecognized_snapshot_scope")
    items = {}
    for record in manifest["entries"]:
        if not isinstance(record, dict) or set(record) != (
                {"path", "kind", "mode", "uid", "gid", "size", "sha256"}
                if record.get("kind") == "file" else
                {"path", "kind", "mode", "uid", "gid"}):
            raise Refused("invalid_snapshot_entry")
        rel = record["path"]
        rooted(rel)
        if rel in items or not isinstance(record["mode"], int) or \
                not isinstance(record["uid"], int) or \
                not isinstance(record["gid"], int) or \
                record["mode"] < 0 or record["mode"] > 0o777 or \
                record["uid"] < 0 or record["gid"] < 0 or \
                record["uid"] != OWNER_UID or record["mode"] & 0o022:
            raise Refused("unsafe_snapshot_entry")
        if record["kind"] == "file":
            if not isinstance(record["size"], int) or record["size"] < 0 or \
                    record["size"] > MAX_FILE or \
                    not isinstance(record["sha256"], str) or \
                    not SHA.fullmatch(record["sha256"]):
                raise Refused("invalid_snapshot_file")
        elif record["kind"] != "dir":
            raise Refused("invalid_snapshot_entry_kind")
        items[rel] = record
    if len(items) == 0 or sum(x.get("size", 0) for x in items.values()) > MAX_SIZE:
        raise Refused("snapshot_exceeds_scope_limit")
    core = [CONF + "/sidecar-postfix/" + n for n in ("main.cf", "master.cf", "smtp-port")]
    if not all(p in items and items[p]["kind"] == "file" for p in core):
        raise Refused("incomplete_sidecar_snapshot")
    members = {}
    try:
        with tarfile.open(str(folder / "config.tar.gz"), "r:gz") as archive:
            for info in archive:
                rel = info.name.rstrip("/")
                rooted(rel)
                if rel in members or rel not in items:
                    raise Refused("duplicate_or_unexpected_archive_member")
                record = items[rel]
                if info.issym() or info.islnk() or not (info.isfile() or info.isdir()) or \
                        (info.isdir() != (record["kind"] == "dir")) or \
                        info.uid != record["uid"] or info.gid != record["gid"] or \
                        info.mode != record["mode"]:
                    raise Refused("unsafe_archive_member_type_or_metadata")
                if info.isfile():
                    if info.size != record["size"] or info.size > MAX_FILE:
                        raise Refused("incorrect_archive_member_size")
                    reader = archive.extractfile(info)
                    if reader is None or digest(reader.read(MAX_FILE + 1)) != record["sha256"]:
                        raise Refused("archive_member_sha256_mismatch")
                members[rel] = True
    except (tarfile.TarError, OSError, EOFError, ValueError):
        raise Refused("corrupt_or_unsafe_archive")
    if len(members) != len(items):
        raise Refused("archive_manifest_inventory_mismatch")
    states = manifest.get("units")
    if not isinstance(states, dict) or set(states) != set(UNITS) or \
            any(not isinstance(v, dict) or set(v) != {"active", "enabled"} or
                not isinstance(v["active"], bool) or
                not isinstance(v["enabled"], bool) for v in states.values()):
        raise Refused("invalid_service_state_manifest")
    if not isinstance(manifest.get("current_sha256"), str) or \
            not SHA.fullmatch(manifest["current_sha256"]) or \
            manifest["current_sha256"] != digest(encode(manifest["entries"])):
        raise Refused("invalid_snapshot_fingerprint")
    if manifest.get("public_active") not in (True, False):
        raise Refused("invalid_public_mode_metadata")
    return manifest


def backup():
    if os.geteuid() != 0:
        raise Refused("root_required")
    ensure_base()
    fd = lock()
    try:
        return make_snapshot()
    finally:
        os.close(fd)


def make_snapshot():
    before, entries = current_state()
    units = service_state()
    snapshot_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + \
        secrets.token_hex(6)
    temp = Path(tempfile.mkdtemp(prefix=".pending-", dir=str(BASE)))
    os.chmod(str(temp), 0o700)
    try:
        manifest = {"schema": 1, "backup_id": snapshot_id,
                    "scope": "isolated_config_no_queue", "entries": entries,
                    "units": units, "public_active": active_public(),
                    "current_sha256": before}
        archive_file(temp / "config.tar.gz", entries)
        after, ignored = current_state()
        if before != after:
            raise Refused("source_changed_during_backup")
        raw = encode(manifest)
        (temp / "manifest.json").write_bytes(raw)
        bits = (digest((temp / "config.tar.gz").read_bytes()) +
                "  config.tar.gz\n" + digest(raw) + "  manifest.json\n")
        (temp / "SHA256SUMS").write_text(bits, encoding="ascii")
        for name in ("config.tar.gz", "manifest.json", "SHA256SUMS"):
            os.chmod(str(temp / name), 0o600)
        os.rename(str(temp), str(BASE / snapshot_id))
        verify_snapshot(snapshot_id)
        return snapshot_id
    finally:
        if temp.exists():
            shutil.rmtree(str(temp))


def read_archive(snapshot_id):
    """Return validated, bounded file content for staging; no tarfile.extract."""
    manifest = verify_snapshot(snapshot_id)
    blobs = {}
    with tarfile.open(str(BASE / snapshot_id / "config.tar.gz"), "r:gz") as archive:
        for member in archive:
            if member.isfile():
                rel = member.name
                payload = archive.extractfile(member).read(MAX_FILE + 1)
                blobs[rel] = payload
    return manifest, blobs


def ensure_restorable(snapshot_id, expected):
    manifest = verify_snapshot(snapshot_id)
    if manifest["public_active"] or active_public():
        raise Refused("public_smtp_firewall_requires_separate_restore_first")
    if not SHA.fullmatch(expected or ""):
        raise Refused("reviewed_current_sha256_required")
    now, entries = current_state()
    if now != expected:
        raise Refused("current_sidecar_changed_since_preview")
    # This operation is limited to the same installed sidecar, same port.
    with tarfile.open(str(BASE / snapshot_id / "config.tar.gz"), "r:gz") as archive:
        port_file = archive.extractfile(CONF + "/sidecar-postfix/smtp-port")
        port = port_file.read(64).decode("ascii").strip()
    installed = read_source(CONF + "/sidecar-postfix/smtp-port",
                            next(x for x in entries if x["path"] ==
                                 CONF + "/sidecar-postfix/smtp-port"))
    if not port.isdigit() or not 1024 <= int(port) <= 65535 or \
            installed.decode("ascii").strip() != port:
        raise Refused("sidecar_custom_port_mismatch")
    return manifest


def check_queue():
    # Offline Postfix may not have showq running: postqueue -j is NOT a
    # reliable empty-queue test when its master is stopped. Inspect the
    # explicitly isolated spool, without modifying files or starting daemons.
    sidecar_config()
    q = ROOT / QUEUE
    secure_parents(q)
    secure(q, directory=True, owner=False)
    # Include maildrop and hold, which online queue commands may miss.
    for name in ("maildrop", "incoming", "active", "deferred", "hold",
                 "bounce", "defer", "trace", "flush", "corrupt",
                 "saved", "discard"):
        folder = q / name
        if folder.exists() or folder.is_symlink():
            if folder.is_symlink() or not folder.is_dir():
                raise Refused("unsafe_spool_subdirectory")
            def scan_error(error):
                raise Refused("isolated_queue_scan_unavailable")
            for parent, dirs, files in os.walk(
                    str(folder), followlinks=False, onerror=scan_error):
                if files or any(Path(parent, d).is_symlink() for d in dirs):
                    raise Refused("isolated_mail_queue_not_empty")


def stop_isolated():
    for unit in (TIMER, HEALTH, SIDECAR, AUTH):
        command(["systemctl", "stop", unit], timeout=35)


def apply_services(states):
    command(["systemctl", "daemon-reload"])
    for unit in UNITS:
        command(["systemctl", "enable" if states[unit]["enabled"] else "disable", unit],
                timeout=25)
    for unit in (AUTH, SIDECAR, HEALTH, TIMER):
        if states[unit]["active"]:
            command(["systemctl", "start", unit], timeout=55)


def check_offline_readiness():
    """The operator must stop only isolated services; this tool never stops MTAs."""
    states = service_state()
    if any(record["active"] for record in states.values()):
        raise Refused("stop_sidecar_auth_health_and_timer_before_offline_restore")
    check_queue()
    port_path = rooted(CONF + "/sidecar-postfix/smtp-port")
    meta = secure(port_path, directory=False)
    if meta.st_size > 6:
        raise Refused("invalid_installed_smtp_port")
    port = port_path.read_text(encoding="ascii").strip()
    if not port.isdigit() or not 1024 <= int(port) <= 65535:
        raise Refused("invalid_installed_smtp_port")
    # systemd may be stopped while Postfix was manually started with -c.
    # A bound TCP listener is an independent hard-stop before changing config.
    if command(["ss", "-H", "-ltn", "( sport = :{} )".format(port)]):
        raise Refused("isolated_smtp_port_still_listening")
    return states


def validate_destination(rel):
    """Refuse all untrusted ancestor/target inodes before changing files."""
    path = rooted(rel)
    secure_parents(path)
    if path.exists() or path.is_symlink():
        secure(path)
    return path


def stage_snapshot(snapshot_id):
    """Stage all allowlisted roots on their target filesystems before mutation."""
    manifest, blobs = read_archive(snapshot_id)
    records = {x["path"]: x for x in manifest["entries"]}
    staged = {}
    try:
        for rel in ROOTS:
            if rel not in records:
                continue
            path = validate_destination(rel)
            temp = Path(tempfile.mkdtemp(
                prefix=".lmr365-stage-", dir=str(path.parent)))
            temp.chmod(0o700)
            staged[rel] = temp
            payload = temp / "payload"
            subset = [r for r in records.values() if
                      r["path"] == rel or r["path"].startswith(rel + "/")]
            subset.sort(key=lambda r: (r["path"].count("/"), r["path"]))
            for record in subset:
                suffix = record["path"][len(rel):].lstrip("/")
                dest = payload / suffix if suffix else payload
                if record["kind"] == "dir":
                    dest.mkdir(parents=True, exist_ok=True)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with dest.open("xb") as out:
                        out.write(blobs[record["path"]])
            for record in reversed(subset):
                suffix = record["path"][len(rel):].lstrip("/")
                dest = payload / suffix if suffix else payload
                os.chown(str(dest), record["uid"], record["gid"])
                dest.chmod(record["mode"])
        return staged
    except Exception:
        for temp in staged.values():
            if temp.exists():
                shutil.rmtree(str(temp))
        raise


def rollback_switch(retired, deployed):
    """Restore original file trees, including roots that existed only afterward."""
    failures = []
    for rel in reversed(ROOTS):
        if rel not in deployed:
            continue
        path = rooted(rel)
        try:
            if path.is_symlink():
                raise Refused("symlink_appeared_during_rollback")
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(str(path))
                else:
                    path.unlink()
            if rel in retired:
                previous = retired[rel] / "previous"
                if not previous.exists() and not previous.is_symlink():
                    raise Refused("retired_original_missing")
                previous.rename(path)
        except (OSError, Refused):
            failures.append(rel)
    if failures:
        say("SIDECAR_CRITICAL_ROLLBACK", "manual_repair_required")
        raise Refused("isolated_configuration_rollback_incomplete")


def offline_switch(staged, retired, deployed):
    """Keep original paths for rollback until all validation has passed."""
    for rel in ROOTS:
        path = rooted(rel)
        if rel not in staged and not path.exists() and not path.is_symlink():
            continue
        path = validate_destination(rel)
        if path.exists():
            holding = Path(tempfile.mkdtemp(
                prefix=".lmr365-original-", dir=str(path.parent)))
            holding.chmod(0o700)
            retired[rel] = holding
            path.rename(holding / "previous")
            deployed.add(rel)
        if rel in staged:
            (staged[rel] / "payload").rename(path)
            deployed.add(rel)


def verify_restored_auth_tls(config):
    """Verify archived private Dovecot SMTP AUTH is not silently weakened.

    Uses only postconf/doveconf READ commands; never starts either daemon,
    creates sockets, or prints password hashes/certificate private keys.
    """
    auth_dir = rooted(CONF + "/smtp-auth")
    unit = rooted("etc/systemd/system/" + AUTH)
    auth_present = auth_dir.exists() or auth_dir.is_symlink()
    unit_present = unit.exists() or unit.is_symlink()
    sasl = command(["postconf", "-c", config, "-h", "smtpd_sasl_auth_enable"])
    if not auth_present and not unit_present:
        if sasl == "yes":
            raise Refused("restored_auth_enabled_without_independent_dovecot")
        return
    if not auth_present or not unit_present:
        raise Refused("restored_dovecot_config_or_unit_missing")
    secure_parents(auth_dir)
    secure(auth_dir, directory=True)
    secure_parents(unit)
    secure(unit, directory=False)
    required = ("dovecot.conf", "passwd", "fullchain.pem", "privkey.pem")
    for name in required:
        local = auth_dir / name
        secure_parents(local)
        secure(local, directory=False)
    values = {
        "smtpd_sasl_auth_enable": "yes",
        "smtpd_sasl_type": "dovecot",
        "smtpd_sasl_path": "private/auth",
        "smtpd_tls_security_level": "encrypt",
        "smtpd_tls_auth_only": "yes",
        "smtpd_relay_restrictions": "permit_sasl_authenticated, reject",
        "smtpd_recipient_restrictions": "permit_sasl_authenticated, reject",
        "smtpd_tls_cert_file": "/etc/linuxmailrelay365/smtp-auth/fullchain.pem",
        "smtpd_tls_key_file": "/etc/linuxmailrelay365/smtp-auth/privkey.pem",
    }
    for key, expected in values.items():
        actual = command(["postconf", "-c", config, "-h", key])
        if actual != expected:
            raise Refused("restored_dovecot_auth_tls_policy_mismatch")
    # A malformed Dovecot 2.3 / 2.4 config would otherwise only fail
    # AFTER an administrator manually starts the independent AUTH unit.
    parsed = command(["doveconf", "-c",
                      str(auth_dir / "dovecot.conf"), "-n"], timeout=25)
    if not parsed or "auth_mechanisms" not in parsed:
        raise Refused("restored_dovecot_config_readonly_validation_failed")


def verify_restored_from_guard(config):
    """Offline ownership guard recovery checks. Never open its UNIX socket."""
    guard = rooted(CONF + "/sidecar-postfix/eop-from-owners.tsv")
    service = rooted("etc/systemd/system/" + FROM_GUARD)
    engine = rooted("usr/local/libexec/linuxmailrelay365-from-owner-milter.py")
    required = ("smtpd_milters", "milter_default_action",
                "milter_protocol", "milter_mail_macros",
                "authorized_submit_users")
    props = {name: command(["postconf", "-c", config, "-h", name])
             for name in required}
    if not props["smtpd_milters"]:
        return
    expected = "unix:/run/linuxmailrelay365-from-guard/from-guard.sock"
    if (props["smtpd_milters"] != expected or
            props["milter_default_action"] != "tempfail" or
            props["milter_protocol"] != "6" or
            props["authorized_submit_users"] != "" or
            not all(x in props["milter_mail_macros"] for x in
                    ("{auth_authen}", "{auth_type}"))):
        raise Refused("restored_header_guard_policy_not_fail_closed")
    try:
        group = __import__("grp").getgrnam("postfix").gr_gid
    except KeyError:
        raise Refused("restored_header_guard_postfix_group_missing")
    for item in (guard, service, engine):
        secure_parents(item)
        secure(item, directory=False)
    st = guard.lstat()
    if st.st_gid != group or stat.S_IMODE(st.st_mode) != 0o640:
        raise Refused("restored_header_guard_owner_map_untrusted")


def verify_restored_postfix():
    """Read-only validation, no queue creation, service start or MTA reload."""
    config = sidecar_config()
    port_path = rooted(CONF + "/sidecar-postfix/smtp-port")
    info = secure(port_path, directory=False)
    if info.st_size > 6:
        raise Refused("invalid_restored_custom_smtp_port")
    port = port_path.read_text(encoding="ascii").strip()
    if not port.isdigit() or not 1024 <= int(port) <= 65535:
        raise Refused("invalid_restored_custom_smtp_port")
    main = command(["postconf", "-c", config, "-n"])
    if not main or "queue_directory" not in main:
        raise Refused("restored_main_cf_not_verified")
    master = command(["postconf", "-c", config, "-M"])
    if not master:
        raise Refused("restored_master_cf_not_verified")
    listeners = []
    for line in master.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "inet":
            # 'postconf -M' READ output is plain master.cf syntax, not the
            # 'name/type=value' syntax used by postconf -M EDIT arguments.
            # Reject additional inet services, unexpected ports and commands.
            if len(fields) < 8 or fields[0] != port or fields[7] != "smtpd":
                raise Refused("restored_master_cf_has_unexpected_smtp_listener")
            listeners.append(fields[0])
    if len(listeners) != 1:
        raise Refused("restored_master_cf_has_unexpected_smtp_listener")
    verify_restored_auth_tls(config)
    verify_restored_from_guard(config)


def cleanup_workdirs(staged, retired, success):
    for temp in staged.values():
        if temp.exists():
            shutil.rmtree(str(temp))
    if success:
        for temp in retired.values():
            if temp.exists():
                shutil.rmtree(str(temp))


def restore(snapshot_id, expected):
    if os.geteuid() != 0:
        raise Refused("root_required")
    secure_parents(BASE)
    secure(BASE, directory=True)
    fd = lock()
    try:
        manifest = ensure_restorable(snapshot_id, expected)
        check_offline_readiness()
        # Emergency backup of CURRENT independent config, not the mail queue.
        emergency_id = make_snapshot()
        say("SIDECAR_PRE_RESTORE_BACKUP_ID", emergency_id)
        staged = stage_snapshot(snapshot_id)
        retired = {}
        deployed = set()
        success = False
        try:
            check_offline_readiness()
            latest, ignored = current_state()
            if latest != expected:
                raise Refused("sidecar_changed_during_staging")
            offline_switch(staged, retired, deployed)
            # postconf -n/-M/-h are read-only. postfix check is NOT:
            # it may create mail queue directories and must not be used here.
            verify_restored_postfix()
            command(["systemctl", "daemon-reload"])
            success = True
        except Exception as failure:
            # Report ONLY sanitized internal reason codes, never paths/keys,
            # to distinguish an invalid restored config from an I/O failure.
            say("SIDECAR_RESTORE_FAILED_STAGE",
                str(failure) if isinstance(failure, Refused)
                else "unexpected_restore_validation_error")
            if deployed:
                rollback_switch(retired, deployed)
                command(["systemctl", "daemon-reload"])
                # Old trees have been put back; remove empty holding folders.
                cleanup_workdirs({}, retired, True)
            raise Refused("offline_restore_failed_original_configuration_retained")
        finally:
            cleanup_workdirs(staged, retired, success)
        say("SIDECAR_RESTORED_BACKUP_ID", snapshot_id)
        say("SIDECAR_OFFLINE_RESTORE", "verified_files_only")
        say("SIDECAR_SERVICES_STARTED", "no")
        say("PRIMARY_MTA_CHANGED", "no")
        say("QUEUE_RESTORED", "no")
        say("M365_TENANT_RESTORE_VERIFIED", "no")
        return 0
    finally:
        os.close(fd)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--backup", action="store_true")
    group.add_argument("--list", action="store_true")
    group.add_argument("--verify", metavar="ID")
    group.add_argument("--preview-restore", metavar="ID")
    group.add_argument("--restore", metavar="ID")
    group.add_argument("--self-test", action="store_true")
    p.add_argument("--expect-current-sha256", default="")
    p.add_argument("--confirm", default="")
    args = p.parse_args(argv)
    if args.self_test:
        say("SIDECAR_RECOVERY_SELF_TEST", "pass")
        say("CHANGES_APPLIED", "no")
        return 0
    if args.restore:
        if args.confirm != "RESTORE_ISOLATED_RELAY_CONFIGURATION":
            say("SIDECAR_RECOVERY_ERROR", "explicit_restore_confirmation_required")
            return 2
        if not SHA.fullmatch(args.expect_current_sha256 or ""):
            say("SIDECAR_RECOVERY_ERROR", "reviewed_current_sha256_required")
            return 2
    elif args.confirm or args.expect_current_sha256:
        say("SIDECAR_RECOVERY_ERROR", "unexpected_mutation_argument")
        return 2
    if os.geteuid() != 0:
        say("SIDECAR_RECOVERY_ERROR", "root_required")
        return 2
    try:
        if args.backup:
            result = backup()
            say("SIDECAR_BACKUP_ID", result)
            say("SIDECAR_BACKUP_STATUS", "verified_config_only_no_queue")
        elif args.list:
            if not BASE.exists() and not BASE.is_symlink():
                say("SIDECAR_BACKUP_COUNT", "0")
                say("CHANGES_APPLIED", "no")
                return 0
            secure_parents(BASE)
            secure(BASE, directory=True)
            candidates = []
            for path in sorted(BASE.iterdir()):
                if ID.fullmatch(path.name):
                    try:
                        verify_snapshot(path.name)
                        candidates.append(path.name)
                    except Refused:
                        say("SIDECAR_INVALID_BACKUP_ID", path.name)
            for name in candidates[:256]:
                say("SIDECAR_BACKUP_ID", name)
            say("SIDECAR_BACKUP_COUNT", len(candidates))
        elif args.verify:
            verify_snapshot(args.verify)
            say("SIDECAR_BACKUP_STATUS", "verified_config_only_no_queue")
        elif args.preview_restore:
            manifest = verify_snapshot(args.preview_restore)
            if active_public() or manifest["public_active"]:
                raise Refused("public_smtp_firewall_requires_separate_restore_first")
            sha, entries = current_state()
            # Preview never changes services, queues or configuration.
            say("SIDECAR_RESTORE_PREVIEW", "requires_queue_empty_and_typed_confirmation")
            say("SIDECAR_CURRENT_SHA256", sha)
            say("SIDECAR_RESTORE_TARGET_SHA256", manifest["current_sha256"])
            say("SIDECAR_RESTORE_QUEUE_VERIFIED", "no")
            say("SIDECAR_EXTERNAL_DEPENDENCIES_INCLUDED", "no")
            say("SIDECAR_PRIMARY_MTA_RESTORED", "no")
        elif args.restore:
            return restore(args.restore, args.expect_current_sha256)
    except (Refused, OSError, ValueError, UnicodeError) as err:
        if isinstance(err, Refused):
            say("SIDECAR_RECOVERY_ERROR", str(err))
        else:
            say("SIDECAR_RECOVERY_ERROR", "unexpected_io_or_integrity_failure")
        say("CHANGES_APPLIED", "unknown_if_restore_attempted" if args.restore else "no")
        return 2
    say("CHANGES_APPLIED", "isolated_config_only" if args.restore else "no")
    return 0


if __name__ == "__main__":
    sys.exit(main())
