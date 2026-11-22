#!/usr/bin/env python3
"""Opt-in root-only renewal of Multi-mailbox SMTP ingress attestations.

A receipt is a static local SMTP AUTH/From-Guard configuration audit ONLY,
not proof of a real SMTP login, Microsoft 365 authorization or mail delivery.
No default activation. Preview SHA + typed confirmation required to enable;
explicit disable stops timer and revokes its receipt. Python 3.6+.
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
import stat
import subprocess
import sys
import time

ROOT = Path("/usr/local/libexec/linuxmailrelay365-multi-oauth")
PROOF = Path("/etc/linuxmailrelay365/oauth-ingress-proof.json")
MAP = Path("/etc/linuxmailrelay365/oauth-runtime-senders.tsv")
CONF = Path("/etc/linuxmailrelay365/sidecar-postfix")
ACTIVE = Path("/var/backups/linuxmailrelay365-multi-oauth/active.json")
SERVICE = Path("/etc/systemd/system/linuxmailrelay365-multi-proof.service")
TIMER = Path("/etc/systemd/system/linuxmailrelay365-multi-proof.timer")
STATE_ROOT = Path("/var/lib/linuxmailrelay365-multi-proof-timer")
STATE = STATE_ROOT / "state.json"
LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")
# Share the existing offline route lock with Restore/Apply/Acceptance.
SYSTEMCTL = "/usr/bin/systemctl"
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
NAME = re.compile(r"\A[A-Za-z0-9_.-]+\.py\Z")
APPROVAL = "ENABLE_REVIEWED_MULTI_INGRESS_TIMER"
REVOCATION = "DISABLE_AND_REVOKE_MULTI_INGRESS_TIMER"


class Refused(Exception):
    pass


def digest(value):
    return hashlib.sha256(value).hexdigest()


def parents(path):
    current = Path(path)
    while True:
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022):
            raise Refused("untrusted_directory")
        if current == current.parent:
            return
        current = current.parent


def read(path, maximum, modes, gid=None):
    path = Path(path)
    parents(path.parent)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or
            before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in modes or
            (gid is not None and before.st_gid != gid) or
            not 0 <= before.st_size <= maximum):
        raise Refused("unsafe_protected_file")
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_uid,
                     s.st_gid, s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if key(opened) != key(before):
            raise Refused("file_changed_before_read")
        left, parts = opened.st_size, []
        while left:
            block = os.read(fd, min(left, 65536))
            if not block:
                raise Refused("short_protected_read")
            parts.append(block)
            left -= len(block)
        if (os.read(fd, 1) or key(os.fstat(fd)) != key(opened)
                or key(path.lstat()) != key(opened)):
            raise Refused("file_changed_during_read")
        return b"".join(parts)
    finally:
        os.close(fd)


def record(raw):
    """Reject duplicate, nested duplicate or nonfinite protected JSON keys."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refused("duplicate_protected_json_key")
            result[key] = value
        return result

    def nonfinite(_):
        raise Refused("nonfinite_protected_json_value")

    obj = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
                     parse_constant=nonfinite)
    if not isinstance(obj, dict):
        raise Refused("invalid_state_record")
    return obj


def service_text(map_sha):
    if not isinstance(map_sha, str) or not SHA.fullmatch(map_sha):
        raise Refused("invalid_reviewed_map_hash")
    return ("""[Unit]
Description=LinuxMailRelay365 experimental static ingress audit (not SMTP acceptance)
ConditionPathExists=/etc/linuxmailrelay365/oauth-runtime-senders.tsv

[Service]
Type=oneshot
User=root
Group=root
UMask=0027
ExecStart=/usr/bin/python3 /usr/local/libexec/linuxmailrelay365-multi-oauth/refresh-multi-mailbox-proof.py --map-sha256 %s --confirm REFRESH_PRIVILEGED_MULTI_INGRESS_PROOF
TimeoutStartSec=30
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
ProtectSystem=strict
ReadWritePaths=/etc/linuxmailrelay365
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
""" % map_sha).encode("ascii")


def timer_text():
    return b"""[Unit]
Description=Renew experimental LinuxMailRelay365 ingress proof

[Timer]
OnBootSec=45s
OnUnitActiveSec=60s
AccuracySec=5s
Persistent=false
Unit=linuxmailrelay365-multi-proof.service

[Install]
WantedBy=timers.target
"""


def systemctl(*args, allow_inactive=False):
    if not Path(SYSTEMCTL).is_file():
        raise Refused("systemctl_missing")
    result = subprocess.run([SYSTEMCTL] + list(args),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, timeout=40,
                            universal_newlines=True, check=False)
    if len(result.stdout) > 4096 or (result.returncode and not allow_inactive):
        raise Refused("systemd_command_refused")
    return result.returncode == 0


def attest():
    """Require installed route, pinned code, running static ingress guards."""
    if os.geteuid() != 0:
        raise Refused("root_required")
    raw = read(ACTIVE, 4096, (0o600,))
    meta = record(raw)
    pinned = meta.get("runtime_map_sha256")
    if not isinstance(pinned, str) or not SHA.fullmatch(pinned):
        raise Refused("invalid_active_route_marker")
    group = grp.getgrnam("m365mailer").gr_gid
    if digest(read(MAP, 65536, (0o640,), group)) != pinned:
        raise Refused("sender_map_drift")
    configs = meta.get("active")
    if not isinstance(configs, dict):
        raise Refused("invalid_active_config_record")
    for name in ("main.cf", "master.cf"):
        expected = configs.get(name)
        if (not isinstance(expected, str) or not SHA.fullmatch(expected) or
                digest(read(CONF / name, 1048576,
                            (0o600, 0o640, 0o644))) != expected):
            raise Refused("active_postfix_config_drift")
    sources = meta.get("source")
    if not isinstance(sources, dict) or not 1 <= len(sources) <= 16 or \
            "refresh-multi-mailbox-proof.py" not in sources:
        raise Refused("invalid_installed_source_manifest")
    for name, expected in sources.items():
        if (not isinstance(name, str) or not NAME.fullmatch(name) or
                not isinstance(expected, str) or not SHA.fullmatch(expected) or
                digest(read(ROOT / name, 262144, (0o644,))) != expected):
            raise Refused("installed_audit_source_changed")
    spec = importlib.util.spec_from_file_location(
        "lmr365_timer_auditor", str(ROOT / "refresh-multi-mailbox-proof.py"))
    if spec is None or spec.loader is None:
        raise Refused("audit_module_missing")
    module = importlib.util.module_from_spec(spec)
    # The read-only Preview must not create Python __pycache__ in the
    # installed runtime directory. Importing our dynamically loaded auditor
    # (and its nested guards) otherwise writes bytecode when run as root.
    bytecode_before = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
        proof = module.inspect(pinned)
    except Exception:
        # Nested auditors have independent Refused/Unverified exception
        # classes. Never echo their message, traceback, path or credentials
        # back to the SSH client/Windows Wizard.
        raise Refused("installed_ingress_audit_refused") from None
    finally:
        sys.dont_write_bytecode = bytecode_before
    if (not isinstance(proof, dict) or
            proof.get("map_sha256") != pinned or
            type(proof.get("expires_at")) is not int or
            proof["expires_at"] <= int(time.time()) or
            proof.get("ingress") != "root_static_audit_consistent_not_live_delivery"):
        raise Refused("ingress_policy_not_current")
    return pinned, digest(raw)


def plan():
    pinned, route_sha = attest()
    parents(SERVICE.parent)
    if any(p.exists() or p.is_symlink() for p in (SERVICE, TIMER, STATE, STATE_ROOT)):
        raise Refused("timer_already_present_or_unsafe")
    service, timer = service_text(pinned), timer_text()
    values = {"map": pinned, "route": route_sha,
              "service": digest(service), "timer": digest(timer)}
    approval = digest(json.dumps(
        values, sort_keys=True, separators=(",", ":")).encode("ascii"))
    return approval, values, service, timer


def create_file(path, data, mode):
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        rest = memoryview(data)
        while rest:
            written = os.write(fd, rest)
            if written < 1:
                raise Refused("short_protected_write")
            rest = rest[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if read(path, len(data), (mode,)) != data:
        raise Refused("write_readback_failed")


def locked(callback):
    parents(LOCK.parent)
    fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600):
            raise Refused("untrusted_manager_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return callback()
    finally:
        os.close(fd)


def installed():
    state = record(read(STATE, 1024, (0o600,)))
    if (set(state) != {"version", "plan", "map", "service", "timer"} or
            type(state["version"]) is not int or
            state["version"] != 1 or
            not all(isinstance(state[k], str) and SHA.fullmatch(state[k])
                    for k in ("plan", "map", "service", "timer"))):
        raise Refused("invalid_installed_timer")
    expected = {SERVICE: service_text(state["map"]), TIMER: timer_text()}
    if state["service"] != digest(expected[SERVICE]) or \
            state["timer"] != digest(expected[TIMER]):
        raise Refused("unit_record_changed")
    for path, value in expected.items():
        if read(path, 4096, (0o644,)) != value:
            raise Refused("installed_timer_unit_changed")
    return state


def revoke(map_sha):
    if PROOF.exists() or PROOF.is_symlink():
        gid = grp.getgrnam("m365mailer").gr_gid
        proof = record(read(PROOF, 2048, (0o640,), gid))
        if proof.get("map_sha256") != map_sha:
            raise Refused("unexpected_proof_identity")
        PROOF.unlink()


def disable():
    state = installed()
    systemctl("disable", "--now", TIMER.name)
    systemctl("stop", SERVICE.name)
    if (systemctl("is-active", "--quiet", TIMER.name, allow_inactive=True) or
            systemctl("is-enabled", "--quiet", TIMER.name, allow_inactive=True)):
        raise Refused("timer_still_active_or_enabled")
    revoke(state["map"])
    for path in (TIMER, SERVICE):
        read(path, 4096, (0o644,))
        path.unlink()
    read(STATE, 1024, (0o600,))
    STATE.unlink()
    STATE_ROOT.rmdir()
    systemctl("daemon-reload")
    return True


def enable(reviewed_sha):
    if not isinstance(reviewed_sha, str) or not SHA.fullmatch(reviewed_sha):
        raise Refused("reviewed_sha_required")
    approved, info, service, timer = plan()
    if approved != reviewed_sha or plan()[0] != reviewed_sha:
        raise Refused("approval_stale")
    parents(STATE_ROOT.parent)
    state = {"version": 1, "plan": approved, "map": info["map"],
             "service": info["service"], "timer": info["timer"]}
    state_bytes = (json.dumps(state, sort_keys=True,
                   separators=(",", ":")) + "\n").encode("ascii")
    expected = ((SERVICE, service, 0o644), (TIMER, timer, 0o644),
                (STATE, state_bytes, 0o600))
    created = []
    state_dir_created = False
    refresh_attempted = False
    try:
        STATE_ROOT.mkdir(mode=0o700)
        state_dir_created = True
        for path, data, mode in expected:
            create_file(path, data, mode)
            created.append((path, data, mode))
        systemctl("daemon-reload")
        # An initial successful audit is mandatory before timer activation.
        # Even a reported start failure may have already written a receipt.
        refresh_attempted = True
        systemctl("start", SERVICE.name)
        gid = grp.getgrnam("m365mailer").gr_gid
        proof = record(read(PROOF, 2048, (0o640,), gid))
        issued = proof.get("issued_at")
        if (proof.get("map_sha256") != info["map"] or
                type(issued) is not int or abs(int(time.time()) - issued) > 45 or
                proof.get("expires_at") != issued + 120):
            raise Refused("initial_proof_not_current")
        systemctl("enable", "--now", TIMER.name)
        if not systemctl("is-active", "--quiet", TIMER.name):
            raise Refused("timer_not_active")
        return True
    except Exception:
        # Never leave an activated timer behind after a failed installation.
        # Cleanup is deliberately conservative: only exactly recorded,
        # root-owned bytes are eligible for deletion. Partially created or
        # changed files remain in place and force a manual-review refusal.
        try:
            systemctl("disable", "--now", TIMER.name, allow_inactive=True)
            systemctl("stop", SERVICE.name, allow_inactive=True)
            if (systemctl("is-active", "--quiet", TIMER.name,
                          allow_inactive=True) or
                    systemctl("is-active", "--quiet", SERVICE.name,
                              allow_inactive=True) or
                    systemctl("is-enabled", "--quiet", TIMER.name,
                              allow_inactive=True)):
                raise Refused("timer_remains_active_or_enabled_after_failure")
            if refresh_attempted:
                # A failed activation must never leave its newly issued
                # authorization receipt usable for another 120 seconds.
                revoke(info["map"])
            for path, data, mode in reversed(created):
                if read(path, len(data), (mode,)) != data:
                    raise Refused("partial_timer_write_changed")
                path.unlink()
            if state_dir_created:
                STATE_ROOT.rmdir()
            systemctl("daemon-reload")
        except Exception:
            print("MULTI_PROOF_TIMER_ROLLBACK=manual_review_required",
                  file=sys.stderr)
        raise


def receipt_age_status(map_sha, now=None):
    """TTL-only, read-only information; never a live SMTP acceptance result.

    Checks the transport's exact receipt schema, sender-map pin and age,
    without modifying, refreshing or accepting a policy. A malformed
    receipt is an error rather than a reassuring successful status.
    """
    if not isinstance(map_sha, str) or not SHA.fullmatch(map_sha):
        raise Refused("invalid_status_map_pin")
    if not PROOF.exists() and not PROOF.is_symlink():
        return "missing"
    gid = grp.getgrnam("m365mailer").gr_gid
    candidate = record(read(PROOF, 2048, (0o640,), gid))
    required = {"version", "map_sha256", "issued_at", "expires_at",
                "mailboxes", "main_meta", "master_meta", "ingress"}
    issued, expires = candidate.get("issued_at"), candidate.get("expires_at")
    if (set(candidate) != required or
            type(candidate.get("version")) is not int or
            candidate["version"] != 1 or
            candidate.get("ingress") !=
            "root_static_audit_consistent_not_live_delivery" or
            not isinstance(candidate.get("map_sha256"), str) or
            not SHA.fullmatch(candidate["map_sha256"]) or
            type(issued) is not int or type(expires) is not int or
            expires - issued != 120 or
            type(candidate.get("mailboxes")) is not int or
            not 1 <= candidate["mailboxes"] <= 64 or
            not isinstance(candidate.get("main_meta"), list) or
            not isinstance(candidate.get("master_meta"), list)):
        raise Refused("invalid_receipt_status_metadata")
    current = int(time.time()) if now is None else int(now)
    if (candidate["map_sha256"] != map_sha or
            digest(read(MAP, 65536, (0o640,), gid)) != map_sha):
        return "map_changed"
    if issued > current + 5:
        raise Refused("receipt_from_future")
    if current >= expires:
        return "expired"
    return "fresh_ttl_only"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--enable-reviewed", action="store_true")
    mode.add_argument("--disable-reviewed", action="store_true")
    mode.add_argument("--status", action="store_true")
    parser.add_argument("--approve-sha256", default="")
    parser.add_argument("--confirm", default="")
    a = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Refused("root_required")
        if a.plan:
            if a.approve_sha256 or a.confirm:
                raise Refused("no_approval_in_preview")
            sha, _, _, _ = plan()
            print("MULTI_PROOF_TIMER_PLAN_SHA256=" + sha)
            print("MULTI_PROOF_TIMER=review_only")
        elif a.enable_reviewed:
            if a.confirm != APPROVAL:
                raise Refused("typed_enable_approval_required")
            locked(lambda: enable(a.approve_sha256))
            print("MULTI_PROOF_TIMER=enabled_static_audit_only")
        elif a.disable_reviewed:
            if a.approve_sha256 or a.confirm != REVOCATION:
                raise Refused("typed_disable_approval_required")
            locked(disable)
            print("MULTI_PROOF_TIMER=disabled_and_receipt_revoked")
        else:
            if a.approve_sha256 or a.confirm:
                raise Refused("no_approval_in_status")
            present = any(p.exists() or p.is_symlink()
                          for p in (SERVICE, TIMER, STATE, STATE_ROOT))
            if not present:
                print("MULTI_PROOF_TIMER=not_installed")
                print("MULTI_PROOF_RECEIPT=not_applicable")
            else:
                state = installed()
                active = systemctl("is-active", "--quiet", TIMER.name,
                                   allow_inactive=True)
                print("MULTI_PROOF_TIMER=" + ("active" if active else "inactive"))
                print("MULTI_PROOF_RECEIPT=" +
                      receipt_age_status(state["map"]))
        print("MULTI_PROOF_TIMER_MESSAGES_SENT=no")
        print("MULTI_PROOF_TIMER_PRIMARY_MTA_CHANGED=no")
        print("MULTI_PROOF_TIMER_M365_DELIVERY_VERIFIED=no")
        return 0
    except (Refused, OSError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired, subprocess.SubprocessError):
        print("MULTI_PROOF_TIMER=refused_or_incomplete_manual_review",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
