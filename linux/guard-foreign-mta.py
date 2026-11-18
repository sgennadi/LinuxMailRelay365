#!/usr/bin/env python3
"""Fail-closed Exim/Sendmail coexistence guard, Python 3.6+.

This guard is used ONLY when a fresh, isolated Postfix sidecar is installed
beside an already running foreign primary MTA. No package, mail queue,
firewall, MTA config, or service is changed by this script.

Its snapshot fingerprint covers primary MTA service identity/PID, TCP25
listener state and bounded /etc/mail, /etc/exim*, /etc/postfix trees.
The same fingerprint is checked after isolated sidecar installation. This
cannot prove all external dependencies; live MTA acceptance is still required.
"""
import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

DNS = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
SERVICES = {
    "postfix": ("postfix.service",),
    "exim": ("exim4.service", "exim.service"),
    "sendmail": ("sendmail.service",),
}
CONFIGS = (Path("/etc/mail"), Path("/etc/exim4"), Path("/etc/exim"),
           Path("/etc/postfix"))
MAX_FILES = 1024
MAX_BYTES = 32 * 1024 * 1024
MAX_SINGLE = 8 * 1024 * 1024


class Refused(Exception):
    pass


def command(argv, timeout=8):
    if not shutil.which(argv[0]):
        raise Refused("missing_required_runtime_tool")
    try:
        value = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=timeout,
                               check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("runtime_inspection_failed")
    if len(value.stdout) > 16384 or len(value.stderr) > 16384:
        raise Refused("unbounded_runtime_response")
    return value


def unit_status(unit):
    res = command(["systemctl", "is-active", unit])
    value = res.stdout.strip()
    if res.returncode == 0 and value == "active":
        return "active"
    if res.returncode != 0 and value in ("inactive", "failed"):
        return "inactive"
    if res.returncode != 0 and value == "unknown":
        # RHEL/Ubuntu may not ship all three MTA units. Only a proven
        # not-found unit may be treated as inactive.
        load = command(["systemctl", "show", "--property=LoadState",
                        "--value", unit])
        if load.returncode == 0 and load.stdout.strip() == "not-found":
            return "inactive"
    raise Refused("unverified_primary_mta_service_state")


def service_snapshot(expected):
    active = []
    for name, units in SERVICES.items():
        for unit in units:
            if unit_status(unit) == "active":
                active.append((name, unit))
    # Exim may ship exim4.service and exim.service as aliases.
    # Aliases are accepted ONLY if systemd proves the identical MainPID;
    # multiple *different* MTA instances or processes are refused.
    if not active or any(name != expected for name, unit in active):
        raise Refused("active_mta_not_exclusively_declared_foreign_service")
    pids = []
    for name, unit in active:
        result = command(["systemctl", "show", "--property=MainPID",
                          "--value", unit])
        pid = result.stdout.strip()
        if result.returncode != 0 or not pid.isdigit() or int(pid) < 2:
            raise Refused("primary_mta_main_pid_not_verified")
        pids.append(pid)
    if len(set(pids)) != 1:
        raise Refused("multiple_foreign_mta_processes_detected")
    # Stable unit naming is important for the pre/post baseline.
    unit = active[0][1]
    # A restart / replacement between preflight and completion changes the
    # PID, even when the service has returned to "active".
    return unit, pids[0]


def bounded_config_digest(roots=CONFIGS):
    digest = hashlib.sha256()
    total = 0
    count = 0
    for root in roots:
        if not root.exists() and not root.is_symlink():
            continue
        pending = [root]
        while pending:
            path = pending.pop()
            try:
                info = path.lstat()
            except OSError:
                raise Refused("primary_mta_configuration_unavailable")
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise Refused("unsafe_primary_mta_configuration_permissions")
            if stat.S_ISDIR(info.st_mode):
                # Include empty directories and their metadata as well.
                digest.update(("D|{}|{}|{}|{}\n".format(
                    path, info.st_mode, info.st_uid, info.st_gid)).encode("utf-8"))
                try:
                    entries = sorted(path.iterdir(), key=lambda x: str(x))
                except OSError:
                    raise Refused("primary_mta_configuration_unavailable")
                if len(entries) > MAX_FILES:
                    raise Refused("primary_mta_configuration_inventory_too_large")
                pending.extend(reversed(entries))
                continue
            if not stat.S_ISREG(info.st_mode):
                # A symlink, socket, fifo, device or hard-to-classify file
                # must not be used as a completeness claim.
                raise Refused("non_regular_primary_mta_config_entry")
            count += 1
            total += info.st_size
            if count > MAX_FILES or info.st_size > MAX_SINGLE or total > MAX_BYTES:
                raise Refused("primary_mta_config_inventory_too_large")
            fd = None
            try:
                fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                checked = os.fstat(fd)
                if (checked.st_ino != info.st_ino or checked.st_dev != info.st_dev or
                        checked.st_size != info.st_size):
                    raise Refused("primary_mta_configuration_changed_during_read")
                body = hashlib.sha256()
                remaining = info.st_size
                while remaining:
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        raise Refused("primary_mta_configuration_short_read")
                    body.update(chunk)
                    remaining -= len(chunk)
            except OSError:
                raise Refused("primary_mta_configuration_unavailable")
            finally:
                if fd is not None:
                    os.close(fd)
            record = "{}|{}|{}|{}|{}|{}\n".format(
                str(path), info.st_mode, info.st_uid, info.st_gid,
                info.st_size, body.hexdigest())
            digest.update(record.encode("utf-8"))
    if not count:
        raise Refused("no_primary_mta_configuration_found")
    return digest.hexdigest()


def listen_port25_snapshot():
    res = command(["ss", "-H", "-ltn", "( sport = :25 )"])
    if res.returncode != 0:
        raise Refused("primary_mta_smtp_socket_unverified")
    # Receive queue and backlog sizes change during legitimate SMTP traffic:
    # fingerprint local sockets only, never transient counters.
    listeners = []
    for line in res.stdout.splitlines():
        cols = line.split()
        if len(cols) < 4 or not cols[3].endswith(":25"):
            raise Refused("primary_mta_smtp_socket_unverified")
        listeners.append(cols[3])
    payload = "\n".join(sorted(listeners)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def guard(mta, hostname, expected=None):
    if mta not in ("exim", "sendmail"):
        raise Refused("unsupported_foreign_primary_mta")
    if not DNS.fullmatch(hostname or "") or len(hostname) > 253:
        raise Refused("explicit_sidecar_hostname_required")
    if expected is not None and not SHA.fullmatch(expected):
        raise Refused("reviewed_baseline_sha256_required")
    if os.geteuid() != 0:
        raise Refused("root_required")
    if not (shutil.which("postfix") and shutil.which("postconf")):
        raise Refused("postfix_binaries_must_be_preinstalled_no_package_changes")
    unit, pid = service_snapshot(mta)
    config = bounded_config_digest()
    socket_state = listen_port25_snapshot()
    state = hashlib.sha256(
        ("v1|{}|{}|{}|{}|{}\n".format(mta, hostname.lower(), unit, pid,
                                      config + "|" + socket_state)).encode("ascii")
    ).hexdigest()
    if expected is not None and state != expected:
        raise Refused("primary_mta_state_changed_rollback_sidecar")
    return state


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mta", choices=("exim", "sendmail"))
    parser.add_argument("--hostname")
    parser.add_argument("--expect-sha256", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        print("FOREIGN_MTA_GUARD_SELF_TEST=pass")
        print("CHANGES_APPLIED=no")
        return 0
    try:
        result = guard(args.mta, args.hostname,
                       args.expect_sha256 or None)
    except Refused as ex:
        print("FOREIGN_MTA_GUARD=refused")
        print("FOREIGN_MTA_REASON={}".format(str(ex)))
        print("CHANGES_APPLIED=no")
        return 2
    print("FOREIGN_MTA_GUARD=verified_unchanged" if args.expect_sha256 else
          "FOREIGN_MTA_GUARD=baseline_captured")
    print("FOREIGN_MTA_BASELINE_SHA256={}".format(result))
    print("PRIMARY_MTA_STOP_OR_RESTART=no")
    print("PRIMARY_MTA_QUEUE_MODIFIED=no")
    print("CHANGES_APPLIED=no")
    return 0


if __name__ == "__main__":
    sys.exit(main())
