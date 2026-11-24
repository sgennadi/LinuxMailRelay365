#!/usr/bin/env python3
"""Read-only outbound transport SELinux readiness (Python 3.6+).

No relabel, policy mutation, service control, credential read or SMTP traffic.
Port labels are policy metadata, not proof of name_connect permission.
An unavailable diagnostic never authorizes a configuration change.
"""
import argparse
import os
import pwd
import re
import signal
import sys

sys.dont_write_bytecode = True
from pathlib import Path
import importlib.util

spec = importlib.util.spec_from_file_location(
    "transport_labels", str(Path(__file__).with_name(
        "inspect-conditional-transport-selinux.py")))
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
P, C, M = L.P, L.C, L.M

PREFIX = "SELINUX_ROUTE_"
ACTIVE = ("enforcing", "permissive")
GENERIC = {"reserved_port_t", "unreserved_port_t", "port_t"}


def port_types(ports, raw):
    """Strictly parse complete C-locale semanage output, never infer access."""
    if not isinstance(raw, str) or len(raw) > 131072:
        raise L.Refused("unverified_port_policy")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines or lines[0].split() != ["SELinux", "Port", "Type", "Proto", "Port", "Number"]:
        raise L.Refused("unverified_port_policy_header")
    matches = {port: set() for port in ports}
    seen_smtp = False
    for line in lines[1:]:
        match = re.fullmatch(r"([A-Za-z0-9_]+)\s+(tcp|udp|sctp|dccp)\s+(.+)", line)
        if not match:
            raise L.Refused("unverified_port_policy_row")
        kind, proto, values = match.groups()
        ranges = []
        for value in values.split(","):
            interval = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?", value.strip())
            if not interval:
                raise L.Refused("unverified_port_policy_range")
            lo, hi = int(interval[1]), int(interval[2] or interval[1])
            # Policy-wide ranges can include 0, while requested SMTP ports cannot.
            if not 0 <= lo <= hi <= 65535:
                raise L.Refused("unverified_port_policy_range")
            ranges.append((lo, hi))
        if proto != "tcp":
            continue
        seen_smtp = seen_smtp or kind == "smtp_port_t"
        if kind in GENERIC:
            continue
        for port in ports:
            if any(lo <= port <= hi for lo, hi in ranges):
                matches[port].add(kind)
    if not seen_smtp:
        raise L.Refused("smtp_port_policy_unverified")
    return {port: "smtp_port_t" if kinds == {"smtp_port_t"} else
            "other_type" if kinds else "no_specific_type"
            for port, kinds in matches.items()}


def native_options(rules, requested, runner=M.native_command):
    try:
        available = C.command(runner, "postconf", ["-m"]).decode("ascii").split()
        backend = next((name for name in ("hash", "lmdb") if name in available), None)
        if requested != "auto":
            backend = requested if requested in available else None
        backend = backend or "unavailable"
    except Exception:
        backend = "unverified"
    if all(rule["auth"] == "none" for rule in rules):
        sasl = "not_required"
    else:
        try:
            available = C.command(runner, "postconf", ["-A"]).decode("ascii").split()
            sasl = "cyrus_available" if "cyrus" in available else "unavailable"
        except Exception:
            sasl = "unverified"
    return backend, sasl


def report(config, rules, requested, installed, uid, gid, guard,
           mode, command=P.system_command, runner=M.native_command):
    normalized, plan = C.plan(rules)
    L.need(requested in ("auto", "hash", "lmdb") and
           (not installed or requested != "auto"), "installed_backend_required")
    ports = sorted({rule["port"] for rule in normalized})
    guard()
    backend, sasl = native_options(normalized, requested, runner)
    labels = "not_checked"
    port_report = dict.fromkeys(ports, "not_checked")
    if mode in ACTIVE:
        try:
            raw = command("semanage", ["port", "-l"])
            port_report = port_types(ports, raw)
            # Refuse incomplete or inconsistent observations rather than
            # reporting a missing mapping on ambiguous output.
            if command("semanage", ["port", "-l"]) != raw:
                raise L.Refused("port_policy_changed")
        except Exception:
            port_report = dict.fromkeys(ports, "unverified")
        if backend in ("hash", "lmdb"):
            try:
                L.observe(config, normalized, backend, uid, gid, installed, guard, command)
                labels = "policy_match_read_only"
            except Exception:
                labels = "unverified"
    guard()
    L.need(native_options(normalized, requested, runner) == (backend, sasl),
           "native_options_changed")
    guard()
    return {"STATUS": "read_only", "MODE": mode, "PLAN": plan,
            "BACKEND": backend, "SASL": sasl, "LABELS": labels,
            "PORTS": ",".join("{}:{}".format(port, port_report[port]) for port in ports),
            "WRITE_ALLOWED": "no", "RUNTIME_VERIFIED": "no",
            "CHANGES_APPLIED": "no", "MAIL_SENT": "no"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--backend", choices=("auto", "hash", "lmdb"), default="auto")
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args(argv)
    fd = None
    try:
        L.need(os.geteuid() == 0, "root_required")
        # Limit a multi-rule inspection; never output partial or raw diagnostics.
        def timeout(signum, frame):
            raise SystemExit(2)
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(180)
        raw = sys.stdin.buffer.read(M.MAX_BYTES + 1)
        L.need(0 < len(raw) <= M.MAX_BYTES, "invalid_request_size")
        rules = M.decode(raw)
        mode = L.selinux_mode()
        L.need(mode in ACTIVE + ("inactive_or_unavailable", "unverified"),
               "invalid_selinux_mode")
        fd = P.open_directory(P.CONFIG)
        account = pwd.getpwnam("postfix")

        def guard():
            before = os.fstat(fd)
            current = os.stat(P.CONFIG, follow_symlinks=False)
            L.need(L.selinux_mode() == mode and
                   (before.st_dev, before.st_ino) == (current.st_dev, current.st_ino) and
                   pwd.getpwnam("postfix") == account, "readiness_context_changed")

        result = report(fd, rules, args.backend, args.installed, 0,
                        account.pw_gid, guard, mode)
        for key, value in result.items():
            print(PREFIX + key + "=" + value)
        return 0
    except Exception:
        print(PREFIX + "STATUS=unverified")
        return 2
    finally:
        signal.alarm(0)
        if fd is not None:
            os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
