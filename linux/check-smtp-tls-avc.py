#!/usr/bin/env python3
"""Bounded read-only SELinux AVC hints. Never generate or modify policy."""
import argparse
import importlib.util
import json
import os
import re
import selectors
import shlex
import subprocess
import time
from pathlib import Path

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
MAX_BYTES = 2 * 1024 * 1024
HEADER = re.compile(r"^(?:node=(\S+)\s+)?type=(AVC|USER_AVC)\s+msg=audit\(([0-9]+\.[0-9]+:[0-9]+)\):\s+(.*)$")
DECISION = re.compile(r"^avc:\s+(denied|granted)\s+\{\s*([a-z_0-9 ]+)\s*\}\s+for\s+(.+)$")
CONTEXT = re.compile(r"[A-Za-z0-9_]+:[A-Za-z0-9_]+:([A-Za-z0-9_]+):[A-Za-z0-9_.,:-]+")


def adapter():
    spec = importlib.util.spec_from_file_location("postfix", Path(__file__).with_name("smtp-tls-postfix.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bounded(args, limit=MAX_BYTES, seconds=25):
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=ENV)
    deadline = time.monotonic() + seconds
    data = bytearray()
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(process.stdout, selectors.EVENT_READ)
            while True:
                left = deadline - time.monotonic()
                if left <= 0 or not sel.select(left):
                    raise ValueError("audit query timeout")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                if len(data) + len(chunk) > limit:
                    raise ValueError("audit query exceeds limit")
                data.extend(chunk)
        return process.wait(timeout=max(0.1, deadline - time.monotonic())), bytes(data)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()


def audit_health(trusted, query=bounded):
    try:
        code, raw = query([trusted("/usr/sbin/auditctl"), "-s"], 4096, 5)
        if code:
            return {"audit_health": "unverified", "audit_lost_total": None}
        fields = {}
        for line in raw.decode("ascii").splitlines():
            words = line.split()
            if len(words) == 2 and words[0] in ("enabled", "pid", "lost"):
                if words[0] in fields or not words[1].isdigit():
                    raise ValueError("invalid audit health")
                fields[words[0]] = int(words[1])
        if set(fields) != {"enabled", "pid", "lost"}:
            raise ValueError("missing audit health")
        state = "active" if fields["enabled"] in (1, 2) and fields["pid"] > 0 else "inactive_or_disabled"
        return {"audit_health": state, "audit_lost_total": fields["lost"]}
    except Exception:
        return {"audit_health": "unverified", "audit_lost_total": None}


def summarize(raw):
    if not raw or len(raw) > MAX_BYTES or not raw.endswith(b"\n"):
        raise ValueError("incomplete audit output")
    events = {}
    parsed = 0
    unparsed = 0
    for line in raw.splitlines():
        # ENRICHED log interpretation is not original kernel evidence.
        line = line.split(b"\x1d", 1)[0].decode("utf-8", "strict")
        if not re.match(r"^(?:node=\S+\s+)?type=(?:AVC|USER_AVC)(?:\s|$)", line):
            continue
        header = HEADER.fullmatch(line)
        decision = DECISION.fullmatch(header.group(4)) if header else None
        if not decision:
            unparsed += 1
            continue
        try:
            fields = {}
            for token in shlex.split(decision.group(3), comments=False, posix=True):
                key, sep, value = token.partition("=")
                if not sep or key in fields:
                    raise ValueError("ambiguous audit fields")
                fields[key] = value
            source = CONTEXT.fullmatch(fields.get("scontext", ""))
            target = CONTEXT.fullmatch(fields.get("tcontext", ""))
            if not source or not target or "tclass" not in fields:
                raise ValueError("context missing")
        except ValueError:
            unparsed += 1
            continue
        parsed += 1
        if decision.group(1) != "denied":
            continue
        related = (source.group(1).startswith("postfix_") or target.group(1).startswith("postfix_")
                   or fields.get("comm") in ("smtp", "smtpd", "postfix", "master")
                   or any("lmr365-smtp-tls" in fields.get(key, "").split("/") for key in ("name", "path")))
        if not related:
            continue
        event = (header.group(1), header.group(3))
        mode = {"0": "enforcing", "1": "permissive"}.get(fields.get("permissive"), "unknown")
        previous = events.get(event, mode)
        events[event] = mode if mode == previous else "unknown"
    if not parsed and not unparsed:
        raise ValueError("no audit records")
    return {"matching_denials": len(events),
            "enforcing_denials": sum(v == "enforcing" for v in events.values()),
            "permissive_denials": sum(v == "permissive" for v in events.values()),
            "unknown_mode_denials": sum(v == "unknown" for v in events.values()),
            "parsed_records": parsed, "unparsed_records": unparsed}


def inspect(window="today", trusted=None, query=bounded):
    if window not in ("today", "recent"):
        raise ValueError("unsupported audit window")
    report = dict(version=1, status="unverified", window=window, matching_denials=0,
                  enforcing_denials=0, permissive_denials=0, unknown_mode_denials=0,
                  parsed_records=0, unparsed_records=0, audit_health="unverified",
                  audit_lost_total=None, access_verified=False, policy_changed=False,
                  raw_records_exported=False)
    try:
        if os.geteuid() != 0:
            raise ValueError("root required")
        trusted = trusted or adapter().trusted_binary
        report.update(audit_health(trusted, query))
        code, raw = query([trusted("/usr/sbin/ausearch"), "-m", "AVC,USER_AVC",
                           "-ts", window, "--raw"])
        if code == 0:
            counts = summarize(raw)
            report.update(counts)
            report["status"] = "partial" if counts["unparsed_records"] else "observed"
        elif code == 1:
            report["status"] = "no_matches_or_audit_unavailable"
    except Exception:
        pass
    # Neither a successful read nor zero matching denials proves process access.
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--recent", action="store_true")
    args = parser.parse_args()
    print(json.dumps(inspect("recent" if args.recent else "today"), sort_keys=True))


if __name__ == "__main__":
    main()
