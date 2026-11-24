#!/usr/bin/env python3
"""Bounded, read-only historical AVC hints for the Postfix outbound SMTP domain.

Only aggregate counts for selected destination ports are exported. No raw
audit records, sender/recipient, addresses, paths, command lines or contexts.
No package installation, policy edits, daemon control or network requests.
"""
import importlib.util
import os
import re
import selectors
import shlex
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "avc_labels", str(Path(__file__).with_name("inspect-conditional-transport-selinux.py")))
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)

PREFIX = "SELINUX_AVC_"
ACTIVE = ("enforcing", "permissive")
MAX_OUTPUT = 2 * 1024 * 1024
MAX_COUNT = MAX_OUTPUT
AVC_HEADER = re.compile(
    r"^(?:node=(\S+)\s+)?type=AVC\s+msg=audit\(([0-9]+\.[0-9]+:[0-9]+)\):"
    r"\s+avc:\s+(denied|granted)\s+\{\s*([a-z_0-9 ]+)\s*\}\s+for\s+(.+)$")
AVC_PREFIX = re.compile(r"^(?:node=\S+\s+)?type=AVC(?:\s|$)")
CONTEXT = re.compile(r"[A-Za-z0-9_]+:[A-Za-z0-9_]+:([A-Za-z0-9_]+):[A-Za-z0-9_.,:-]+")


def query():
    """No shell, no inherited environment; cap stdout before buffering it.

    ausearch exit 1 is ambiguous: no matches, argument or read errors.
    Never convert it into a definitive clean audit log.
    """
    path = L.P.trusted_tool("ausearch")
    process = subprocess.Popen(
        [path, "--message", "AVC", "--start", "recent", "--raw"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=L.P.SYSTEM_ENV)
    deadline = time.monotonic() + 15
    data = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                left = deadline - time.monotonic()
                if left <= 0 or not selector.select(left):
                    raise L.Refused("audit_query_timeout")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                if len(data) + len(chunk) > MAX_OUTPUT:
                    raise L.Refused("audit_query_oversized")
                data.extend(chunk)
        code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        return code, bytes(data)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()


def summarize(raw, ports):
    """Count distinct matching (audit event, destination, event mode) tuples.

    Raw AVC records can contain quoted or hex-encoded untrusted fields.
    Parse complete tokens, not substring matches within comm/path values.
    An unrecognized AVC format makes the report unverified, never clean.
    """
    L.need(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT and raw.endswith(b"\n"),
           "audit_output_unverified")
    records = {port: [set(), set(), set()] for port in ports}
    seen = False
    for binary in raw.split(b"\n"):
        # ENRICHED logs can append interpreted fields after the separator.
        # Only the original kernel record is considered.
        line = binary.split(b"\x1d", 1)[0].decode("utf-8", "strict")
        if not AVC_PREFIX.match(line):
            continue
        seen = True
        match = AVC_HEADER.fullmatch(line)
        L.need(match is not None, "audit_avc_format_unverified")
        node, event, decision, permissions, tail = match.groups()
        if decision != "denied" or "name_connect" not in permissions.split():
            continue
        fields = {}
        for token in shlex.split(tail, comments=False, posix=True):
            key, sep, value = token.partition("=")
            L.need(sep and key and key not in fields, "audit_avc_fields_unverified")
            fields[key] = value
        source = CONTEXT.fullmatch(fields.get("scontext", ""))
        L.need(source is not None and "tclass" in fields, "audit_avc_context_unverified")
        if source.group(1) != "postfix_smtp_t" or fields["tclass"] != "tcp_socket":
            continue
        dest = fields.get("dest", "")
        L.need(re.fullmatch(r"[0-9]{1,5}", dest) is not None and
               1 <= int(dest) <= 65535, "audit_destination_unverified")
        port = int(dest)
        if port not in records:
            continue
        mode = {"0": 0, "1": 1}.get(fields.get("permissive"), 2)
        records[port][mode].add((node, event))
    L.need(seen, "audit_records_unverified")
    return {port: tuple(len(group) for group in counts)
            for port, counts in records.items()}


def report(rules, mode, read=query):
    normalized, plan = L.C.plan(rules)
    ports = sorted({rule["port"] for rule in normalized})
    counts = dict.fromkeys(ports, (0, 0, 0))
    status = "not_checked"
    if mode in ACTIVE:
        try:
            code, raw = read()
            if code == 0:
                counts = summarize(raw, ports)
                status = "records_read"
            elif code == 1 and raw == b"":
                status = "no_matches_or_unavailable"
            else:
                status = "unverified"
        except Exception:
            status = "unverified"
    return {"STATUS": status, "MODE": mode, "PLAN": plan, "WINDOW": "recent",
            "PORTS": ",".join("{}:{}:{}:{}".format(port, *counts[port]) for port in ports),
            "WRITE_ALLOWED": "no", "RUNTIME_VERIFIED": "no",
            "CHANGES_APPLIED": "no", "MAIL_SENT": "no"}


def main():
    try:
        L.need(os.geteuid() == 0 and len(sys.argv) == 1, "invalid_audit_request")
        raw = sys.stdin.buffer.read(L.M.MAX_BYTES + 1)
        L.need(0 < len(raw) <= L.M.MAX_BYTES, "invalid_request_size")
        mode = L.selinux_mode()
        L.need(mode in ACTIVE + ("inactive_or_unavailable", "unverified"),
               "invalid_selinux_mode")
        result = report(L.M.decode(raw), mode)
        L.need(L.selinux_mode() == mode, "audit_context_changed")
        for key, value in result.items():
            print(PREFIX + key + "=" + value)
        return 0
    except Exception:
        print(PREFIX + "STATUS=unverified")
        return 2


if __name__ == "__main__":
    sys.exit(main())
