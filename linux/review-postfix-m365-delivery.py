#!/usr/bin/env python3
"""Explicit two-recipient primary Postfix relay probe. No config or queue mutations
except submission of two approved messages. Trace never sends or retries mail.
"""
import argparse
import email.utils
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/var/lib/linuxmailrelay365-postfix-probes")
CONFIG = Path("/etc/postfix")
SHA = re.compile(r"[a-f0-9]{64}")
RUN = re.compile(r"[a-f0-9]{32}")
QID = re.compile(r"[A-Za-z0-9]{5,80}")
DNS = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
MAIL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9_+-])?@[A-Za-z0-9.-]+")
ROLES = ("internal", "external")
# Deliberately narrow: do not claim to resolve arbitrary Postfix maps or filters.
EMPTY = ("transport_maps", "sender_dependent_relayhost_maps",
         "sender_dependent_default_transport_maps", "smtp_fallback_relay",
         "content_filter", "virtual_alias_maps", "virtual_alias_domains",
         "virtual_mailbox_domains", "canonical_maps", "sender_canonical_maps",
         "recipient_canonical_maps", "smtp_generic_maps", "header_checks",
         "mime_header_checks", "nested_header_checks", "body_checks",
         "non_smtpd_milters", "smtp_tls_policy_maps")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def load_adapter():
    spec = importlib.util.spec_from_file_location("postfix_adapter", Path(__file__).with_name("smtp-tls-postfix.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def domain_of(address):
    return address.rsplit("@", 1)[1].lower()


def validate_request(req):
    if not isinstance(req, dict) or set(req) != {"run_id", "sender", "internal", "external", "mx", "accepted_domain"}:
        raise ValueError("invalid request fields")
    if not isinstance(req["run_id"], str) or not RUN.fullmatch(req["run_id"]):
        raise ValueError("invalid run id")
    for key in ("sender", *ROLES):
        value = req[key]
        if (not isinstance(value, str) or len(value) > 254 or not MAIL.fullmatch(value)
                or ".." in value or not DNS.fullmatch(domain_of(value))):
            raise ValueError("invalid mailbox")
    domain, mx = req["accepted_domain"], req["mx"]
    if (not isinstance(domain, str) or not DNS.fullmatch(domain) or len(domain) > 253
            or not isinstance(mx, str) or not DNS.fullmatch(mx) or len(mx) > 253
            or not mx.endswith(".mail.protection.outlook.com")):
        raise ValueError("invalid accepted domain or Microsoft 365 MX")
    if (domain_of(req["sender"]) != domain or domain_of(req["internal"]) != domain
            or domain_of(req["external"]) == domain
            or req["internal"].lower() == req["external"].lower()):
        raise ValueError("recipient domain mismatch")
    return req


def directory(path):
    for item in [path, *path.parents]:
        st = item.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("unsafe directory")


def read_file(path, limit, private=False):
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                or st.st_mode & (0o077 if private else 0o022) or st.st_size > limit):
            raise ValueError("unsafe file")
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("file too large")
        return raw


def route_settings(read, overrides, req):
    if read("config_directory") != str(CONFIG) or read("multi_instance_directories"):
        raise ValueError("default single Postfix instance required")
    if read("relayhost").lower() not in ("[" + req["mx"] + "]:25", "[" + req["mx"] + "]"):
        raise ValueError("reviewed MX is not the active relayhost")
    if read("default_transport") != "smtp" or read("relay_transport") not in ("smtp", "relay"):
        raise ValueError("custom transport requires review")
    if read("smtp_sasl_auth_enable") != "no" or read("smtp_tls_security_level") not in ("encrypt", "verify", "secure"):
        raise ValueError("connector route with mandatory TLS required")
    for key in EMPTY:
        if read(key):
            raise ValueError("routing or rewriting override requires review")
    # Resolve expanded static destination lists only. Dynamic domain lists
    # require the existing routing audit and are not supported by this probe.
    for key in ("mydestination", "relay_domains"):
        values = [v.lower() for v in re.split(r"[\s,]+", read(key)) if v]
        if any(not DNS.fullmatch(v) and v != "localhost" for v in values):
            raise ValueError("dynamic destination list")
        if key == "mydestination" and any(
                domain_of(req[role]) == v or domain_of(req[role]).endswith("." + v)
                for v in values for role in ROLES):
            raise ValueError("recipient may be locally routed")
    for line in overrides.splitlines():
        if re.search(r"/(?:smtp_|relayhost|default_transport|relay_transport|transport_maps|sender_dependent_|content_filter|cleanup_service_name|receive_override_options)", line):
            raise ValueError("service-specific route or TLS override")
    return {"relayhost": req["mx"], "smtp_tls_security_level": read("smtp_tls_security_level"),
            "smtp_sasl_auth_enable": "no"}


def verify_postfix_package(binary, adapter, runner=subprocess.run):
    # Alternatives can point at a different MTA even with Postfix installed.
    # Accept only distro-owned native Postfix sendmail, not a custom wrapper.
    for path, args in (("/usr/bin/dpkg-query", ["-S", binary]),
                       ("/usr/bin/rpm", ["-qf", "--qf", "%{NAME}\n", binary])):
        try:
            tool = adapter.trusted_binary(path)
        except FileNotFoundError:
            continue
        result = runner([tool, *args], stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, timeout=15, env=ENV)
        if result.returncode or len(result.stdout) > 4096:
            continue
        rows = result.stdout.decode("utf-8", "strict").splitlines()
        if path.endswith("dpkg-query"):
            valid = len(rows) == 1 and bool(re.fullmatch(
                r"postfix(?::[a-z0-9-]+)?: " + re.escape(binary), rows[0]))
        else:
            valid = rows == ["postfix"]
        if valid:
            return
    raise ValueError("native Postfix package ownership unverified")


def prepare(req, adapter=None):
    validate_request(req)
    adapter = adapter or load_adapter()
    pf = adapter.Postfix()
    def config_hashes():
        return {name: digest(read_file(CONFIG / name, 8 * 1024 * 1024))
                for name in ("main.cf", "master.cf")}
    before = config_hashes()
    read = lambda key: pf.run(pf.postconf, "-h", "-x", key)
    settings = route_settings(read, pf.run(pf.postconf, "-P"), req)
    # Pin the native sendmail executable; never use a PATH-selected MTA.
    binary = adapter.trusted_binary("/usr/sbin/sendmail")
    if binary != adapter.trusted_binary(read("sendmail_path")):
        raise ValueError("sendmail implementation mismatch")
    verify_postfix_package(binary, adapter)
    for service in ("smtp/unix", "relay/unix"):
        fields = pf.run(pf.postconf, "-M", service).split()
        if len(fields) < 8 or fields[0] != service.split("/")[0] or fields[1] != "unix" or fields[7] != "smtp":
            raise ValueError("nonstandard SMTP transport service")
    pf.run(pf.postfix, "status")
    if config_hashes() != before:
        raise ValueError("configuration changed during review")
    st = os.stat(binary)
    evidence = {"request_sha256": digest(canonical(req)), "configuration": before,
                "sendmail_identity": [binary, st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size],
                "settings": settings}
    return {"status": "review_ready", "plan_sha256": digest(canonical(evidence)),
            "run_id": req["run_id"], "settings": settings, "mail_sent": False,
            "recipient_role_proof": "domain_comparison_only", "inbox_verified": False,
            "_binary": binary}


def ledger_file(req):
    return ROOT / (req["run_id"] + ".jsonl")


def reserve(req, expected):
    directory(ROOT.parent)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    directory(ROOT)
    if stat.S_IMODE(ROOT.lstat().st_mode) != 0o700:
        raise ValueError("private ledger required")
    fd = os.open(ledger_file(req), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        record(fd, {"event": "reserved", "request_sha256": digest(canonical(req)),
                    "plan_sha256": expected, "started": int(time.time())})
        dfd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def record(fd, entry):
    raw = canonical(entry) + b"\n"
    if os.write(fd, raw) != len(raw):
        raise OSError("short ledger write")
    os.fsync(fd)


def message_id(req, role):
    return "<lmr365-" + req["run_id"] + "-" + role + "@" + req["accepted_domain"] + ">"


def message(req, role):
    return ("From: " + req["sender"] + "\r\nTo: " + req[role] +
            "\r\nDate: " + email.utils.formatdate(localtime=False, usegmt=True) +
            "\r\nMessage-ID: " + message_id(req, role) +
            "\r\nSubject: LinuxMailRelay365 delivery probe " + role +
            "\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\n" +
            "Content-Type: text/plain; charset=us-ascii\r\n\r\n" +
            "Operator-approved mail relay test. Run: " + req["run_id"] + "\r\n").encode("ascii")


def submit(req, expected, prepare_fn=prepare, runner=subprocess.run):
    if prepare_fn(req)["plan_sha256"] != expected:
        raise ValueError("stale review")
    fd = reserve(req, expected)
    outcomes = {}
    try:
        for role in ROLES:
            plan = prepare_fn(req)
            if plan["plan_sha256"] != expected:
                raise ValueError("route changed")
            record(fd, {"event": "attempted", "role": role})
            try:
                result = runner([plan["_binary"], "-i", "-f", req["sender"], "--", req[role]],
                    input=message(req, role), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=60, env=ENV)
                outcome = "local_submission_accepted" if result.returncode == 0 else "submission_uncertain"
            except (OSError, subprocess.SubprocessError):
                outcome = "submission_uncertain"
            record(fd, {"event": outcome, "role": role})
            outcomes[role] = outcome
            if outcome != "local_submission_accepted":
                break
        return {"status": "submission_recorded", "run_id": req["run_id"],
                "plan_sha256": expected, "outcomes": outcomes, "inbox_verified": False,
                "automatic_retry": False}
    finally:
        os.close(fd)


def ledger(req):
    raw = read_file(ledger_file(req), 16384, True)
    rows = [json.loads(line, object_pairs_hook=strict_object) for line in raw.splitlines()]
    first = rows[0] if rows else {}
    if (first.get("event") != "reserved" or first.get("request_sha256") != digest(canonical(req))
            or type(first.get("started")) is not int or first["started"] > time.time() + 60
            or not SHA.fullmatch(first.get("plan_sha256", ""))):
        raise ValueError("ledger request mismatch")
    result = {role: "not_attempted" for role in ROLES}
    for row in rows[1:]:
        role, event = row.get("role"), row.get("event")
        if role not in ROLES or event not in ("attempted", "local_submission_accepted", "submission_uncertain"):
            raise ValueError("invalid ledger event")
        if (event == "attempted" and result[role] != "not_attempted") or (
                event != "attempted" and result[role] != "attempted"):
            raise ValueError("invalid ledger sequence")
        result[role] = event
    return first["started"], result


def log_lines(started, adapter):
    # Journal is best-effort: bounded recent rows, no raw log data exported.
    try:
        binary = adapter.trusted_binary("/usr/bin/journalctl")
        result = subprocess.run([binary, "--no-pager", "-o", "cat", "-n", "4000",
            "--since=@" + str(max(0, started - 5)), "-t", "postfix/cleanup",
            "-t", "postfix/smtp", "-t", "postfix/relay"], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=25, env=ENV)
        if result.returncode == 0 and len(result.stdout) <= 8 * 1024 * 1024:
            return result.stdout.decode("utf-8", "replace").splitlines(), "journal_recent_only"
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return [], "journal_unavailable"


def queue_rows(adapter):
    try:
        binary = adapter.trusted_binary("/usr/sbin/postqueue")
        result = subprocess.run([binary, "-j"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=25, env=ENV)
        if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
            return None
        return [json.loads(line, object_pairs_hook=strict_object)
                for line in result.stdout.splitlines() if line.strip()]
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def correlate(req, role, lines, queue, attempted):
    if attempted == "not_attempted":
        return {"submission": attempted, "transport": "not_attempted"}
    marker = message_id(req, role)
    ids = set()
    for line in lines:
        match = re.fullmatch(r"([A-Za-z0-9]{5,80}): message-id=(<[^>]+>)", line.strip())
        if match and match.group(2) == marker:
            ids.add(match.group(1))
    if len(ids) != 1:
        return {"submission": attempted, "transport": "correlation_unavailable"}
    ident = next(iter(ids))
    observation = {"submission": attempted, "queue_id": ident, "transport": "unknown"}
    for line in lines:
        # Match only actual structured log fields before the diagnostic
        # response in parentheses. Remote text is not trusted evidence.
        prefix = ident + ": to=<" + req[role] + ">,"
        if not line.startswith(prefix):
            continue
        fields = line[len(prefix):].split(" (", 1)[0]
        state = re.search(r"(?:^|,)\s*status=(sent|deferred|bounced)$", fields)
        dsn = re.search(r"(?:^|,)\s*dsn=([245]\.[0-9]{1,3}\.[0-9]{1,3})(?=,|$)", fields)
        relay = re.search(r"(?:^|,)\s*relay=([A-Za-z0-9.-]+)\[[0-9A-Fa-f:.]+\]:25(?=,|$)", fields)
        if not state:
            continue
        if dsn:
            observation["dsn"] = dsn.group(1)
        else:
            observation.pop("dsn", None)
        if state.group(1) == "sent":
            observation["transport"] = ("exchange_relay_accepted" if relay and
                relay.group(1).lower() == req["mx"] and dsn and dsn.group(1).startswith("2.")
                else "smtp_sent_destination_unverified")
        else:
            observation["transport"] = state.group(1)
    if queue is not None:
        matches = [row for row in queue if isinstance(row, dict) and row.get("queue_id") == ident]
        observation["queue"] = "not_observed"
        if len(matches) == 1 and isinstance(matches[0].get("recipients"), list):
            row = matches[0]
            if any(isinstance(r, dict) and r.get("address") == req[role] for r in row["recipients"]):
                name = row.get("queue_name")
                observation["queue"] = name if name in ("active", "deferred", "incoming", "hold", "maildrop") else "other"
    else:
        observation["queue"] = "unavailable"
    return observation


def trace(req):
    started, events = ledger(req)
    adapter = load_adapter()
    lines, source = log_lines(started, adapter)
    queue = queue_rows(adapter)
    return {"status": "trace_observed", "run_id": req["run_id"], "source": source,
            "started_unix": started, "request_sha256": digest(canonical(req)),
            "outcomes": {role: correlate(req, role, lines, queue, events[role]) for role in ROLES},
            "inbox_verified": False, "tls_handshake_verified": False, "automatic_retry": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preview", "submit", "trace"))
    parser.add_argument("--expected-sha")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("root required")
        os.umask(0o077)
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError("request too large")
        req = validate_request(json.loads(raw, object_pairs_hook=strict_object))
        if args.action == "submit":
            if not SHA.fullmatch(args.expected_sha or ""):
                raise ValueError("approval required")
            report = submit(req, args.expected_sha)
        elif args.expected_sha is not None:
            raise ValueError("unexpected approval")
        elif args.action == "preview":
            report = prepare(req)
            report.pop("_binary")
        else:
            report = trace(req)
        print(json.dumps(report))
        return 0
    except Exception:
        print(json.dumps({"status": "refused_or_uncertain", "inbox_verified": False, "automatic_retry": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
