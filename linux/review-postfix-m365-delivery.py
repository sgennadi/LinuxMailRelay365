#!/usr/bin/env python3
"""Explicit two-recipient primary Postfix relay probe. No config or queue mutations
except submission of two approved messages. Trace never sends or retries mail.
"""
import argparse
import email.utils
import email.parser
import grp
import signal
import hashlib
import importlib.util
import ipaddress
import json
import os
import pwd
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


def ledger(req, roles=ROLES, include_plan=False):
    raw = read_file(ledger_file(req), 16384, True)
    rows = [json.loads(line, object_pairs_hook=strict_object) for line in raw.splitlines()]
    first = rows[0] if rows else {}
    if (first.get("event") != "reserved" or first.get("request_sha256") != digest(canonical(req))
            or type(first.get("started")) is not int or first["started"] > time.time() + 60
            or not SHA.fullmatch(first.get("plan_sha256", ""))):
        raise ValueError("ledger request mismatch")
    result = {role: "not_attempted" for role in roles}
    for row in rows[1:]:
        role, event = row.get("role"), row.get("event")
        if role not in roles or event not in ("attempted", "local_submission_accepted", "submission_uncertain"):
            raise ValueError("invalid ledger event")
        if (event == "attempted" and result[role] != "not_attempted") or (
                event != "attempted" and result[role] != "attempted"):
            raise ValueError("invalid ledger sequence")
        result[role] = event
    if include_plan:
        return first["started"], result, first["plan_sha256"]
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


# Display only bounded allowlisted configuration values. Unknown syntax or
# map expressions are never exported, and credentials are never requested.
AUDIT_SETTINGS = (
    "myhostname", "mydomain", "myorigin", "mydestination", "relay_domains",
    "inet_interfaces", "inet_protocols", "relayhost", "smtp_bind_address",
    "smtp_bind_address6", "smtp_tls_security_level", "smtp_sasl_auth_enable",
    "default_transport", "relay_transport", "local_transport", "virtual_transport",
)
AUDIT_FLAGS = tuple(sorted(set(EMPTY + (
    "multi_instance_directories", "smtpd_milters", "masquerade_domains",
    "relocated_maps", "smtp_tls_chain_files", "smtp_tls_cert_file",
    "smtp_tls_key_file", "smtp_tls_eccert_file", "smtp_tls_eckey_file",
))))
AUDIT_KEYS = tuple(sorted(set(AUDIT_SETTINGS + AUDIT_FLAGS + ("config_directory",))))
QUEUE_NAMES = ("active", "deferred", "incoming", "hold", "maildrop", "other")


def audit_request(req):
    if (not isinstance(req, dict) or set(req) != {"accepted_domain", "mx"}
            or not isinstance(req["accepted_domain"], str) or len(req["accepted_domain"]) > 253
            or not DNS.fullmatch(req["accepted_domain"]) or not isinstance(req["mx"], str)
            or (req["mx"] and (len(req["mx"]) > 253 or not DNS.fullmatch(req["mx"])
                              or not req["mx"].endswith(".mail.protection.outlook.com")))):
        raise ValueError("invalid primary audit selection")
    return req


def audit_values(pf):
    raw = pf.run(pf.postconf, "-x", *AUDIT_KEYS)
    if len(raw) > 131072:
        raise ValueError("oversized configuration")
    values = {}
    for line in raw.splitlines():
        key, sep, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if (not sep or key not in AUDIT_KEYS or key in values or len(value) > 8192
                or any(ord(c) < 32 and c != "\t" for c in value)):
            raise ValueError("invalid configuration evidence")
        values[key] = value
    if set(values) != set(AUDIT_KEYS):
        raise ValueError("incomplete configuration")
    return values


def dns_token(value):
    return value == "localhost" or (len(value) <= 253 and bool(DNS.fullmatch(value.lower())))


def address_token(value):
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return None


def display_value(key, value):
    if not value:
        return ""
    if key in ("myhostname", "mydomain", "myorigin"):
        return value if dns_token(value) else None
    if key in ("mydestination", "relay_domains"):
        rows = [s for s in re.split(r"[\s,]+", value) if s]
        return ", ".join(rows) if len(rows) <= 40 and all(dns_token(s) for s in rows) else None
    if key == "inet_interfaces":
        rows = [s for s in re.split(r"[\s,]+", value) if s]
        if len(rows) > 40:
            return None
        if all(s in ("all", "loopback-only") or dns_token(s) or address_token(s) is not None for s in rows):
            return ", ".join(rows)
        return None
    if key in ("smtp_bind_address", "smtp_bind_address6"):
        try:
            addr = ipaddress.ip_address(value)
            if addr.version == (4 if key == "smtp_bind_address" else 6):
                return str(addr)
        except ValueError:
            pass
        return None
    if key == "inet_protocols":
        rows = [s for s in re.split(r"[\s,]+", value) if s]
        return ", ".join(rows) if len(rows) <= 3 and all(s in ("all", "ipv4", "ipv6") for s in rows) else None
    if key == "relayhost":
        match = re.fullmatch(r"(\[([a-zA-Z0-9.-]+)\]|([a-zA-Z0-9.-]+))(?::([0-9]{1,5}))?", value)
        if match:
            host = match.group(2) or match.group(3)
            if dns_token(host) or address_token(host) is not None:
                port = int(match.group(4) or 25)
                if 1 <= port <= 65535:
                    return value
        return None
    if key == "smtp_tls_security_level":
        return value if value in ("none", "may", "encrypt", "verify", "secure", "dane", "dane-only", "fingerprint") else None
    if key == "smtp_sasl_auth_enable":
        return value if value in ("yes", "no") else None
    if key.endswith("_transport"):
        return value if value in ("smtp", "relay", "local", "virtual", "error", "discard", "lmtp") else None
    return None


def summarize_queue(rows):
    if rows is None or len(rows) > 100000:
        return {"status": "unavailable", "total": None, "counts": {}}
    counts = dict((name, 0) for name in QUEUE_NAMES)
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("queue_id"), str)
                or not QID.fullmatch(row["queue_id"]) or row["queue_id"] in seen
                or not isinstance(row.get("queue_name"), str)):
            return {"status": "unavailable", "total": None, "counts": {}}
        seen.add(row["queue_id"])
        name = row["queue_name"]
        counts[name if name in counts else "other"] += 1
    return {"status": "sampled", "total": len(rows), "counts": counts}


def primary_audit(req, adapter=None, queue_reader=queue_rows, config_reader=read_file):
    audit_request(req)
    adapter = adapter or load_adapter()
    pf = adapter.Postfix()
    def hashes():
        return {name: digest(config_reader(CONFIG / name, 8 * 1024 * 1024))
                for name in ("main.cf", "master.cf")}
    before = hashes()
    values = audit_values(pf)
    overrides = pf.run(pf.postconf, "-P")
    if len(overrides) > 131072:
        raise ValueError("oversized override evidence")
    single = values["config_directory"] == str(CONFIG) and not values["multi_instance_directories"]
    active = "unverified"
    try:
        pf.run(pf.postfix, "status")
        active = "running"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        pass
    queue = summarize_queue(queue_reader(adapter) if single and active == "running" else None)
    shown = dict((key, display_value(key, values[key])) for key in AUDIT_SETTINGS)
    declared = [key for key in AUDIT_FLAGS if values[key]]
    blockers = []
    if not single:
        blockers.append("not_default_single_instance")
    if active != "running":
        blockers.append("service_status_unverified")
    if overrides:
        blockers.append("service_specific_overrides")
    if any(shown[k] is None for k in AUDIT_SETTINGS):
        blockers.append("unsupported_setting_syntax")
    if any(k in declared for k in EMPTY + ("smtpd_milters", "masquerade_domains", "relocated_maps")):
        blockers.append("routing_or_rewrite_policy")
    if values["default_transport"] != "smtp" or values["relay_transport"] not in ("smtp", "relay"):
        blockers.append("custom_transport")
    if values["smtp_sasl_auth_enable"] != "no":
        blockers.append("smtp_auth_configured_or_unknown")
    if values["smtp_tls_security_level"] not in ("encrypt", "verify", "secure"):
        blockers.append("mandatory_tls_not_established")
    if values["inet_protocols"] != "ipv4":
        blockers.append("public_ipv4_connector_protocol_review")
    if values["smtp_bind_address"] or values["smtp_bind_address6"]:
        blockers.append("explicit_source_bind_review")
    if shown["mydestination"] is None or any(
            req["accepted_domain"] == token.lower() or req["accepted_domain"].endswith("." + token.lower())
            for token in re.split(r"[\s,]+", values["mydestination"]) if token):
        blockers.append("accepted_domain_local_delivery_review")
    if queue["status"] != "sampled":
        blockers.append("queue_unverified")
    elif queue["total"]:
        blockers.append("queue_not_empty")
    mx = req["mx"]
    if not mx:
        blockers.append("mx_not_selected")
    elif values["relayhost"].lower() not in ("[" + mx + "]:25", "[" + mx + "]"):
        blockers.append("relayhost_differs")
    if hashes() != before or audit_values(pf) != values or pf.run(pf.postconf, "-P") != overrides:
        raise ValueError("configuration changed during inspection")
    # The queue is a moving sample, not a guarantee that it remains empty.
    return dict(version=1, status="review_required" if blockers else "basic_route_observed",
                accepted_domain=req["accepted_domain"], mx=mx, settings=shown,
                declared=declared, service_overrides=bool(overrides),
                single_instance=single, service=active, queue=queue, blockers=blockers,
                config_sha256=before, postfix_modified=False, queue_modified=False, mail_sent=False,
                apply_supported=False, exchange_acceptance_verified=False)


# The local probe accepts only a narrowly reviewed alias lookup and standard
# .forward search with no existing forwarding file for the selected account.
# Other maps or forwarding syntax still require manual review.
LOCAL_EMPTY = tuple(sorted(set(EMPTY + (
    "mailbox_command", "mailbox_command_maps",
    "mailbox_transport", "mailbox_transport_maps", "fallback_transport",
    "fallback_transport_maps", "luser_relay", "always_bcc", "sender_bcc_maps",
    "recipient_bcc_maps", "relocated_maps", "masquerade_domains", "smtpd_milters",
    "virtual_mailbox_maps", "smtp_generic_maps",
))))
ALIAS_MAPS = {
    "hash:/etc/aliases": ("/etc/aliases", "/etc/aliases.db"),
    "lmdb:/etc/aliases": ("/etc/aliases", "/etc/aliases.lmdb"),
    "hash:/etc/postfix/aliases": ("/etc/postfix/aliases", "/etc/postfix/aliases.db"),
    "lmdb:/etc/postfix/aliases": ("/etc/postfix/aliases", "/etc/postfix/aliases.lmdb"),
}
FORWARD_PATHS = (
    "$home/.forward",
    "$home/.forward${recipient_delimiter}${extension},$home/.forward",
    "$home/.forward$recipient_delimiter$extension,$home/.forward",
)
LOCAL_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


def local_request(req):
    if (not isinstance(req,dict) or set(req)!={"run_id","recipient"} or
            not isinstance(req["run_id"],str) or not RUN.fullmatch(req["run_id"]) or
            not isinstance(req["recipient"],str) or len(req["recipient"])>254 or
            req["recipient"].count("@")!=1):
        raise ValueError("invalid local probe request")
    user,host=req["recipient"].split("@")
    if (not LOCAL_USER.fullmatch(user) or len(host)>253 or not DNS.fullmatch(host) or
            user in ("root","postmaster","mailer-daemon","double-bounce") or
            user.startswith("owner-") or user.endswith("-request")):
        raise ValueError("exact local UNIX user and hostname required")
    return req


def local_account(user):
    # Require a matching local passwd entry as well as the effective NSS
    # result; remote NSS users and privileged/service users are out of scope.
    raw=read_file(Path("/etc/passwd"),4*1024*1024)
    rows=[line.split(":") for line in raw.decode("utf-8","strict").splitlines()
          if line.split(":",1)[0]==user]
    if len(rows)!=1 or len(rows[0])!=7:
        raise ValueError("local account not found")
    row=rows[0]
    account=pwd.getpwnam(user)
    uid,gid=int(row[2]),int(row[3])
    if (not 1000<=uid<65534 or gid<=0 or
            (account.pw_name,account.pw_uid,account.pw_gid,account.pw_dir,account.pw_shell)!=
            (user,uid,gid,row[5],row[6]) or
            not row[5].startswith("/") or row[5] in ("/","/root","/nonexistent") or
            row[6].endswith(("/nologin","/false"))):
        raise ValueError("unsupported local account")
    return {"uid":uid,"gid":gid,"home":row[5],
            "account_sha256":digest(canonical([user,uid,gid,row[5],row[6]]))}


def local_policy(read,overrides,req):
    user,host=req["recipient"].split("@")
    if (read("config_directory")!=str(CONFIG) or read("multi_instance_directories") or
            read("myhostname")!=host or read("local_transport") not in ("local","local:"+host) or overrides):
        raise ValueError("nonstandard local route")
    destinations=[v.lower() for v in re.split(r"[\s,]+",read("mydestination")) if v]
    if host not in destinations or any(not DNS.fullmatch(v) and v!="localhost" for v in destinations):
        raise ValueError("hostname is not an explicit local destination")
    for key in LOCAL_EMPTY:
        if read(key):
            raise ValueError("local redirection or forwarding requires manual review")
    alias=read("alias_maps")
    forward=re.sub(r"[\s]+","",read("forward_path"))
    delimiter=read("recipient_delimiter")
    if alias and alias not in ALIAS_MAPS:
        raise ValueError("unsupported alias map")
    if forward and forward not in FORWARD_PATHS:
        raise ValueError("unsupported forward_path")
    if delimiter not in ("","+"):
        raise ValueError("unsupported recipient delimiter")
    # Standard passwd lookup, optionally followed by the exact same alias
    # map. No LDAP/regexp or alternative recipient lookup is accepted.
    lookup=[v for v in re.split(r"[\s,]+",read("local_recipient_maps")) if v]
    if (not lookup or lookup[0] not in ("proxy:unix:passwd.byname","unix:passwd.byname") or
            lookup[1:] not in ([],[alias]) or (len(lookup)>1 and not alias)):
        raise ValueError("unsupported local recipient lookup")
    mailbox=read("home_mailbox")
    spool=read("mail_spool_directory") if not mailbox else ""
    if mailbox not in ("","Maildir/") or (not mailbox and spool not in ("/var/mail","/var/spool/mail")):
        raise ValueError("nonstandard mailbox destination")
    return {"hostname":host,"user":user,"mailbox_kind":"maildir" if mailbox else "system_spool",
            "alias_map":alias,"forward_path":forward,"recipient_delimiter":delimiter,
            "spool_directory":spool}


def alias_evidence(alias,user,adapter,runner=subprocess.run,reader=read_file):
    if not alias:
        return {"status":"not_configured"}
    if alias not in ALIAS_MAPS or not LOCAL_USER.fullmatch(user):
        raise ValueError("unsupported alias lookup")
    source,db=ALIAS_MAPS[alias]
    def files():
        return {name:digest(reader(Path(path),32*1024*1024)) for name,path in
                (("source",source),("database",db))}
    before=files()
    tool=adapter.trusted_invocation("/usr/sbin/postalias")
    # -q only; no rebuild, delete, or output of aliases. An error is not
    # equivalent to a missing key. The tool must exit 1 with no diagnostics
    # or output, and both protected source/database must remain unchanged.
    result=runner([tool,"-c",str(CONFIG),"-q",user,alias],input=b"",
                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,env=ENV)
    if result.returncode!=1 or result.stdout or result.stderr:
        raise ValueError("alias found or lookup unavailable")
    if files()!=before:
        raise ValueError("alias map changed")
    return {"status":"recipient_not_found","files":before}


def forward_evidence(account,settings,read_default_filter,read_filter):
    if not settings["forward_path"]:
        return {"status":"not_configured"}
    # Only an unambiguous ASCII home and the distribution's default
    # expansion filter are supported. No reading user-controlled .forward
    # content; a symlink, regular file or any other entry is a refusal.
    home=account["home"]
    if (not re.fullmatch(r"/[A-Za-z0-9_./-]+",home) or home=="/" or
            any(part in ("",".","..") for part in home.split("/")[1:]) or
            read_filter()!=read_default_filter()):
        raise ValueError("unsupported forward expansion")
    path=Path(home)
    for parent in reversed(path.parents):
        st=parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe home parent")
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    fd=os.open(str(path),flags)
    try:
        st=os.fstat(fd)
        if (st.st_uid!=account["uid"] or st.st_mode & 0o022):
            raise ValueError("unsafe home directory")
        # For unextended addresses check both the current and older
        # Postfix delimiter expansion possibilities conservatively.
        for name in (".forward",".forward+"):
            try:
                os.stat(name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("forwarding file present")
        current=path.lstat()
        if (current.st_dev,current.st_ino,current.st_uid,current.st_mode)!=(st.st_dev,st.st_ino,st.st_uid,st.st_mode):
            raise ValueError("home directory changed")
        return {"status":"no_forward_file_observed","home_identity":[st.st_dev,st.st_ino,st.st_uid,st.st_mode]}
    finally:
        os.close(fd)


def prepare_local(req,adapter=None,account_reader=local_account,alias_reader=alias_evidence,
                  forward_reader=forward_evidence):
    local_request(req)
    adapter=adapter or load_adapter()
    pf=adapter.Postfix()
    def hashes():
        return {name:digest(read_file(CONFIG/name,8*1024*1024)) for name in ("main.cf","master.cf")}
    before=hashes()
    # forward_path has delivery-time variables, not postconf -x variables.
    def read(key):
        args=("-h",key) if key=="forward_path" else ("-h","-x",key)
        return pf.run(pf.postconf,*args)
    settings=local_policy(read,pf.run(pf.postconf,"-P"),req)
    account=account_reader(settings["user"])
    def redirects():
        return {
            "alias":alias_reader(settings["alias_map"],settings["user"],adapter),
            "forward":forward_reader(account,settings,
                lambda:pf.run(pf.postconf,"-d","-h","forward_expansion_filter"),
                lambda:read("forward_expansion_filter"))
        }
    routing=redirects()
    binary=adapter.trusted_invocation("/usr/sbin/sendmail")
    resolved=adapter.trusted_binary(binary)
    if resolved!=adapter.trusted_binary(read("sendmail_path")):
        raise ValueError("sendmail implementation mismatch")
    verify_postfix_package(resolved,adapter)
    fields=pf.run(pf.postconf,"-M","local/unix").split()
    if len(fields)!=8 or fields[0:2]!=["local","unix"] or fields[7]!="local":
        raise ValueError("nonstandard local delivery service")
    pf.run(pf.postfix,"status")
    if (hashes()!=before or local_policy(read,pf.run(pf.postconf,"-P"),req)!=settings or
            account_reader(settings["user"])!=account or redirects()!=routing or hashes()!=before):
        raise ValueError("local configuration changed")
    st=os.stat(resolved)
    evidence={"request_sha256":digest(canonical(req)),"configuration":before,"settings":settings,
              "account":account,"redirection_evidence":routing,
              "sendmail_identity":[binary,resolved,st.st_dev,st.st_ino,st.st_mtime_ns,st.st_size]}
    return {"status":"local_review_ready","plan_sha256":digest(canonical(evidence)),
            "run_id":req["run_id"],"recipient":req["recipient"],"mailbox_kind":settings["mailbox_kind"],
            "alias_status":routing["alias"]["status"],"forward_status":routing["forward"]["status"],
            "mail_sent":False,"mailbox_verified":False,"_binary":binary,
            "_mailbox":{"account":account,"settings":settings}}


def local_message_id(req):
    return "<lmr365-"+req["run_id"]+"-local@"+req["recipient"].split("@")[1]+">"


def local_message(req):
    return ("From: postmaster@"+req["recipient"].split("@")[1]+"\r\nTo: "+req["recipient"]+
            "\r\nDate: "+email.utils.formatdate(localtime=False,usegmt=True)+
            "\r\nMessage-ID: "+local_message_id(req)+
            "\r\nSubject: LinuxMailRelay365 local delivery probe\r\n"+
            "Auto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\n"+
            "Content-Type: text/plain; charset=us-ascii\r\n\r\n"+
            "Operator-approved local mailbox test. Run: "+req["run_id"]+"\r\n").encode("ascii")


def submit_local(req,expected,prepare_fn=prepare_local,runner=subprocess.run):
    local_request(req)
    if not SHA.fullmatch(expected or "") or prepare_fn(req)["plan_sha256"]!=expected:
        raise ValueError("stale local review")
    fd=reserve(req,expected)
    try:
        plan=prepare_fn(req)
        if plan["plan_sha256"]!=expected:
            raise ValueError("local route changed")
        record(fd,{"event":"attempted","role":"local"})
        try:
            # Null reverse path: do not generate a delivery failure message.
            result=runner([plan["_binary"],"-i","-f","<>","--",req["recipient"]],
                          input=local_message(req),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                          timeout=60,env=ENV)
            outcome="local_submission_accepted" if result.returncode==0 else "submission_uncertain"
        except (OSError,subprocess.SubprocessError):
            outcome="submission_uncertain"
        record(fd,{"event":outcome,"role":"local"})
        return {"status":"local_submission_recorded","run_id":req["run_id"],
                "plan_sha256":expected,"submission":outcome,
                "mailbox_verified":False,"automatic_retry":False}
    finally:
        os.close(fd)


def local_logs(started,adapter,runner=subprocess.run):
    # Keep the journal tags separate; never promote an SMTP log line or its
    # free-form response text to local delivery evidence.
    output=[]
    for tag in ("postfix/cleanup","postfix/local"):
        try:
            tool=adapter.trusted_binary("/usr/bin/journalctl")
            result=runner([tool,"--no-pager","-o","cat","-n","4000",
                           "--since=@"+str(max(0,started-5)),"-t",tag],
                          stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=25,env=ENV)
            if result.returncode or len(result.stdout)>8*1024*1024:
                return [],[],"journal_unavailable"
            output.append(result.stdout.decode("utf-8","replace").splitlines())
        except (OSError,ValueError,subprocess.SubprocessError):
            return [],[],"journal_unavailable"
    return output[0],output[1],"journal_recent_only"


def correlate_local(req,cleanup,local,queue,attempted):
    observation={"submission":attempted,"transport":"not_attempted" if attempted=="not_attempted" else "correlation_unavailable"}
    if attempted=="not_attempted":
        return observation
    marker=local_message_id(req)
    ids={m.group(1) for line in cleanup for m in
         [re.fullmatch(r"([A-Za-z0-9]{5,80}): message-id=(<[^>]+>)",line.strip())]
         if m and m.group(2)==marker}
    if len(ids)!=1:
        return observation
    ident=next(iter(ids))
    observation.update(queue_id=ident,transport="unknown")
    prefix=ident+": to=<"+req["recipient"]+">,"
    for line in local:
        if not line.startswith(prefix):
            continue
        fields=line[len(prefix):].split(" (",1)[0]
        state=re.search(r"(?:^|,)\s*status=(sent|deferred|bounced)$",fields)
        dsn=re.search(r"(?:^|,)\s*dsn=([245]\.[0-9]{1,3}\.[0-9]{1,3})(?=,|$)",fields)
        relay=re.search(r"(?:^|,)\s*relay=local(?=,|$)",fields)
        if not state:
            continue
        observation.pop("dsn",None)
        if dsn:
            observation["dsn"]=dsn.group(1)
        if state.group(1)=="sent":
            observation["transport"]=("local_agent_accepted" if relay and dsn and dsn.group(1).startswith("2.")
                                      else "local_destination_unverified")
        else:
            observation["transport"]=state.group(1)
    observation["queue"]="unavailable" if queue is None else "not_observed"
    if queue is not None:
        rows=[r for r in queue if isinstance(r,dict) and r.get("queue_id")==ident]
        if len(rows)==1 and isinstance(rows[0].get("recipients"),list) and any(
                isinstance(r,dict) and r.get("address")==req["recipient"] for r in rows[0]["recipients"]):
            name=rows[0].get("queue_name")
            observation["queue"]=name if name in QUEUE_NAMES else "other"
    return observation


def trace_local(req):
    local_request(req)
    started,events=ledger(req,("local",))
    adapter=load_adapter()
    cleanup,local,source=local_logs(started,adapter)
    return {"status":"local_trace_observed","run_id":req["run_id"],"source":source,
            "request_sha256":digest(canonical(req)),"started_unix":started,
            "outcome":correlate_local(req,cleanup,local,queue_rows(adapter),events["local"]),
            "mailbox_verified":False,"automatic_retry":False}


# Separate read-only observation, never called automatically by submit/trace.
# Operates only on the exact ledger-bound reviewed local account and storage.
MAILBOX_BYTE_LIMIT=32*1024*1024
MAILBOX_HEADER_LIMIT=64*1024
MAILBOX_FILE_LIMIT=2048
MBOX_SEPARATOR=re.compile(rb"From [^\s]+ (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?: [A-Za-z0-9+-]{1,8})? [0-9]{4}\r?\n")


class MailboxIncomplete(ValueError):
    pass


def exact_test_headers(raw,req):
    # No header values leave this helper. Duplicate markers and malformed
    # headers do not qualify, and body lines are never parsed as headers.
    try:
        message=email.parser.BytesHeaderParser().parsebytes(raw)
        if message.defects:
            return False
        expected={"Message-ID":local_message_id(req),
                  "Subject":"LinuxMailRelay365 local delivery probe",
                  "To":req["recipient"],
                  "From":"postmaster@"+req["recipient"].split("@")[1],
                  "Auto-Submitted":"auto-generated"}
        return all(message.get_all(name)==[value] for name,value in expected.items())
    except (ValueError,UnicodeError):
        return False


def bounded_line(stream,budget):
    if budget[0]<=0:
        raise MailboxIncomplete("scan limit")
    limit=min(budget[0],MAILBOX_HEADER_LIMIT)
    line=stream.readline(limit+1)
    if len(line)>limit or (line and not line.endswith(b"\n")):
        raise MailboxIncomplete("line or scan limit")
    budget[0]-=len(line)
    return line


def scan_headers(stream,req,budget):
    raw=bytearray()
    while True:
        line=bounded_line(stream,budget)
        if not line or len(raw)+len(line)>MAILBOX_HEADER_LIMIT:
            raise MailboxIncomplete("incomplete headers")
        raw.extend(line)
        if line in (b"\n",b"\r\n"):
            return exact_test_headers(bytes(raw),req)


def scan_mbox_stream(stream,req,budget):
    first=True
    while True:
        line=bounded_line(stream,budget)
        if not line:
            return False
        if MBOX_SEPARATOR.fullmatch(line):
            if scan_headers(stream,req,budget):
                return True
            first=False
        elif first:
            raise MailboxIncomplete("unsupported mbox format")


def identity(st):
    return (st.st_dev,st.st_ino,st.st_uid,st.st_gid,st.st_mode,st.st_nlink,
            st.st_size,st.st_mtime_ns,st.st_ctime_ns)


def safe_directory(fd,owner,mail_gid=None):
    st=os.fstat(fd)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=owner or st.st_mode&0o002 or
            (st.st_mode&0o020 and (mail_gid is None or st.st_gid!=mail_gid))):
        raise MailboxIncomplete("unsafe mailbox directory")
    return st


def open_mail_directory(path,owner,mail_gid=None):
    # Walk from / by descriptors. The only user-owned path component is
    # the selected home itself. Never follow an arbitrary symlink.
    if (not isinstance(path,str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+",path) or
            any(p in ("",".","..") for p in path.split("/")[1:])):
        raise MailboxIncomplete("unsupported mailbox path")
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    fd=os.open("/",flags)
    try:
        safe_directory(fd,0)
        parts=path.split("/")[1:]
        for i,part in enumerate(parts):
            child=os.open(part,flags,dir_fd=fd)
            try:
                safe_directory(child,owner if i==len(parts)-1 else 0,
                               mail_gid if i==len(parts)-1 else None)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd=child
        return fd
    except BaseException:
        os.close(fd)
        raise


def inspect_mail_file(fd,name,uid,req,budget,mbox=False,mail_gid=None):
    # Open nonblocking before examining type; reject links and special
    # files. O_NOATIME preserves message-file access time for its owner.
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_NOATIME
    file=os.open(name,flags,dir_fd=fd)
    with os.fdopen(file,"rb") as stream:
        before=os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=uid or before.st_nlink!=1 or
                before.st_mode&0o002 or (before.st_mode&0o020 and
                (not mbox or mail_gid is None or before.st_gid!=mail_gid))):
            raise MailboxIncomplete("unsafe mailbox file")
        found=scan_mbox_stream(stream,req,budget) if mbox else scan_headers(stream,req,budget)
        if (identity(os.fstat(stream.fileno()))!=identity(before) or
                identity(os.stat(name,dir_fd=fd,follow_symlinks=False))!=identity(before)):
            raise MailboxIncomplete("mailbox changed during read")
        return found


def scan_maildir(home,uid,req,budget):
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NOATIME
    homefd=open_mail_directory(home,uid)
    try:
        try:
            mailfd=os.open("Maildir",flags,dir_fd=homefd)
        except FileNotFoundError:
            return "mailbox_not_present"
        try:
            safe_directory(mailfd,uid)
            before=identity(os.fstat(mailfd))
            found=False
            count=0
            for folder in ("new","cur"):
                child=os.open(folder,flags,dir_fd=mailfd)
                try:
                    old=identity(safe_directory(child,uid))
                    # /proc/self/fd supports descriptor-anchored streaming
                    # directory iteration on Python 3.6 as well.
                    with os.scandir("/proc/self/fd/"+str(child)) as entries:
                        for entry in entries:
                            count+=1
                            if count>MAILBOX_FILE_LIMIT:
                                raise MailboxIncomplete("maildir file limit")
                            if inspect_mail_file(child,entry.name,uid,req,budget):
                                found=True
                                break
                    if (identity(os.fstat(child))!=old or
                            identity(os.stat(folder,dir_fd=mailfd,follow_symlinks=False))!=old):
                        raise MailboxIncomplete("maildir changed")
                finally:
                    os.close(child)
                if found:
                    break
            if (identity(os.fstat(mailfd))!=before or
                    identity(os.stat("Maildir",dir_fd=homefd,follow_symlinks=False))!=before):
                raise MailboxIncomplete("maildir replaced")
            # Verify the selected home is still the same anchored directory.
            if identity(os.stat(home,follow_symlinks=False))!=identity(os.fstat(homefd)):
                raise MailboxIncomplete("home changed")
            return "message_observed" if found else "not_observed"
        finally:
            os.close(mailfd)
    finally:
        os.close(homefd)


def scan_mailbox(context,req,mail_gid):
    account,settings=context["account"],context["settings"]
    uid=account["uid"]
    budget=[MAILBOX_BYTE_LIMIT]
    try:
        if settings["mailbox_kind"]=="maildir":
            return scan_maildir(account["home"],uid,req,budget)
        if settings["mailbox_kind"]!="system_spool":
            raise MailboxIncomplete("unsupported mailbox kind")
        # Permit the conventional /var/mail <-> /var/spool/mail alias,
        # but no symlink to any other location.
        spool=os.path.realpath(settings["spool_directory"])
        if spool not in ("/var/mail","/var/spool/mail"):
            raise MailboxIncomplete("unsupported spool path")
        fd=open_mail_directory(spool,0,mail_gid)
        try:
            try:
                found=inspect_mail_file(fd,settings["user"],uid,req,budget,True,mail_gid)
            except FileNotFoundError:
                return "mailbox_not_present"
            if identity(os.stat(spool,follow_symlinks=False))!=identity(os.fstat(fd)):
                raise MailboxIncomplete("spool changed")
            return "message_observed" if found else "not_observed"
        finally:
            os.close(fd)
    except (OSError,ValueError):
        return "scan_incomplete"


def drop_mailbox_privileges(account):
    uid,gid=account["uid"],account["gid"]
    if os.geteuid()!=0 or not 1000<=uid<65534 or gid<=0:
        raise ValueError("invalid mailbox identity")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.getresuid()!=(uid,uid,uid) or os.getresgid()!=(gid,gid,gid) or os.getgroups():
        raise ValueError("privilege drop incomplete")


def observe_local_mailbox(req,ledger_fn=ledger,prepare_fn=prepare_local,
                          drop=drop_mailbox_privileges,scanner=scan_mailbox):
    local_request(req)
    _,events,expected=ledger_fn(req,("local",),include_plan=True)
    result={"status":"local_mailbox_observation","run_id":req["run_id"],
            "request_sha256":digest(canonical(req)),"mailbox_kind":None,
            "observation":"not_attempted","mailbox_verified":False,
            "mail_sent":False,"mailbox_modified":False,"content_exported":False,
            "automatic_retry":False}
    if events["local"]=="not_attempted":
        return result
    plan=prepare_fn(req)
    if plan["plan_sha256"]!=expected:
        result["observation"]="review_context_changed"
        return result
    context=plan["_mailbox"]
    result["mailbox_kind"]=context["settings"]["mailbox_kind"]
    try:
        mail_gid=grp.getgrnam("mail").gr_gid
    except KeyError:
        mail_gid=None
    # This CLI process has no further privileged tasks. Do not restore
    # root or supplemental groups, even if the mailbox is unavailable.
    drop(context["account"])
    def expired(*_):
        raise TimeoutError("mailbox scan deadline")
    previous=signal.signal(signal.SIGALRM,expired)
    signal.alarm(25)
    try:
        result["observation"]=scanner(context,req,mail_gid)
    except (OSError,ValueError):
        result["observation"]="scan_incomplete"
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM,previous)
    if result["observation"] not in ("message_observed","not_observed","scan_incomplete","mailbox_not_present"):
        raise ValueError("invalid observation")
    result["mailbox_verified"]=result["observation"]=="message_observed"
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preview", "submit", "trace", "audit", "local-preview", "local-submit", "local-trace", "local-mailbox"))
    parser.add_argument("--expected-sha")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("root required")
        os.umask(0o077)
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError("request too large")
        req = json.loads(raw, object_pairs_hook=strict_object)
        if args.action == "audit":
            if args.expected_sha is not None:
                raise ValueError("unexpected approval")
            print(json.dumps(primary_audit(req)))
            return 0
        if args.action.startswith("local-"):
            local_request(req)
            if args.action == "local-submit":
                report=submit_local(req,args.expected_sha)
            else:
                if args.expected_sha is not None:
                    raise ValueError("unexpected approval")
                if args.action=="local-preview":
                    report=prepare_local(req)
                    report.pop("_binary")
                    report.pop("_mailbox")
                elif args.action=="local-mailbox":
                    report=observe_local_mailbox(req)
                else:
                    report=trace_local(req)
            print(json.dumps(report))
            return 0
        req = validate_request(req)
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
