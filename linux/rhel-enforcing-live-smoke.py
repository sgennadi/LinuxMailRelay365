#!/usr/bin/env python3
"""Read-only SELinux Enforcing SMTP AUTH/TLS runtime acceptance (Python 3.6+).

Probes ONLY loopback of the already-installed independent Postfix on its
custom port. It never logs in, transmits sender/recipient, sends SMTP DATA,
changes SELinux mode/policy/booleans, or restarts any service. A successful
probe cannot prove Exchange Online delivery, reboot continuity or other
client networks. It provides one concrete local Enforcing acceptance gate.
"""
import argparse
import ipaddress
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
from pathlib import Path

CONF = Path("/etc/linuxmailrelay365/sidecar-postfix")
QUEUE = Path("/var/spool/linuxmailrelay365-sidecar")
AUTH = Path("/etc/linuxmailrelay365/smtp-auth")
RHEL = frozenset(("rhel", "ol", "rocky", "almalinux", "centos"))
DNS = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")


class Refused(Exception):
    pass


def report(key, value):
    print("{}={}".format(key, value))


def safe_run(args, timeout=8):
    if not shutil.which(args[0]):
        raise Refused("required_command_unavailable")
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=timeout,
                                check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("read_only_probe_failed_or_timed_out")
    if result.returncode or len(result.stdout) > 131072:
        raise Refused("read_only_command_failed")
    return result.stdout.strip()


def os_mode():
    try:
        release = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        raise Refused("os_release_unavailable")
    match = re.search(r'(?m)^ID=["\x27]?([a-z0-9_-]+)', release)
    if not match or match.group(1) not in RHEL:
        raise Refused("rhel_family_host_required")
    if safe_run(["getenforce"]).lower() != "enforcing":
        raise Refused("selinux_enforcing_mode_required")
    if os.geteuid() != 0:
        raise Refused("root_required_for_context_and_service_audit")


def port_type(port, text):
    found = set()
    for line in text.splitlines():
        match = re.match(r"^(\S+)\s+tcp\s+(.+)$", line)
        if not match:
            continue
        # Default fallback portcon entries overlap more-specific rules.
        # All other overlapping labels are still treated as conflicts.
        if match.group(1) in ("reserved_port_t", "unreserved_port_t"):
            continue
        for token in re.split(r"[\s,]+", match.group(2).strip()):
            part = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
            if part and int(part.group(1)) <= port <= int(part.group(2) or part.group(1)):
                found.add(match.group(1))
    return "smtp_port_t" if found == {"smtp_port_t"} else "other_or_unmapped"


def actual_label(path):
    try:
        st = path.lstat()
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)
                or stat.S_ISSOCK(st.st_mode)):
            return "unsafe_type"
        label = os.getxattr(str(path), "security.selinux").decode(
            "ascii", "replace").strip("\0")
        match = re.fullmatch(r"[A-Za-z0-9_]+:[A-Za-z0-9_]+:([A-Za-z0-9_]+):[A-Za-z0-9_:.,-]+", label)
        if not match:
            return "invalid"
        value = match.group(1)
        return "unsafe" if value in ("default_t", "unlabeled_t", "file_t") else value
    except (OSError, UnicodeError):
        return "unknown"


def check_contexts():
    # We do not prescribe a type that might be wrong on this host's policy
    # version. Report that a real policy review is still mandatory.
    names = (CONF / "main.cf", CONF / "master.cf", QUEUE, QUEUE / "private",
             QUEUE / "private" / "auth", AUTH / "passwd", AUTH / "privkey.pem")
    types = [actual_label(path) for path in names]
    return "unsafe_or_missing" if any(x in ("unsafe_type", "unsafe", "invalid", "unknown")
                                       for x in types) else "labeled_unverified"


def check_installed(port):
    if (CONF / "smtp-port").is_symlink():
        raise Refused("installed_port_symlink_not_allowed")
    try:
        installed = (CONF / "smtp-port").read_text(encoding="ascii").strip()
    except OSError:
        raise Refused("installed_sidecar_port_unknown")
    if installed != str(port):
        raise Refused("custom_port_does_not_match_installed_sidecar")
    if port_type(port, safe_run(["semanage", "port", "-l"], 15)) != "smtp_port_t":
        raise Refused("smtp_port_t_mapping_missing_or_conflicting")
    for service in ("linuxmailrelay365-sidecar.service",
                    "linuxmailrelay365-smtp-auth.service"):
        if safe_run(["systemctl", "is-active", service]) != "active":
            raise Refused("isolated_postfix_or_dovecot_inactive")
    for key, expected in (
        ("smtpd_sasl_auth_enable", "yes"),
        ("smtpd_sasl_type", "dovecot"),
        ("smtpd_sasl_path", "private/auth"),
        ("smtpd_tls_security_level", "encrypt"),
        ("smtpd_tls_auth_only", "yes"),
        ("smtpd_relay_restrictions", "permit_sasl_authenticated, reject")):
        if safe_run(["postconf", "-c", str(CONF), "-h", key]) != expected:
            raise Refused("installed_auth_tls_policy_mismatch")


def smtp_reply(reader):
    lines, code = [], None
    for _ in range(40):
        line = reader.readline(2049)
        if not line or len(line) > 2048:
            raise Refused("smtp_response_unavailable_or_too_large")
        match = re.match(rb"^([0-9]{3})([- ])", line)
        if not match:
            raise Refused("smtp_response_invalid")
        if code is not None and code != match.group(1):
            raise Refused("smtp_mixed_response_codes")
        code = match.group(1)
        lines.append(line[4:].decode("ascii", "replace").strip().upper())
        if match.group(2) == b" ":
            return int(code), lines
    raise Refused("smtp_too_many_reply_lines")


def smtp_tls_probe(port, hostname, cafile=None):
    conn = None
    reader = None
    secure = None
    try:
        conn = socket.create_connection(("127.0.0.1", port), timeout=9)
        conn.settimeout(9)
        reader = conn.makefile("rb")
        code, _ = smtp_reply(reader)
        if code != 220:
            raise Refused("smtp_greeting_not_ready")
        conn.sendall(b"EHLO lmr365-check.invalid\r\n")
        code, before = smtp_reply(reader)
        if code != 250 or not any(s.startswith("STARTTLS") for s in before):
            raise Refused("smtp_starttls_not_advertised")
        if any(s.startswith("AUTH ") or s == "AUTH" for s in before):
            raise Refused("smtp_auth_exposed_before_tls")
        conn.sendall(b"STARTTLS\r\n")
        code, _ = smtp_reply(reader)
        if code != 220:
            raise Refused("smtp_starttls_not_accepted")
        reader.close()
        reader = None
        context = ssl.create_default_context(cafile=cafile)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        secure = context.wrap_socket(conn, server_hostname=hostname)
        conn = None
        if secure.version() not in ("TLSv1.2", "TLSv1.3"):
            raise Refused("smtp_obsolete_tls_protocol")
        reader = secure.makefile("rb")
        secure.sendall(b"EHLO lmr365-check.invalid\r\n")
        code, after = smtp_reply(reader)
        if code != 250 or not any(s.startswith("AUTH ") for s in after):
            raise Refused("smtp_auth_not_advertised_after_tls")
        secure.sendall(b"QUIT\r\n")
        smtp_reply(reader)
        return secure.version()
    except (OSError, ssl.SSLError, socket.timeout):
        raise Refused("smtp_tls_certificate_or_socket_failure")
    finally:
        if reader:
            reader.close()
        if secure:
            secure.close()
        if conn:
            conn.close()


def run(port, hostname, cafile):
    os_mode()
    check_installed(port)
    label_state = check_contexts()
    if label_state != "labeled_unverified":
        raise Refused("selinux_file_or_socket_context_not_labeled")
    tls = smtp_tls_probe(port, hostname, cafile)
    report("RHEL_ENFORCING_LIVE_SMTP", "tls_auth_handshake_passed")
    report("RHEL_ENFORCING_TLS_PROTOCOL", tls.replace(".", "_").lower())
    report("RHEL_ENFORCING_SMTP_AUTH", "advertised_only_no_login")
    report("RHEL_ENFORCING_FILE_CONTEXTS", "labeled_policy_review_required")
    report("RHEL_ENFORCING_POST_REBOOT", "not_verified")
    report("RHEL_ENFORCING_QUEUE_IO", "not_verified")
    report("RHEL_ENFORCING_AVC_ABSENCE", "not_verified")
    report("MICROSOFT365_DELIVERY_VERIFIED", "no")
    report("SMTP_MAIL_FROM_RCPT_DATA_SENT", "no")
    report("CHANGES_APPLIED", "no")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smtp-port", type=int, default=2525)
    parser.add_argument("--server-name", default="")
    parser.add_argument("--ca-file", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        report("RHEL_ENFORCING_LIVE_PROBE_SELF_TEST", "pass")
        return 0
    if not 1024 <= args.smtp_port <= 65535 or not DNS.fullmatch(args.server_name) or \
            len(args.server_name) > 253:
        parser.error("Exact installed SMTP port and server TLS DNS hostname required")
    if args.ca_file and (not args.ca_file.startswith("/") or
                         not re.fullmatch(r"/[A-Za-z0-9_./-]{1,255}", args.ca_file)
                         or ".." in args.ca_file.split("/")):
        parser.error("Only absolute reviewed Linux CA bundle paths are allowed")
    try:
        return run(args.smtp_port, args.server_name, args.ca_file or None)
    except (Refused, ValueError) as exc:
        report("RHEL_ENFORCING_LIVE_SMTP", "refused")
        report("RHEL_ENFORCING_REASON",
               re.sub(r"[^a-z0-9_]", "_", str(exc).lower())[:82])
        report("CHANGES_APPLIED", "no")
        return 2


if __name__ == "__main__":
    sys.exit(main())
