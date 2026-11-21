#!/usr/bin/env python3
"""Read-only comparison: planned multi-mailbox map versus installed SMTP ingress.

NEVER enables XOAUTH2, starts services, edits Postfix, authenticates SMTP,
loads OAuth secrets, or sends mail. Python 3.6+ for RHEL/OL/Rocky/Alma 8-10.
Sanitized status codes only: no usernames, addresses, paths or hash contents.
This tool is intentionally NOT an authorization gate for sending messages.
"""
import argparse
import grp
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

AUDITOR_FILE = Path(__file__).with_name("audit-oauth-sender-map.py")
HASHES = "/etc/linuxmailrelay365/smtp-auth/passwd"
GUARD = "/etc/linuxmailrelay365/sidecar-postfix/eop-from-owners.tsv"
OWNER_RULES = "/etc/linuxmailrelay365/sidecar-postfix/eop-sender-owners.regexp"
CONF = "/etc/linuxmailrelay365/sidecar-postfix"
SOCKET = "/run/linuxmailrelay365-from-guard/from-guard.sock"
MILTER = "unix:" + SOCKET
OWNER_MAP = "regexp:" + CONF + "/eop-sender-owners.regexp"
SMTP_PORT_FILE = CONF + "/smtp-port"
TRACE_HEADER_FILE = CONF + "/eop-reject-trace-header.regexp"
TRACE_HEADER_MAP = "regexp:" + TRACE_HEADER_FILE
TRACE_HEADER_EXACT = b"/^Return-Path:/ REJECT client_supplied_return_path_denied\n"
SENDER_POLICY = "reject_authenticated_sender_login_mismatch, check_sender_access regexp:" + CONF + "/eop-fixed-sender.regexp, reject"
HASH_RE = re.compile(
    r"\{SHA512-CRYPT\}\$6\$(?:rounds=[0-9]{3,9}\$)?"
    r"[A-Za-z0-9./]{8,32}\$[A-Za-z0-9./]{30,128}\Z"
)
MAX_HASHES = 32768
MAX_OWNERS = 16384

class AuditRefused(Exception):
    pass


def auditor_module():
    spec = importlib.util.spec_from_file_location("lmr365_sender_audit", str(AUDITOR_FILE))
    if spec is None or spec.loader is None:
        raise AuditRefused("source_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, ValueError, SyntaxError):
        raise AuditRefused("source_module_unavailable")
    return module


def parse_auth_users(raw, username_re):
    """Load only the login names. Never return, print or persist password hashes."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_HASHES or b"\r" in raw or b"\0" in raw:
        raise AuditRefused("unsafe_auth_file")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        raise AuditRefused("unsafe_auth_file")
    if not 1 <= len(lines) <= 64:
        raise AuditRefused("auth_account_count_outside_1_64")
    names = set()
    for line in lines:
        if line.count(":") != 1:
            raise AuditRefused("invalid_auth_account_record")
        username, hashed = line.split(":", 1)
        if not username_re.fullmatch(username) or not HASH_RE.fullmatch(hashed):
            raise AuditRefused("invalid_auth_account_record")
        folded = username.casefold()
        if folded in names:
            raise AuditRefused("duplicate_auth_account")
        names.add(folded)
    return names


def parse_guard_owners(raw, email_re, login_re):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OWNERS or b"\r" in raw or b"\0" in raw:
        raise AuditRefused("unsafe_guard_policy")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        raise AuditRefused("unsafe_guard_policy")
    if not 1 <= len(lines) <= 64:
        raise AuditRefused("guard_owner_count_outside_1_64")
    result = {}
    for line in lines:
        parts = line.split()
        if len(parts) != 2 or not email_re.fullmatch(parts[0]) or not login_re.fullmatch(parts[1]):
            raise AuditRefused("invalid_guard_owner_record")
        sender, login = parts[0].casefold(), parts[1].casefold()
        if sender in result:
            raise AuditRefused("duplicate_guard_sender")
        result[sender] = login
    return result



def exact_postfix_owner_rules(raw, rows):
    """Compare only the literal rules this application's EOP deployer writes.

    Never evaluate user-controlled regexp content; compare byte-for-byte rule
    lines against trusted literal rules derived from the reviewed sender map.
    Order is immaterial. Extra rules, wildcard rules or duplicate rules fail.
    """
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OWNERS or \
            b"\r" in raw or b"\x00" in raw or not raw.endswith(b"\n"):
        return False
    try:
        actual = raw.decode("ascii").splitlines()
    except UnicodeError:
        return False
    expected = []
    for login, sender, _mailbox, _identity in rows:
        escaped = sender.replace(".", "[.]").replace("+", "[+]")
        expected.append("/^{}$/ {}".format(escaped, login))
    return len(actual) == len(expected) and set(actual) == set(expected)


def guard_pinned_policy(policy_hash):
    """Check the guard's configured systemd ExecStart SHA without restart."""
    if not re.fullmatch(r"[a-f0-9]{64}", policy_hash):
        return False
    binary = _trusted_binary("systemctl", ("/usr/bin/systemctl", "/bin/systemctl"))
    if binary is None:
        return False
    try:
        proc = subprocess.run(
            [binary, "show", "-p", "ExecStart", "--value",
             "linuxmailrelay365-from-guard.service"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            universal_newlines=True, timeout=5, check=False)
        return (proc.returncode == 0 and len(proc.stdout) < 8192 and
                "/usr/local/libexec/linuxmailrelay365-from-owner-milter.py" in proc.stdout and
                "--expected-map-sha256 " + policy_hash in proc.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return False


def _trusted_binary(name, choices):
    path = shutil.which(name)
    if path not in choices:
        return None
    return path


def read_postconf(key):
    """Run fixed argv; do not log stderr/config output."""
    binary = _trusted_binary("postconf", ("/usr/sbin/postconf", "/usr/bin/postconf"))
    if not binary:
        return None
    try:
        p = subprocess.run(
            [binary, "-c", CONF, "-h", key],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            universal_newlines=True, timeout=5, check=False)
        if p.returncode or len(p.stdout) > 4096:
            return None
        return p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None



def read_master_readback():
    """Read only Postfix master.cf services and explicit -o overrides."""
    binary = _trusted_binary("postconf", ("/usr/sbin/postconf", "/usr/bin/postconf"))
    if not binary:
        return None
    output = []
    for flag in ("-M", "-P"):
        try:
            proc = subprocess.run([binary, "-c", CONF, flag],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                universal_newlines=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode or not isinstance(proc.stdout, str) or len(proc.stdout) > 32768:
            return None
        output.append(proc.stdout)
    return tuple(output)


def inspect_master_service(port_raw, master_text, overrides):
    """Fail closed on unexpected inet listeners or any master.cf -o overrides."""
    if not isinstance(port_raw, bytes) or not re.fullmatch(rb"[0-9]{4,5}\n?", port_raw):
        return "unavailable_or_unsafe"
    port = int(port_raw.strip())
    if port < 1024 or port > 65535:
        return "unavailable_or_unsafe"
    if (not isinstance(master_text, str) or not isinstance(overrides, str) or
            not 1 <= len(master_text) <= 32768 or len(overrides) > 32768 or
            any(c in master_text + overrides for c in ("\x00", "\r"))):
        return "unavailable_or_unsafe"
    listeners = []
    for line in master_text.splitlines():
        if not line or line.startswith(("#", " ", "\t")):
            continue
        fields = line.split()
        if len(fields) < 2:
            return "unavailable_or_unsafe"
        if fields[1] == "inet":
            if len(fields) != 8 or fields[0] != str(port) or fields[-1] != "smtpd":
                return "unexpected_inet_service"
            listeners.append(fields[0])
    if len(listeners) != 1:
        return "unexpected_inet_service"
    if overrides.strip():
        return "per_service_overrides_present"
    return "single_private_smtpd_no_overrides"


def service_active(unit):
    if unit not in ("linuxmailrelay365-sidecar.service",
                    "linuxmailrelay365-smtp-auth.service",
                    "linuxmailrelay365-from-guard.service"):
        return False
    binary = _trusted_binary("systemctl", ("/usr/bin/systemctl", "/bin/systemctl"))
    if not binary:
        return False
    try:
        r = subprocess.run([binary, "is-active", "--quiet", unit],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=5, check=False)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def socket_metadata():
    """A local socket is *presence* only, never proof of Milter message checks."""
    try:
        st = os.lstat(SOCKET)
        parent = os.lstat(str(Path(SOCKET).parent))
        service = __import__("pwd").getpwnam("linuxmailrelay365-fromguard")
        postfix = grp.getgrnam("postfix")
        return (stat.S_ISSOCK(st.st_mode) and st.st_uid == service.pw_uid and
                st.st_gid == postfix.gr_gid and stat.S_IMODE(st.st_mode) == 0o660 and
                stat.S_ISDIR(parent.st_mode) and parent.st_uid == service.pw_uid and
                parent.st_gid == postfix.gr_gid and
                stat.S_IMODE(parent.st_mode) == 0o750)
    except (OSError, KeyError):
        return False


def assess(rows, auditor, read_file=None, config=None, active=None,
           gids=None, socket_check=None, guard_pin=None, master_reader=None):
    """Pure report orchestration: mocked inputs can test every negative branch.

    Even an entirely positive report is only a *static configuration* review.
    It cannot prove a real client presented SMTP AUTH or the running Postfix
    accepted/rejected a message, and it cannot authorize OAuth transmission.
    """
    read_file = read_file or auditor.secure_read
    config = config or read_postconf
    active = active or service_active
    socket_check = socket_check or socket_metadata
    guard_pin = guard_pin or guard_pinned_policy
    master_reader = master_reader or read_master_readback
    if gids is None:
        try:
            gids = (grp.getgrnam("dovecot").gr_gid, grp.getgrnam("postfix").gr_gid)
        except (OSError, KeyError):
            gids = (None, None)
    logins = set(row[0] for row in rows)
    expected_owners = {row[1]: row[0] for row in rows}
    result = {
        "AUTH_ACCOUNTS": "unavailable_or_unsafe",
        "FROM_GUARD_POLICY": "unavailable_or_unsafe",
        "POSTFIX_OWNER_RULES": "unavailable_or_unsafe",
        "FROM_GUARD_SHA_PIN": "not_verified",
        "SASL_TLS_CONFIG": "not_verified",
        "SENDER_LOGIN_CONFIG": "not_verified",
        "FROM_GUARD_MILTER_CONFIG": "not_verified",
        "TRACE_HEADER_GUARD": "not_verified",
        "SERVICES": "not_all_active",
        "MILTER_SOCKET": "not_verified",
        "MASTER_CF_SERVICE": "unavailable_or_unsafe",
        "TRANSPORT": "not_multi_mailbox_xoauth2",
        "OVERALL": "not_ready",
    }
    if len(rows) <= 64 and gids[0] is not None:
        try:
            actual_logins = parse_auth_users(
                read_file(HASHES, MAX_HASHES, 0o640, gids[0]), auditor.LOGIN)
            result["AUTH_ACCOUNTS"] = (
                "exact_match" if actual_logins == logins else "different")
        except (OSError, ValueError, AuditRefused, auditor.Refused):
            pass
    elif len(rows) > 64:
        result["AUTH_ACCOUNTS"] = "over_64_account_limit"
    if len(rows) <= 64 and gids[1] is not None:
        try:
            guard_raw = read_file(GUARD, MAX_OWNERS, 0o640, gids[1])
            actual_owners = parse_guard_owners(
                guard_raw, auditor.EMAIL, auditor.LOGIN)
            result["FROM_GUARD_POLICY"] = (
                "exact_match" if actual_owners == expected_owners else "different")
            if result["FROM_GUARD_POLICY"] == "exact_match" and \
                    guard_pin(hashlib.sha256(guard_raw).hexdigest()):
                result["FROM_GUARD_SHA_PIN"] = "configured_pinned_only"
        except (OSError, ValueError, AuditRefused, auditor.Refused):
            pass
    elif len(rows) > 64:
        result["FROM_GUARD_POLICY"] = "over_64_account_limit"

    if len(rows) <= 64:
        try:
            rule_data = read_file(OWNER_RULES, MAX_OWNERS, 0o644, None)
            result["POSTFIX_OWNER_RULES"] = (
                "exact_match" if exact_postfix_owner_rules(rule_data, rows) else "different")
        except (OSError, ValueError, AuditRefused, auditor.Refused):
            pass
    else:
        result["POSTFIX_OWNER_RULES"] = "over_64_account_limit"

    try:
        readback = master_reader()
        if readback is not None and len(readback) == 2:
            port_data = read_file(SMTP_PORT_FILE, 8, 0o644, None)
            result["MASTER_CF_SERVICE"] = inspect_master_service(port_data, readback[0], readback[1])
    except (OSError, ValueError, AuditRefused, auditor.Refused, TypeError):
        pass

    values = {}
    for key in (
        "smtpd_sasl_auth_enable", "smtpd_tls_security_level",
        "smtpd_tls_auth_only", "smtpd_sasl_type", "smtpd_sasl_path",
        "smtpd_relay_restrictions", "smtpd_client_restrictions",
        "smtpd_recipient_restrictions", "smtpd_sender_login_maps",
        "smtpd_sender_restrictions", "smtpd_milters", "milter_protocol",
        "milter_default_action", "milter_mail_macros",
        "non_smtpd_milters", "smtpd_milter_maps", "authorized_submit_users",
        "default_transport", "header_checks", "mime_header_checks",
        "nested_header_checks",
    ):
        values[key] = config(key)
    if all(values.get(key) == value for key, value in (
        ("smtpd_sasl_auth_enable", "yes"),
        ("smtpd_tls_security_level", "encrypt"),
        ("smtpd_tls_auth_only", "yes"),
        ("smtpd_sasl_type", "dovecot"),
        ("smtpd_sasl_path", "private/auth"),
        ("smtpd_relay_restrictions", "permit_sasl_authenticated, reject"),
        ("smtpd_client_restrictions", "permit_mynetworks, reject"),
        ("smtpd_recipient_restrictions",
         "check_recipient_access regexp:" + CONF + "/eop-recipients.regexp, reject"),
    )):
        result["SASL_TLS_CONFIG"] = "configured_only"
    if (values["smtpd_sender_login_maps"] == OWNER_MAP and
            values["smtpd_sender_restrictions"] == SENDER_POLICY):
        result["SENDER_LOGIN_CONFIG"] = "configured_only"
    # Postfix discards Return-Path before the Milter can inspect it. An
    # exact header_checks regexp must reject client-controlled Return-Path
    # before cleanup discards the trace header. Missing or altered rules
    # invalidate the static ingress review (no Postfix changes here).
    if (values["header_checks"] == TRACE_HEADER_MAP and
            values["mime_header_checks"] == "" and
            values["nested_header_checks"] == ""):
        try:
            actual_trace = read_file(TRACE_HEADER_FILE, MAX_OWNERS, 0o644, None)
            result["TRACE_HEADER_GUARD"] = (
                "exact_static_reject" if actual_trace == TRACE_HEADER_EXACT
                else "different_rule")
        except (OSError, ValueError, KeyError, AuditRefused, auditor.Refused):
            result["TRACE_HEADER_GUARD"] = "unavailable_or_unsafe"
    else:
        result["TRACE_HEADER_GUARD"] = "different_configuration"
    if (values["smtpd_milters"] == MILTER and
            values["milter_protocol"] == "6" and
            values["milter_default_action"] == "tempfail" and
            values["milter_mail_macros"] == "i {mail_addr} {auth_authen} {auth_type}" and
            values["non_smtpd_milters"] == "" and
            values["smtpd_milter_maps"] == "" and
            values["authorized_submit_users"] == ""):
        result["FROM_GUARD_MILTER_CONFIG"] = "configured_fail_closed_only"

    if all(active(unit) for unit in (
        "linuxmailrelay365-sidecar.service",
        "linuxmailrelay365-smtp-auth.service",
        "linuxmailrelay365-from-guard.service",
    )):
        result["SERVICES"] = "all_report_active"
    if socket_check():
        result["MILTER_SOCKET"] = "metadata_matches_only"
    if isinstance(values["default_transport"], str) and \
            values["default_transport"].startswith("smtp:["):
        result["TRANSPORT"] = "eop_smtp_not_xoauth2_multi"
    if all(result[key] == target for key, target in (
        ("AUTH_ACCOUNTS", "exact_match"),
        ("FROM_GUARD_POLICY", "exact_match"),
        ("POSTFIX_OWNER_RULES", "exact_match"),
        ("FROM_GUARD_SHA_PIN", "configured_pinned_only"),
        ("SASL_TLS_CONFIG", "configured_only"),
        ("SENDER_LOGIN_CONFIG", "configured_only"),
        ("FROM_GUARD_MILTER_CONFIG", "configured_fail_closed_only"),
        ("TRACE_HEADER_GUARD", "exact_static_reject"),
        ("SERVICES", "all_report_active"),
        ("MILTER_SOCKET", "metadata_matches_only"),
        ("MASTER_CF_SERVICE", "single_private_smtpd_no_overrides"),
    )):
        result["OVERALL"] = "ingress_config_consistent_not_live_verified"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only SMTP ingress versus XOAUTH2 sender map review")
    parser.add_argument("--map-path", required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise AuditRefused("root_required")
        auditor = auditor_module()
        auditor.allowed_path(args.map_path)
        try:
            structural = auditor.audit(args.map_path)
            raw = auditor.secure_read(args.map_path, auditor.MAX_MAP, 0o600, None)
            if hashlib.sha256(raw).hexdigest() != structural["MAP_SHA256"]:
                raise AuditRefused("sender_map_changed_during_review")
            rows = auditor.parse_map(raw)
        except auditor.Refused:
            raise AuditRefused("read_only_inputs_not_valid")
        report = assess(rows, auditor)
        print("OAUTH_INGRESS_REVIEW=read_only")
        print("OAUTH_INGRESS_MAP_SHA256=" + structural["MAP_SHA256"])
        for key in ("AUTH_ACCOUNTS", "FROM_GUARD_POLICY", "POSTFIX_OWNER_RULES",
                    "FROM_GUARD_SHA_PIN", "SASL_TLS_CONFIG",
                    "SENDER_LOGIN_CONFIG", "FROM_GUARD_MILTER_CONFIG",
                    "TRACE_HEADER_GUARD",
                    "SERVICES", "MILTER_SOCKET", "MASTER_CF_SERVICE", "TRANSPORT", "OVERALL"):
            print("OAUTH_INGRESS_" + key + "=" + report[key])
        print("OAUTH_INGRESS_REAL_SMTP_LOGIN_VERIFIED=no")
        print("OAUTH_INGRESS_REAL_FROM_GUARD_MESSAGE_VERIFIED=no")
        print("OAUTH_INGRESS_M365_SENDAS_VERIFIED=no")
        print("OAUTH_INGRESS_MASTER_CF_OVERRIDES_VERIFIED=no")
        print("OAUTH_INGRESS_MULTI_MAILBOX_ENABLED=no")
        print("OAUTH_INGRESS_POSTFIX_CHANGED=no")
        print("OAUTH_INGRESS_MESSAGES_SENT=no")
        return 0
    except (AuditRefused, OSError, ValueError) as exc:
        # Refusal codes are fixed literals; never print raw exception messages
        # from Postfix, files, tenant identity, or external programs.
        if isinstance(exc, AuditRefused) and str(exc) in (
            "root_required", "sender_map_changed_during_review",
            "source_module_unavailable"):
            reason = str(exc)
        else:
            reason = "read_only_inputs_not_valid"
        print("OAUTH_INGRESS_REVIEW=refused", file=sys.stderr)
        print("OAUTH_INGRESS_ERROR=" + reason, file=sys.stderr)
        print("OAUTH_INGRESS_POSTFIX_CHANGED=no", file=sys.stderr)
        print("OAUTH_INGRESS_MESSAGES_SENT=no", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
