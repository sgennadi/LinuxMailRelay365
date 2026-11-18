#!/usr/bin/env python3
"""LinuxMailRelay365: read-only installed isolated SMTP security audit.

Runs on Python 3.6+ (RHEL/Oracle/Rocky/Alma 8-10, Ubuntu/Debian).
Never changes Postfix, SELinux, firewall, credentials or queues; sends no mail.
Only coded findings are emitted, never local hostnames, usernames or secret data.
"""
import argparse
import grp
import ipaddress
import os
import re
import shutil
import smtplib
import socket
import ssl
import stat
import subprocess
from pathlib import Path

CONF = Path("/etc/linuxmailrelay365/sidecar-postfix")
AUTH_DIR = Path("/etc/linuxmailrelay365/smtp-auth")
QUEUE = Path("/var/spool/linuxmailrelay365-sidecar")
PRIVATE = tuple(ipaddress.ip_network(x) for x in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def run(*argv, timeout=6):
    if not argv or not shutil.which(argv[0]):
        return None
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout, check=False)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def postconf(key):
    return run("postconf", "-c", str(CONF), "-h", key)


def normalized_restrictions(value):
    if value is None:
        return None
    return tuple(x.strip().lower() for x in value.split(",") if x.strip())


def private_listener(value):
    if value is None:
        return "unknown"
    parts = value.replace(",", " ").split()
    if not parts:
        return "unknown"
    try:
        addresses = [ipaddress.ip_address(x) for x in parts]
    except ValueError:
        return "unsafe"
    if any(not isinstance(x, ipaddress.IPv4Address) for x in addresses):
        return "unsafe"
    for address in addresses:
        if address != ipaddress.IPv4Address("127.0.0.1") and not any(
                address in p for p in PRIVATE):
            return "unsafe"
    if not any(x == ipaddress.IPv4Address("127.0.0.1") for x in addresses):
        return "unknown"
    return "loopback_only" if all(x.is_loopback for x in addresses) else "private_ipv4"


def trusted_networks(value):
    if value is None:
        return "unknown"
    parts = value.replace(",", " ").split()
    if not parts:
        return "unknown"
    try:
        ranges = [ipaddress.ip_network(x, strict=False) for x in parts]
    except ValueError:
        return "unsafe"
    for network in ranges:
        if not isinstance(network, ipaddress.IPv4Network):
            return "unsafe"
        if not (network.network_address in ipaddress.ip_network("127.0.0.0/8") and
                network.broadcast_address in ipaddress.ip_network("127.0.0.0/8")) and not any(
                network.network_address in p and network.broadcast_address in p for p in PRIVATE):
            return "unsafe"
    return "private_only"


def port_configuration(port):
    try:
        installed = (CONF / "smtp-port").read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[0-9]{4,5}", installed):
            return "unrecognized"
        if int(installed) != port:
            return "mismatch"
        lines = (CONF / "master.cf").read_text(encoding="utf-8", errors="replace")
        for raw in lines.splitlines():
            tokens = raw.split()
            if len(tokens) >= 2 and tokens[0] == installed and tokens[1] == "inet":
                return "matched"
        return "listener_definition_missing"
    except (OSError, UnicodeError, ValueError):
        return "unavailable"


def service_status(unit):
    if not shutil.which("systemctl"):
        return "unknown"
    if run("systemctl", "is-active", unit) == "active":
        return "active"
    return "inactive_or_unavailable"


def auth_file_status():
    # Do not read passwords, hash values or private key contents.
    expected = {
        AUTH_DIR / "passwd": "dovecot",
        AUTH_DIR / "privkey.pem": "postfix",
    }
    for filename, group in expected.items():
        try:
            info = filename.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
                return "unsafe_permissions"
            if info.st_mode & 0o007 or info.st_mode & 0o020:
                return "unsafe_permissions"
            if info.st_mode & 0o040 == 0:
                return "unreadable_group"
            if grp.getgrnam(group).gr_gid != info.st_gid:
                return "wrong_group"
        except FileNotFoundError:
            return "missing"
        except (PermissionError, KeyError, OSError):
            return "unknown"
    try:
        info = AUTH_DIR.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            return "unsafe_permissions"
    except OSError:
        return "unknown"
    return "restricted"


def auth_socket_status():
    try:
        socket_path = QUEUE / "private/auth"
        s = socket_path.lstat()
        if not stat.S_ISSOCK(s.st_mode):
            return "not_socket"
        if s.st_mode & 0o007:
            return "unsafe_permissions"
        return "present"
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unknown"


def selinux_port_type(data, port):
    if data is None:
        return "unverified"
    owners = set()
    for line in data.splitlines():
        match = re.match(r"^(\S+)\s+tcp\s+(.+)$", line)
        if not match:
            continue
        for item in re.split(r"[\s,]+", match.group(2).strip()):
            token = re.fullmatch(r"(\d+)(?:-(\d+))?", item)
            if token and int(token.group(1)) <= port <= int(token.group(2) or token.group(1)):
                owners.add(match.group(1))
    if owners == {"smtp_port_t"}:
        return "smtp_port_t"
    return "conflicting_type" if owners else "unmapped"


def selinux_file_label_hints(auth_enabled):
    """Check labels exist without assuming any label grants actual policy access.

    Real allow/deny evidence needs AVC logs, service domains and an
    Enforcing integration test. No label is printed to the user.
    """
    paths = [QUEUE, QUEUE / "private"]
    if auth_enabled:
        paths.extend((QUEUE / "private/auth", AUTH_DIR / "passwd",
                      AUTH_DIR / "privkey.pem"))
    for pathname in paths:
        try:
            raw = os.getxattr(str(pathname), "security.selinux")
            label = raw.decode("ascii", "replace").strip("\x00")
        except FileNotFoundError:
            return "missing_files"
        except (OSError, UnicodeError, AttributeError):
            return "unavailable"
        if not re.fullmatch(r"[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_.,:-]+",
                            label):
            return "unrecognized_label"
        if any(bad in label for bad in (":unlabeled_t:", ":default_t:")):
            return "unlabeled_or_default_type"
    return "labels_present_requires_policy_review"


def smtp_handshake(port, require_tls):
    """Local feature probe; never sends MAIL, RCPT, AUTH or DATA."""
    result = {"SMTP_EHLO": "unreachable", "SMTP_STARTTLS": "unknown",
              "SMTP_AUTH_BEFORE_TLS": "unknown", "SMTP_AUTH_AFTER_TLS": "unknown"}
    try:
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as client:
            code, _ = client.ehlo("lmr365-audit.invalid")
            if code != 250:
                return result
            result["SMTP_EHLO"] = "responding"
            result["SMTP_STARTTLS"] = "offered" if client.has_extn("starttls") else "not_offered"
            result["SMTP_AUTH_BEFORE_TLS"] = "yes" if client.has_extn("auth") else "no"
            if require_tls and client.has_extn("starttls"):
                # Only testing TLS feature negotiation on loopback. This is
                # NOT client CA trust or DNS-name validation.
                ctx = ssl._create_unverified_context()
                client.starttls(context=ctx)
                code, _ = client.ehlo("lmr365-audit.invalid")
                if code == 250:
                    result["SMTP_AUTH_AFTER_TLS"] = "yes" if client.has_extn("auth") else "no"
    except (OSError, smtplib.SMTPException, ssl.SSLError, ValueError):
        if result["SMTP_EHLO"] == "responding" and require_tls:
            result["SMTP_AUTH_AFTER_TLS"] = "handshake_failed"
    return result


def audit(port, live=True):
    d = {
        "INSTALLED_SMTP_AUDIT_VERSION": "1",
        "CUSTOM_SMTP_PORT": str(port),
        "SIDECAR": "not_installed",
        "SIDECAR_SERVICE": "unknown",
        "SIDECAR_PORT_CONFIG": "unavailable",
        "SMTP_LISTENER_SCOPE": "unknown",
        "SMTP_TRUSTED_NETWORKS": "unknown",
        "SMTP_POLICY": "unknown",
        "SMTP_RELAY_RESTRICTIONS": "unknown",
        "AUTH_MATERIAL_PERMISSIONS": "not_applicable",
        "DOVECOT_SASL_SOCKET": "not_applicable",
        "DOVECOT_AUTH_SERVICE": "not_applicable",
        "SELINUX_MODE": "unknown",
        "SELINUX_SMTP_PORT": "not_checked",
        "SELINUX_QUEUE_AND_SOCKET_LABELS": "not_verified",
        "SMTP_EHLO": "not_checked",
        "SMTP_STARTTLS": "not_checked",
        "SMTP_AUTH_BEFORE_TLS": "not_checked",
        "SMTP_AUTH_AFTER_TLS": "not_checked",
        "SMTP_SECURITY_RESULT": "not_installed",
        "TLS_CLIENT_CERT_TRUST": "not_verified",
        "PUBLIC_INTERNET_ACCESS_VERIFIED": "no",
        "MICROSOFT365_DELIVERY_VERIFIED": "no",
        "CHANGES_APPLIED": "no",
    }
    mode = run("getenforce")
    if mode and mode.lower() in ("enforcing", "permissive", "disabled"):
        d["SELINUX_MODE"] = mode.lower()
    if d["SELINUX_MODE"] == "unknown" and not Path("/sys/fs/selinux/enforce").exists():
        try:
            os_data = Path("/etc/os-release").read_text(encoding="utf-8")
        except OSError:
            os_data = ""
        if re.search(r"(?m)^ID=(?:\"|')?(?:ubuntu|debian)(?:\"|')?\s*$", os_data):
            d["SELINUX_MODE"] = "not_installed"
    if d["SELINUX_MODE"] in ("enforcing", "permissive"):
        d["SELINUX_SMTP_PORT"] = selinux_port_type(
            run("semanage", "port", "-l", timeout=12), port)
    if not (CONF / "main.cf").is_file() or not (CONF / "master.cf").is_file():
        return d

    d["SIDECAR"] = "present"
    d["SIDECAR_SERVICE"] = service_status("linuxmailrelay365-sidecar.service")
    d["SIDECAR_PORT_CONFIG"] = port_configuration(port)
    d["SMTP_LISTENER_SCOPE"] = private_listener(postconf("inet_interfaces"))
    d["SMTP_TRUSTED_NETWORKS"] = trusted_networks(postconf("mynetworks"))
    client_rule = normalized_restrictions(postconf("smtpd_client_restrictions"))
    relay_rule = normalized_restrictions(postconf("smtpd_relay_restrictions"))
    recipient_rule = normalized_restrictions(postconf("smtpd_recipient_restrictions"))
    tls = postconf("smtpd_tls_security_level")
    auth = postconf("smtpd_sasl_auth_enable")
    auth_only = postconf("smtpd_tls_auth_only")
    if d["SELINUX_MODE"] in ("enforcing", "permissive"):
        d["SELINUX_QUEUE_AND_SOCKET_LABELS"] = selinux_file_label_hints(auth == "yes")
    d["SMTP_RELAY_RESTRICTIONS"] = (
        "auth_required" if relay_rule == ("permit_sasl_authenticated", "reject")
        and recipient_rule == ("permit_sasl_authenticated", "reject")
        else "private_clients" if relay_rule == ("permit_mynetworks", "reject_unauth_destination")
        else "unrecognized"
    )
    if auth == "yes":
        d["DOVECOT_AUTH_SERVICE"] = service_status("linuxmailrelay365-smtp-auth.service")
        d["DOVECOT_SASL_SOCKET"] = auth_socket_status()
        d["AUTH_MATERIAL_PERMISSIONS"] = auth_file_status()
        if (tls == "encrypt" and auth_only == "yes" and
                client_rule == ("permit_mynetworks", "reject") and
                postconf("smtpd_sasl_type") == "dovecot" and
                postconf("smtpd_sasl_path") == "private/auth" and
                d["SMTP_RELAY_RESTRICTIONS"] == "auth_required"):
            d["SMTP_POLICY"] = "mandatory_tls_and_auth"
        else:
            d["SMTP_POLICY"] = "insecure_or_misconfigured"
    elif auth == "no":
        if (client_rule == ("permit_mynetworks", "reject") and
                d["SMTP_RELAY_RESTRICTIONS"] == "private_clients"):
            d["SMTP_POLICY"] = "trusted_clients_without_auth"
        else:
            d["SMTP_POLICY"] = "insecure_or_misconfigured"
    else:
        d["SMTP_POLICY"] = "unknown"

    if live and d["SIDECAR_PORT_CONFIG"] == "matched":
        d.update(smtp_handshake(port, d["SMTP_POLICY"] == "mandatory_tls_and_auth"))

    common_safe = (
        d["SIDECAR_SERVICE"] == "active" and
        d["SIDECAR_PORT_CONFIG"] == "matched" and
        d["SMTP_LISTENER_SCOPE"] in ("loopback_only", "private_ipv4") and
        d["SMTP_TRUSTED_NETWORKS"] == "private_only" and
        d["SMTP_RELAY_RESTRICTIONS"] != "unrecognized" and
        d["SELINUX_MODE"] != "unknown" and
        (d["SELINUX_MODE"] != "enforcing" or d["SELINUX_SMTP_PORT"] == "smtp_port_t")
    )
    if not common_safe:
        d["SMTP_SECURITY_RESULT"] = "needs_manual_review"
    elif d["SMTP_POLICY"] == "mandatory_tls_and_auth":
        local_ready = (
            d["DOVECOT_AUTH_SERVICE"] == "active" and
            d["DOVECOT_SASL_SOCKET"] == "present" and
            d["AUTH_MATERIAL_PERMISSIONS"] == "restricted" and
            d["SMTP_EHLO"] == "responding" and
            d["SMTP_STARTTLS"] == "offered" and
            d["SMTP_AUTH_BEFORE_TLS"] == "no" and
            d["SMTP_AUTH_AFTER_TLS"] == "yes")
        d["SMTP_SECURITY_RESULT"] = (
            "local_auth_tls_verified_external_unverified"
            if local_ready and d["SELINUX_MODE"] != "enforcing"
            else "needs_manual_review")
    elif d["SMTP_POLICY"] == "trusted_clients_without_auth":
        d["SMTP_SECURITY_RESULT"] = "private_unauthenticated_not_public_safe"
    else:
        d["SMTP_SECURITY_RESULT"] = "needs_manual_review"
    return d


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smtp-port", type=int, required=True)
    parser.add_argument("--no-live-probe", action="store_true")
    args = parser.parse_args()
    if not 1024 <= args.smtp_port <= 65535:
        parser.error("Custom SMTP port must be 1024-65535")
    findings = audit(args.smtp_port, live=not args.no_live_probe)
    for key, value in findings.items():
        print("{}={}".format(key, value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
