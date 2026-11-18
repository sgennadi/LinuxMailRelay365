#!/usr/bin/env python3
"""Explicit public AUTH/STARTTLS SMTP submission on an isolated XOAUTH2 sidecar.

This is NOT an MX server or an unauthenticated relay. Exposes only an explicitly
bound private IPv4 to all source networks (e.g. behind separately approved NAT).
Requires existing Dovecot AUTH, system-CA-valid TLS identity, an active local
health timer, and externally tested Fail2ban. Uses SHA-guarded backup/rollback.
Never alters the primary Postfix, its queue, system SELinux policy, or port 25.
Python 3.6+; read-only --check-only and --status never send email.
"""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import smtplib
import ssl
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

CONF = Path("/etc/linuxmailrelay365/sidecar-postfix")
PRIMARY = Path("/etc/postfix")
STATE = Path("/var/lib/linuxmailrelay365-public-smtp")
MANIFEST = STATE / "active.json"
BACKUP = STATE / "main.before"
LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")
EOP_ACTIVE = Path("/var/lib/linuxmailrelay365-eop-route-recovery/active.json")
HEX = re.compile(r"[a-f0-9]{64}\Z")
FQDN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")
PRIVATE = tuple(ipaddress.ip_network(x) for x in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
CHANGES = {
    "smtpd_client_restrictions": "",
    "smtpd_client_connection_count_limit": "10",
    "smtpd_client_connection_rate_limit": "20",
    "smtpd_client_auth_rate_limit": "10",
    "smtpd_client_message_rate_limit": "30",
    "smtpd_client_recipient_rate_limit": "60",
    "smtpd_client_new_tls_session_rate_limit": "20",
    "smtpd_client_event_limit_exceptions": "",
    "smtpd_soft_error_limit": "5",
    "smtpd_hard_error_limit": "10",
    "smtpd_error_sleep_time": "2s"
}


class Refused(Exception):
    pass


def output(key, value):
    print("{}={}".format(key, value))


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def cmd(args, timeout=18):
    if not shutil.which(args[0]):
        raise Refused("missing_" + args[0])
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, universal_newlines=True, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("tool_unavailable_or_timeout")
    if result.returncode:
        raise Refused("command_failed_" + args[0])
    return result.stdout.strip()


def postconf(key):
    return cmd(["postconf", "-c", str(CONF), "-h", key])


def must_regular(path, private=False):
    try:
        meta = path.lstat()
    except OSError:
        raise Refused("required_file_missing")
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or \
            (meta.st_mode & (0o077 if private else 0o022)):
        raise Refused("unsafe_file_owner_or_permissions")
    return meta


def state_dir():
    if STATE.exists() or STATE.is_symlink():
        try:
            meta = STATE.lstat()
        except OSError:
            raise Refused("unsafe_recovery_directory")
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or (meta.st_mode & 0o077):
            raise Refused("unsafe_recovery_directory")
    else:
        STATE.mkdir(parents=True, mode=0o700)
        os.chmod(str(STATE), 0o700)


def atomic(path, content, mode):
    fd, name = tempfile.mkstemp(prefix=".lmr365-public-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, mode)
        os.replace(name, str(path))
    finally:
        if os.path.exists(name):
            os.unlink(name)


def os_approved():
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        raise Refused("os_release_unavailable")
    m = re.search(r"(?m)^ID=['\"]?([a-z0-9_-]+)", text)
    if not m or m.group(1) not in ("ubuntu", "debian", "rhel", "ol", "rocky", "almalinux", "centos"):
        raise Refused("os_family_not_supported")
    kernel = Path("/sys/fs/selinux/enforce")
    if kernel.is_file():
        # SELinux enforcing container policy and socket rights must be verified
        # on a real host; never disable or override SELinux automatically.
        raise Refused("selinux_policy_not_accepted_for_public_mode")
    if m.group(1) in ("rhel", "ol", "rocky", "almalinux", "centos"):
        selinux = cmd(["getenforce"]).lower()
        if selinux != "disabled":
            raise Refused("rhel_selinux_public_mode_unverified")


def primary_sha():
    must_regular(PRIMARY / "main.cf")
    must_regular(PRIMARY / "master.cf")
    return digest((PRIMARY / "main.cf").read_bytes() + b"\0" +
                  (PRIMARY / "master.cf").read_bytes())


def basic_host(port, ip, hostname):
    if os.geteuid() != 0:
        raise Refused("root_required")
    if EOP_ACTIVE.exists() or EOP_ACTIVE.is_symlink():
        raise Refused("eop_route_active_must_restore_before_public_mode")
    os_approved()
    for path in (CONF / "main.cf", CONF / "master.cf", CONF / "smtp-port"):
        must_regular(path)
    if (CONF / "smtp-port").read_text(encoding="ascii").strip() != str(port):
        raise Refused("sidecar_port_mismatch")
    if cmd(["systemctl", "is-active", "linuxmailrelay365-sidecar.service"]) != "active":
        raise Refused("sidecar_service_inactive")
    if cmd(["systemctl", "is-active", "linuxmailrelay365-smtp-auth.service"]) != "active":
        raise Refused("smtp_auth_service_inactive")
    if cmd(["systemctl", "is-active", "linuxmailrelay365-health.timer"]) != "active":
        raise Refused("local_health_timer_required")
    if cmd(["systemctl", "is-active", "fail2ban.service"]) != "active":
        raise Refused("fail2ban_not_active")
    for jail in ("postfix", "dovecot"):
        cmd(["fail2ban-client", "status", jail])
    # Active jails alone do not prove that the isolated instance's journal and
    # auth failures are matched. An explicit ban drill is operator attestation.
    if postconf("default_transport") != "m365xoauth2:" or \
            postconf("relay_transport") != "m365xoauth2:":
        raise Refused("public_mode_requires_isolated_fixed_mailbox_xoauth2")
    for key, value in (
        ("smtpd_sasl_auth_enable", "yes"),
        ("smtpd_tls_security_level", "encrypt"),
        ("smtpd_tls_auth_only", "yes"),
        ("smtpd_sasl_type", "dovecot"),
        ("smtpd_sasl_path", "private/auth"),
        ("smtpd_relay_restrictions", "permit_sasl_authenticated, reject"),
        ("smtpd_recipient_restrictions", "permit_sasl_authenticated, reject"),
        ("inet_protocols", "ipv4")
    ):
        if postconf(key) != value:
            raise Refused("smtp_security_policy_unexpected_" + key)
    if postconf("smtpd_sender_restrictions") or postconf("sender_canonical_maps"):
        raise Refused("nonstandard_sender_policy_manual_review")
    interfaces = postconf("inet_interfaces").replace(",", " ").split()
    if set(interfaces) != {"127.0.0.1", ip}:
        raise Refused("isolated_listener_must_use_exact_private_ip_and_loopback")
    networks = postconf("mynetworks").replace(",", " ").split()
    if not networks:
        raise Refused("empty_mynetworks")
    try:
        for value in networks:
            subnet = ipaddress.ip_network(value, strict=False)
            if not isinstance(subnet, ipaddress.IPv4Network) or not (
                subnet.network_address in ipaddress.ip_network("127.0.0.0/8") and
                subnet.broadcast_address in ipaddress.ip_network("127.0.0.0/8") or
                any(subnet.network_address in network and subnet.broadcast_address in network
                    for network in PRIVATE)):
                raise Refused("unsafe_existing_mynetworks")
    except ValueError:
        raise Refused("invalid_existing_mynetworks")
    if postconf("smtpd_client_restrictions") not in ("permit_mynetworks, reject", ""):
        raise Refused("unexpected_client_restrictions")
    if postconf("smtpd_client_restrictions") == "" and not MANIFEST.exists():
        raise Refused("unmanaged_existing_public_client_access")
    if not FQDN.fullmatch(hostname):
        raise Refused("invalid_tls_dns_name")


def verify_starttls(port, hostname):
    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with smtplib.SMTP("127.0.0.1", port, timeout=9) as smtp:
            smtp.ehlo("lmr365-public-preflight.invalid")
            if not smtp.has_extn("starttls") or smtp.has_extn("auth"):
                raise Refused("smtp_auth_exposed_before_starttls_or_starttls_missing")
            # smtplib uses the connection host for TLS hostname verification.
            # This is a localhost connection, so set the *verified* peer name.
            smtp._host = hostname
            smtp.starttls(context=context)
            smtp.ehlo("lmr365-public-preflight.invalid")
            if not smtp.has_extn("auth"):
                raise Refused("smtp_auth_missing_after_tls")
            code, _ = smtp.mail("probe@invalid.test")
            if code == 250:
                code, _ = smtp.rcpt("probe@invalid.test")
                if code == 250:
                    raise Refused("unauthenticated_relay_accepted")
            if code < 500:
                raise Refused("unauthenticated_relay_not_rejected")
    except (OSError, ssl.SSLError, smtplib.SMTPException):
        raise Refused("starttls_dns_ca_or_auth_relay_probe_failed")


def interface_for(ip):
    raw = cmd(["ip", "-o", "-4", "addr", "show"])
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3].split("/")[0] == ip:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,30}", parts[1]):
                raise Refused("untrusted_interface_name")
            return parts[1]
    raise Refused("requested_ipv4_not_assigned")


def firewall(ip, port):
    iface = interface_for(ip)
    ufw = shutil.which("ufw") and "Status: active" in cmd(["ufw", "status"])
    firewalld = shutil.which("firewall-cmd") and \
        cmd(["firewall-cmd", "--state"]) == "running"
    if bool(ufw) == bool(firewalld):
        raise Refused("single_active_firewall_backend_required")
    if firewalld:
        zone = cmd(["firewall-cmd", "--get-zone-of-interface=" + iface])
        if zone == "no zone":
            zone = cmd(["firewall-cmd", "--get-default-zone"])
        if not re.fullmatch(r"[A-Za-z0-9_+-]{1,32}", zone):
            raise Refused("unverifiable_firewall_zone")
        rule = ('rule family="ipv4" destination address="{}" port port="{}" '
                'protocol="tcp" accept').format(ip, port)
        if not cmd(["firewall-cmd", "--zone=" + zone, "--query-rich-rule=" + rule]):
            pass
        return {"backend": "firewalld", "zone": zone, "rule": rule}
    # For UFW check any existing unrestricted port exposure; refuse changing
    # or taking ownership of an existing rule (the user must review it).
    raw = cmd(["ufw", "status"])
    if re.search(r"(?m)^\s*{}(/tcp)?\s+ALLOW\s+Anywhere\b".format(port), raw):
        raise Refused("preexisting_public_firewall_rule")
    return {"backend": "ufw", "zone": "", "rule": ""}


def firewall_apply(net, ip, port):
    if net["backend"] == "firewalld":
        zone, rule = net["zone"], net["rule"]
        cmd(["firewall-cmd", "--zone=" + zone, "--add-rich-rule=" + rule])
        cmd(["firewall-cmd", "--permanent", "--zone=" + zone, "--add-rich-rule=" + rule])
    else:
        cmd(["ufw", "allow", "in", "proto", "tcp", "from", "any", "to",
             ip, "port", str(port), "comment", "LinuxMailRelay365Public"])


def firewall_remove(net, ip, port):
    if net["backend"] == "firewalld":
        zone, rule = net["zone"], net["rule"]
        cmd(["firewall-cmd", "--zone=" + zone, "--remove-rich-rule=" + rule])
        cmd(["firewall-cmd", "--permanent", "--zone=" + zone, "--remove-rich-rule=" + rule])
    elif net["backend"] == "ufw":
        cmd(["ufw", "--force", "delete", "allow", "in", "proto", "tcp",
             "from", "any", "to", ip, "port", str(port)])
    else:
        raise Refused("invalid_owned_firewall_rule")


def mutate_main(data, changes):
    text = data.decode("utf-8")
    if "\0" in text or "\r" in text:
        raise Refused("unsupported_postfix_config_encoding")
    seen, lines = set(), []
    for line in text.split("\n"):
        m = re.match(r"^([a-z][a-z0-9_]*)\s*=", line)
        if m and m.group(1) in changes:
            if m.group(1) in seen:
                raise Refused("duplicate_postfix_parameter")
            seen.add(m.group(1))
            lines.append("{} = {}".format(m.group(1), changes[m.group(1)]))
        else:
            lines.append(line)
    lines.extend("{} = {}".format(k, v) for k, v in changes.items() if k not in seen)
    return ("\n".join(lines).rstrip("\n") + "\n").encode("utf-8")


def reload_postfix(main):
    atomic(CONF / "main.cf", main, 0o644)
    cmd(["postfix", "-c", str(CONF), "check"])
    cmd(["postfix", "-c", str(CONF), "reload"])
    if cmd(["systemctl", "is-active", "linuxmailrelay365-sidecar.service"]) != "active":
        raise Refused("isolated_postfix_not_active_after_reload")


def read_manifest(port, ip, hostname):
    must_regular(MANIFEST, private=True)
    must_regular(BACKUP, private=True)
    if STATE.is_symlink():
        raise Refused("unsafe_recovery_directory")
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data.get("version") != 1 or data.get("port") != port or \
            data.get("ip") != ip or data.get("hostname") != hostname or \
            data.get("firewall", {}).get("backend") not in ("ufw", "firewalld"):
        raise Refused("invalid_public_exposure_manifest")
    if digest(BACKUP.read_bytes()) != data.get("before"):
        raise Refused("recovery_baseline_hash_mismatch")
    return data


def preflight(args):
    basic_host(args.smtp_port, args.listen_ip, args.server_name)
    if MANIFEST.exists() or MANIFEST.is_symlink():
        raise Refused("public_mode_already_active_use_status")
    if postconf("smtpd_client_restrictions") != "permit_mynetworks, reject":
        raise Refused("unexpected_private_client_access")
    verify_starttls(args.smtp_port, args.server_name)
    net = firewall(args.listen_ip, args.smtp_port)
    before = (CONF / "main.cf").read_bytes()
    output("PUBLIC_SMTP_PREFLIGHT", "ready_with_operator_acceptance_required")
    output("PUBLIC_SMTP_CURRENT_MAIN_SHA256", digest(before))
    output("PUBLIC_SMTP_FIREWALL_BACKEND", net["backend"])
    output("PUBLIC_SMTP_NAT_EXTERNAL_REACHABILITY", "not_verified")
    output("PUBLIC_SMTP_FAIL2BAN_JAIL_EFFECTIVENESS", "manual_attack_simulation_required")
    output("PUBLIC_SMTP_MODE", "authenticated_starttls_only")
    output("CHANGES_APPLIED", "no")
    return 0


def deploy(args):
    before = (CONF / "main.cf").read_bytes()
    if digest(before) != args.expect_main_sha256:
        raise Refused("postfix_changed_since_preview")
    basic_host(args.smtp_port, args.listen_ip, args.server_name)
    if postconf("smtpd_client_restrictions") != "permit_mynetworks, reject":
        raise Refused("nonprivate_baseline_refused")
    verify_starttls(args.smtp_port, args.server_name)
    net = firewall(args.listen_ip, args.smtp_port)
    if MANIFEST.exists() or MANIFEST.is_symlink() or BACKUP.exists() or BACKUP.is_symlink():
        raise Refused("public_exposure_recovery_already_exists")
    main = mutate_main(before, CHANGES)
    original_primary = primary_sha()
    state_dir()
    atomic(BACKUP, before, 0o600)
    edited, firewall_started = False, False
    try:
        edited = True
        reload_postfix(main)
        for key, value in CHANGES.items():
            if postconf(key) != value:
                raise Refused("new_postfix_policy_verification_failed")
        verify_starttls(args.smtp_port, args.server_name)
        firewall_started = True
        firewall_apply(net, args.listen_ip, args.smtp_port)
        if primary_sha() != original_primary:
            raise Refused("primary_postfix_changed")
        data = {
            "version": 1, "port": args.smtp_port, "ip": args.listen_ip,
            "hostname": args.server_name, "before": digest(before),
            "active": digest(main), "primary": original_primary, "firewall": net
        }
        atomic(MANIFEST, (json.dumps(data, sort_keys=True) + "\n").encode("ascii"), 0o600)
    except (Refused, OSError, ValueError):
        if firewall_started:
            try:
                firewall_remove(net, args.listen_ip, args.smtp_port)
            except Refused:
                output("PUBLIC_SMTP_FIREWALL_ROLLBACK", "manual_attention_required")
        if edited:
            try:
                reload_postfix(before)
                output("PUBLIC_SMTP_POSTFIX_ROLLBACK", "previous_private_configuration_restored")
            except Refused:
                output("PUBLIC_SMTP_POSTFIX_ROLLBACK", "manual_recovery_required")
        raise
    output("PUBLIC_SMTP_APPLIED", "authenticated_starttls_only")
    output("PUBLIC_SMTP_CUSTOM_PORT", args.smtp_port)
    output("PUBLIC_SMTP_FIREWALL_RULE", "added_for_all_sources_to_selected_ipv4")
    output("PUBLIC_SMTP_NAT_EXTERNAL_REACHABILITY", "not_verified")
    output("MICROSOFT365_DELIVERY_VERIFIED", "no")
    return 0


def status(args):
    if os.geteuid():
        raise Refused("root_required")
    data = read_manifest(args.smtp_port, args.listen_ip, args.server_name)
    must_regular(CONF / "main.cf")
    current = digest((CONF / "main.cf").read_bytes())
    if current != data["active"]:
        raise Refused("public_exposure_config_changed")
    output("PUBLIC_SMTP_STATUS", "active")
    output("PUBLIC_SMTP_CURRENT_MAIN_SHA256", current)
    output("PUBLIC_SMTP_CUSTOM_PORT", args.smtp_port)
    output("CHANGES_APPLIED", "no")
    return 0


def restore(args):
    data = read_manifest(args.smtp_port, args.listen_ip, args.server_name)
    current = (CONF / "main.cf").read_bytes()
    if digest(current) != data["active"] or digest(current) != args.expect_main_sha256:
        raise Refused("public_postfix_config_modified")
    if primary_sha() != data["primary"]:
        raise Refused("primary_postfix_changed_manual_review_required")
    original = BACKUP.read_bytes()
    # Firewall is closed before Postfix's client restrictions are restored.
    # Never re-open a public firewall rule to recover a failed restoration.
    firewall_remove(data["firewall"], args.listen_ip, args.smtp_port)
    reload_postfix(original)
    if digest((CONF / "main.cf").read_bytes()) != data["before"]:
        raise Refused("restored_postfix_hash_mismatch")
    MANIFEST.unlink()
    output("PUBLIC_SMTP_RESTORED", "private_client_restrictions")
    output("PUBLIC_SMTP_RECOVERY_BACKUP_RETAINED", "yes")
    output("FIREWALL_PUBLIC_RULE_REMOVED", "yes")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    select = parser.add_mutually_exclusive_group(required=True)
    select.add_argument("--check-only", action="store_true")
    select.add_argument("--apply", action="store_true")
    select.add_argument("--status", action="store_true")
    select.add_argument("--restore", action="store_true")
    select.add_argument("--self-test", action="store_true")
    parser.add_argument("--smtp-port", type=int, required=True)
    parser.add_argument("--listen-ip", default="")
    parser.add_argument("--server-name", default="")
    parser.add_argument("--expect-main-sha256", default="")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--risk-attestation", default="")
    args = parser.parse_args()
    if args.self_test:
        output("PUBLIC_SMTP_PARSER", "ready")
        return 0
    if not 1024 <= args.smtp_port <= 65535:
        parser.error("Custom SMTP port must be 1024-65535")
    try:
        ip = ipaddress.IPv4Address(args.listen_ip)
        if not any(ip in p for p in PRIVATE) or str(ip) != args.listen_ip:
            raise ValueError("private_explicit_listener_required")
        if not FQDN.fullmatch(args.server_name):
            raise ValueError("server_dns_name_required")
    except ValueError:
        output("PUBLIC_SMTP_RESULT", "refused")
        output("PUBLIC_SMTP_ERROR", "explicit_private_listener_and_tls_dns_required")
        return 2
    if args.apply or args.restore:
        confirmation = ("ENABLE_REVIEWED_PUBLIC_AUTH_SUBMISSION" if args.apply else
                        "RESTORE_PRIVATE_SMTP_ACCESS")
        if args.confirm != confirmation or not HEX.fullmatch(args.expect_main_sha256):
            output("PUBLIC_SMTP_RESULT", "refused")
            output("PUBLIC_SMTP_ERROR", "reviewed_sha_and_typed_confirmation_required")
            return 2
        if args.apply and args.risk_attestation != "TESTED_BANS_AND_PUBLIC_EXPOSURE":
            output("PUBLIC_SMTP_RESULT", "refused")
            output("PUBLIC_SMTP_ERROR", "operator_security_attestation_required")
            return 2
    try:
        if args.check_only:
            return preflight(args)
        if args.status:
            return status(args)
        if os.geteuid():
            raise Refused("root_required")
        fd = os.open(str(LOCK), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return restore(args) if args.restore else deploy(args)
        finally:
            os.close(fd)
    except (Refused, OSError, ValueError, UnicodeError) as exc:
        output("PUBLIC_SMTP_RESULT", "refused")
        output("PUBLIC_SMTP_ERROR", re.sub(r"[^a-z0-9_]", "_", str(exc).lower())[:90])
        output("CHANGES_APPLIED", "no" if args.check_only or args.status
               else "unknown_inspect_recovery_and_firewall")
        return 2


if __name__ == "__main__":
    sys.exit(main())
