#!/usr/bin/env python3
"""Fail-closed outbound EOP route for an installed isolated Postfix sidecar.
Direct Send blocks external recipients locally. Connector requires explicit
operator attestation, never fabricates Exchange tenant validation.
Original primary Postfix, its queue and port 25 are never modified.
Python 3.6+ / RHEL-compatible. No mail is sent by this program.
"""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

CONF = Path("/etc/linuxmailrelay365/sidecar-postfix")
PRIMARY = Path("/etc/postfix")
RECOVERY = Path("/var/lib/linuxmailrelay365-eop-route-recovery")
ACTIVE = RECOVERY / "active.json"
LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")
MAPS = ("eop-fixed-sender.regexp", "eop-sender-canonical.regexp", "eop-recipients.regexp",
        "eop-sender-owners.regexp")
AUTH_USERS = Path("/etc/linuxmailrelay365/smtp-auth/passwd")
OWNER = re.compile(r"([A-Za-z0-9._+-]+@[A-Za-z0-9.-]+)[ \t]+([A-Za-z0-9][A-Za-z0-9._@-]{2,63})\Z")
DNS = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")
SENDER = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@([A-Za-z0-9.-]+)\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
SAFE = re.compile(r"/[A-Za-z0-9_./-]{1,255}\Z")


class Refused(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def say(key, value):
    print("{}={}".format(key, value))


def run(args):
    try:
        return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=35, universal_newlines=True, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("command_unavailable_or_timeout")


def owned_file(path):
    try:
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid or meta.st_mode & 0o022:
            raise Refused("unsafe_or_nonregular_file")
        return meta
    except OSError:
        raise Refused("required_file_missing")


def owned_dir(path, private=False):
    try:
        meta = path.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid or meta.st_mode & 0o022:
            raise Refused("unsafe_directory")
        if private and meta.st_mode & 0o077:
            raise Refused("backup_directory_not_root_only")
    except OSError:
        raise Refused("required_directory_missing")


def validate(args):
    if not 1024 <= args.smtp_port <= 65535:
        raise Refused("invalid_custom_port")
    if args.sender_policy not in ("fixed-mailbox", "preserve-domain", "masquerade"):
        raise Refused("invalid_sender_policy")
    if args.restore or args.status:
        if getattr(args, "expect_owner_sha256", ""):
            raise Refused("unexpected_owner_fingerprint")
        if any((args.mode, args.mx_host, args.sender, args.recipient_domain,
                args.public_ip, args.tls_cert, args.tls_key,
                getattr(args, "sender_owner_file", ""))) or args.sender_policy != "fixed-mailbox":
            raise Refused("restore_accepts_only_port_and_expected_sha")
    else:
        if args.mode not in ("direct-send", "connector") or \
                not DNS.fullmatch(args.mx_host or "") or \
                not args.mx_host.lower().endswith(".mail.protection.outlook.com"):
            raise Refused("invalid_mode_or_eop_mx_host")
        if not SENDER.fullmatch(args.sender or ""):
            raise Refused("approved_fixed_sender_required")
        if not 1 <= len(args.recipient_domain) <= 8 or \
                any(not DNS.fullmatch(d) for d in args.recipient_domain) or \
                len({d.lower() for d in args.recipient_domain}) != len(args.recipient_domain):
            raise Refused("invalid_accepted_domain_allowlist")
        if args.sender.rsplit("@", 1)[1].lower() not in [d.lower() for d in args.recipient_domain]:
            raise Refused("sender_not_in_accepted_domain")
        if args.mode == "connector" and args.sender_policy != "fixed-mailbox":
            owner_path = getattr(args, "sender_owner_file", "")
            if not owner_path or not SAFE.fullmatch(owner_path) or ".." in owner_path.split("/"):
                raise Refused("connector_sender_ownership_file_required")
            if args.apply and not SHA.fullmatch(getattr(args, "expect_owner_sha256", "")):
                raise Refused("reviewed_sender_owner_sha256_required")
        elif getattr(args, "sender_owner_file", "") or getattr(args, "expect_owner_sha256", ""):
            raise Refused("sender_owners_only_for_connector_preserve_or_masquerade")
        if args.mode == "direct-send" and args.sender_policy != "fixed-mailbox":
            raise Refused("direct_send_requires_fixed_sender")
        if args.mode == "direct-send" and (args.public_ip or args.tls_cert or args.tls_key):
            raise Refused("direct_send_has_no_connector_identity")
        if args.mode == "connector":
            try:
                public = ipaddress.ip_address(args.public_ip) if args.public_ip else None
            except ValueError:
                raise Refused("connector_public_ipv4_invalid")
            if public is not None and (not isinstance(public, ipaddress.IPv4Address) or
                                       not public.is_global):
                raise Refused("connector_public_ipv4_invalid")
            if not args.public_ip and not (args.tls_cert and args.tls_key):
                raise Refused("connector_public_ip_or_certificate_required")
            if bool(args.tls_cert) != bool(args.tls_key):
                raise Refused("connector_certificate_and_key_required")
    for name in (args.tls_cert, args.tls_key):
        if name and (not SAFE.fullmatch(name) or ".." in name.split("/")):
            raise Refused("invalid_linux_certificate_path")
    if args.apply or args.restore:
        if not SHA.fullmatch(args.expect_main_sha256 or ""):
            raise Refused("reviewed_sha256_required")
        confirmation = "DEPLOY_PRIVATE_EOP_ROUTE" if args.apply else "RESTORE_PRIVATE_EOP_ROUTE"
        if args.confirm != confirmation:
            raise Refused("typed_confirmation_required")
    if args.apply and args.mode == "connector" and \
            args.connector_attestation != "TENANT_CONNECTOR_CHECKED":
        raise Refused("operator_must_confirm_existing_tenant_connector")


def fixed_regex(domain):
    return domain.lower().replace(".", "[.]")


def policy_maps(args):
    """Restrict sender domain at SMTP and use Postfix regexp map lookups.

    Connector is the only outbound mode allowed to preserve senders or
    masquerade accepted-domain subdomains. Do not use broad catch-all rules.
    """
    accepted = args.sender.rsplit("@", 1)[1].lower()
    domain = fixed_regex(accepted)
    exact = "/^[^@[:space:]]+@{}$/ OK\n".format(domain)
    if args.sender_policy == "fixed-mailbox":
        # Fixed mailbox: reject every other local-part in the same domain.
        # The colon delimiter cannot appear in the validated mailbox syntax.
        sender = ":^{}$: OK\n".format(re.escape(args.sender.lower()))
        # Postfix regexp-table RHS uses $1/$2 for capture expansion; escape
        # literal dollar signs in a valid mailbox local-part as $$.
        canonical = "/^.+$/ {}\n".format(args.sender.lower().replace("$", "$$"))
    elif args.sender_policy == "preserve-domain":
        sender = exact
        canonical = "# Preserve accepted-domain sender identity\n"
    else:
        subdomain = r"([A-Za-z0-9-]+[.])+{}".format(domain)
        sender = exact + "/^[^@[:space:]]+@{}$/ OK\n".format(subdomain)
        canonical = "/^([^@[:space:]]+)@{}$/ {}@{}\n".format(
            subdomain, chr(36) + "{1}", accepted)
    if args.mode == "direct-send":
        recipients = "".join("/^[^@[:space:]]+@{}$/ OK\n".format(fixed_regex(d))
                             for d in args.recipient_domain)
    else:
        recipients = "/^[^@[:space:]]+@[^@[:space:]]+$/ OK\n"
    return sender, canonical, recipients


def policy_changes(args, ca, auth_enabled):
    mx = args.mx_host.lower()
    rewriting = args.sender_policy != "preserve-domain"
    return {
        "default_transport": "smtp:[{}]:25".format(mx),
        "relay_transport": "smtp:[{}]:25".format(mx),
        "relayhost": "[{}]:25".format(mx),
        "local_transport": "error:LocalDeliveryDisabled",
        "smtpd_relay_restrictions": (
            "permit_sasl_authenticated, reject" if auth_enabled else
            "permit_mynetworks, reject"),
        "smtpd_sender_restrictions": (
            "reject_authenticated_sender_login_mismatch, check_sender_access regexp:{}, reject".format(CONF / MAPS[0])
            if args.mode == "connector" and args.sender_policy != "fixed-mailbox" else
            "check_sender_access regexp:{}, reject".format(CONF / MAPS[0])),
        "smtpd_sender_login_maps": (
            "regexp:{}".format(CONF / MAPS[3])
            if args.mode == "connector" and args.sender_policy != "fixed-mailbox" else ""),
        "smtpd_recipient_restrictions": "check_recipient_access regexp:{}, reject".format(CONF / MAPS[2]),
        "sender_canonical_maps": "regexp:{}".format(CONF / MAPS[1]) if rewriting else "",
        "sender_canonical_classes": "envelope_sender, header_sender" if rewriting else "",
        # Permit header rewrite only for the isolated, access-controlled SMTP
        # listener. Postfix otherwise does not rewrite remote SMTP headers.
        "local_header_rewrite_clients": "static:all" if rewriting else "",
        "smtp_tls_security_level": "secure",
        "smtp_tls_secure_cert_match": "nexthop",
        "smtp_tls_CAfile": ca,
        "smtp_tls_mandatory_protocols": "!SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
        "smtp_tls_cert_file": args.tls_cert if args.mode == "connector" else "",
        "smtp_tls_key_file": args.tls_key if args.mode == "connector" else "",
    }

def sender_owner_map(args):
    """Require explicitly owned MAIL FROM addresses for each authenticated app.

    Source is a root:root 0600 Linux-only file: one 'sender@domain login'
    per line, 1..64 entries. This does not claim to validate RFC5322 From:
    header ownership; a separate reviewed Milter would be required.
    """
    if args.mode != "connector" or args.sender_policy == "fixed-mailbox":
        return "# Fixed approved sender; sender-login ownership map not enabled\n"
    if (postconf("smtpd_sasl_auth_enable") != "yes" or
            postconf("smtpd_tls_security_level") != "encrypt" or
            postconf("smtpd_tls_auth_only") != "yes"):
        raise Refused("connector_sender_ownership_requires_auth_tls")
    if run(["systemctl", "is-active", "--quiet",
            "linuxmailrelay365-smtp-auth.service"]).returncode:
        raise Refused("dedicated_smtp_auth_service_inactive")
    source = Path(args.sender_owner_file)
    st = owned_file(source)
    if st.st_mode & 0o077 or not 1 <= st.st_size <= 16384:
        raise Refused("sender_owner_source_requires_root_only_0600")
    auth_meta = owned_file(AUTH_USERS)
    if auth_meta.st_mode & 0o022 or not 1 <= auth_meta.st_size <= 32768:
        raise Refused("dedicated_smtp_auth_users_unverified")
    try:
        logins = {row.split(":", 1)[0].lower() for row in
                  AUTH_USERS.read_text(encoding="ascii").splitlines()}
        rows = source.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        raise Refused("sender_owner_source_unreadable")
    if not 1 <= len(rows) <= 64 or len(logins) > 64:
        raise Refused("sender_owner_record_count_invalid")
    domain = args.sender.rsplit("@", 1)[1].lower()
    seen, rules = set(), []
    for row in rows:
        match = OWNER.fullmatch(row)
        if not match:
            raise Refused("invalid_sender_owner_record")
        sender, login = match.group(1).lower(), match.group(2)
        owner_domain = sender.rsplit("@", 1)[1]
        if not DNS.fullmatch(owner_domain) or not (
            owner_domain == domain or
            (args.sender_policy == "masquerade" and owner_domain.endswith("." + domain))
        ):
            raise Refused("sender_owner_outside_accepted_domain")
        if login.lower() not in logins:
            raise Refused("sender_owner_not_active_smtp_account")
        if sender in seen:
            raise Refused("duplicate_sender_owner")
        seen.add(sender)
        # Explicitly literal, case-insensitive Postfix regexp maps. The owner
        # login is emitted as data and never interpreted as a command.
        escaped = sender.replace(".", "[.]").replace("+", "[+]")
        rules.append("/^{}$/ {}\n".format(escaped, login))
    return "".join(rules)


def rewrite_main(data, changes):
    text = data.decode("utf-8")
    if "\r" in text or "\x00" in text:
        raise Refused("unsupported_main_encoding")
    output, found = [], set()
    for line in text.splitlines():
        m = re.match(r"^([a-z][a-z0-9_]*)\s*=", line)
        if m and m.group(1) in changes:
            if m.group(1) in found:
                raise Refused("duplicate_configuration_key")
            output.append("{} = {}".format(m.group(1), changes[m.group(1)]))
            found.add(m.group(1))
        else:
            output.append(line)
    output.extend("{} = {}".format(key, value) for key, value in changes.items() if key not in found)
    return ("\n".join(output) + "\n").encode("utf-8")


def rewrite_master(data):
    original = data.decode("utf-8")
    if "\r" in original or "\x00" in original or re.search(r"(?m)^smtp\s+unix\b", original):
        raise Refused("unexpected_existing_smtp_transport")
    return (original.rstrip("\n") + "\nsmtp unix - - n - 5 smtp\n").encode("utf-8")


def local_policy(port):
    owned_dir(CONF)
    owned_dir(PRIMARY)
    for item in (CONF / "main.cf", CONF / "master.cf", CONF / "smtp-port",
                 PRIMARY / "main.cf", PRIMARY / "master.cf"):
        owned_file(item)
    if (CONF / "smtp-port").read_text(encoding="ascii").strip() != str(port):
        raise Refused("installed_custom_port_mismatch")
    main = (CONF / "main.cf").read_bytes()
    master = (CONF / "master.cf").read_bytes()
    if len(main) > 2 * 1024 * 1024 or len(master) > 2 * 1024 * 1024:
        raise Refused("configuration_too_large")
    if not re.search(rb"(?m)^default_transport\s*=\s*m365xoauth2:\s*$", main) or \
            not re.search(rb"(?m)^relay_transport\s*=\s*m365xoauth2:\s*$", main):
        raise Refused("only_unmodified_xoauth2_outbound_supported")
    if not re.search(rb"(?m)^m365xoauth2\s+unix\b", master) or \
            not re.search((r"(?m)^{}\s+inet\s".format(port)).encode("ascii"), master):
        raise Refused("original_sidecar_service_definition_missing")
    return main, master


def postconf(key):
    result = run(["postconf", "-c", str(CONF), "-h", key])
    if result.returncode:
        raise Refused("postfix_query_failed")
    return result.stdout.strip()


def require_empty_sidecar_queue():
    # No message addresses, queue IDs or content are printed. Read only the
    # first JSON line; refuse changing transport while messages are queued.
    import select
    if not shutil.which("postqueue"):
        raise Refused("postqueue_missing")
    try:
        proc = subprocess.Popen(["postqueue", "-c", str(CONF), "-j"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                universal_newlines=True)
    except OSError:
        raise Refused("isolated_queue_probe_unavailable")
    try:
        readable, _, _ = select.select([proc.stdout], [], [], 12)
        if not readable:
            raise Refused("isolated_queue_probe_timeout")
        if proc.stdout.readline().strip():
            raise Refused("sidecar_queue_not_empty_drain_before_reroute")
        if proc.wait(timeout=8):
            raise Refused("isolated_queue_probe_failed")
    except subprocess.TimeoutExpired:
        raise Refused("isolated_queue_probe_timeout")
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def runtime_checks(allow_active_route=False):
    if os.geteuid():
        raise Refused("root_required")
    public_active = Path("/var/lib/linuxmailrelay365-public-smtp/active.json")
    if public_active.exists() or public_active.is_symlink():
        raise Refused("restore_public_smtp_before_eop_reroute")
    for tool in ("postfix", "postconf", "systemctl"):
        if not shutil.which(tool):
            raise Refused("missing_{}".format(tool))
    osid = ""
    try:
        release = Path("/etc/os-release").read_text(encoding="utf-8")
        match = re.search(r'(?m)^ID=["\']?([a-z0-9_-]+)["\']?\s*$', release)
        osid = match.group(1) if match else ""
    except OSError:
        pass
    selinux = run(["getenforce"]).stdout.strip() if shutil.which("getenforce") else "unknown"
    kernel = Path("/sys/fs/selinux/enforce")
    if kernel.is_file():
        selinux = "Enforcing" if kernel.read_text().strip() == "1" else "Permissive"
    if selinux == "Enforcing" or (osid in ("rhel", "ol", "rocky", "almalinux", "centos") and selinux != "Disabled"):
        raise Refused("selinux_enforcing_or_unverified_blocked")
    if run(["systemctl", "is-active", "--quiet",
            "linuxmailrelay365-sidecar.service"]).returncode:
        raise Refused("isolated_postfix_service_inactive")
    interfaces = postconf("inet_interfaces").replace(",", " ").split()
    trusted = postconf("mynetworks").replace(",", " ").split()
    private = tuple(ipaddress.ip_network(x) for x in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if "127.0.0.1" not in interfaces:
        raise Refused("loopback_interface_missing")
    try:
        if any(not (ipaddress.ip_address(x).is_loopback or
                    any(ipaddress.ip_address(x) in v for v in private)) for x in interfaces):
            raise Refused("public_listener_blocked")
        for item in trusted:
            net = ipaddress.ip_network(item, strict=False)
            if not isinstance(net, ipaddress.IPv4Network) or not (
                    net.network_address in ipaddress.ip_network("127.0.0.0/8") and
                    net.broadcast_address in ipaddress.ip_network("127.0.0.0/8") or
                    any(net.network_address in v and net.broadcast_address in v for v in private)):
                raise Refused("untrusted_client_network_blocked")
    except ValueError:
        raise Refused("invalid_private_cidr")
    if postconf("smtpd_client_restrictions") != "permit_mynetworks, reject":
        raise Refused("unexpected_client_access_control")
    sasl = postconf("smtpd_sasl_auth_enable")
    if sasl == "yes":
        if (postconf("smtpd_relay_restrictions") != "permit_sasl_authenticated, reject" or
                postconf("smtpd_tls_security_level") != "encrypt"):
            raise Refused("unexpected_sasl_tls_policy")
    elif sasl == "no":
        allowed = ("permit_mynetworks, reject_unauth_destination",
                   "permit_mynetworks, reject") if allow_active_route else (
                   "permit_mynetworks, reject_unauth_destination",)
        if postconf("smtpd_relay_restrictions") not in allowed:
            raise Refused("unexpected_trusted_network_policy")
    else:
        raise Refused("unknown_sasl_policy")
    if not allow_active_route:
        # Only the original generated sidecar is eligible for transition.
        original_rcpt = postconf("smtpd_recipient_restrictions")
        if original_rcpt not in ("permit_mynetworks, reject_unauth_destination",
                                 "permit_sasl_authenticated, reject"):
            raise Refused("unexpected_original_recipient_policy")
        for key in ("sender_canonical_maps", "recipient_canonical_maps",
                    "transport_maps", "smtp_tls_policy_maps", "relayhost",
                    "smtpd_sender_login_maps",
                    "smtpd_sender_restrictions"):
            if postconf(key):
                raise Refused("existing_routing_override_requires_manual_review")
    else:
        expected = "check_recipient_access regexp:{}, reject".format(CONF / MAPS[2])
        if postconf("smtpd_recipient_restrictions") != expected:
            raise Refused("active_eop_recipient_policy_modified")
    if "regexp" not in run(["postconf", "-m"]).stdout.splitlines():
        raise Refused("regexp_dictionary_not_available")
    require_empty_sidecar_queue()


def system_ca():
    for location in ("/etc/ssl/certs/ca-certificates.crt",
                     "/etc/pki/tls/certs/ca-bundle.crt",
                     "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"):
        p = Path(location)
        if not p.is_file():
            continue
        # RHEL's documented CA bundle is commonly a root-owned symlink.
        # Resolve it only inside known system-trust directories.
        try:
            target = p.resolve(strict=True)
            path = str(target)
            trusted_root = (path.startswith("/etc/ssl/certs/") or
                            path.startswith("/etc/pki/ca-trust/extracted/"))
            info = target.stat()
            if trusted_root and stat.S_ISREG(info.st_mode) and not info.st_uid and \
                    not info.st_mode & 0o022 and 0 < info.st_size <= 32 * 1024 * 1024:
                return location
        except OSError:
            pass
    raise Refused("system_ca_bundle_not_found")


def check_connector_cert(args):
    if not args.tls_key:
        return
    for name in (args.tls_cert, args.tls_key):
        meta = owned_file(Path(name))
        if not 0 < meta.st_size <= 16 * 1024 * 1024:
            raise Refused("connector_certificate_size_invalid")
    import grp
    key = Path(args.tls_key).stat()
    postfix_gid = grp.getgrnam("postfix").gr_gid
    if key.st_mode & 0o007 or key.st_gid != postfix_gid or not key.st_mode & 0o040:
        raise Refused("connector_private_key_not_readable_by_postfix_only")
    certificate = run(["openssl", "x509", "-in", args.tls_cert,
                       "-noout", "-checkend", "604800"])
    san = run(["openssl", "x509", "-in", args.tls_cert, "-noout",
               "-ext", "subjectAltName"])
    if certificate.returncode or san.returncode:
        raise Refused("connector_certificate_invalid_or_expiring")
    names = re.findall(r"DNS:([A-Za-z0-9.-]+)", san.stdout)
    if args.sender.rsplit("@", 1)[1].lower() not in [v.lower() for v in names]:
        raise Refused("connector_certificate_accepted_domain_missing")
    pub = run(["openssl", "x509", "-in", args.tls_cert, "-pubkey", "-noout"])
    key = run(["openssl", "pkey", "-in", args.tls_key, "-pubout"])
    if pub.returncode or key.returncode or not pub.stdout or pub.stdout != key.stdout:
        raise Refused("connector_certificate_key_mismatch")


def primary_digest():
    return digest((PRIMARY / "main.cf").read_bytes() + b"\0" +
                  (PRIMARY / "master.cf").read_bytes())


def write_atomic(path, data, mode=0o644):
    owned_dir(path.parent)
    fd, temp = tempfile.mkstemp(prefix=".lmr365.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp, mode)
        os.replace(temp, str(path))
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def post_reload(main, master, rules=None):
    # Prepare policy maps first. Main/master are installed only after
    # rule files exist; each file update is atomic.
    if rules is not None:
        for name, data in zip(MAPS, rules):
            write_atomic(CONF / name, data.encode("ascii"))
    write_atomic(CONF / "master.cf", master)
    write_atomic(CONF / "main.cf", main)
    if run(["postfix", "-c", str(CONF), "check"]).returncode or \
            run(["postfix", "-c", str(CONF), "reload"]).returncode:
        raise Refused("isolated_postfix_check_or_reload_failed")
    if run(["systemctl", "is-active", "--quiet",
            "linuxmailrelay365-sidecar.service"]).returncode:
        raise Refused("isolated_postfix_not_active_after_reload")


def backup(before, master):
    if RECOVERY.exists() or RECOVERY.is_symlink():
        owned_dir(RECOVERY, private=True)
    else:
        RECOVERY.mkdir(mode=0o700, parents=True)
    if ACTIVE.exists() or ACTIVE.is_symlink():
        raise Refused("existing_eop_route_must_be_restored")
    base = Path(tempfile.mkdtemp(prefix="recovery.", dir=str(RECOVERY)))
    os.chmod(str(base), 0o700)
    write_atomic(base / "main.before", before, 0o600)
    write_atomic(base / "master.before", master, 0o600)
    if digest((base / "main.before").read_bytes()) != digest(before) or \
            digest((base / "master.before").read_bytes()) != digest(master):
        raise Refused("recovery_archive_copy_mismatch")
    return base


def deploy(args):
    if ACTIVE.exists() or ACTIVE.is_symlink():
        raise Refused("outbound_route_already_active")
    before, master = local_policy(args.smtp_port)
    if digest(before) != args.expect_main_sha256:
        raise Refused("main_configuration_changed_since_preview")
    require_empty_sidecar_queue()
    if any((CONF / m).exists() or (CONF / m).is_symlink() for m in MAPS):
        raise Refused("existing_eop_policy_map_conflict")
    if args.sender_policy != "fixed-mailbox" and \
            digest(Path(args.sender_owner_file).read_bytes()) != args.expect_owner_sha256:
        raise Refused("sender_owners_changed_since_preview")
    ca = system_ca()
    auth_enabled = postconf("smtpd_sasl_auth_enable") == "yes"
    main = rewrite_main(before, policy_changes(args, ca, auth_enabled))
    newmaster = rewrite_master(master)
    archive = backup(before, master)
    previous_primary = primary_digest()
    changed = False
    try:
        changed = True
        post_reload(main, newmaster, policy_maps(args) + (sender_owner_map(args),))
        if digest((CONF / "main.cf").read_bytes()) != digest(main) or \
                digest((CONF / "master.cf").read_bytes()) != digest(newmaster):
            raise Refused("post_reload_fingerprint_mismatch")
        if primary_digest() != previous_primary:
            raise Refused("primary_postfix_changed_during_deploy")
        metadata = {
            "version": 1, "port": args.smtp_port,
            "mode": args.mode, "sender_policy": args.sender_policy,
            "archive": archive.name,
            "before_main": digest(before), "before_master": digest(master),
            "active_main": digest(main), "active_master": digest(newmaster),
        }
        write_atomic(ACTIVE, (json.dumps(metadata, sort_keys=True) + "\n").encode("ascii"), 0o600)
    except (OSError, Refused):
        if changed:
            try:
                post_reload(before, master)
                for item in MAPS:
                    path = CONF / item
                    if path.is_file() and not path.is_symlink():
                        path.unlink()
                say("EOP_ROUTE_ROLLBACK", "previous_config_restored")
            except (OSError, Refused):
                say("EOP_ROUTE_ROLLBACK", "manual_recovery_required")
        raise
    say("EOP_ROUTE_APPLIED", "yes")
    say("EOP_ROUTE_MODE", args.mode.replace("-", "_"))
    say("EOP_ROUTE_SENDER_POLICY", args.sender_policy.replace("-", "_"))
    say("EOP_ROUTE_SENDER_OWNERSHIP", "auth_mail_from_login_map" if args.sender_policy != "fixed-mailbox" else "fixed_sender")
    say("EOP_ROUTE_HEADER_FROM_MATCH_VERIFIED", "no")
    say("EOP_ROUTE_CUSTOM_PORT", args.smtp_port)
    say("EOP_ROUTE_OUTBOUND_PORT", 25)
    say("EOP_ROUTE_RECIPIENT_SCOPE", "internal_only" if args.mode == "direct-send" else "connector_authorized")
    say("EXCHANGE_CONNECTOR_VERIFIED", "operator_attestation_only" if args.mode == "connector" else "not_applicable")
    say("MICROSOFT365_DELIVERY_VERIFIED", "no")
    say("PRIMARY_POSTFIX_CONFIG_UNCHANGED", "yes")
    return 0


def route_status(args):
    # Returns no address/recipient content, only aggregate state and SHA.
    if os.geteuid() != 0:
        raise Refused("root_required")
    local_policy_port = CONF / "smtp-port"
    owned_file(local_policy_port)
    if local_policy_port.read_text(encoding="ascii").strip() != str(args.smtp_port):
        raise Refused("installed_custom_port_mismatch")
    if not ACTIVE.exists() and not ACTIVE.is_symlink():
        say("EOP_ROUTE_STATUS", "not_installed")
        say("CHANGES_APPLIED", "no")
        return 0
    owned_file(ACTIVE)
    owned_dir(RECOVERY, private=True)
    data = json.loads(ACTIVE.read_text(encoding="ascii"))
    if data.get("version") != 1 or data.get("port") != args.smtp_port or \
            data.get("mode") not in ("direct-send", "connector"):
        raise Refused("active_route_manifest_invalid")
    main = CONF / "main.cf"
    master = CONF / "master.cf"
    owned_file(main)
    owned_file(master)
    msha = digest(main.read_bytes())
    if msha != data.get("active_main") or \
            digest(master.read_bytes()) != data.get("active_master"):
        raise Refused("active_route_configuration_changed_since_deploy")
    say("EOP_ROUTE_STATUS", "active")
    say("EOP_ROUTE_CURRENT_MAIN_SHA256", msha)
    say("EOP_ROUTE_MODE", data["mode"].replace("-", "_"))
    say("EOP_ROUTE_SENDER_POLICY", data.get("sender_policy", "fixed-mailbox").replace("-", "_"))
    say("EOP_ROUTE_CUSTOM_PORT", args.smtp_port)
    say("CHANGES_APPLIED", "no")
    return 0


def rollback_route(args):
    owned_file(ACTIVE)
    owned_dir(RECOVERY, private=True)
    meta = json.loads(ACTIVE.read_text(encoding="ascii"))
    if meta.get("version") != 1 or meta.get("port") != args.smtp_port or \
            not re.fullmatch(r"recovery\.[A-Za-z0-9_]{8}", meta.get("archive", "")):
        raise Refused("invalid_active_route_manifest")
    directory = RECOVERY / meta["archive"]
    owned_dir(directory, private=True)
    for name in ("main.before", "master.before"):
        owned_file(directory / name)
    before = (directory / "main.before").read_bytes()
    original_master = (directory / "master.before").read_bytes()
    if digest(before) != meta.get("before_main") or \
            digest(original_master) != meta.get("before_master"):
        raise Refused("tampered_original_archive")
    current = (CONF / "main.cf").read_bytes()
    master = (CONF / "master.cf").read_bytes()
    if digest(current) != args.expect_main_sha256 or \
            digest(current) != meta.get("active_main") or \
            digest(master) != meta.get("active_master"):
        raise Refused("active_route_configuration_modified_since_deploy")
    require_empty_sidecar_queue()
    before_primary = primary_digest()
    try:
        post_reload(before, original_master)
        if primary_digest() != before_primary:
            raise Refused("primary_postfix_changed_during_restore")
        ACTIVE.unlink()
        for name in MAPS:
            path = CONF / name
            if path.is_file() and not path.is_symlink():
                path.unlink()
    except (OSError, Refused):
        try:
            post_reload(current, master)
            say("EOP_ROUTE_RESTORE_ROLLBACK", "eop_route_reinstated")
        except (OSError, Refused):
            say("EOP_ROUTE_RESTORE_ROLLBACK", "manual_recovery_required")
        raise
    say("EOP_ROUTE_RESTORED", "yes")
    say("EOP_ROUTE_BACKUP_RETAINED", "yes")
    say("PRIMARY_POSTFIX_CONFIG_UNCHANGED", "yes")
    say("MICROSOFT365_DELIVERY_VERIFIED", "no")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    exclusive = p.add_mutually_exclusive_group(required=True)
    exclusive.add_argument("--check-only", action="store_true")
    exclusive.add_argument("--apply", action="store_true")
    exclusive.add_argument("--restore", action="store_true")
    exclusive.add_argument("--status", action="store_true")
    p.add_argument("--smtp-port", type=int, required=True)
    p.add_argument("--mode", choices=("direct-send", "connector"))
    p.add_argument("--mx-host", default="")
    p.add_argument("--sender", default="")
    p.add_argument("--sender-policy", choices=("fixed-mailbox", "preserve-domain", "masquerade"),
                   default="fixed-mailbox")
    p.add_argument("--sender-owner-file", default="")
    p.add_argument("--expect-owner-sha256", default="")
    p.add_argument("--recipient-domain", action="append", default=[])
    p.add_argument("--public-ip", default="")
    p.add_argument("--tls-cert", default="")
    p.add_argument("--tls-key", default="")
    p.add_argument("--expect-main-sha256", default="")
    p.add_argument("--confirm", default="")
    p.add_argument("--connector-attestation", default="")
    a = p.parse_args()
    try:
        validate(a)
        if a.status:
            return route_status(a)
        runtime_checks(allow_active_route=a.restore)
        # Preflight is read-only; the apply/restore operations take the
        # same exclusive lock used by private SMTP AUTH and certificate changes.
        if a.check_only:
            before, _ = local_policy(a.smtp_port)
            if ACTIVE.exists() or ACTIVE.is_symlink():
                raise Refused("eop_route_already_active")
            if a.mode == "connector":
                check_connector_cert(a)
            sender_owner_map(a)
            system_ca()
            say("EOP_ROUTE_PREFLIGHT", "ready")
            say("EOP_ROUTE_MAIN_SHA256", digest(before))
            say("EOP_ROUTE_MODE", a.mode.replace("-", "_"))
            say("EOP_ROUTE_CUSTOM_PORT", a.smtp_port)
            say("EOP_ROUTE_OUTBOUND_PORT", 25)
            say("EOP_ROUTE_RECIPIENT_SCOPE", "internal_only" if a.mode == "direct-send" else "connector_candidate")
            say("EOP_ROUTE_SENDER_POLICY", a.sender_policy.replace("-", "_"))
            say("EOP_ROUTE_SENDER_OWNERSHIP", "auth_mail_from_login_map" if a.sender_policy != "fixed-mailbox" else "fixed_sender")
            if a.sender_policy != "fixed-mailbox":
                say("EOP_ROUTE_OWNER_FILE_SHA256", digest(Path(a.sender_owner_file).read_bytes()))
            say("EOP_ROUTE_HEADER_FROM_MATCH_VERIFIED", "no")
            say("EOP_ROUTE_FIXED_SENDER", "yes" if a.sender_policy == "fixed-mailbox" else "no")
            say("EXCHANGE_CONNECTOR_VERIFIED", "no")
            say("MICROSOFT365_DELIVERY_VERIFIED", "no")
            say("CHANGES_APPLIED", "no")
            return 0
        fd = os.open(str(LOCK), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if a.restore:
                return rollback_route(a)
            before, _ = local_policy(a.smtp_port)
            if ACTIVE.exists() or ACTIVE.is_symlink():
                raise Refused("eop_route_already_active")
            if a.mode == "connector":
                check_connector_cert(a)
            sender_owner_map(a)
            system_ca()
            return deploy(a)
        finally:
            os.close(fd)
    except (Refused, OSError, UnicodeError, ValueError) as err:
        say("EOP_ROUTE_RESULT", "refused")
        say("EOP_ROUTE_ERROR", re.sub(r"[^a-z0-9_]", "_", str(err).lower())[:85])
        say("CHANGES_APPLIED", "no" if a.check_only or a.status else "unknown_inspect_recovery")
        return 2


if __name__ == "__main__":
    sys.exit(main())
