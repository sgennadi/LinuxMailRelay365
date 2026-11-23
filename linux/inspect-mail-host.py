#!/usr/bin/env python3
"""Read-only Linux hostname/domain and Postfix, Exim, Sendmail settings summary.

Does not mutate configuration, open SMTP sessions, or reveal raw config files.
OS hostname/domain are NOT proof of Microsoft 365 accepted-domain ownership.
Python 3.6+ (supports RHEL-family 8-10).
"""
import argparse
import os
import stat
import pathlib
import re
import ipaddress
import shutil
import subprocess

HOST = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
SHORT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
VALUE = re.compile(r"^[A-Za-z0-9_.$/,: @{}\[\]+-]{0,200}$")
POSTFIX = ("myhostname", "mydomain", "myorigin", "mydestination",
           "inet_interfaces", "inet_protocols")
# Report only presence of advanced delivery/routing settings, NEVER values.
# Source maps may contain sensitive addresses, LDAP URLs or even credentials.
POSTFIX_ROLE_KEYS = (
    "virtual_mailbox_domains", "virtual_alias_domains", "relay_domains",
    "virtual_mailbox_maps", "virtual_alias_maps", "transport_maps",
    "sender_dependent_relayhost_maps", "sender_canonical_maps",
    "smtp_generic_maps", "masquerade_domains", "local_transport",
    "relayhost", "sender_dependent_default_transport_maps",
    "smtp_sasl_password_maps", "smtp_sender_dependent_authentication",
    "smtp_sasl_auth_enable", "smtp_tls_policy_maps",
)



def call(argv):
    if not shutil.which(argv[0]):
        return None
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, check=False, timeout=6)
        # systemctl returns 3 for an inactive service and 4 for an
        # unknown unit. Those are valid *read-only evidence*, unlike a
        # failed postconf/exim query which must remain unavailable.
        inactive_unit = (argv[:2] == ["systemctl", "is-active"] and
                         p.returncode in (3, 4) and
                         p.stdout.strip() in ("inactive", "failed", "unknown", "dead"))
        output_cap = 65536 if argv == ["postconf", "-M"] else 4096
        if (p.returncode == 0 or inactive_unit) and len(p.stdout) <= output_cap:
            return p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        pass
    return None


def safe(value):
    if value is None:
        return "unavailable"
    value = value.strip()
    return value if value and len(value) <= 200 and VALUE.fullmatch(value) else "unavailable"


def host(value, fqdn=True):
    value = (value or "").strip().rstrip(".").lower()
    if len(value) > 253 or not (HOST if fqdn else SHORT).fullmatch(value):
        return "unavailable"
    if value in ("localhost", "localhost.localdomain") or value.endswith(".localhost"):
        return "unavailable"
    return value


def identity(runner=call):
    fqdn = host(runner(["hostname", "-f"]))
    short = host(runner(["hostname", "-s"]), False)
    domain = host(runner(["hostname", "-d"]))
    if fqdn != "unavailable":
        if short == "unavailable":
            short = fqdn.split(".")[0]
        if domain == "unavailable":
            domain = fqdn.partition(".")[2]
    elif short != "unavailable" and domain != "unavailable":
        fqdn = host(short + "." + domain)
    return short, fqdn, domain


def service_state(unit, runner=call):
    status = runner(["systemctl", "is-active", unit])
    if status == "active":
        return True
    if status == "failed":
        # A failed primary MTA is not equivalent to a clean unused host.
        return None
    if status in ("inactive", "unknown", "dead"):
        return False
    return None


def mta_status(runner=call):
    # Multiple active MTAs or unknown service status require manual review.
    groups = {
        "postfix": ("postfix.service", "postfix@-.service"),
        "exim": ("exim.service", "exim4.service"),
        "sendmail": ("sendmail.service",),
    }
    current = {}
    for mta, units in groups.items():
        states = [service_state(unit, runner) for unit in units]
        current[mta] = True if True in states else (
            None if any(value is None for value in states) else False)
    active = [name for name, status in current.items() if status]
    if len(active) > 1 or any(s is None for s in current.values()):
        return "unknown", "manual_review"
    if active:
        return active[0], "active"
    if runner(["postconf", "-h", "myhostname"]) is not None:
        return "postfix", "installed_inactive"
    if pathlib.Path("/etc/mail/sendmail.cf").is_file():
        return "sendmail", "installed_inactive"
    if shutil.which("exim") or shutil.which("exim4"):
        return "exim", "installed_inactive"
    return "none", "not_detected"


def exim_setting(tool, key, runner=call):
    value = runner([tool, "-bP", key])
    if value is None:
        return "unavailable"
    match = re.fullmatch(r"\s*" + re.escape(key) + r"\s*=\s*(.*?)\s*", value)
    return safe(match.group(1)) if match else "unavailable"


def limited_config_text(path, limit=2 * 1024 * 1024):
    """Bounded race-resistant, no-follow read of Sendmail/Exim config."""
    fd = None
    try:
        before = os.lstat(str(path))
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= limit:
            return None
        fd = os.open(str(path), os.O_RDONLY |
                     getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0))
        after = os.fstat(fd)
        if (not stat.S_ISREG(after.st_mode) or
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns) !=
                (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns)):
            return None
        remaining = after.st_size
        pieces = []
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                return None
            pieces.append(part)
            remaining -= len(part)
        # Catch appends after the recorded file size without reading them.
        if os.read(fd, 1):
            return None
        checked = os.fstat(fd)
        if (checked.st_dev, checked.st_ino, checked.st_size,
            checked.st_mtime_ns, checked.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns):
            return None
        raw = b"".join(pieces)
        return raw.decode("utf-8") if b"\x00" not in raw else None
    except (OSError, UnicodeError, ValueError):
        return None
    finally:
        if fd is not None:
            os.close(fd)


def exim_ports(tool, runner=call):
    """Parse ONLY literal -bP ports. Expanded/macros remain unverified."""
    raw = exim_setting(tool, "daemon_smtp_ports", runner)
    if raw == "unavailable":
        return "unverified"
    services = {"smtp": 25, "submission": 587, "smtps": 465, "submissions": 465}
    tokens = [item for item in re.split(r"[\s,:]+", raw.lower()) if item]
    if not tokens or len(tokens) > 16:
        return "unverified"
    numbers = []
    for item in tokens:
        if item in services:
            value = services[item]
        elif re.fullmatch(r"[0-9]{1,5}", item):
            value = int(item)
        else:
            return "dynamic_or_unverified"
        if value < 1 or value > 65535:
            return "dynamic_or_unverified"
        numbers.append(value)
    return ",".join(str(n) for n in sorted(set(numbers)))



# Explicit service names map to TCP ports. Never infer ports from non-literal
# macros or from an unrelated process listening on a socket.
SMTP_SERVICE_PORTS = {"smtp": 25, "submission": 587, "submissions": 465,
                      "smtps": 465}


def literal_smtp_port(name):
    name = name.strip().lower()
    if name in SMTP_SERVICE_PORTS:
        return SMTP_SERVICE_PORTS[name]
    if re.fullmatch(r"[0-9]{1,5}", name):
        number = int(name)
        return number if 1 <= number <= 65535 else None
    return None


def format_configured_ports(ports):
    if len(ports) > 16:
        return "dynamic_or_unverified"
    return ",".join(str(n) for n in sorted(set(ports))) if ports else "none_configured"


def postfix_ports(runner=call):
    """Read effective active master.cf inet services via postconf -M.

    smtp/unix is an outbound transport, NOT a listening TCP/25 service.
    An unknown service name means the complete port set is unverified.
    """
    raw = runner(["postconf", "-M"])
    if not isinstance(raw, str) or not raw or len(raw) > 65536:
        return "unverified"
    found = []
    for line in raw.splitlines():
        row = line.strip()
        if not row or row.startswith("#") or (line[:1].isspace() and row.startswith("-o ")):
            continue
        fields = row.split()
        if len(fields) < 2:
            return "dynamic_or_unverified"
        if fields[1] not in ("inet", "unix", "fifo", "pass", "unix-dgram"):
            return "dynamic_or_unverified"
        if fields[1] != "inet":
            continue
        service = fields[0]
        if "=" in service:
            left, right = service.split("=", 1)
            if left != right + "/inet":
                return "dynamic_or_unverified"
            service = right
        # Postfix supports optional IP/hostname:port service names.
        if ":" in service:
            service = service.rsplit(":", 1)[-1]
        port = literal_smtp_port(service)
        if port is None:
            return "dynamic_or_unverified"
        found.append(port)
    return format_configured_ports(found)


def sendmail_cf_ports(path):
    """Use only the compiled .cf DaemonPortOptions, NOT a possibly stale .mc.

    An omitted Port in a declared daemon uses Sendmail's documented smtp
    default (TCP 25). Missing/unreadable compiled config stays UNKNOWN.
    """
    text = limited_config_text(path)
    if text is None:
        return "unverified"
    declarations = [line for line in text.splitlines()
                    if re.match(r"^O\s+DaemonPortOptions\s*=", line)]
    if not declarations:
        return "unverified"
    found = []
    for line in declarations:
        raw = line.split("=", 1)[1]
        options = {}
        for item in raw.split(","):
            match = re.fullmatch(r"\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(\S.*?)\s*", item)
            if not match:
                return "dynamic_or_unverified"
            key = match.group(1).lower()
            if key in options:
                return "dynamic_or_unverified"
            options[key] = match.group(2)
        port = literal_smtp_port(options.get("port", "smtp"))
        if port is None:
            return "dynamic_or_unverified"
        found.append(port)
    return format_configured_ports(found)

def exim_security_declarations(tool, runner=call):
    """Only MAIN option declarations; never live SMTP AUTH or TLS proof."""
    def option(key):
        raw = runner([tool, "-bP", key])
        if raw is None or not isinstance(raw, str):
            return None
        match = re.fullmatch(r"\s*" + re.escape(key) +
                             r"\s*=\s*(.*?)\s*", raw, flags=re.DOTALL)
        if not match or len(match.group(1)) > 1024:
            return None
        value = match.group(1).strip()
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            return None
        return value

    advertised = option("tls_advertise_hosts")
    cert = option("tls_certificate")
    key = option("tls_privatekey")
    auth_hosts = option("auth_advertise_hosts")
    if None in (advertised, cert, key):
        tls = "unverified"
    elif any("$" in v or "\\" in v for v in (advertised, cert, key)):
        tls = "dynamic_or_unverified"
    elif not advertised:
        tls = "starttls_not_declared"
    elif cert and key:
        tls = "starttls_cert_key_declared_unverified"
    else:
        tls = "partial_tls_declaration"
    if auth_hosts is None:
        auth = "unverified"
    elif "$" in auth_hosts or "\\" in auth_hosts:
        auth = "dynamic_or_unverified"
    elif not auth_hosts:
        auth = "auth_not_advertised"
    else:
        auth = "auth_hosts_declared_backend_unverified"
    return tls, auth


def exim_bind_policy(raw):
    """Configured interfaces only; NOT a live socket or a firewall check."""
    if raw == "unavailable" or not raw.strip():
        return "unverified"
    tokens = [part for part in re.split(r"\s+:\s+|[,\s]+", raw) if part]
    if not tokens or len(tokens) > 16:
        return "unverified"
    try:
        addresses = [ipaddress.ip_address(token.strip("[]")) for token in tokens]
        return ("loopback_declared" if all(ip.is_loopback for ip in addresses)
                else "non_loopback_declared_requires_review")
    except ValueError:
        return "dynamic_or_unverified"


def exim_debian_router_hint(path):
    """Debian smarthost template is a HINT, never effective Exim routing."""
    text = limited_config_text(path, 65536)
    if text is None:
        return "unverified"
    values = {}
    for line in text.splitlines():
        match = re.fullmatch(
            r"""\s*(dc_eximconfig_configtype|dc_smarthost)\s*=\s*(['"])(.*?)\2\s*""",
            line)
        if match:
            if match.group(1) in values:
                return "unverified"
            values[match.group(1)] = match.group(3)
    if values.get("dc_eximconfig_configtype") == "smarthost" and values.get("dc_smarthost"):
        return "template_declares_smarthost_requires_router_review"
    return "template_only_no_verified_router"


def sendmail_cf_summary(path):
    """Read bounded compiled sendmail.cf. Never expose relay destinations."""
    text = limited_config_text(path)
    if text is None:
        return "unverified", "unverified", "unverified"
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    daemons = [line for line in lines
               if re.match(r"^O\s+DaemonPortOptions\s*=", line)]
    if not daemons:
        listener = "unverified"
    else:
        loopback = True
        for line in daemons:
            address = re.search(r"(?:^|,)\s*Addr\s*=\s*([^,\s]+)", line)
            if not address or address.group(1).strip("[]") not in ("127.0.0.1", "::1"):
                loopback = False
                break
        listener = ("loopback_declared" if loopback
                    else "non_loopback_or_default_requires_review")
    ds = [line[2:].strip() for line in lines if line.startswith("DS")]
    smarthost = ("declared" if len(ds) == 1 and ds[0] else
                 "not_declared" if len(ds) == 1 else "unverified")
    dm = [line[2:].strip() for line in lines if line.startswith("DM")]
    masquerade = ("declared" if len(dm) == 1 and dm[0] else
                  "not_declared" if len(dm) == 1 else "unverified")
    return listener, smarthost, masquerade


def sendmail_cf_security(path):
    """Compiled .cf option declarations only, no TLS session or AUTH proof."""
    data = limited_config_text(path)
    if data is None:
        return "unverified", "unverified"
    options = {}
    for line in data.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"O\s+([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)", line)
        if match and match.group(1) in (
                "ServerCertFile", "ServerKeyFile", "AuthMechanisms"):
            name, val = match.groups()
            if name in options:
                return "unverified", "unverified"
            options[name] = val.strip()
    cert = options.get("ServerCertFile", "")
    key = options.get("ServerKeyFile", "")
    tls = ("server_cert_key_declared_unverified" if cert and key else
           "partial_tls_declaration" if cert or key else
           "server_tls_not_observed")
    auth = ("mechanisms_declared_backend_unverified"
            if options.get("AuthMechanisms") else
            "mechanisms_not_observed")
    return tls, auth


def sendmail_mc_flags(path):
    try:
        if not path.is_file() or path.stat().st_size > 131072:
            return "unavailable", "unverified", "unverified"
        text = limited_config_text(path, 131072)
        if text is None:
            return "unavailable", "unverified", "unverified"
    except (OSError, UnicodeError):
        return "unavailable", "unverified", "unverified"
    live = [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("dnl")]
    interfaces = [line for line in live if "DAEMON_OPTIONS(" in line]
    if not interfaces:
        listener = "not_explicitly_restricted"
    elif all(re.search(r"\bAddr\s*=\s*(?:127\.0\.0\.1|::1)(?:\b|[,\s])", line)
             for line in interfaces):
        listener = "loopback_declared"
    else:
        listener = "manual_review"
    masquerade = "declared" if any("MASQUERADE_AS(" in line for line in live) else "not_declared"
    return "readable", listener, masquerade


def postfix_role_state(key, raw):
    """Read-only declaration state, never return a sensitive lookup value."""
    if raw is None:
        return "unverified"
    normalized = raw.strip()
    # Standard Postfix relay_domains often equals $mydestination. This is not
    # evidence of an additional externally relayed domain or transport map.
    if not normalized or (key == "relay_domains" and normalized == "$mydestination"):
        return "not_declared"
    # These values are boolean in Postfix; "no" is NOT a configured SMTP
    # authentication policy. Never return a secret or map location.
    if key in ("smtp_sasl_auth_enable", "smtp_sender_dependent_authentication"):
        if normalized.lower() == "no":
            return "not_declared"
        if normalized.lower() != "yes":
            return "unverified"
    return "declared"


def inspect(runner=call):
    short, fqdn, domain = identity(runner)
    mta, state = mta_status(runner)
    result = {
        "MAIL_HOST_VERSION": "1", "MAIL_HOST_SHORT": short,
        "MAIL_HOST_FQDN": fqdn, "MAIL_HOST_DOMAIN": domain,
        "MAIL_HOST_MTA": mta, "MAIL_HOST_MTA_STATE": state,
        "MAIL_HOST_TRUST": "os_report_unverified",
        "MAIL_HOST_CHANGES": "no",
        "MAIL_HOST_SMTP_CONFIG_SOURCE": "unverified",
        "MAIL_HOST_SMTP_CONFIG_PORTS": "unverified"
    }
    if mta == "postfix":
        result["MAIL_HOST_SMTP_CONFIG_SOURCE"] = "postfix_master_cf"
        result["MAIL_HOST_SMTP_CONFIG_PORTS"] = postfix_ports(runner)
        for key in POSTFIX:
            result["MAIL_HOST_POSTFIX_" + key.upper()] = safe(
                runner(["postconf", "-h", key]))
        for key in POSTFIX_ROLE_KEYS:
            raw = runner(["postconf", "-h", key])
            # Not a configuration value: only a bounded proof of declaration.
            value = postfix_role_state(key, raw)
            result["MAIL_HOST_POSTFIX_ROLE_" + key.upper()] = value
    elif mta == "exim":
        tool = "exim4" if shutil.which("exim4") else "exim"
        for key in ("primary_hostname", "qualify_domain", "local_interfaces"):
            result["MAIL_HOST_EXIM_" + key.upper()] = exim_setting(tool, key, runner)
        result["MAIL_HOST_EXIM_LOCAL_DOMAINS"] = "routers_and_acls_require_review"
        result["MAIL_HOST_EXIM_SMTP_PORTS"] = exim_ports(tool, runner)
        result["MAIL_HOST_SMTP_CONFIG_SOURCE"] = "exim_daemon_smtp_ports"
        result["MAIL_HOST_SMTP_CONFIG_PORTS"] = result["MAIL_HOST_EXIM_SMTP_PORTS"]
        result["MAIL_HOST_EXIM_BIND_POLICY"] = exim_bind_policy(
            result["MAIL_HOST_EXIM_LOCAL_INTERFACES"])
        result["MAIL_HOST_EXIM_SMARTHOST_HINT"] = exim_debian_router_hint(
            pathlib.Path("/etc/exim4/update-exim4.conf.conf"))
        result["MAIL_HOST_EXIM_RELAY_POLICY"] = "routers_transports_and_acl_unverified"
        tls, auth = exim_security_declarations(tool, runner)
        result["MAIL_HOST_EXIM_TLS_DECLARATION"] = tls
        result["MAIL_HOST_EXIM_AUTH_DECLARATION"] = auth
    elif mta == "sendmail":
        mc, listener, masquerade = sendmail_mc_flags(pathlib.Path("/etc/mail/sendmail.mc"))
        cf_path = pathlib.Path("/etc/mail/sendmail.cf")
        result["MAIL_HOST_SMTP_CONFIG_SOURCE"] = "sendmail_cf"
        result["MAIL_HOST_SMTP_CONFIG_PORTS"] = sendmail_cf_ports(cf_path)
        effective_listener, smarthost, effective_masquerade = sendmail_cf_summary(cf_path)
        tls, auth = sendmail_cf_security(cf_path)
        result.update({
            "MAIL_HOST_SENDMAIL_TLS_DECLARATION": tls,
            "MAIL_HOST_SENDMAIL_AUTH_DECLARATION": auth,
            "MAIL_HOST_SENDMAIL_MC": mc,
            "MAIL_HOST_SENDMAIL_LISTENER": listener,
            "MAIL_HOST_SENDMAIL_MASQUERADE": masquerade,
            "MAIL_HOST_SENDMAIL_CF": "present" if cf_path.is_file() and not cf_path.is_symlink() else "unavailable",
            "MAIL_HOST_SENDMAIL_CF_LISTENER": effective_listener,
            "MAIL_HOST_SENDMAIL_CF_SMARTHOST": smarthost,
            "MAIL_HOST_SENDMAIL_CF_MASQUERADE": effective_masquerade,
            "MAIL_HOST_SENDMAIL_RELAY_POLICY": "access_maps_and_relay_checks_unverified"
        })
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--inspect", action="store_true")
    group.add_argument("--self-test", action="store_true")
    options = parser.parse_args(argv)
    if options.self_test:
        def mock(args):
            mapping = {
                ("hostname", "-f"): "mail.example.com",
                ("hostname", "-s"): "mail",
                ("hostname", "-d"): "example.com",
                ("systemctl", "is-active", "postfix.service"): "active",
                ("systemctl", "is-active", "postfix@-.service"): "inactive",
                ("systemctl", "is-active", "exim.service"): "inactive",
                ("systemctl", "is-active", "exim4.service"): "inactive",
                ("systemctl", "is-active", "sendmail.service"): "inactive",
            }
            return mapping.get(tuple(args))
        assert identity(mock) == ("mail", "mail.example.com", "example.com")
        assert mta_status(mock) == ("postfix", "active")
        assert host("danger;touch /tmp/file") == "unavailable"
        assert safe("foo\nbar=secret") == "unavailable"
        assert safe("$mydomain") == "$mydomain"
        assert exim_setting("exim", "primary_hostname",
                            lambda _: "primary_hostname = smtp.example.com") == "smtp.example.com"
        assert exim_ports("exim", lambda _: "daemon_smtp_ports = smtp : submission") == "25,587"
        assert postfix_ports(lambda _: "smtp inet n - n - - smtpd\n"
                             "smtp unix - - n - - smtp\n"
                             "2525 inet n - n - - smtpd") == "25,2525"
        assert exim_bind_policy("127.0.0.1 ::1") == "loopback_declared"
        assert exim_bind_policy("0.0.0.0") == "non_loopback_declared_requires_review"
        print("MAIL_HOST_SELF_TEST=pass")
        return 0
    for key, value in inspect().items():
        print(key + "=" + value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
