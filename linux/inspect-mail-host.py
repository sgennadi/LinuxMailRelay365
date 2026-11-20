#!/usr/bin/env python3
"""Read-only Linux hostname/domain and Postfix, Exim, Sendmail settings summary.

Does not mutate configuration, open SMTP sessions, or reveal raw config files.
OS hostname/domain are NOT proof of Microsoft 365 accepted-domain ownership.
Python 3.6+ (supports RHEL-family 8-10).
"""
import argparse
import pathlib
import re
import shutil
import subprocess

HOST = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
SHORT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
VALUE = re.compile(r"^[A-Za-z0-9_.$/,: @{}\[\]+-]{0,200}$")
POSTFIX = ("myhostname", "mydomain", "myorigin", "mydestination",
           "inet_interfaces", "inet_protocols")


def call(argv):
    if not shutil.which(argv[0]):
        return None
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, check=False, timeout=6)
        # systemctl returns 3 for an inactive service and 4 for an
        # unknown unit. Those are valid *read-only evidence*, unlike a
        # failed postconf/exim query which must remain unavailable.
        inactive_unit = (argv[:2] == ["systemctl", "is-active"] and
                         p.returncode in (3, 4) and
                         p.stdout.strip() in ("inactive", "failed", "unknown", "dead"))
        if (p.returncode == 0 or inactive_unit) and len(p.stdout) <= 4096:
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


def sendmail_mc_flags(path):
    try:
        if not path.is_file() or path.stat().st_size > 131072:
            return "unavailable", "unverified", "unverified"
        text = path.read_text(encoding="utf-8")
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


def inspect(runner=call):
    short, fqdn, domain = identity(runner)
    mta, state = mta_status(runner)
    result = {
        "MAIL_HOST_VERSION": "1", "MAIL_HOST_SHORT": short,
        "MAIL_HOST_FQDN": fqdn, "MAIL_HOST_DOMAIN": domain,
        "MAIL_HOST_MTA": mta, "MAIL_HOST_MTA_STATE": state,
        "MAIL_HOST_TRUST": "os_report_unverified",
        "MAIL_HOST_CHANGES": "no"
    }
    if mta == "postfix":
        for key in POSTFIX:
            result["MAIL_HOST_POSTFIX_" + key.upper()] = safe(
                runner(["postconf", "-h", key]))
    elif mta == "exim":
        tool = "exim4" if shutil.which("exim4") else "exim"
        for key in ("primary_hostname", "qualify_domain", "local_interfaces"):
            result["MAIL_HOST_EXIM_" + key.upper()] = exim_setting(tool, key, runner)
        result["MAIL_HOST_EXIM_LOCAL_DOMAINS"] = "routers_and_acls_require_review"
    elif mta == "sendmail":
        mc, listener, masquerade = sendmail_mc_flags(pathlib.Path("/etc/mail/sendmail.mc"))
        result.update({
            "MAIL_HOST_SENDMAIL_MC": mc,
            "MAIL_HOST_SENDMAIL_LISTENER": listener,
            "MAIL_HOST_SENDMAIL_MASQUERADE": masquerade,
            "MAIL_HOST_SENDMAIL_CF": "present" if pathlib.Path(
                "/etc/mail/sendmail.cf").is_file() else "not_found"
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
        print("MAIL_HOST_SELF_TEST=pass")
        return 0
    for key, value in inspect().items():
        print(key + "=" + value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
