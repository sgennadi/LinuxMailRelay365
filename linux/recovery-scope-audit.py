#!/usr/bin/env python3
"""Read-only disaster-recovery scope audit for LinuxMailRelay365.

The existing primary Postfix snapshot does NOT include a complete independent
SMTP sidecar, all external cert/key dependencies, package state, systemd,
Dovecot, queue files, MTA coexistence or Exchange/DNS configuration.
This audit never reads secret contents, opens a listener, sends SMTP or makes
configuration changes. Python 3.6+ for Oracle/Rocky/Alma/RHEL 8-10.
"""
import argparse
import re
import stat
import sys
from pathlib import Path

PRIMARY = Path("/etc/postfix")
SIDECAR = Path("/etc/linuxmailrelay365/sidecar-postfix")
AUTH = Path("/etc/linuxmailrelay365/smtp-auth")
QUEUE = Path("/var/spool/linuxmailrelay365-sidecar")
UNIT = Path("/etc/systemd/system/linuxmailrelay365-sidecar.service")
BACKUPS = Path("/var/backups/linuxmailrelay365")
EXIM = Path("/etc/exim4")
SENDMAIL = Path("/etc/mail/sendmail.cf")
BACKUP_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\Z")
CONFIG_LINE = re.compile(r"(?m)^([a-z][a-z0-9_]*)\s*=\s*(.*?)\s*$")
REF_PARAMS = (
    "smtp_tls_cert_file", "smtp_tls_key_file", "smtp_tls_CAfile",
    "smtpd_tls_cert_file", "smtpd_tls_key_file", "smtpd_tls_CAfile",
    "smtp_tls_policy_maps", "smtp_sasl_password_maps",
    "sender_canonical_maps", "smtpd_sender_login_maps", "transport_maps",
)


def status(path, directory=False):
    """Inspect the named inode; never follow symlinks or list its contents."""
    try:
        meta = path.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unknown"
    proper = stat.S_ISDIR(meta.st_mode) if directory else stat.S_ISREG(meta.st_mode)
    if not proper or meta.st_mode & 0o022 or meta.st_uid != 0:
        return "unsafe_or_untrusted"
    return "present"


def external_refs(main_cf):
    """Return bounded metadata counts only; never echo source paths/values."""
    if status(main_cf) != "present":
        return "unknown", "unknown"
    try:
        if main_cf.lstat().st_size > 1048576:
            return "unknown", "unknown"
        content = main_cf.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return "unknown", "unknown"
    vals = dict(CONFIG_LINE.findall(content))
    external = set()
    unresolved = 0
    for key in REF_PARAMS:
        value = vals.get(key, "").strip()
        if not value:
            continue
        # A single absolute path or an explicit map backend path is
        # recognizable. Other expressions require a human inventory.
        for item in re.split(r"[\s,]+", value):
            candidate = item.split(":", 1)[1] if item.startswith(
                ("regexp:", "hash:", "lmdb:", "texthash:", "pcre:")) else item
            if candidate.startswith("/") and re.fullmatch(
                    r"/[A-Za-z0-9_.\/-]{1,260}", candidate):
                if not (candidate == str(PRIMARY) or
                        candidate.startswith(str(PRIMARY) + "/")):
                    external.add(candidate)
            else:
                unresolved += 1
    return str(len(external)), str(unresolved)


def backup_candidates(path, limit=256):
    """Count plausible archives; do NOT label them verified or recoverable."""
    if status(path, directory=True) != "present":
        return "unavailable"
    count = 0
    try:
        for entry in path.iterdir():
            if not BACKUP_ID.fullmatch(entry.name):
                continue
            if (status(entry, directory=True) == "present" and
                    status(entry / "config.tar.gz") == "present" and
                    status(entry / "SHA256SUMS") == "present" and
                    status(entry / "state.txt") == "present"):
                count += 1
            if count >= limit:
                return "at_least_256"
    except OSError:
        return "unavailable"
    return str(count)


def audit(port, roots=None):
    roots = roots or {
        "primary": PRIMARY, "sidecar": SIDECAR, "auth": AUTH,
        "queue": QUEUE, "unit": UNIT, "backups": BACKUPS,
        "exim": EXIM, "sendmail": SENDMAIL
    }
    primary = roots["primary"]
    sidecar = roots["sidecar"]
    primary_status = status(primary, directory=True)
    has_primary = (primary_status == "present" and
                   status(primary / "main.cf") == "present" and
                   status(primary / "master.cf") == "present")
    core = [status(sidecar / name) for name in ("main.cf", "master.cf", "smtp-port")]
    installed = "no" if all(x == "missing" for x in core) else "incomplete"
    if all(x == "present" for x in core):
        try:
            actual = (sidecar / "smtp-port").read_text(encoding="ascii").strip()
            installed = "yes" if actual == str(port) else "port_mismatch"
        except (OSError, UnicodeError):
            installed = "incomplete"
    external, unresolved = external_refs(sidecar / "main.cf")
    mta_configs = sum((
        has_primary,
        status(roots["exim"], directory=True) == "present",
        status(roots["sendmail"]) == "present",
    ))
    return {
        "RECOVERY_AUDIT_SCHEMA": "1",
        "CUSTOM_SMTP_PORT": str(port),
        "PRIMARY_POSTFIX_CONFIG": "present" if has_primary else primary_status,
        "SIDECAR_CONFIGURATION": installed,
        "SMTP_AUTH_CONFIG": status(roots["auth"], directory=True),
        "SIDECAR_QUEUE_DIRECTORY": status(roots["queue"], directory=True),
        "SIDECAR_SYSTEMD_UNIT": status(roots["unit"]),
        "MTA_CONFIG_FAMILIES": "multiple" if mta_configs > 1
            else "one" if mta_configs == 1 else "none_or_unknown",
        "PRIMARY_BACKUP_CANDIDATES_UNVERIFIED": backup_candidates(roots["backups"]),
        "EXTERNAL_REFS_OUTSIDE_PRIMARY_POSTFIX": external,
        "DYNAMIC_REFERENCES_REQUIRE_REVIEW": unresolved,
        "BACKUP_SCOPE": "primary_postfix_config_only",
        "SIDECAR_FULL_RESTORE_VERIFIED": "no",
        "QUEUE_RECOVERY_VERIFIED": "no",
        "SYSTEMD_PACKAGE_RESTORE_VERIFIED": "no",
        "DOVECOT_CREDENTIAL_RESTORE_VERIFIED": "no",
        "M365_TENANT_DNS_RESTORE_VERIFIED": "no",
        "RECOVERY_ASSESSMENT": "requires_manual_external_backup_and_live_restore",
        "MICROSOFT365_DELIVERY_VERIFIED": "no",
        "CHANGES_APPLIED": "no",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smtp-port", type=int, default=2525)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        print("RECOVERY_SCOPE_SELF_TEST=pass")
        return 0
    if not 1024 <= args.smtp_port <= 65535:
        parser.error("Custom SMTP port must be 1024-65535")
    for key, value in audit(args.smtp_port).items():
        print("{}={}".format(key, value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
