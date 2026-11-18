#!/usr/bin/env python3
"""Read-only multi-MTA coexistence audit for Postfix, Sendmail, Exim.

Does not install/remove MTA packages, change service selection/alternatives,
open ports, modify queues, or claim that Postfix is safe to install on a host
whose primary mail delivery currently depends on another MTA. Python 3.6+.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SERVICES = {"postfix": ("postfix.service",),
            "exim": ("exim4.service", "exim.service"),
            "sendmail": ("sendmail.service",)}
POSTFIX_CONF = Path("/etc/postfix")
SIDECAR_CONF = Path("/etc/linuxmailrelay365/sidecar-postfix")


def run(argv, timeout=8):
    if not shutil.which(argv[0]):
        return None
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout,
                                universal_newlines=True, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def active_service(name, runner=run):
    if not shutil.which("systemctl"):
        return None
    try:
        for unit in SERVICES[name]:
            result = runner(["systemctl", "is-active", unit], timeout=8)
            if result == "active":
                return True
    except (OSError, ValueError):
        return None
    return False


def port_busy(port, runner=run):
    output = runner(["ss", "-H", "-ltn"], timeout=8)
    if output is None:
        return "unknown"
    # Parse only local endpoint column; never print host/network addresses.
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 4:
            continue
        local = columns[3]
        if local.endswith(":" + str(port)):
            return "yes"
    return "no"


def path_present(path):
    try:
        return path.exists() and not path.is_symlink()
    except OSError:
        return False


def audit(port, runner=run, services=None, binaries=None, paths=None):
    services = services if services is not None else {
        name: active_service(name, runner) for name in SERVICES
    }
    available = binaries if binaries is not None else {
        "postfix": bool(shutil.which("postfix") and shutil.which("postconf")),
        "sendmail": bool(shutil.which("sendmail")),
        "exim": bool(shutil.which("exim4") or shutil.which("exim"))
    }
    if paths is None:
        paths = {
            "postfix": path_present(POSTFIX_CONF / "main.cf") and
                       path_present(POSTFIX_CONF / "master.cf"),
            "sendmail": path_present(Path("/etc/mail/sendmail.cf")),
            "exim": path_present(Path("/etc/exim4")) or path_present(Path("/etc/exim"))
        }
    active = sorted(name for name, enabled in services.items() if enabled is True)
    if any(x is None for x in services.values()):
        primary = "unknown_service_state"
    elif len(active) > 1:
        primary = "multiple_active_mta"
    elif active:
        primary = active[0]
    else:
        primary = "none_running"
    installed = paths.get("postfix", False) and available.get("postfix", False)
    marker = SIDECAR_CONF / "smtp-port"
    sidecar = "yes" if path_present(marker) and path_present(SIDECAR_CONF / "main.cf") and \
        path_present(SIDECAR_CONF / "master.cf") else "no"
    if sidecar == "yes":
        readiness = "sidecar_already_installed_no_overwrite"
    elif primary == "multiple_active_mta":
        readiness = "active_mta_conflict_manual_review"
    elif primary == "unknown_service_state":
        readiness = "active_mta_unknown_manual_review"
    elif primary in ("exim", "sendmail"):
        if installed:
            readiness = "preinstalled_postfix_candidate_manual_isolation_required"
        else:
            readiness = "postfix_not_preinstalled_package_mutation_blocked"
    elif primary == "postfix" and installed:
        readiness = "primary_postfix_preserve_sidecar_candidate"
    else:
        readiness = "no_verified_primary_mta_manual_review"
    return {
        "MTA_COEXISTENCE_VERSION": "1",
        "CUSTOM_SMTP_PORT": str(port),
        "ACTIVE_PRIMARY_MTA": primary,
        "POSTFIX_CLI_PREINSTALLED": "yes" if available.get("postfix") else "no",
        "POSTFIX_CONFIG_PREEXISTING": "yes" if paths.get("postfix") else "no",
        "SENDMAIL_CONFIG_FOUND": "yes" if paths.get("sendmail") else "no",
        "EXIM_CONFIG_FOUND": "yes" if paths.get("exim") else "no",
        "INDEPENDENT_POSTFIX_INSTALLED": sidecar,
        "CUSTOM_PORT_IN_USE": port_busy(port, runner),
        "MULTI_MTA_READINESS": readiness,
        "MTA_PACKAGE_INSTALL_ALLOWED": "no",
        "PRIMARY_MTA_STOP_OR_RESTART": "no",
        "PRIMARY_MTA_QUEUE_MODIFIED": "no",
        "MICROSOFT365_DELIVERY_VERIFIED": "no",
        "CHANGES_APPLIED": "no"
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--smtp-port", type=int, required=True)
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()
    if a.self_test:
        print("MTA_COEXISTENCE_SELF_TEST=pass")
        return 0
    if not 1024 <= a.smtp_port <= 65535:
        p.error("Custom SMTP port must be 1024-65535")
    for key, value in audit(a.smtp_port).items():
        print("{}={}".format(key, value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
