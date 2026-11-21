#!/usr/bin/env python3
"""Read-only RHEL SELinux Enforcing installation readiness report.

Python 3.6+; does not setenforce, semanage, restorecon, install any package,
restart mail services or expose raw contexts/addresses to the Windows GUI.
An AVC or context hint does NOT prove allow rules. Never claims supported
Enforcing deployment without a real end-to-end host integration test.
"""
import argparse
import os
import re
import shutil
import socket
import stat
import subprocess
from pathlib import Path

OS_RELEASE = Path("/etc/os-release")
QUEUE = Path("/var/spool/linuxmailrelay365-sidecar")
CONF = Path("/etc/linuxmailrelay365/sidecar-postfix")
AUTH = Path("/etc/linuxmailrelay365/smtp-auth")


def run(argv, timeout=6):
    if not argv or not shutil.which(argv[0]):
        return None
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout, check=False)
        return p.stdout[:32768] if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def os_family(text):
    m = re.search(r'(?m)^ID=(["\']?)([A-Za-z0-9_-]+)\1\s*$', text)
    name = m.group(2).lower() if m else ""
    return "rhel_family" if name in ("rhel", "ol", "rocky", "almalinux", "centos") else (
        "debian_family" if name in ("ubuntu", "debian") else "unknown")


def selinux_mode():
    value = run(["getenforce"])
    if value:
        value = value.strip().lower()
        if value in ("enforcing", "permissive", "disabled"):
            return value
    try:
        if Path("/sys/fs/selinux/enforce").is_file():
            return "enforcing" if Path("/sys/fs/selinux/enforce").read_text().strip() == "1" else "permissive"
    except OSError:
        pass
    return "unknown"


def port_label(port, data):
    if data is None:
        return "unknown"
    matches = set()
    for line in data.splitlines():
        m = re.match(r'^(\S+)\s+tcp\s+(.+)$', line)
        if not m:
            continue
        # The SELinux base policy includes broad default portcon ranges.
        # These are shadows, not a conflict with a specific smtp_port_t.
        # Any OTHER explicit type remains a conflict and blocks approval.
        if m.group(1) in ("reserved_port_t", "unreserved_port_t"):
            continue
        for chunk in re.split(r'[\s,]+', m.group(2).strip()):
            val = re.fullmatch(r'(\d+)(?:-(\d+))?', chunk)
            if val and int(val.group(1)) <= port <= int(val.group(2) or val.group(1)):
                matches.add(m.group(1))
    if matches == {"smtp_port_t"}:
        return "smtp_port_t"
    return "other_label" if matches else "unmapped"


def file_label(path):
    try:
        item = path.lstat()
        if not (stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode) or stat.S_ISSOCK(item.st_mode)):
            return "unsupported_file_type"
        raw = os.getxattr(str(path), "security.selinux")
        label = raw.decode("ascii", "replace").strip("\x00")
        m = re.fullmatch(r'[A-Za-z0-9_]+:[A-Za-z0-9_]+:([A-Za-z0-9_]+):[A-Za-z0-9_.,:-]+', label)
        if not m:
            return "unrecognized"
        return "bad_default_type" if m.group(1) in ("default_t", "unlabeled_t") else "present_not_policy_verified"
    except FileNotFoundError:
        return "missing"
    except (OSError, UnicodeError):
        return "unknown"


def unit_state(name):
    state = run(["systemctl", "is-active", name])
    return "active" if state is not None and state.strip() == "active" else "not_active_or_unknown"


def process_context_state():
    raw = run(["ps", "-eZ", "-o", "label=,comm="])
    if raw is None:
        return "not_available"
    postfix = False
    dovecot = False
    for line in raw.splitlines():
        if "postfix" in line or "master" in line:
            postfix = True
        if "dovecot" in line or "auth" in line:
            dovecot = True
    return "both_processes_seen_context_not_verified" if postfix and dovecot else "partial_or_unknown"


def audit(port, installed=True):
    try:
        family = os_family(OS_RELEASE.read_text(encoding="utf-8"))
    except OSError:
        family = "unknown"
    mode = selinux_mode()
    data = run(["semanage", "port", "-l"], timeout=12) if mode in ("permissive", "enforcing") else None
    labels = []
    names = [QUEUE, QUEUE / "private", CONF / "main.cf", CONF / "master.cf"]
    if installed and AUTH.is_dir():
        names.extend([QUEUE / "private/auth", AUTH / "passwd", AUTH / "privkey.pem"])
    for name in names:
        labels.append(file_label(name))
    result = {
        "RHEL_SELINUX_DOCTOR_VERSION": "1",
        "CUSTOM_SMTP_PORT": str(port),
        "OS_FAMILY": family,
        "SELINUX_MODE": mode,
        "SMTP_PORT_TYPE": port_label(port, data) if mode in ("permissive", "enforcing") else "not_checked",
        "POSTFIX_SIDECAR_SERVICE": unit_state("linuxmailrelay365-sidecar.service"),
        "SMTP_AUTH_SERVICE": unit_state("linuxmailrelay365-smtp-auth.service"),
        "FILE_CONTEXTS": "missing_or_unsafe" if any(x in ("missing", "bad_default_type", "unrecognized", "unsupported_file_type") for x in labels) else
                         "not_verified" if any(x == "unknown" for x in labels) else
                         "present_not_policy_verified",
        "PROCESS_CONTEXTS": process_context_state() if mode == "enforcing" else "not_verified",
        "SELINUX_AVC_POLICY_ACCESS": "not_verified",
        "SELINUX_BOOLEAN_PLAN": "manual_review_required",
        "POST_REBOOT_SERVICE_TEST": "not_verified",
        "PUBLIC_SMTP_REACHABILITY": "not_verified",
        "SMTP_AUTH_ENFORCING_TESTED": "no",
        "MICROSOFT365_DELIVERY_VERIFIED": "no",
        "CHANGES_APPLIED": "no",
    }
    if family != "rhel_family":
        state = "not_rhel_family"
    elif mode != "enforcing":
        state = "enforcing_mode_required_for_acceptance"
    elif result["SMTP_PORT_TYPE"] != "smtp_port_t":
        state = "smtp_port_policy_review"
    elif result["FILE_CONTEXTS"] != "present_not_policy_verified":
        state = "file_context_review"
    else:
        state = "manual_avc_and_runtime_test_required"
    result["SELINUX_ACCEPTANCE_STATUS"] = state
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smtp-port", type=int, required=True)
    args = parser.parse_args()
    if not 1024 <= args.smtp_port <= 65535:
        parser.error("Custom SMTP port must be 1024-65535")
    for key, value in audit(args.smtp_port).items():
        print("{}={}".format(key, value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
