#!/usr/bin/env python3
"""Read-only distribution, Dovecot and SELinux preflight for LinuxMailRelay365.

No package install, policy changes, firewall changes, port opening, or messages.
Status is intentionally conservative: a local inspection does not prove mail delivery.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

KNOWN_RHEL = {"rhel", "ol", "rocky", "almalinux"}
KNOWN_DEBIAN = {"ubuntu", "debian"}
SUPPORTED_RHEL_MAJORS = {8, 9, 10}


def parse_os_release(data: str) -> dict[str, str]:
    # /etc/os-release is data, NEVER shell-source it.
    result: dict[str, str] = {}
    for line in data.splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line.strip())
        if not match:
            continue
        value = match.group(2).strip()
        if len(value) > 512:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
            if match.group(2).strip().startswith('"'):
                value = value.replace('\\"', '"').replace("\\\\", "\\")
        result[match.group(1)] = value
    return result


def distro_info(info: dict[str, str]) -> tuple[str, str, str]:
    name = info.get("ID", "").lower()
    version = info.get("VERSION_ID", "")
    major_match = re.match(r"^(\d+)(?:\.|$)", version)
    major = int(major_match.group(1)) if major_match else 0
    if name in KNOWN_RHEL and major in SUPPORTED_RHEL_MAJORS:
        return "rhel", str(major), "candidate"
    if name == "centos" and major in (9, 10) and "stream" in info.get("NAME", "").lower():
        return "rhel", str(major), "candidate"
    if name in KNOWN_DEBIAN:
        if name == "ubuntu" and major in (20, 22, 24, 26):
            return "debian", str(major), "candidate"
        if name == "debian" and major in (11, 12, 13):
            return "debian", str(major), "candidate"
    return "unknown", str(major or "unknown"), "manual_review"


def dovecot_compat(version: str) -> str:
    if not version:
        return "missing"
    # Dovecot 2.4 requires a different configuration grammar; fail closed.
    if re.match(r"^2\.3(?:\.|\s|$)", version.strip()):
        return "2_3_compatible"
    return "unsupported_version"


def parse_selinux_ports(data: str, port: int) -> tuple[str, str]:
    owners = set()
    for line in data.splitlines():
        m = re.match(r"^(\S+)\s+tcp\s+(.+?)\s*$", line)
        if not m:
            continue
        label = m.group(1)
        for token in re.split(r"[\s,]+", m.group(2)):
            segment = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
            if not segment:
                continue
            begin = int(segment.group(1))
            end = int(segment.group(2) or segment.group(1))
            if begin <= port <= end:
                owners.add(label)
    if not owners:
        return "unmapped", "none"
    if owners == {"smtp_port_t"}:
        return "allowed", "smtp_port_t"
    return "conflict", "other_type"


def safe_run(*argv: str, timeout: int = 5) -> str:
    if not argv or not shutil.which(argv[0]):
        return ""
    try:
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=timeout, check=False)
        if completed.returncode:
            return ""
        return (completed.stdout or completed.stderr).strip()[:32768]
    except (OSError, subprocess.TimeoutExpired):
        return ""


def probe(os_release: str, port: int) -> dict[str, str]:
    info = parse_os_release(os_release)
    family, major, status = distro_info(info)
    distro = info.get("ID", "unknown").lower()
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", distro):
        distro = "unknown"
    manager = "dnf" if family == "rhel" else "apt-get" if family == "debian" else "none"
    installed_postfix = bool(shutil.which("postconf"))
    installed_dovecot = bool(shutil.which("dovecot"))
    dovecot_version = safe_run("dovecot", "--version") if installed_dovecot else ""
    sasl = safe_run("postconf", "-a") if installed_postfix else ""
    sasl_state = ("yes" if "dovecot" in sasl.splitlines() else
                  "no" if installed_postfix else "unknown")
    mode = safe_run("getenforce").lower()
    if mode not in ("enforcing", "permissive", "disabled"):
        mode = "unknown" if family == "rhel" else "not_installed"
    selinux_port, port_owner = "not_required", "none"
    if mode in ("enforcing", "permissive"):
        mapped = safe_run("semanage", "port", "-l", timeout=12)
        if mapped:
            selinux_port, port_owner = parse_selinux_ports(mapped, port)
        else:
            selinux_port, port_owner = "unknown_no_semanage", "unknown"
    if status != "candidate":
        readiness = "unsupported_distro_manual_review"
    elif family == "rhel" and mode == "enforcing" and selinux_port != "allowed":
        readiness = "rhel_selinux_preparation_required"
    elif mode == "unknown" and family == "rhel":
        readiness = "selinux_status_unknown"
    else:
        readiness = "platform_candidate_not_delivery_verified"
    return {
        "PLATFORM_PROBE_VERSION": "1",
        "OS_ID": distro,
        "OS_FAMILY": family,
        "OS_MAJOR": major,
        "OS_SUPPORT": status,
        "PACKAGE_MANAGER": manager,
        "POSTFIX_INSTALLED": "yes" if installed_postfix else "no",
        "DOVECOT_INSTALLED": "yes" if installed_dovecot else "no",
        "DOVECOT_CONFIG_FAMILY": dovecot_compat(dovecot_version),
        "POSTFIX_DOVECOT_SASL": sasl_state,
        "SELINUX_MODE": mode,
        "SELINUX_SMTP_PORT": selinux_port,
        "SELINUX_SMTP_PORT_OWNER": port_owner,
        "SMTP_PORT": str(port),
        "PLATFORM_READINESS": readiness,
        "SMTP_AUTH_TLS_CONFIGURED": "not_verified",
        "MICROSOFT365_DELIVERY_VERIFIED": "no",
        "CHANGES_APPLIED": "no",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smtp-port", type=int, default=2525)
    parser.add_argument("--os-release-file", type=Path, default=Path("/etc/os-release"))
    args = parser.parse_args()
    if not 1024 <= args.smtp_port <= 65535:
        parser.error("Isolated SMTP port must be 1024-65535")
    try:
        data = args.os_release_file.read_text(encoding="utf-8")
    except OSError:
        data = ""
    result = probe(data, args.smtp_port)
    for key, value in result.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
