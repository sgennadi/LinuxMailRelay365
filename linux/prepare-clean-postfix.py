#!/usr/bin/env python3
"""Guarded, stand-alone Postfix package preparation for genuinely clean Linux.

No MX, SMTP message, primary Postfix start, firewall or tenant changes. A
read-only SHA256 preflight must be repeated unchanged immediately before Apply.
The packages are NOT silently removed on failure; operator repair may be needed.
Python 3.6+, Ubuntu/Debian, Rocky/Oracle/Alma/RHEL 8-10.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

UNITS = ("postfix.service", "postfix@-.service", "exim.service", "exim4.service",
         "sendmail.service", "opensmtpd.service", "nullmailer.service")
PACKAGES = ("postfix", "exim4", "exim4-base", "exim4-daemon-light",
            "exim4-daemon-heavy", "sendmail", "sendmail-bin", "opensmtpd",
            "nullmailer", "msmtp-mta")
MARKER = pathlib.Path("/etc/linuxmailrelay365/clean-postfix-bootstrap.json")


def run(argv, timeout=12, **kwargs):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=timeout,
                            check=False, **kwargs)
    if len(result.stdout) > 32768:
        raise ValueError("oversized_command_result")
    return result


def platform():
    data = {}
    for line in pathlib.Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in ("ID", "VERSION_ID", "NAME"):
                data[key] = value.strip().strip("'\"").lower()
    name = data.get("ID", "")
    major = data.get("VERSION_ID", "").split(".")[0]
    if (name == "ubuntu" and major in ("20", "22", "24", "26")) or (
            name == "debian" and major in ("11", "12", "13")):
        return name, major, "apt-get"
    if name in ("rhel", "rocky", "almalinux", "ol") and major in ("8", "9", "10"):
        return name, major, "dnf"
    if name == "centos" and major in ("9", "10") and "stream" in data.get("NAME", ""):
        return name, major, "dnf"
    raise ValueError("unsupported_linux_release")


def unit_load(name):
    response = run(["systemctl", "show", "--property=LoadState", "--value", name])
    if response.returncode or response.stdout.strip() not in (
            "not-found", "loaded", "masked", "bad-setting", "error"):
        raise ValueError("systemd_state_unknown")
    return response.stdout.strip()


def sockets():
    result = run(["ss", "-H", "-lnt"])
    if result.returncode:
        raise ValueError("smtp_socket_scan_failed")
    ports = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5 or ":" not in fields[3]:
            raise ValueError("socket_record_unrecognized")
        port = fields[3].rsplit(":", 1)[-1]
        if not port.isdigit():
            raise ValueError("socket_port_unrecognized")
        ports.add(int(port))
    return ports


def installed(manager):
    found = []
    for name in PACKAGES:
        if manager == "apt-get":
            status = run(["dpkg-query", "-s", name])
            if status.returncode == 0 and "Status: install ok installed" in status.stdout:
                found.append(name)
        elif run(["rpm", "-q", "--quiet", name]).returncode == 0:
            found.append(name)
    return found


def inspect(port):
    if not 1024 <= port <= 65535:
        raise ValueError("invalid_custom_smtp_port")
    os_id, major, manager = platform()
    required = ("python3", "ss", "systemctl", manager,
                "dpkg-query" if manager == "apt-get" else "rpm")
    missing = ["missing_" + tool.replace("-", "_")
               for tool in required if shutil.which(tool) is None]
    if missing:
        return {"ready": False, "reasons": missing, "sha": "",
                "os": os_id, "manager": manager}
    states = {name: unit_load(name) for name in UNITS}
    reasons = ["existing_mta_unit_" + name.replace(".", "_").replace("@", "_")
               for name, state in states.items() if state != "not-found"]
    packages = installed(manager)
    if packages:
        reasons.append("existing_mta_package")
    for tool in ("postconf", "postfix", "sendmail", "exim", "exim4"):
        if shutil.which(tool):
            reasons.append("existing_mta_binary_" + tool)
    for path in ("/etc/postfix", "/etc/mail/sendmail.cf", "/etc/exim",
                 "/etc/exim4", "/etc/linuxmailrelay365", "/var/spool/postfix"):
        if os.path.lexists(path):
            reasons.append("existing_mta_path")
    important_ports = (25, 465, 587, port)
    occupied = sorted(x for x in sockets() if x in important_ports)
    if occupied:
        reasons.append("smtp_socket_already_open")
    enforcing = pathlib.Path("/sys/fs/selinux/enforce")
    if enforcing.is_file() and enforcing.read_text().strip() == "1":
        reasons.append("selinux_enforcing_requires_separate_acceptance")
    if manager == "apt-get" and os.path.lexists("/usr/sbin/policy-rc.d"):
        reasons.append("existing_service_start_policy")
    evidence = {"os": os_id, "major": major, "manager": manager,
                "mta_units": states, "mta_packages": packages,
                "busy_smtp_ports": occupied, "selected_port": port, "revision": 1}
    sha = hashlib.sha256(json.dumps(
        evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"ready": not reasons, "reasons": reasons,
            "sha": sha, "os": os_id, "manager": manager}


def apply(port, expected, confirm):
    if confirm != "INSTALL_CLEAN_POSTFIX_PACKAGES":
        raise ValueError("explicit_package_approval_required")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("reviewed_preflight_sha256_required")
    if os.geteuid() != 0:
        raise ValueError("root_required")
    result = inspect(port)
    if not result["ready"] or result["sha"] != expected:
        raise ValueError("preflight_changed_or_server_not_clean")
    if not pathlib.Path("/run/systemd/system").is_dir():
        raise ValueError("live_systemd_required")
    policy = pathlib.Path("/usr/sbin/policy-rc.d")
    masked = False
    policy_created = False
    try:
        if run(["systemctl", "mask", "--runtime", "postfix.service"]).returncode:
            raise RuntimeError("cannot_mask_primary_postfix_start")
        masked = True
        if result["manager"] == "apt-get":
            # Temporary policy blocks legacy invoke-rc.d during Postfix postinst.
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(str(policy), flags, 0o755)
            policy_created = True
            with os.fdopen(fd, "w") as stream:
                stream.write("#!/bin/sh\nexit 101\n")
                stream.flush()
                os.fsync(stream.fileno())
            if shutil.which("debconf-set-selections"):
                seeded = subprocess.run(["debconf-set-selections"],
                    input="postfix postfix/main_mailer_type select Local only\n",
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    universal_newlines=True, timeout=12, check=False)
                if seeded.returncode:
                    raise RuntimeError("debian_local_only_preseed_failed")
            command = ["apt-get", "-q", "-y", "install", "postfix"]
        else:
            command = ["dnf", "-y", "install", "postfix"]
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive",
                   DEBIAN_PRIORITY="critical")
        proc = subprocess.run(command, env=env, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, universal_newlines=True,
                              timeout=900, check=False)
        if proc.returncode:
            raise RuntimeError("package_install_failed_manual_review")
        if not shutil.which("postconf") or not shutil.which("postfix"):
            raise RuntimeError("installed_postfix_binary_unavailable")
        config = ("/etc/postfix/main.cf", "/etc/postfix/master.cf")
        if not all(pathlib.Path(x).is_file() for x in config):
            raise RuntimeError("postfix_config_missing_after_package_install")
        if run(["systemctl", "disable", "postfix.service"]).returncode:
            raise RuntimeError("could_not_disable_primary_postfix")
        if sockets().intersection((25, 465, 587, port)):
            raise RuntimeError("unexpected_primary_smtp_listener")
        for unit in ("exim.service", "exim4.service", "sendmail.service"):
            if unit_load(unit) != "not-found":
                raise RuntimeError("foreign_mta_appeared_during_install")
        hashes = {}
        for path in config:
            with open(path, "rb") as src:
                hashes[path] = hashlib.sha256(src.read()).hexdigest()
        MARKER.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chown(str(MARKER.parent), 0, 0)
        MARKER.parent.chmod(0o700)
        payload = {"schema": 1, "postfix_prepared_for_isolated_relay": True,
                   "port": port, "os_id": result["os"], "plan_sha256": expected,
                   "postfix_config_hashes": hashes, "utc_created": int(time.time())}
        with open(str(MARKER), "x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(payload, stream, sort_keys=True)
        print("CLEAN_POSTFIX_PACKAGES_PREPARED=yes")
        print("PRIMARY_POSTFIX_SERVICE=disabled")
        print("ISOLATED_RELAY_INSTALLED=no")
    finally:
        if policy_created:
            policy.unlink()
        if masked and run(["systemctl", "unmask", "--runtime", "postfix.service"]).returncode:
            raise RuntimeError("temporary_postfix_mask_restore_failed")


def main(argv=None):
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-only", action="store_true")
    group.add_argument("--apply", action="store_true")
    parser.add_argument("--smtp-port", type=int, required=True)
    parser.add_argument("--expected-plan-sha256", default="")
    parser.add_argument("--confirm", default="")
    options = parser.parse_args(argv)
    try:
        if options.check_only:
            if options.expected_plan_sha256 or options.confirm:
                raise ValueError("read_only_action_cannot_accept_confirmation")
            current = inspect(options.smtp_port)
            print("CLEAN_POSTFIX_BOOTSTRAP_VERSION=1")
            print("CLEAN_POSTFIX_BOOTSTRAP_READY=" + ("yes" if current["ready"] else "no"))
            print("CLEAN_POSTFIX_OS=" + current["os"])
            print("CLEAN_POSTFIX_PACKAGE_MANAGER=" + current["manager"].replace("-", "_"))
            print("CLEAN_POSTFIX_BLOCKERS=" + ("none" if not current["reasons"]
                  else ",".join(current["reasons"][:16])))
            print("CLEAN_POSTFIX_PLAN_SHA256=" + current["sha"])
            print("CHANGES_APPLIED=no")
            return 0
        apply(options.smtp_port, options.expected_plan_sha256, options.confirm)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print("CLEAN_POSTFIX_ERROR=" + str(error).replace("\n", "_"),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
