#!/usr/bin/env python3
"""Guarded Postfix primary identity baseline: preview, backup, apply, rollback.

Supports ONLY a fixed mail identity baseline and loopback-only IPv4.
The separately managed authenticated-public-SMTP workflow owns public listeners.
Never edits Exim/Sendmail or a one-time clean Postfix bootstrap. Requires root
and a verified /var/backups/linuxmailrelay365 recovery snapshot for Apply.
Python 3.6+; no SMTP connections, messages, MX or firewall mutations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

MAIN = Path("/etc/postfix/main.cf")
MASTER = Path("/etc/postfix/master.cf")
CLEAN_MARKER = Path("/etc/linuxmailrelay365/clean-postfix-bootstrap.json")
HOSTNAME = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")
HASH = re.compile(r"\A[a-f0-9]{64}\Z")
ID = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\Z")
BASELINE = {
    "myorigin": "$mydomain",
    "mydestination": "$myhostname, localhost.$mydomain, localhost",
    "inet_protocols": "ipv4",
}


class Refused(Exception):
    pass


def run(args, timeout=15):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("required_linux_command_unavailable_or_timed_out")
    if len(p.stdout) > 16384 or len(p.stderr) > 16384:
        raise Refused("oversized_linux_command_response")
    return p


def file_hash(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Refused("unsafe_primary_postfix_configuration_file")
    if info.st_size > 8 * 1024 * 1024:
        raise Refused("postfix_configuration_too_large")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_hostname(hostname, domain):
    if (not HOST.fullmatch(hostname) or not HOST.fullmatch(domain) or
            len(hostname) > 253 or len(domain) > 253 or
            not hostname.endswith("." + domain)):
        raise Refused("fqdn_must_be_in_declared_domain")


def active_units():
    result = []
    for unit in ("postfix.service", "postfix@-.service", "exim.service",
                 "exim4.service", "sendmail.service"):
        p = run(["systemctl", "is-active", unit])
        if p.returncode == 0 and p.stdout.strip() == "active":
            result.append(unit)
        elif p.stdout.strip() not in ("inactive", "failed", "unknown", "dead"):
            raise Refused("mta_service_status_unverified")
    if any(unit.startswith(("exim", "sendmail")) for unit in result):
        raise Refused("foreign_mta_must_remain_untouched")
    if len(result) > 1:
        raise Refused("multiple_mta_unit_instances_require_review")
    return result


def plan(hostname, domain, listener):
    validate_hostname(hostname, domain)
    if os.geteuid() != 0:
        raise Refused("root_required_for_verified_configuration_plan")
    # No script may disturb the one-time clean bootstrap marker / config hashes.
    if CLEAN_MARKER.exists() or CLEAN_MARKER.is_symlink():
        raise Refused("clean_postfix_bootstrap_must_remain_unchanged")
    if listener not in ("loopback-only", "all"):
        raise Refused("unsupported_listener_setting")
    main_hash = file_hash(MAIN)
    master_hash = file_hash(MASTER)
    if not MAIN.parent.is_dir() or MAIN.parent.is_symlink():
        raise Refused("unsafe_postfix_configuration_directory")
    units = active_units()
    desired = dict(BASELINE, myhostname=hostname, mydomain=domain,
                   inet_interfaces=listener)
    evidence = {"revision": 1, "main": main_hash, "master": master_hash,
                "desired": desired, "active_units": units}
    digest = hashlib.sha256(json.dumps(
        evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"sha": digest, "main": main_hash, "desired": desired,
            "active_units": units, "ready": listener != "all"}


def backup(recovery_path):
    if not recovery_path or not Path(recovery_path).is_file():
        raise Refused("verified_recovery_script_required")
    snapshot = run(["bash", recovery_path, "--backup"], timeout=90)
    if snapshot.returncode != 0:
        raise Refused("postfix_configuration_backup_failed")
    m = re.search(r"(?m)^BACKUP_ID=([0-9]{8}T[0-9]{6}Z-[a-f0-9]{12})$", snapshot.stdout)
    if not m or "BACKUP_STATUS=verified" not in snapshot.stdout or not ID.fullmatch(m.group(1)):
        raise Refused("postfix_configuration_backup_not_verified")
    selected = m.group(1)
    verified = run(["bash", recovery_path, "--verify", selected], timeout=90)
    if verified.returncode or "BACKUP_STATUS=verified" not in verified.stdout:
        raise Refused("postfix_configuration_backup_verify_failed")
    return selected


def rollback(recovery_path, backup_id):
    restored = run(["bash", recovery_path, "--restore", backup_id,
                    "--confirm", "AUTO_ROLLBACK_AFTER_FAILED_INSTALL"], timeout=120)
    return restored.returncode == 0 and "RESTORED_BACKUP_ID=" + backup_id in restored.stdout


def apply(hostname, domain, listener, expected_sha, confirm, recovery_path):
    if confirm != "MODIFY_PRIMARY_POSTFIX":
        raise Refused("explicit_primary_postfix_approval_required")
    if not HASH.fullmatch(expected_sha or ""):
        raise Refused("reviewed_preflight_sha256_required")
    if listener == "all":
        raise Refused("public_listener_requires_separate_authenticated_smtp_review")
    state = plan(hostname, domain, listener)
    if not state["ready"] or state["sha"] != expected_sha:
        raise Refused("reviewed_postfix_plan_changed")
    # Lock serializes this manager against itself; the two configuration
    # fingerprints and service state are checked AGAIN immediately pre-write.
    import fcntl
    lock = Path("/run/lock/linuxmailrelay365-postfix-basics.lock")
    fd = os.open(str(lock), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        state = plan(hostname, domain, listener)
        if state["sha"] != expected_sha:
            raise Refused("postfix_config_or_service_changed_before_apply")
        backup_id = backup(recovery_path)
        # Backup alone can take long enough to admit concurrent edits.
        if plan(hostname, domain, listener)["sha"] != expected_sha:
            raise Refused("postfix_changed_after_backup_no_mutation")
        edited = False
        try:
            for key in ("myhostname", "mydomain", "myorigin", "mydestination",
                        "inet_interfaces", "inet_protocols"):
                command = ["postconf", "-e", key + "=" + state["desired"][key]]
                edited = True
                if run(command).returncode:
                    raise Refused("postconf_update_failed")
            if run(["postfix", "check"], timeout=45).returncode:
                raise Refused("postfix_check_failed")
            if file_hash(MASTER) != hashlib.sha256(MASTER.read_bytes()).hexdigest():
                raise Refused("master_cf_changed_during_write")
            # inet_interfaces/inet_protocols need a RESTART (reload is
            # insufficient). The UI displays a strong disruption warning.
            if state["active_units"]:
                if run(["systemctl", "restart", state["active_units"][0]], timeout=75).returncode:
                    raise Refused("postfix_restart_failed")
                if state["active_units"] != active_units():
                    raise Refused("postfix_service_state_changed_after_restart")
            print("POSTFIX_BASICS_APPLIED=yes")
            print("POSTFIX_BASICS_BACKUP_ID=" + backup_id)
            print("POSTFIX_BASICS_SERVICE_RESTARTED=" +
                  ("yes" if state["active_units"] else "no"))
        except (Refused, OSError, subprocess.TimeoutExpired) as error:
            if edited:
                try:
                    recovered = rollback(recovery_path, backup_id)
                except Refused:
                    recovered = False
                raise Refused("apply_failed_backup_restore_" +
                              ("verified" if recovered else "uncertain") +
                              "_" + str(error))
            raise
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser()
    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument("--preview", action="store_true")
    commands.add_argument("--apply", action="store_true")
    commands.add_argument("--self-test", action="store_true")
    parser.add_argument("--hostname", default="")
    parser.add_argument("--domain", default="")
    parser.add_argument("--listener", default="loopback-only")
    parser.add_argument("--expected-sha256", default="")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--recovery-script", default="")
    opts = parser.parse_args(argv)
    try:
        if opts.self_test:
            validate_hostname("mail.example.com", "example.com")
            assert BASELINE["myorigin"] == "$mydomain"
            try:
                validate_hostname("mail.other.net", "example.com")
                raise AssertionError("domain mismatch accepted")
            except Refused:
                pass
            try:
                apply("mail.example.com", "example.com", "all", "", "", "")
                raise AssertionError("unsafe apply accepted")
            except Refused:
                pass
            print("POSTFIX_BASICS_SELF_TEST=pass")
            return 0
        if opts.preview:
            if opts.expected_sha256 or opts.confirm or opts.recovery_script:
                raise Refused("preview_must_not_accept_apply_approval")
            result = plan(opts.hostname, opts.domain, opts.listener)
            print("POSTFIX_BASICS_VERSION=1")
            print("POSTFIX_BASICS_PREFLIGHT=" +
                  ("ready" if result["ready"] else "blocked_public_listener"))
            print("POSTFIX_BASICS_PLAN_SHA256=" + result["sha"])
            print("POSTFIX_BASICS_PRIMARY_MAIN_SHA256=" + result["main"])
            print("POSTFIX_BASICS_SERVICE_ACTIVE=" +
                  ("yes" if result["active_units"] else "no"))
            print("POSTFIX_BASICS_RESTART_IF_APPLIED=" +
                  ("yes" if result["active_units"] else "no"))
            print("POSTFIX_BASICS_PREVIEW_ONLY=yes")
            print("CHANGES_APPLIED=no")
            return 0
        apply(opts.hostname, opts.domain, opts.listener,
              opts.expected_sha256, opts.confirm, opts.recovery_script)
        return 0
    except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("POSTFIX_BASICS_ERROR=" + str(error).replace("\n", "_"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
