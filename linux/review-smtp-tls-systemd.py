#!/usr/bin/env python3
"""Reviewed, create-only systemd setup for managed SMTP TLS."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
LIBEXEC = Path("/usr/local/libexec/linuxmailrelay365")
UNIT_DIR = Path("/etc/systemd/system")
ROOT = Path("/etc/postfix/lmr365-smtp-tls")
TIMER = "linuxmailrelay365-smtp-acme-renew.timer"
SERVICE = "linuxmailrelay365-smtp-acme-renew.service"
RECOVERY = ("linuxmailrelay365-smtp-tls-initial-recovery.service",
            "linuxmailrelay365-smtp-tls-prestart.service")
ACTIONS = ("inspect", "install", "enable-recovery", "enable-timer",
           "start-timer", "stop-timer", "disable-timer", "renew-now")
LIVE = ("enable-timer", "start-timer", "renew-now")
RUNTIME = (
    "test-smtp-acme-renewal.py", "manage-smtp-tls-process-renewal.py",
    "manage-smtp-tls-renewal.py", "manage-smtp-tls-initial.py",
    "smtp-tls-renewal-profile.py", "check-smtp-acme-credentials.py",
    "smtp-tls-postfix.py", "smtp-tls-generation.py", "smtp-tls-transaction.py",
    "smtp-tls-activate.py", "smtp-tls-validate-generation.py",
    "smtp-tls-selinux-prepare.py", "smtp-tls-process-renewal.py",
    "stage-smtp-relay-certificate.py", "check-smtp-relay-certificate.py",
    "smtp-tls-initial-backup.py", "smtp-tls-initial-candidate.py",
    "smtp-tls-initial-journal.py", "smtp-tls-initial-deploy.py",
    "plan-smtp-tls-initial.py", "check-smtp-tls-health.py", "smtp-tls-health-alerts.py")
FIELDS = ("LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath",
          "DropInPaths", "NeedDaemonReload", "Job", "Result", "ExecMainStatus",
          "NextElapseUSecRealtime", "LastTriggerUSec")


def load(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data):
    return hashlib.sha256(data).hexdigest()


def directory(path):
    for item in [path, *path.parents]:
        if not os.path.lexists(item):
            continue
        st = item.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("unsafe directory")


def read_regular(path):
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_size > 262144:
            raise ValueError("unsafe file")
        data = stream.read(262145)
        if len(data) > 262144:
            raise ValueError("file too large")
        return data


def runtime_plan():
    directory(LIBEXEC)
    rows = []
    for name in RUNTIME:
        wanted = digest(read_regular(SOURCE / name))
        target = LIBEXEC / name
        state = "create"
        if os.path.lexists(target):
            try:
                state = "unchanged" if digest(read_regular(target)) == wanted else "conflict"
            except (OSError, ValueError):
                state = "conflict"
        rows.append({"name": name, "sha256": wanted, "status": state})
    return rows


def systemctl(*args):
    binary = load("smtp-tls-postfix").trusted_binary("/usr/bin/systemctl")
    return subprocess.run([binary, *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=20, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def unit_state(name):
    try:
        result = systemctl("show", name, "--property=" + ",".join(FIELDS))
        if len(result.stdout) > 16384:
            return {}
        fields = {}
        for line in result.stdout.decode("utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key in FIELDS and len(value) <= 1024 and not any(ord(c) < 32 for c in value):
                if key in fields:
                    return {}
                fields[key] = value
        if result.returncode and fields.get("LoadState") != "not-found":
            return {}
        return fields if fields.get("LoadState") else {}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}


def exact_unit(row, state, missing_ok=False):
    if not state or state.get("DropInPaths") != "" or state.get("NeedDaemonReload") != "no":
        return False
    if row["status"] == "unchanged":
        return (state.get("LoadState") == "loaded"
                and state.get("FragmentPath") == str(UNIT_DIR / row["name"]))
    return (missing_ok and row["status"] == "create" and state.get("LoadState") == "not-found"
            and state.get("FragmentPath") == "")


def eligibility(action, runtime, units, states):
    if action == "inspect":
        return False, "read_only"
    if action in ("stop-timer", "disable-timer"):
        row = next(u for u in units if u["name"] == TIMER)
        return (True, "timer_only") if exact_unit(row, states.get(TIMER, {})) else (False, "timer_not_verified")
    if any(row["status"] == "conflict" for row in runtime + units):
        return False, "existing_file_conflict"
    if action == "install":
        for row in units:
            state = states.get(row["name"], {})
            if (not exact_unit(row, state, missing_ok=True)
                    or state.get("ActiveState") != "inactive"
                    or state.get("Job") not in ("", "0")
                    or state.get("UnitFileState", "") not in ("", "disabled", "static", "not-found")):
                return False, "installation_requires_inactive_disabled_units"
        return True, "create_only"
    if any(row["status"] != "unchanged" for row in runtime + units):
        return False, "complete_runtime_and_units_required"
    if not all(exact_unit(row, states.get(row["name"], {})) for row in units):
        return False, "effective_units_unverified_or_overridden"
    if action in LIVE:
        if any(states[name].get("UnitFileState") != "enabled" for name in RECOVERY):
            return False, "enable_boot_recovery_first"
        if states[SERVICE].get("ActiveState") not in ("inactive", "failed") or states[SERVICE].get("Job") not in ("", "0"):
            return False, "renewal_running_or_unknown"
    return True, "local_preflight_required"


def preflight(action):
    rotation = load("review-smtp-tls-rotation")
    if rotation.selinux_mode() not in ("disabled", "not_detected"):
        raise ValueError("SELinux requires review")
    pf = load("smtp-tls-postfix").Postfix()
    active = rotation.active_generation()
    if active is None:
        raise ValueError("no active generation")
    state = rotation.config_state(pf)
    rotation.terminal_journals(active, state["main_sha256"])
    pf.verify_managed()
    pf.run(pf.postfix, "status")
    result = {"active": active, "config": state}
    if action in LIVE:
        dry = load("review-smtp-acme-dry-run")
        plan, _, _ = dry.prepare()
        profile = load("smtp-tls-renewal-profile")
        data = profile.load()
        raw = read_regular(profile.BASE / "renewal" / (plan["lineage"] + ".conf"))
        _, params, _ = dry.parse_config(raw.decode("utf-8"))
        if params.get("server") != dry.PRODUCTION:
            raise ValueError("production CA required")
        gen = load("smtp-tls-generation")
        checker = load("check-smtp-relay-certificate")
        if load("smtp-tls-validate-generation").validate(ROOT, active, data["domain"], data["ca_file"], gen, checker).get("status") != "local_checks_passed":
            raise ValueError("active TLS validation failed")
        result.update(lineage=plan["lineage"], provider=plan["provider"], renewal_sha256=plan["plan_sha256"])
    return result


def review(action):
    directory(UNIT_DIR)
    runtime = runtime_plan()
    units = load("plan-smtp-tls-systemd").preview(SOURCE / "systemd", UNIT_DIR)
    states = {row["name"]: unit_state(row["name"]) for row in units["units"]}
    allowed, reason = eligibility(action, runtime, units["units"], states)
    tls = None
    if allowed and action in (*LIVE, "enable-recovery"):
        try:
            tls = preflight(action)
        except Exception:
            allowed, reason = False, "managed_tls_or_renewal_preflight_failed"
    stable = {name: {key: value.get(key) for key in FIELDS[:8]} for name, value in states.items()}
    material = {"action": action, "runtime": runtime, "unit_plan": units, "effective_units": stable,
                "tls": tls, "apply_supported": allowed, "reason": reason}
    sha = digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())
    return dict(material, status="review_ready", units=states, plan_sha256=sha,
                renewal_completion_verified=False, exchange_acceptance="unverified")


def create_runtime(rows):
    directory(LIBEXEC)
    LIBEXEC.mkdir(mode=0o755, parents=True, exist_ok=True)
    directory(LIBEXEC)
    created = []
    for row in rows:
        if row["status"] != "create":
            continue
        data = read_regular(SOURCE / row["name"])
        if digest(data) != row["sha256"]:
            raise ValueError("runtime changed")
        fd, temp = tempfile.mkstemp(prefix=".lmr365-", dir=str(LIBEXEC))
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                os.fchmod(stream.fileno(), 0o644)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temp, LIBEXEC / row["name"])
            created.append(row["name"])
        finally:
            os.unlink(temp)
    fd = os.open(LIBEXEC, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return created


def execute(action, expected, review_fn=review):
    plan = review_fn(action)
    if plan.get("plan_sha256") != expected or not plan.get("apply_supported") or action == "inspect":
        raise ValueError("review changed or unsupported")
    if action == "install":
        created = create_runtime(plan["runtime"])
        if any(row["status"] != "unchanged" for row in runtime_plan()):
            raise ValueError("runtime installation incomplete")
        planner = load("plan-smtp-tls-systemd")
        def reload():
            if systemctl("daemon-reload").returncode:
                raise ValueError("daemon reload failed")
        installed = load("install-smtp-tls-systemd").install(SOURCE / "systemd", UNIT_DIR,
            plan["unit_plan"], planner.preview, reload)
        return {"status": "installed", "runtime_created": len(created),
                "units_created": len(installed), "timer_started": False}
    result = subprocess.run([sys.executable, "-I", "-B", str(SOURCE / "manage-smtp-tls-systemd.py"),
        action, "--confirm", "MANAGE_TLS_UNITS"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=150, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    return {"status": "command_accepted" if result.returncode == 0 else "command_failed",
            "command_exit": result.returncode}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=ACTIONS)
    parser.add_argument("--expected-sha")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("root required")
        os.umask(0o077)
        if args.expected_sha is None:
            result = review(args.action)
        else:
            if not re.fullmatch(r"[a-f0-9]{64}", args.expected_sha):
                raise ValueError("review required")
            result = execute(args.action, args.expected_sha)
            result.update(action=args.action, plan_sha256=args.expected_sha,
                          renewal_completion_verified=False, exchange_acceptance="unverified")
        print(json.dumps(result))
        return 0
    except Exception:
        print(json.dumps({"status": "refused_or_failed", "renewal_completion_verified": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
