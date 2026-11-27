"""Disposable Rocky VM: timed processing of synthetic renewed TLS material.

Called only after the fixture proves an actual new boot and boot recovery.
Keep the production service sandbox. Override only ExecStart to bypass the
external CA and the timer schedule to make the test deterministic.
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

SERVICE = "linuxmailrelay365-smtp-acme-renew.service"
TIMER = "linuxmailrelay365-smtp-acme-renew.timer"
RECOVERY = "linuxmailrelay365-smtp-tls-recovery.service"
UNITS = (RECOVERY, SERVICE, TIMER)
HELPERS = ("manage-smtp-tls-process-renewal.py", "smtp-tls-process-renewal.py",
           "smtp-tls-renewal-profile.py", "smtp-tls-validate-generation.py",
           "smtp-tls-selinux-prepare.py", "stage-smtp-relay-certificate.py")
ACME = Path("/var/lib/linuxmailrelay365/smtp-acme")
LINEAGE = "relay.lab.invalid"
COMMAND = "/usr/bin/python3 /usr/local/libexec/linuxmailrelay365/manage-smtp-tls-process-renewal.py --profile --confirm PROCESS_RENEWED_TLS"


def properties(fixture, unit, *keys):
    raw = fixture.run("systemctl", "show", unit, "--property=" + ",".join(keys)).decode()
    values = {}
    for line in raw.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in keys or key in values:
            raise ValueError("unexpected systemd properties")
        values[key] = value
    if set(values) != set(keys):
        raise ValueError("missing systemd properties")
    return values


def service_state(fixture):
    return properties(fixture, SERVICE, "ActiveState", "Result", "ExecMainStatus",
                      "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic")


def completed(state, previous=0, failure=False):
    start = int(state["ExecMainStartTimestampMonotonic"])
    end = int(state["ExecMainExitTimestampMonotonic"])
    if not previous < start <= end:
        return False
    if failure:
        return (state["ActiveState"] == "failed" and state["Result"] == "exit-code"
                and int(state["ExecMainStatus"]) != 0)
    return (state["ActiveState"] == "inactive" and state["Result"] == "success"
            and state["ExecMainStatus"] == "0")


def lineage(fixture):
    base = ACME / "config"
    archive = base / "archive" / LINEAGE
    live = base / "live" / LINEAGE
    for path in (archive, live, base / "renewal", ACME / "work", ACME / "logs"):
        path.mkdir(parents=True, mode=0o700)
    for number, identity in ((1, "second"), (2, "renewed")):
        for label, source in (("cert", identity + ".pem"), ("chain", "ca.pem"), ("privkey", identity + ".key")):
            fixture.create_file(archive / (label + str(number) + ".pem"), (fixture.WORK / source).read_bytes())
    for label in ("cert", "chain", "privkey"):
        (live / (label + ".pem")).symlink_to("../../archive/" + LINEAGE + "/" + label + "2.pem")
    fixture.create_file(base / "renewal" / (LINEAGE + ".conf"), b"# synthetic lineage; CA never invoked\n")
    profile = {"version": 1, "lineage": LINEAGE, "domain": fixture.IDENTITY,
               "ca_file": str(fixture.WORK / "ca.pem")}
    fixture.create_file(fixture.ROOT / "renewal-profile.json", json.dumps(profile).encode())
    return live


def verify_units(fixture, dropins):
    for name in UNITS:
        state = properties(fixture, name, "FragmentPath", "DropInPaths", "NeedDaemonReload")
        path = fixture.UNIT_DIR / name
        if (state["FragmentPath"] != str(path) or state["NeedDaemonReload"] != "no"
                or state["DropInPaths"] != (str(dropins[name]) if name in dropins else "")
                or path.read_bytes() != (fixture.LIB / "systemd" / name).read_bytes()):
            raise ValueError("unexpected effective synthetic service unit")
    hardening = properties(fixture, SERVICE, "ExecStart", "NoNewPrivileges", "PrivateTmp",
                           "ProtectSystem", "ReadWritePaths")
    if (COMMAND not in hardening["ExecStart"] or "test-smtp-acme-renewal.py" in hardening["ExecStart"]
            or hardening["NoNewPrivileges"] != "yes" or hardening["PrivateTmp"] != "yes"
            or hardening["ProtectSystem"] != "strict"
            or not {str(ACME), str(fixture.ROOT), "/var/spool/postfix", "/var/lib/postfix"}
                .issubset(hardening["ReadWritePaths"].split())):
        raise ValueError("synthetic service sandbox differs from product")


def expected_generation(fixture):
    key = (fixture.WORK / "renewed.key").read_bytes().rstrip()
    cert = (fixture.WORK / "renewed.pem").read_bytes().rstrip()
    ca = (fixture.WORK / "ca.pem").read_bytes()
    return "candidate-" + hashlib.sha256(key + b"\n" + cert + b"\n" + ca).hexdigest()


def run(fixture):
    # Caller already checked real Rocky, changed boot ID and confined Postfix.
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or fixture.run("hostname", "-s").strip() != b"rocky-selinux-ci"
            or fixture.run("getenforce").strip() != b"Enforcing"):
        raise ValueError("disposable enforcing guest required")
    targets = [ACME, fixture.ROOT / "renewal-profile.json"]
    targets += [fixture.UNIT_DIR / name for name in UNITS]
    targets += [fixture.UNIT_DIR / (name + ".d") for name in (SERVICE, TIMER)]
    targets += [fixture.PRODUCT_LIB / name for name in HELPERS]
    if any(os.path.lexists(p) for p in targets):
        raise ValueError("preexisting synthetic renewal state")
    parent_created = not os.path.lexists(ACME.parent)
    ACME.parent.mkdir(mode=0o755, exist_ok=True)
    st = ACME.parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError("unsafe synthetic ACME parent")
    live = lineage(fixture)
    gen = fixture.load("smtp-tls-generation")
    previous = gen.current(fixture.ROOT)
    wanted = expected_generation(fixture)
    if not previous or previous == wanted or os.path.lexists(fixture.ROOT / wanted):
        raise ValueError("new synthetic certificate required")
    main_sha = fixture.sha(fixture.MAIN.read_bytes())
    master_sha = fixture.sha(fixture.MASTER.read_bytes())
    for name in HELPERS:
        fixture.create_file(fixture.PRODUCT_LIB / name, (fixture.LIB / name).read_bytes(), 0o644)
    for name in UNITS:
        fixture.create_file(fixture.UNIT_DIR / name, (fixture.LIB / "systemd" / name).read_bytes(), 0o644)
    overrides = {SERVICE: "[Service]\nExecStart=\nExecStart=" + COMMAND + "\n",
                 TIMER: "[Timer]\nOnCalendar=\nOnActiveSec=2s\nAccuracySec=1s\nRandomizedDelaySec=0\nPersistent=false\n"}
    dropins = {}
    for name, content in overrides.items():
        directory = fixture.UNIT_DIR / (name + ".d")
        directory.mkdir(mode=0o755)
        dropins[name] = directory / "99-lmr365-disposable-test.conf"
        fixture.create_file(dropins[name], content.encode(), 0o644)
    for path in (fixture.PRODUCT_LIB, ACME):
        fixture.run("restorecon", "-R", str(path))
    fixture.run("restorecon", str(fixture.ROOT / "renewal-profile.json"))
    for name in UNITS:
        fixture.run("restorecon", str(fixture.UNIT_DIR / name))
    for path in dropins.values():
        fixture.run("restorecon", "-R", str(path.parent))
    fixture.run("systemctl", "daemon-reload")
    verify_units(fixture, dropins)
    old_start = int(service_state(fixture)["ExecMainStartTimestampMonotonic"])
    fixture.run("systemctl", "start", TIMER)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        state = service_state(fixture)
        if completed(state, old_start):
            break
        if state["ActiveState"] == "failed":
            raise RuntimeError("synthetic renewal service failed")
        time.sleep(1)
    else:
        raise RuntimeError("synthetic renewal service timeout")
    timer = properties(fixture, TIMER, "LastTriggerUSecMonotonic", "Unit")
    if (timer["Unit"] != SERVICE or not 0 < int(timer["LastTriggerUSecMonotonic"])
            <= int(state["ExecMainStartTimestampMonotonic"])):
        raise ValueError("timer trigger not verified")
    fixture.run("systemctl", "stop", TIMER)
    if gen.current(fixture.ROOT) != wanted:
        raise ValueError("new certificate not activated")
    gen.validate(fixture.ROOT, wanted)
    journal = fixture.ROOT / "deployment.json"
    saved = journal.read_bytes()
    if json.loads(saved) != {"version": 1, "phase": "verified", "previous": previous, "candidate": wanted}:
        raise ValueError("renewal activation journal mismatch")
    fixture.probe("renewed", "timer_renewal")
    print("LMR365_VM_CLIENT_TLS_TIMER=synthetic_material_processed", flush=True)
    # A repeated service run with the same generation must be a no-op.
    old_start = int(state["ExecMainStartTimestampMonotonic"])
    fixture.run("systemctl", "start", SERVICE, timeout=180)
    state = service_state(fixture)
    if (not completed(state, old_start) or gen.current(fixture.ROOT) != wanted
            or journal.read_bytes() != saved):
        raise ValueError("unchanged renewal modified active transaction")
    print("LMR365_VM_CLIENT_TLS_RENEWAL_UNCHANGED=verified", flush=True)
    # Certbot archive versions must not be mixed. A bad lineage must fail
    # before switching or rewriting the active certificate.
    link = live / "privkey.pem"
    link.unlink()
    link.symlink_to("../../archive/" + LINEAGE + "/privkey1.pem")
    old_start = int(state["ExecMainStartTimestampMonotonic"])
    result = subprocess.run(["systemctl", "start", SERVICE], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=180, env=fixture.ENV)
    if (result.returncode == 0 or not completed(service_state(fixture), old_start, failure=True)
            or gen.current(fixture.ROOT) != wanted or journal.read_bytes() != saved):
        raise ValueError("mixed renewal lineage was not refused")
    fixture.probe("renewed", "renewal_refusal")
    print("LMR365_VM_CLIENT_TLS_RENEWAL_MIXED=refused", flush=True)
    if (fixture.sha(fixture.MAIN.read_bytes()) != main_sha
            or fixture.sha(fixture.MASTER.read_bytes()) != master_sha
            or fixture.run("getenforce").strip() != b"Enforcing"):
        raise ValueError("renewal changed configuration or enforcement")
    fixture.run("systemctl", "reset-failed", SERVICE)
    fixture.run("systemctl", "stop", SERVICE, RECOVERY)
    for name in UNITS:
        (fixture.UNIT_DIR / name).unlink()
    for path in dropins.values():
        path.unlink()
        path.parent.rmdir()
    fixture.run("systemctl", "daemon-reload")
    (fixture.ROOT / "renewal-profile.json").unlink()
    shutil.rmtree(ACME)
    if parent_created:
        ACME.parent.rmdir()
    print("LMR365_VM_CLIENT_TLS_RENEWAL_REAL_CA=no", flush=True)
