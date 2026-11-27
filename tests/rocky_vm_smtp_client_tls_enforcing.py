#!/usr/bin/env python3
"""Disposable Rocky VM only: actual Postfix SMTP client certificate acceptance.

Synthetic CA, two identities and a loopback SMTP sink. No external relay.
Never run on a production host. Does not change the GUI Enforcing gate.
"""
import hashlib
import importlib.util
import json
import os
import re
import socket
import ssl
import stat
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

LIB = Path("/usr/local/libexec/lmr365-kvm-client-tls")
WORK = Path("/etc/postfix/lmr365-kvm-client-tls")
ROOT = Path("/etc/postfix/lmr365-smtp-tls")
MARKER = Path("/run/lmr365-disposable-client-tls-vm")
MAIN = Path("/etc/postfix/main.cf")
MASTER = Path("/etc/postfix/master.cf")
PRODUCT_LIB = Path("/usr/local/libexec/linuxmailrelay365")
UNIT_DIR = Path("/etc/systemd/system")
BOOT_UNITS = ("linuxmailrelay365-smtp-tls-initial-recovery.service",
              "linuxmailrelay365-smtp-tls-prestart.service")
BOOT_HELPERS = ("manage-smtp-tls-initial.py", "manage-smtp-tls-renewal.py",
                "smtp-tls-generation.py", "smtp-tls-transaction.py", "smtp-tls-activate.py",
                "smtp-tls-postfix.py", "smtp-tls-initial-backup.py", "smtp-tls-initial-candidate.py",
                "smtp-tls-initial-journal.py", "smtp-tls-initial-deploy.py",
                "plan-smtp-tls-initial.py", "check-smtp-relay-certificate.py")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
IDENTITY = "relay.lab.invalid"
SENDER = "sender@source.lab.invalid"
RECIPIENT = "sink@destination.lab.invalid"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def run(*args, data=None, timeout=60):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=ENV)
    if result.returncode:
        if any(str(arg).endswith("/manage-smtp-tls-initial.py") for arg in args):
            # Only fixed product status markers and the journal phase from
            # this disposable synthetic fixture, not subprocess stderr.
            for line in result.stdout.decode("ascii", "replace").splitlines():
                if line in ("INITIAL_TLS=failed; inspect transaction journal", "INITIAL_TLS=unchanged"):
                    print("LMR365_VM_CLIENT_TLS_INITIAL_HELPER=" + line, flush=True)
            try:
                phase = json.loads((ROOT / "initial-deployment.json").read_text())["phase"]
                if phase in ("prepared", "switched", "rollback_required", "rolled_back", "verified"):
                    print("LMR365_VM_CLIENT_TLS_INITIAL_JOURNAL=" + phase, flush=True)
            except (OSError, ValueError, KeyError):
                print("LMR365_VM_CLIENT_TLS_INITIAL_JOURNAL=unavailable", flush=True)
        raise RuntimeError("lab command failed: " + Path(args[0]).name)
    return result.stdout


def load(name):
    spec = importlib.util.spec_from_file_location(name, LIB / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def guard():
    if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("disposable guest only")
    st = MARKER.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1:
        raise RuntimeError("invalid guest marker")
    if MARKER.read_text().strip() != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
        raise RuntimeError("wrong guest boot")
    if Path("/proc/1/comm").read_text().strip() != "systemd" or run("getenforce").strip() != b"Enforcing":
        raise RuntimeError("real enforcing systemd required")
    if Path("/sys/fs/selinux/enforce").read_text().strip() != "1":
        raise RuntimeError("SELinux kernel not enforcing")
    if b'ID="rocky"' not in Path("/etc/os-release").read_bytes() and b"\nID=rocky\n" not in Path("/etc/os-release").read_bytes():
        raise RuntimeError("Rocky required")
    if run("hostname", "-s").strip() != b"rocky-selinux-ci":
        raise RuntimeError("unexpected lab hostname")
    if run("postconf", "-h", "inet_interfaces").strip() != b"loopback-only" or run("postconf", "-h", "inet_protocols").strip() != b"ipv4":
        raise RuntimeError("private listener required")
    if run("postqueue", "-j").strip() or run("postconf", "-h", "relayhost").strip():
        raise RuntimeError("nonempty queue or foreign relay")
    if os.path.lexists(ROOT) or os.path.lexists(WORK):
        raise RuntimeError("preexisting TLS state")
    for path in (MAIN, MASTER):
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or st.st_mode & 0o022:
            raise RuntimeError("unsafe fixture config")
    for key in ("transport_maps", "sender_dependent_relayhost_maps", "sender_dependent_default_transport_maps",
                "smtp_fallback_relay", "content_filter", "canonical_maps", "virtual_alias_maps"):
        # Expand Postfix defaults such as smtp_fallback_relay = $fallback_relay.
        if run("postconf", "-h", "-x", key).strip():
            raise RuntimeError("nonstandard lab route: " + key)
    MARKER.unlink()


def certificates():
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=Disposable client TLS CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout", str(WORK / "ca.key"), "-out", str(WORK / "ca.pem"))
    for name, cn, purpose, san in (
            ("server", "sink.lab.invalid", "serverAuth", "DNS:sink.lab.invalid,IP:127.0.0.2"),
            ("first", IDENTITY, "clientAuth", "DNS:" + IDENTITY),
            ("second", IDENTITY, "clientAuth", "DNS:" + IDENTITY)):
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + cn,
            "-keyout", str(WORK / (name + ".key")), "-out", str(WORK / (name + ".csr")))
        ext = WORK / (name + ".ext")
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=" + purpose + "\nsubjectAltName=" + san + "\n")
        run("openssl", "x509", "-req", "-in", str(WORK / (name + ".csr")),
            "-CA", str(WORK / "ca.pem"), "-CAkey", str(WORK / "ca.key"), "-CAcreateserial",
            "-days", "2", "-sha256", "-extfile", str(ext), "-out", str(WORK / (name + ".pem")))


def fingerprint(name):
    return hashlib.sha256(run("openssl", "x509", "-in", str(WORK / (name + ".pem")), "-outform", "DER")).hexdigest()


def wait_empty():
    for _ in range(40):
        if not run("postqueue", "-j").strip():
            return
        time.sleep(0.5)
    raise RuntimeError("synthetic queue did not drain")


def sink(listener, expected, token, outcome):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(WORK / "server.pem"), str(WORK / "server.key"))
        context.load_verify_locations(cafile=str(WORK / "ca.pem"))
        context.verify_mode = ssl.CERT_REQUIRED
        with listener.accept()[0] as conn:
            conn.settimeout(15)
            conn.sendall(b"220 sink.lab.invalid ESMTP\r\n")
            with conn.makefile("rb") as reader:
                if not reader.readline(2049).upper().startswith(b"EHLO "):
                    raise ValueError("EHLO required")
                conn.sendall(b"250-sink.lab.invalid\r\n250 STARTTLS\r\n")
                if reader.readline(2049).strip().upper() != b"STARTTLS":
                    raise ValueError("STARTTLS required")
                conn.sendall(b"220 Ready\r\n")
            with context.wrap_socket(conn, server_side=True) as tls:
                if hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest() != expected:
                    raise ValueError("wrong presented client certificate")
                if tls.version() not in ("TLSv1.2", "TLSv1.3"):
                    raise ValueError("wrong TLS protocol")
                if not any("postfix_smtp_t" in line for line in run("ps", "-eZ").decode().splitlines()):
                    raise ValueError("confined Postfix SMTP process not observed")
                with tls.makefile("rb") as reader:
                    if not reader.readline(2049).upper().startswith(b"EHLO "):
                        raise ValueError("post-TLS EHLO required")
                    tls.sendall(b"250 sink.lab.invalid\r\n")
                    if reader.readline(2049).strip().upper() != ("MAIL FROM:<" + SENDER + ">").encode().upper():
                        raise ValueError("unexpected synthetic sender")
                    tls.sendall(b"250 OK\r\n")
                    if reader.readline(2049).strip().upper() != ("RCPT TO:<" + RECIPIENT + ">").encode().upper():
                        raise ValueError("unexpected synthetic recipient")
                    tls.sendall(b"250 OK\r\n")
                    if reader.readline(2049).strip().upper() != b"DATA":
                        raise ValueError("DATA required")
                    tls.sendall(b"354 End with dot\r\n")
                    body = bytearray()
                    for _ in range(100):
                        line = reader.readline(4097)
                        if not line or len(line) > 4096:
                            raise ValueError("invalid fixture body")
                        if line == b".\r\n":
                            break
                        body.extend(line)
                    else:
                        raise ValueError("fixture body too long")
                    if token.encode() not in body:
                        raise ValueError("fixture token missing")
                    tls.sendall(b"250 fixture accepted\r\n")
                    if reader.readline(2049).strip().upper() != b"QUIT":
                        raise ValueError("QUIT required")
                    tls.sendall(b"221 Bye\r\n")
        outcome.append("verified")
    except Exception as exc:
        outcome.append(type(exc).__name__)


def probe(name, label):
    expected = fingerprint(name)
    token = "LMR365-LOCAL-ONLY-" + label
    outcome = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.2", 25))
        listener.listen(1)
        listener.settimeout(50)
        thread = threading.Thread(target=sink, args=(listener, expected, token, outcome), daemon=True)
        thread.start()
        message = ("From: " + SENDER + "\nTo: " + RECIPIENT + "\nSubject: " + token + "\n\n" + token + "\n").encode()
        run("/usr/sbin/sendmail", "-i", "-f", SENDER, "--", RECIPIENT, data=message)
        thread.join(80)
    if outcome != ["verified"]:
        # Bounded logs in the disposable synthetic guest only.
        try:
            logs = run("journalctl", "--no-pager", "-o", "cat", "-n", "30",
                       "-t", "postfix/smtp", "-t", "postfix/qmgr", timeout=10)
            print("LMR365_VM_CLIENT_TLS_FAILURE_LOG_BEGIN", flush=True)
            print(logs[-12000:].decode("utf-8", "replace"), flush=True)
            print("LMR365_VM_CLIENT_TLS_FAILURE_LOG_END", flush=True)
        except Exception:
            print("LMR365_VM_CLIENT_TLS_FAILURE_LOG=unavailable", flush=True)
        raise RuntimeError("loopback TLS fixture failed: " + ",".join(outcome))
    wait_empty()
    if run("getenforce").strip() != b"Enforcing":
        raise RuntimeError("SELinux changed")
    print("LMR365_VM_CLIENT_TLS_" + label.upper() + "=presented_verified", flush=True)


def boot_id():
    value = BOOT_ID.read_text().strip()
    if not re.fullmatch(r"[a-f0-9-]{36}", value):
        raise ValueError("invalid boot ID")
    return value


def sha(data):
    return hashlib.sha256(data).hexdigest()


def create_file(path, data, mode=0o600):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def verify_units():
    if run("systemctl", "is-enabled", "postfix.service").strip() != b"enabled":
        raise ValueError("Postfix automatic startup not enabled")
    for helper in BOOT_HELPERS:
        path = PRODUCT_LIB / helper
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022
                or st.st_nlink != 1 or path.read_bytes() != (LIB / helper).read_bytes()):
            raise ValueError("fixture recovery helper changed")
    for name in BOOT_UNITS:
        source, target = LIB / "systemd" / name, UNIT_DIR / name
        st = target.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022
                or st.st_nlink != 1 or target.read_bytes() != source.read_bytes()):
            raise ValueError("fixture recovery unit changed")
        if (run("systemctl", "show", name, "--property=FragmentPath", "--value").decode().strip() != str(target)
                or run("systemctl", "show", name, "--property=DropInPaths", "--value").strip()
                or run("systemctl", "show", name, "--property=NeedDaemonReload", "--value").strip() != b"no"):
            raise ValueError("effective recovery unit unverified")
        if run("systemctl", "is-enabled", name).strip() != b"enabled":
            raise ValueError("boot recovery unit not enabled")
    required = run("systemctl", "show", "postfix.service", "--property=Requires", "--value").decode().split()
    if not all(name in required for name in BOOT_UNITS):
        raise ValueError("Postfix boot recovery dependencies missing")
    for name in BOOT_UNITS:
        before = run("systemctl", "show", name, "--property=Before", "--value").decode().split()
        if "postfix.service" not in before:
            raise ValueError("recovery ordering missing")


def install_boot_recovery():
    if os.path.lexists(PRODUCT_LIB) or any(os.path.lexists(UNIT_DIR / name) for name in BOOT_UNITS):
        raise ValueError("existing product recovery installation")
    PRODUCT_LIB.mkdir(mode=0o755)
    for name in BOOT_HELPERS:
        create_file(PRODUCT_LIB / name, (LIB / name).read_bytes(), 0o644)
    for name in BOOT_UNITS:
        create_file(UNIT_DIR / name, (LIB / "systemd" / name).read_bytes(), 0o644)
    run("restorecon", "-R", str(PRODUCT_LIB))
    for name in BOOT_UNITS:
        run("restorecon", str(UNIT_DIR / name))
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", *BOOT_UNITS)
    verify_units()


def prepare_reboot(baseline, master_sha, first, second, gen, tx):
    # This is reached only after the current-boot disposable guard and the
    # existing successful local delivery/recovery probes.
    install_boot_recovery()
    with tx.deployment_lock(ROOT):
        tx.record(ROOT, second, first, "prepared")
        gen.switch(ROOT, first, second)
        tx.record(ROOT, second, first, "switched")
    if gen.current(ROOT) != first:
        raise ValueError("interrupted rotation not staged")
    create_file(WORK / "baseline.cf", baseline)
    state = {"version": 1, "boot_id": boot_id(), "previous": second, "candidate": first,
             "baseline_sha256": sha(baseline), "main_sha256": sha(MAIN.read_bytes()),
             "master_sha256": master_sha}
    create_file(WORK / "reboot.json", json.dumps(state, sort_keys=True).encode())
    os.sync()
    print("LMR365_VM_CLIENT_TLS_REBOOT_PREPARED=switched", flush=True)


def verify_boot_event(rows, unit, message, current_boot, postfix_active):
    events = [row for row in rows if row.get("_SYSTEMD_UNIT") == unit
              and row.get("_BOOT_ID") == current_boot.replace("-", "")
              and row.get("MESSAGE") == message]
    if len(events) != 1:
        raise ValueError("missing or ambiguous current-boot recovery event")
    stamp = int(events[0]["__MONOTONIC_TIMESTAMP"])
    if not 0 < stamp < postfix_active:
        raise ValueError("recovery was not observed before Postfix activation")


def verify_reboot():
    os_release = Path("/etc/os-release").read_bytes()
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or (b'ID="rocky"' not in os_release and b"\nID=rocky\n" not in os_release)
            or run("hostname", "-s").strip() != b"rocky-selinux-ci"
            or Path("/proc/1/comm").read_text().strip() != "systemd"
            or run("getenforce").strip() != b"Enforcing"
            or Path("/sys/fs/selinux/enforce").read_text().strip() != "1"):
        raise RuntimeError("disposable enforcing guest required")
    backup = load("smtp-tls-initial-backup")
    state = json.loads(backup.read_private(WORK / "reboot.json", 8192), object_pairs_hook=backup.strict_object)
    baseline = backup.read_private(WORK / "baseline.cf", 8388608)
    current_boot = boot_id()
    if (set(state) != {"version", "boot_id", "previous", "candidate", "baseline_sha256",
                       "main_sha256", "master_sha256"} or state["version"] != 1
            or not re.fullmatch(r"[a-f0-9-]{36}", state["boot_id"]) or state["boot_id"] == current_boot
            or sha(baseline) != state["baseline_sha256"] or sha(MAIN.read_bytes()) != state["main_sha256"]
            or sha(MASTER.read_bytes()) != state["master_sha256"]):
        raise ValueError("fixture reboot evidence changed")
    gen = load("smtp-tls-generation")
    for name in ("previous", "candidate"):
        gen.validate(ROOT, state[name])
    if state["previous"] == state["candidate"] or gen.current(ROOT) != state["previous"]:
        raise ValueError("previous certificate not restored")
    journal = json.loads(backup.read_private(ROOT / "deployment.json", 16384), object_pairs_hook=backup.strict_object)
    if journal != {"version": 1, "phase": "rolled_back", "previous": state["previous"], "candidate": state["candidate"]}:
        raise ValueError("rotation recovery journal mismatch")
    verify_units()
    run("systemctl", "is-active", "--quiet", "postfix.service")
    active = int(run("systemctl", "show", "postfix.service", "--property=ActiveEnterTimestampMonotonic", "--value"))
    for unit, message in zip(BOOT_UNITS, ("INITIAL_TLS=unchanged", "TLS_TRANSACTION=restored")):
        rows = [json.loads(line) for line in run("journalctl", "-b", "-u", unit, "--no-pager",
                "-n", "100", "-o", "json").splitlines()]
        verify_boot_event(rows, unit, message, current_boot, active)
    print("LMR365_VM_CLIENT_TLS_REBOOT_ORDER=verified_before_postfix", flush=True)
    if (run("postconf", "-h", "-x", "relayhost").strip() != b"[127.0.0.2]:25"
            or run("postconf", "-h", "-x", "smtp_fallback_relay").strip()
            or run("postqueue", "-j").strip()):
        raise ValueError("isolated fixture route not verified after reboot")
    probe("second", "boot_recovery")
    run("systemctl", "stop", "postfix.service")
    run("systemctl", "disable", *BOOT_UNITS)
    for name in BOOT_UNITS:
        (UNIT_DIR / name).unlink()
    run("systemctl", "daemon-reload")
    shutil.rmtree(PRODUCT_LIB)
    restore_baseline(baseline, state["master_sha256"])


def restore_baseline(baseline, master_sha):
    if hashlib.sha256(MASTER.read_bytes()).hexdigest() != master_sha:
        raise RuntimeError("master.cf changed")
    run("systemctl", "stop", "postfix.service")
    MAIN.write_bytes(baseline)
    run("restorecon", str(MAIN))
    run("postfix", "check")
    run("systemctl", "start", "postfix.service")
    if MAIN.read_bytes() != baseline or run("postqueue", "-j").strip():
        raise RuntimeError("baseline restore failed")
    if run("getenforce").strip() != b"Enforcing":
        raise RuntimeError("SELinux no longer enforcing")
    shutil.rmtree(ROOT)
    shutil.rmtree(WORK)
    print("LMR365_VM_CLIENT_TLS_BASELINE=restored_exact_bytes")
    print("LMR365_VM_CLIENT_TLS_EXTERNAL_DELIVERY=no")


def main(prepare_boot=False):
    guard()
    os.umask(0o077)
    WORK.mkdir(mode=0o700)
    baseline = MAIN.read_bytes()
    master_sha = hashlib.sha256(MASTER.read_bytes()).hexdigest()
    # Synthetic mail may only leave through this local socket.
    run("postconf", "-e", "relayhost = [127.0.0.2]:25",
        "smtp_tls_security_level = encrypt", "smtp_sasl_auth_enable = no",
        "smtp_connection_cache_on_demand = no", "smtp_connection_cache_destinations =",
        "smtp_tls_loglevel = 1", "smtp_tls_wrappermode = no", "smtp_fallback_relay =")
    if (run("postconf", "-h", "-x", "relayhost").strip() != b"[127.0.0.2]:25" or
            run("postconf", "-h", "-x", "smtp_fallback_relay").strip()):
        raise RuntimeError("loopback-only relay not verified")
    run("postfix", "reload")
    certificates()
    stage = load("stage-smtp-relay-certificate")
    gen = load("smtp-tls-generation")
    tx = load("smtp-tls-transaction")
    activate = load("smtp-tls-activate")
    checker = load("check-smtp-relay-certificate")
    validator = load("smtp-tls-validate-generation")
    labels = load("smtp-tls-selinux-prepare")
    adapter = load("smtp-tls-postfix")
    pf = adapter.Postfix()
    def stage_one(name):
        candidate = stage.stage(str(WORK / (name + ".pem")), str(WORK / "ca.pem"),
                                str(WORK / (name + ".key")), IDENTITY, str(WORK / "ca.pem"))
        # This root was created by this disposable fixture, not inherited from a user.
        run("restorecon", "-F", str(ROOT))
        try:
            if labels.prepare(ROOT, candidate, gen, adapter.trusted_invocation) != "contexts_verified":
                raise RuntimeError("candidate SELinux labels not verified")
        except Exception:
            # Report only label metadata of the synthetic fixture, never keys.
            for path in (ROOT, ROOT / candidate, *(ROOT / candidate / x for x in
                         ("client-chain.pem", "fullchain.pem", "key.pem"))):
                try:
                    actual = os.getxattr(str(path), "security.selinux", follow_symlinks=False).rstrip(b"\x00")
                    expected = run("matchpathcon", "-n", str(path)).strip()
                    print("LMR365_VM_CLIENT_TLS_CONTEXT", path.name,
                          "actual=" + actual.decode("ascii"), "expected=" + expected.decode("ascii"), flush=True)
                except Exception:
                    print("LMR365_VM_CLIENT_TLS_CONTEXT=unavailable", flush=True)
            raise
        print("LMR365_VM_CLIENT_TLS_CANDIDATE_CONTEXTS=verified", flush=True)
        return candidate
    first, second = stage_one("first"), stage_one("second")
    def validate(candidate):
        result = validator.validate(ROOT, candidate, IDENTITY, str(WORK / "ca.pem"), gen, checker)
        if result["status"] != "local_checks_passed":
            raise RuntimeError("candidate check failed")
    with tx.deployment_lock(ROOT):
        gen.switch(ROOT, first, None)
    run("restorecon", str(ROOT / "active"))
    builder = load("smtp-tls-initial-candidate")
    initial = builder.preview(MAIN.read_bytes())
    # Identify the exact failed phase without exposing private file contents.
    planner = load("plan-smtp-tls-initial")
    try:
        plan = planner.plan_postfix(pf)
        if not plan["changes"]:
            raise ValueError("fixture expected new TLS configuration")
    except (ValueError, RuntimeError) as exc:
        # These planner errors are fixed messages, never configuration values.
        print("LMR365_VM_CLIENT_TLS_INITIAL_PREFLIGHT=" + str(exc), flush=True)
        raise
    print("LMR365_VM_CLIENT_TLS_INITIAL_PREFLIGHT=verified", flush=True)
    validate(first)
    print("LMR365_VM_CLIENT_TLS_INITIAL_MATERIAL=verified", flush=True)
    result = run(sys.executable, "-I", "-B", str(LIB / "manage-smtp-tls-initial.py"),
                 "--confirm", "INITIAL_TLS_DEPLOYMENT", "--original-sha", initial["original_sha256"],
                 "--candidate-sha", initial["candidate_sha256"], "--generation", first,
                 "--domain", IDENTITY, "--ca-file", str(WORK / "ca.pem"))
    if result.strip() != b"INITIAL_TLS=reloaded":
        raise RuntimeError("initial deployment not verified")
    probe("first", "initial")
    def rotate(candidate):
        if activate.activate(ROOT, candidate, gen, tx, pf.check, pf.reload, validate) != "reloaded":
            raise RuntimeError("rotation not verified")
    rotate(second)
    probe("second", "rotation")
    # Inject one reload failure into the real transaction. The rollback
    # callback then executes the actual Postfix reload.
    calls = [0]
    def fail_once():
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("synthetic reload failure")
        pf.reload()
    try:
        activate.activate(ROOT, first, gen, tx, pf.check, fail_once, validate)
    except RuntimeError as exc:
        if str(exc) != "synthetic reload failure":
            raise
    else:
        raise RuntimeError("failure was not propagated")
    if calls[0] != 2 or gen.current(ROOT) != second or json.loads((ROOT / "deployment.json").read_text())["phase"] != "rolled_back":
        raise RuntimeError("rollback not verified")
    probe("second", "rollback")
    # Simulate a durable interrupted switch, then use the real recovery primitive.
    with tx.deployment_lock(ROOT):
        tx.record(ROOT, second, first, "prepared")
        gen.switch(ROOT, first, second)
        tx.record(ROOT, second, first, "switched")
    if activate.recover(ROOT, gen, tx, pf.check, pf.reload) != "restored" or gen.current(ROOT) != second:
        raise RuntimeError("interrupted transaction recovery failed")
    probe("second", "recovery")
    if prepare_boot:
        prepare_reboot(baseline, master_sha, first, second, gen, tx)
    else:
        restore_baseline(baseline, master_sha)


if __name__ == "__main__":
    if sys.argv[1:] == ["--prepare-reboot"]:
        main(prepare_boot=True)
    elif sys.argv[1:] == ["--verify-reboot"]:
        verify_reboot()
    elif not sys.argv[1:]:
        main()
    else:
        raise SystemExit("invalid fixture arguments")
