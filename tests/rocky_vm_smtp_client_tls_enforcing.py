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
IDENTITY = "relay.lab.invalid"
SENDER = "sender@source.lab.invalid"
RECIPIENT = "sink@destination.lab.invalid"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def run(*args, data=None, timeout=60):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=ENV)
    if result.returncode:
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
        if run("postconf", "-h", key).strip():
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
                if not reader.readline(2049).startswith(b"EHLO "):
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
                    if not reader.readline(2049).startswith(b"EHLO "):
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
        raise RuntimeError("loopback TLS fixture failed: " + ",".join(outcome))
    wait_empty()
    if run("getenforce").strip() != b"Enforcing":
        raise RuntimeError("SELinux changed")
    print("LMR365_VM_CLIENT_TLS_" + label.upper() + "=presented_verified", flush=True)


def main():
    guard()
    os.umask(0o077)
    WORK.mkdir(mode=0o700)
    baseline = MAIN.read_bytes()
    master_sha = hashlib.sha256(MASTER.read_bytes()).hexdigest()
    # Synthetic mail may only leave through this local socket.
    run("postconf", "-e", "relayhost = [127.0.0.2]:25",
        "smtp_tls_security_level = encrypt", "smtp_sasl_auth_enable = no",
        "smtp_connection_cache_on_demand = no", "smtp_connection_cache_destinations =",
        "smtp_tls_loglevel = 1", "smtp_tls_wrappermode = no")
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
        run("restorecon", str(ROOT))
        if labels.prepare(ROOT, candidate, gen, adapter.trusted_binary) != "contexts_verified":
            raise RuntimeError("candidate SELinux labels not verified")
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
    if hashlib.sha256(MASTER.read_bytes()).hexdigest() != master_sha:
        raise RuntimeError("master.cf changed")
    # Restore only the disposable lab's baseline before later VM scenarios.
    run("systemctl", "stop", "postfix.service")
    MAIN.write_bytes(baseline)
    run("restorecon", str(MAIN))
    run("postfix", "check")
    run("systemctl", "start", "postfix.service")
    if MAIN.read_bytes() != baseline or run("postqueue", "-j").strip():
        raise RuntimeError("baseline restore failed")
    if run("getenforce").strip() != b"Enforcing":
        raise RuntimeError("SELinux no longer enforcing")
    # Only fixture directories created after the current-boot guard.
    shutil.rmtree(ROOT)
    shutil.rmtree(WORK)
    print("LMR365_VM_CLIENT_TLS_BASELINE=restored_exact_bytes")
    print("LMR365_VM_CLIENT_TLS_EXTERNAL_DELIVERY=no")


if __name__ == "__main__":
    main()
