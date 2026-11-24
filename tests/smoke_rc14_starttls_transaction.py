#!/usr/bin/env python3
"""RC14 offline transaction + native authenticated STARTTLS in a disposable lab."""
from contextlib import ExitStack
from email.message import EmailMessage
import grp
import importlib.util
import json
import os
from pathlib import Path
import queue
import smtplib
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
CONF = Path("/etc/postfix")
QUEUE = Path("/var/spool/postfix")
LOG = Path("/var/log/postfix-rc14-lab.log")
MAILBOX = Path("/var/mail/lmrfixture")
BASE_HOST, TARGET_HOST = "default.lab.invalid", "target.lab.invalid"
BASE_PORT, MAP_PORT = 46510, 46517
SENDER, REMOTE, LOCAL = "mapped@sender.invalid", "recipient@remote.invalid", "lmrfixture@local.invalid"


def check(ok, why):
    if not ok:
        raise RuntimeError(why)


def run(*args, **kwargs):
    return subprocess.run(args, check=kwargs.get("check", True),
                          capture_output=True, text=True, timeout=20)


def wait(pred, what, seconds=22):
    deadline = time.monotonic() + seconds
    while True:
        value = pred()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise RuntimeError("timeout: " + what)
        time.sleep(0.15)


def listener():
    try:
        with smtplib.SMTP("127.0.0.1", 25, timeout=1) as client:
            return client.noop()[0] == 250
    except (OSError, smtplib.SMTPException):
        return False


def queue_clear():
    return not any(p.is_file() or p.is_symlink()
                   for name in ("active", "incoming", "deferred", "hold", "maildrop", "corrupt")
                   for p in (QUEUE / name).rglob("*"))


def guard():
    status = run("postfix", "status", check=False)
    check(status.returncode != 0 and "not running" in status.stderr + status.stdout
          and not listener() and queue_clear(), "offline/empty lab maintenance gate failed")


def stop():
    run("postfix", "stop")
    wait(lambda: not listener(), "Postfix listener to stop")
    guard()


def start():
    run("postfix", "check")
    run("postfix", "start")
    wait(listener, "Postfix listener")


def credentials(directory):
    directory.chmod(0o755)
    ca = directory / "ca.pem"
    cakey = directory / "ca.key"
    run("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-subj", "/CN=Only the disposable Postfix lab CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(cakey), "-out", str(ca))
    ca.chmod(0o644)
    result = {}
    for host in (BASE_HOST, TARGET_HOST, "wrong.lab.invalid"):
        key = directory / (host + ".key")
        csr = directory / (host + ".csr")
        crt = directory / (host + ".pem")
        cnf = directory / (host + ".ext")
        cnf.write_text("subjectAltName = DNS:" + host + "\nextendedKeyUsage = serverAuth\n",
                       encoding="ascii")
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
            "/CN=" + host, "-keyout", str(key), "-out", str(csr))
        run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
            "-CAkey", str(cakey), "-CAcreateserial", "-days", "1",
            "-extfile", str(cnf), "-out", str(crt))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(crt, key)
        result[host] = ctx
    return ca, result


class Sink(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port, context):
        self.context = context
        self.delivered = queue.Queue()
        self.clear_envelope = threading.Event()
        super().__init__(("127.0.0.1", port), SmtpHandler)


class SmtpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        conn.settimeout(10)
        tls = False
        sender = recipient = b""
        reader = conn.makefile("rb")

        def reply(value):
            conn.sendall(value + b"\r\n")

        try:
            reply(b"220 loopback-fixture ESMTP")
            while True:
                line = reader.readline(8193)
                if not line or len(line) > 8192:
                    return
                line = line.strip()
                upper = line.upper()
                if upper.startswith(b"EHLO "):
                    reply(b"250-loopback-fixture")
                    if not tls:
                        reply(b"250-STARTTLS")
                    reply(b"250 SIZE 65536")
                elif upper.startswith(b"HELO "):
                    reply(b"250 loopback-fixture")
                elif upper == b"STARTTLS" and not tls:
                    reply(b"220 begin TLS")
                    reader.close()
                    conn = self.server.context.wrap_socket(conn, server_side=True)
                    reader = conn.makefile("rb")
                    tls = True
                    sender = recipient = b""
                elif upper == b"QUIT":
                    reply(b"221 bye")
                    return
                elif upper in (b"NOOP", b"RSET"):
                    if upper == b"RSET":
                        sender = recipient = b""
                    reply(b"250 ok")
                elif not tls:
                    self.server.clear_envelope.set()
                    reply(b"530 STARTTLS required")
                elif upper.startswith(b"MAIL FROM:<"):
                    sender, recipient = line.split(b"<", 1)[1].split(b">", 1)[0], b""
                    reply(b"250 sender")
                elif upper.startswith(b"RCPT TO:<") and sender:
                    recipient = line.split(b"<", 1)[1].split(b">", 1)[0]
                    reply(b"250 recipient")
                elif upper == b"DATA" and sender and recipient:
                    reply(b"354 finish with a dot")
                    payload = bytearray()
                    while True:
                        data = reader.readline(8193)
                        if not data or len(data) > 8192:
                            return
                        if data == b".\r\n":
                            break
                        payload.extend(data[1:] if data.startswith(b"..") else data)
                        if len(payload) > 65536:
                            return
                    self.server.delivered.put((sender, recipient, bytes(payload), conn.version()))
                    reply(b"250 accepted TLS fixture")
                    sender = recipient = b""
                else:
                    reply(b"500 unknown fixture command")
        except (OSError, ssl.SSLError):
            # Postfix may close the handshake on the intentionally wrong certificate.
            pass
        finally:
            reader.close()
            conn.close()


def submit(recipient, marker):
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = SENDER, recipient, marker
    message.set_content(marker)
    with smtplib.SMTP("127.0.0.1", 25, timeout=7) as client:
        check(not client.send_message(message), "fixture ingress failure")


def remote(sinks, chosen, marker):
    submit(REMOTE, marker)
    sender, recipient, data, protocol = sinks[chosen].delivered.get(timeout=22)
    check((sender, recipient) == (SENDER.encode(), REMOTE.encode())
          and marker.encode() in data and protocol in ("TLSv1.2", "TLSv1.3"),
          "incorrect TLS delivery")
    wait(queue_clear, "remote delivery to drain queue")
    check(all(s.delivered.empty() and not s.clear_envelope.is_set() for s in sinks.values()),
          "wrong port, duplicate, or cleartext envelope")
    print(marker + "=PASS; protocol=" + protocol, flush=True)


def local(sinks, marker):
    submit(LOCAL, marker)
    wait(lambda: MAILBOX.is_file() and marker.encode() in MAILBOX.read_bytes(),
         "local mailbox marker")
    wait(queue_clear, "local delivery to drain queue")
    check(all(s.delivered.empty() for s in sinks.values()), "local mail reached upstream")
    print(marker + "=PASS", flush=True)


def wrong_identity(sinks, context):
    sinks["default"].context = context
    submit(REMOTE, "WRONG_IDENTITY_FIXTURE")
    def deferred():
        for line in run("postqueue", "-j").stdout.splitlines():
            item = json.loads(line)
            if item["queue_name"] == "deferred":
                return item
        return None
    item = wait(deferred, "bad certificate to defer synthetic mail")
    check(item["sender"] == SENDER and len(item["recipients"]) == 1
          and item["recipients"][0]["address"] == REMOTE
          and "certificate" in item["recipients"][0].get("delay_reason", "").lower(),
          "wrong certificate did not produce certificate-specific deferral")
    check(all(s.delivered.empty() and not s.clear_envelope.is_set() for s in sinks.values()),
          "wrong identity allowed SMTP DATA or cleartext fallback")
    run("postsuper", "-d", item["queue_id"])
    wait(queue_clear, "fixture queue removal")
    print("WRONG_STARTTLS_PEER_REFUSED_WITHOUT_DATA=PASS", flush=True)


def lab():
    check(os.geteuid() == 0 and Path("/.dockerenv").exists()
          and os.environ.get("LMR_TEST_CONTAINER") == "network-none"
          and {n for _, n in socket.if_nameindex()} == {"lo"},
          "only fresh Docker --network none disposable fixture allowed")
    check(not MAILBOX.exists(), "unexpected mailbox in fixture")
    guard()
    spec = importlib.util.spec_from_file_location("offline_transaction", ROOT / "linux/conditional-postfix-transaction.py")
    transaction = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transaction)
    stage = transaction.M
    gid = grp.getgrnam("postfix").gr_gid
    with ExitStack() as resources:
        running = False
        try:
            temp = Path(resources.enter_context(tempfile.TemporaryDirectory(dir="/var/lib", prefix="lmr-rc14-lab-")))
            tlsdir = temp / "tls"
            tlsdir.mkdir(mode=0o755)
            temp.chmod(0o755)
            ca, ctx = credentials(tlsdir)
            with Path("/etc/hosts").open("a", encoding="ascii") as hosts:
                hosts.write("127.0.0.1 " + BASE_HOST + " " + TARGET_HOST + "\n")
            sinks = {}
            for name, host, port in (("default", BASE_HOST, BASE_PORT), ("target", TARGET_HOST, MAP_PORT)):
                server = resources.enter_context(Sink(port, ctx[host]))
                threading.Thread(target=server.serve_forever, daemon=True).start()
                resources.callback(server.shutdown)
                sinks[name] = server
            run("postconf", "-F", "smtp/inet/chroot=n", "smtp/unix/chroot=n",
                "relay/unix/chroot=n", "rewrite/unix/chroot=n")
            run("postconf", "-e",
                "myhostname = mail.local.invalid", "mydomain = local.invalid",
                "myorigin = local.invalid", "mydestination = local.invalid, localhost",
                "inet_interfaces = 127.0.0.1", "inet_protocols = ipv4",
                "mynetworks = 127.0.0.1/32", "smtpd_relay_restrictions = permit_mynetworks, reject",
                "relayhost = [" + BASE_HOST + "]:" + str(BASE_PORT), "smtp_host_lookup = native",
                "smtp_fallback_relay =", "smtp_sasl_auth_enable = no", "transport_maps =",
                "smtp_tls_wrappermode = no", "smtp_tls_security_level = secure",
                "smtp_tls_CAfile = " + str(ca), "smtp_tls_secure_cert_match = nexthop",
                "smtp_tls_loglevel = 1", "smtp_connection_cache_on_demand = no",
                "smtp_connection_cache_destinations =", "mail_spool_directory = /var/mail",
                "home_mailbox =", "maillog_file = " + str(LOG))
            # Native package files must be valid refused/accepted by the unmodified
            # library. Do not silently normalize unsupported ACLs/xattrs.
            baseline, master = ((CONF / n).read_bytes() for n in ("main.cf", "master.cf"))
            running = True
            start()
            remote(sinks, "default", "BEFORE_DEFAULT_STARTTLS")
            stop()
            running = False

            scratch = temp / "reviews"
            scratch.mkdir(mode=0o700)
            fd = os.open(str(CONF), stage.DIR_FLAGS)
            parent = os.open(str(scratch), stage.DIR_FLAGS)
            resources.callback(os.close, fd)
            resources.callback(os.close, parent)
            rules = [dict(selector="exact-envelope-sender", pattern=SENDER, host=TARGET_HOST,
                          port=MAP_PORT, tls="starttls", auth="none")]
            plan, _ = stage.build(rules)
            old_umask = os.umask(0o077)
            resources.callback(os.umask, old_umask)
            _, stage_sha = stage.stage(parent, rules, plan, "STAGE_CONDITIONAL_MAPS_ONLY", 0)
            receipt = stage.compile_stage(parent, plan, stage_sha, "COMPILE_CONDITIONAL_MAPS_ONLY", 0, str(scratch))

            def preview():
                guard()
                verified = stage.verify_compiled(parent, plan, 0, str(scratch))
                check(verified == receipt and verified[-1] == 1, "native receipt drift")
                reviewed, files = stage.load_stage(parent, plan, 0)
                backend, databases, compiled_sha = stage.read_compiled(parent, plan, reviewed, files, 0)
                check(len(databases) == 1, "only one managed sender map supported")
                return transaction.preview(fd, plan, backend, reviewed, compiled_sha,
                                           next(iter(databases.values())), 0, guard)

            def verify(value):
                guard()
                run("postfix", "check")
                check(run("postconf", "-h", transaction.PARAMETER).stdout.strip() == value,
                      "effective map path differs from the reviewed configuration")
                if value:
                    check(run("postmap", "-q", SENDER, value).stdout.strip()
                          == "[" + TARGET_HOST + "]:" + str(MAP_PORT), "native installed lookup differs")

            approved, _, _ = preview()
            check(transaction.apply(fd, parent, approved, transaction.CONFIRM, 0, gid,
                                    guard, verify, preview) == approved, "transaction not applied")
            print("OFFLINE_STAGE_COMPILE_INSTALL=PASS", flush=True)
            check((CONF / "master.cf").read_bytes() == master, "master.cf drift")
            running = True
            start()
            remote(sinks, "target", "MAPPED_CUSTOM_PORT_STARTTLS")
            local(sinks, "MAPPED_LOCAL_MAIL_NOT_RELAYED")
            stop()
            running = False

            check(transaction.restore(fd, parent, approved, transaction.RESTORE, 0, gid,
                                      guard, verify) == approved, "restore not completed")
            mapname, suffix = transaction.checked_name(plan, receipt[2])
            check((CONF / "main.cf").read_bytes() == baseline
                  and (CONF / "master.cf").read_bytes() == master
                  and not (CONF / (mapname + suffix)).exists(), "rollback bytes or map removal differ")
            transaction.load_backup(parent, approved, 0)
            running = True
            start()
            remote(sinks, "default", "RESTORED_DEFAULT_STARTTLS")
            local(sinks, "RESTORED_LOCAL_MAIL")
            stop()
            running = False

            # Force a new SMTP client process and new handshake for the negative test.
            running = True
            start()
            wrong_identity(sinks, ctx["wrong.lab.invalid"])
            stop()
            running = False
        finally:
            if running:
                run("postfix", "stop", check=False)


if __name__ == "__main__":
    try:
        lab()
    except Exception as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stdout or "")
            print(error.stderr or "")
        if LOG.is_file():
            print(LOG.read_text(errors="replace")[-12000:])
        raise
