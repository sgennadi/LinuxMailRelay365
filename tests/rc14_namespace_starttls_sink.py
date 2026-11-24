#!/usr/bin/env python3
"""SMTP STARTTLS sink restricted to a disposable synthetic network namespace."""
import os
from pathlib import Path
import queue
import socket
import socketserver
import ssl
import subprocess
import sys
import threading

BASE_HOST, TARGET_HOST = "default.lab.invalid", "target.lab.invalid"
BASE_PORT, MAP_PORT = 46510, 46517

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20)

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
        super().__init__(("192.0.2.2", port), SmtpHandler)


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
                    print("DELIVERED port={} sender={} recipient={} TLS={} DATA={}".format(
                        self.server.server_address[1], sender.decode("ascii"), recipient.decode("ascii"),
                        conn.version(), "MAPPED_SMTP_FIXTURE" if b"MAPPED_SMTP_FIXTURE" in payload else
                        "RESTORED_SMTP_FIXTURE" if b"RESTORED_SMTP_FIXTURE" in payload else "unexpected"), flush=True)
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



if __name__ == "__main__":
    if (os.geteuid() != 0 or sys.argv[1] not in ("wrong", "right") or
            {name for _, name in socket.if_nameindex()} != {"lo", "lmr-sink"}):
        raise SystemExit("synthetic isolated namespace required")
    directory = Path(sys.argv[2])
    if not (directory / "ca.pem").is_file():
        credentials(directory)
    def load_context(host):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(directory / (host + ".pem"), directory / (host + ".key"))
        return ctx
    with Sink(BASE_PORT, load_context(BASE_HOST)) as baseline:
        threading.Thread(target=baseline.serve_forever, daemon=True).start()
        selected = "wrong.lab.invalid" if sys.argv[1] == "wrong" else TARGET_HOST
        with Sink(MAP_PORT, load_context(selected)) as target:
            print("SINK_READY=" + sys.argv[1], flush=True)
            target.serve_forever()
