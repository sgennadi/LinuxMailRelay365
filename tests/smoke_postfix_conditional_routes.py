#!/usr/bin/env python3
"""Real Postfix route/rollback smoke, for a fresh Docker --network none lab only."""
from contextlib import ExitStack
from email.message import EmailMessage
import os
from pathlib import Path
import smtplib
import socket
import subprocess
import threading
import time

import smoke_local_postfix_sink as sink

CONFIG = Path("/etc/postfix/main.cf")
MASTER = Path("/etc/postfix/master.cf")
MAPS = (Path("/etc/postfix/lmr-fixture-sender"), Path("/etc/postfix/lmr-fixture-transport"))
LOCAL = "lmrfixture@local.invalid"
MAILBOX = Path("/var/mail/lmrfixture")
PORTS = {"baseline": 46510, "exact": 46511, "domain": 46512, "recipient": 46513}
LOG = Path("/var/log/postfix-routing-fixture.log")


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20).stdout


def require(value, message):
    if not value:
        raise RuntimeError(message)


def wait_for(predicate, description, timeout=15):
    stop = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= stop:
            raise RuntimeError("timed out: " + description)
        time.sleep(0.1)


def smtp_ready():
    try:
        with smtplib.SMTP("127.0.0.1", 25, timeout=1) as client:
            return client.noop()[0] == 250
    except (OSError, smtplib.SMTPException):
        return False


def postconf(*values):
    command("postconf", "-e", *values)


def route_files():
    sender, recipient = MAPS
    sender.write_text(
        "exact@sender.invalid [127.0.0.1]:46511\n"
        "@sender.invalid [127.0.0.1]:46512\n", encoding="ascii")
    recipient.write_text("recipient.invalid smtp:[127.0.0.1]:46513\n", encoding="ascii")
    for path in MAPS:
        command("postmap", "hash:" + str(path))
    return ("sender_dependent_relayhost_maps = hash:" + str(sender),
            "transport_maps = hash:" + str(recipient))


def smtp_envelope(sender, recipient, marker, expected, servers, counts):
    # Reuse strict fixture SMTP protocol, configuring one envelope at a time.
    sink.SENDER, sink.RECIPIENT = sender, recipient
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = marker
    message.set_content(marker)
    with smtplib.SMTP("127.0.0.1", 25, timeout=5) as client:
        require(client.send_message(message, from_addr=sender, to_addrs=[recipient]) == {},
                "synthetic envelope rejected")

    if expected is None:
        wait_for(lambda: MAILBOX.is_file() and marker.encode() in MAILBOX.read_bytes(),
                 "local mailbox marker " + marker)
    else:
        counts[expected] += 1
        wait_for(lambda: len(servers[expected].messages) >= counts[expected],
                 "selected port " + str(PORTS[expected]))
        received_sender, received_recipient, body = servers[expected].messages[counts[expected] - 1]
        require((received_sender, received_recipient) == (sender, recipient)
                and marker.encode() in body, "unexpected SMTP envelope or DATA marker")
    wait_for(lambda: not command("postqueue", "-j").strip(), "queue drained")
    require(all(len(servers[name].messages) == count for name, count in counts.items()),
            "message reached an unexpected or duplicate next hop")
    print(marker + "=PASS", flush=True)


def main():
    require(os.geteuid() == 0 and Path("/.dockerenv").exists()
            and os.environ.get("LMR_TEST_CONTAINER") == "network-none"
            and {name for _, name in socket.if_nameindex()} == {"lo"},
            "fresh isolated Docker network namespace with only loopback required")
    require(not smtp_ready() and not MAILBOX.exists()
            and not any(p.exists() or p.with_suffix(".db").exists() for p in MAPS),
            "fixture requires a clean container")
    original = CONFIG.read_bytes()
    master_original = MASTER.read_bytes()
    started = False
    try:
        with ExitStack() as resources:
            servers = {}
            counts = dict.fromkeys(PORTS, 0)
            for name, port in PORTS.items():
                server = resources.enter_context(sink.Sink(("127.0.0.1", port)))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                resources.callback(server.shutdown)
                servers[name] = server

            postconf("myhostname = mail.local.invalid", "mydomain = local.invalid",
                     "myorigin = local.invalid", "mydestination = local.invalid, localhost",
                     "inet_interfaces = 127.0.0.1", "inet_protocols = ipv4",
                     "mynetworks = 127.0.0.1/32",
                     "smtpd_relay_restrictions = permit_mynetworks, reject",
                     "relayhost = [127.0.0.1]:46510", "smtp_fallback_relay =",
                     "smtp_tls_security_level = none", "smtp_sasl_auth_enable = no",
                     "sender_dependent_relayhost_maps =", "transport_maps =",
                     "mail_spool_directory = /var/mail", "home_mailbox =",
                     "maillog_file = " + str(LOG))
            baseline = CONFIG.read_bytes()
            print("POSTFIX_VERSION=" + command("postconf", "-h", "mail_version").strip(), flush=True)
            require(master_original == MASTER.read_bytes(), "master.cf changed")
            command("postfix", "check")
            started = True
            command("postfix", "start")
            wait_for(smtp_ready, "fixture SMTP listener")
            require(not command("postqueue", "-j").strip(), "initial queue is nonempty")
            smtp_envelope("exact@sender.invalid", "one@other.invalid", "BEFORE_DEFAULT",
                          "baseline", servers, counts)

            postconf(*route_files())
            command("postfix", "check")
            # Stop/start rather than racing a previously forked trivial-rewrite
            # process on its old config. The queue was verified empty above.
            command("postfix", "stop")
            command("postfix", "start")
            wait_for(smtp_ready, "mapped SMTP listener")
            for sender, recipient, marker, expected in (
                ("exact@sender.invalid", "one@other.invalid", "EXACT_SENDER", "exact"),
                ("other@sender.invalid", "one@other.invalid", "SENDER_DOMAIN", "domain"),
                ("exact@sender.invalid", "one@recipient.invalid", "RECIPIENT_OVERRIDES_SENDER", "recipient"),
                ("exact@sender.invalid", LOCAL, "LOCAL_NOT_RELAYED", None),
                ("other@unmapped.invalid", "one@other.invalid", "UNMATCHED_DEFAULT", "baseline"),
            ):
                smtp_envelope(sender, recipient, marker, expected, servers, counts)

            command("postfix", "stop")
            CONFIG.write_bytes(baseline)
            for path in MAPS:
                path.unlink()
                path.with_suffix(".db").unlink()
            require(CONFIG.read_bytes() == baseline and MASTER.read_bytes() == master_original,
                    "baseline config bytes not restored")
            require(command("postconf", "-h", "relayhost").strip() == "[127.0.0.1]:46510"
                    and not command("postconf", "-h", "transport_maps").strip()
                    and not command("postconf", "-h", "sender_dependent_relayhost_maps").strip(),
                    "baseline effective Postfix controls not restored")
            command("postfix", "check")
            command("postfix", "start")
            wait_for(smtp_ready, "restored SMTP listener")
            smtp_envelope("exact@sender.invalid", "one@recipient.invalid", "RESTORED_DEFAULT",
                          "baseline", servers, counts)
            smtp_envelope("other@sender.invalid", LOCAL, "RESTORED_LOCAL", None, servers, counts)
    finally:
        if started:
            subprocess.run(["postfix", "stop"], capture_output=True, timeout=20)
        CONFIG.write_bytes(original)
        for path in MAPS:
            path.unlink(missing_ok=True)
            path.with_suffix(".db").unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError, OSError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stdout or "")
            print(error.stderr or "")
        if LOG.is_file():
            print(LOG.read_text(errors="replace")[-8000:])
        raise
