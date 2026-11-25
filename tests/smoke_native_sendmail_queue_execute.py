#!/usr/bin/env python3
"""Native, isolated Sendmail Retry / Flush acceptance; no mail is delivered.

The target queue and a sentinel in the other queue live on separate tmpfs
mounts. The only network interface is loopback in a private namespace.
A synthetic SMTP receiver rejects every RCPT with 451, and never accepts DATA.
"""
import socket
import socketserver
import sys
import threading
import re

import smoke_native_sendmail_queue_preview as fixture


class Receiver(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(12)
        self.wfile.write(b"220 lmr365-fixture.invalid ESMTP\r\n")
        sender_ok = False
        for _ in range(32):
            line = self.rfile.readline(4097)
            if not line:
                return
            if len(line) > 4096 or not line.endswith(b"\n"):
                self.server.unexpected.set()
                return
            command = line.rstrip(b"\r\n")
            upper = command.upper()
            if upper.startswith((b"EHLO ", b"HELO ")):
                reply = b"250 lmr365-fixture.invalid\r\n"
            elif upper.startswith(b"MAIL FROM:"):
                sender_ok = re.fullmatch(rb"MAIL FROM:\s*<>(?:\s+.*)?", command, re.I) is not None
                if not sender_ok:
                    self.server.unexpected.set()
                reply = b"250 2.1.0 OK\r\n" if sender_ok else b"550 5.7.1 Refused\r\n"
            elif upper.startswith(b"RCPT TO:"):
                expected = (b"RCPT TO:<" + fixture.RECIPIENT.encode("ascii") + b">")
                if sender_ok and (upper == expected.upper() or upper.startswith(expected.upper() + b" ")):
                    self.server.attempted.set()
                else:
                    self.server.unexpected.set()
                # All recipients are rejected. Never accept a message.
                reply = b"451 4.3.0 Synthetic temporary refusal\r\n"
            elif upper == b"RSET":
                sender_ok = False
                reply = b"250 2.0.0 OK\r\n"
            elif upper == b"QUIT":
                self.wfile.write(b"221 2.0.0 Bye\r\n")
                return
            elif upper == b"NOOP":
                reply = b"250 2.0.0 OK\r\n"
            elif upper.startswith(b"DATA") or upper.startswith(b"BDAT"):
                self.server.unexpected.set()
                reply = b"554 5.7.1 Message body refused\r\n"
            else:
                reply = b"502 5.5.1 Unsupported\r\n"
            self.wfile.write(reply)


class RejectingSink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.attempted = threading.Event()
        self.unexpected = threading.Event()
        super().__init__(("0.0.0.0", 25), Receiver)

    def handle_error(self, request, client_address):
        # Do not log SMTP envelope or peer details.
        self.unexpected.set()


def main():
    fixture.require(len(sys.argv) == 3 and sys.argv[1] in ("mta", "msp")
                    and sys.argv[2] in ("retry", "flush"), "invalid_fixture_arguments")
    queue, action = sys.argv[1:]
    other = "msp" if queue == "mta" else "mta"
    fixture.isolated_spools()
    fixture.require({name for _, name in socket.if_nameindex()} == {"lo"},
                    "isolated_network_required")
    # The TEST-NET destination is locally routed, not added as a local
    # interface address (which could make Sendmail treat it as a local domain).
    fixture.run(["ip", "link", "set", "lo", "up"])
    fixture.run(["ip", "route", "add", "local", "192.0.2.1/32", "dev", "lo"])
    fixture.require(not fixture.run(["ip", "-4", "route", "show", "default"]).stdout.strip()
                    and not fixture.run(["ip", "-6", "route", "show", "default"]).stdout.strip(),
                    "unexpected_default_route")

    # Create one synthetic message in each independent queue; no immediate
    # delivery. A fresh namespace is used for every queue/action combination.
    for mode, _ in fixture.QUEUES.values():
        fixture.run(["/usr/sbin/sendmail", mode, "-odq", "-i", "-f", "<>", fixture.RECIPIENT],
                    "Subject: Native synthetic queue execution fixture\n\nSynthetic test only.\n")
    for name in fixture.QUEUES:
        fixture.inventory(name, 1)
    before = fixture.snapshot()
    def queue_files(files):
        return {name for name in files if name.startswith("qf")}
    fixture.require(all(len(queue_files(files)) == 1 for files in before.values()),
                    "synthetic_queue_files_missing")

    # Bind only inside the private network namespace, after isolation checks.
    with RejectingSink() as sink:
        thread = threading.Thread(target=sink.serve_forever, daemon=True)
        thread.start()
        try:
            args, plan = fixture.preview(queue, action, fixture.inventory(queue, 1))
            digest = plan.get("SENDMAIL_ACTION_PLAN_SHA256", "")
            fixture.require(plan.get("SENDMAIL_ACTION_OUTCOME") == "candidate"
                            and plan.get("SENDMAIL_ACTION_TARGET_COUNT") == "1"
                            and plan.get("SENDMAIL_ACTION_COMMAND_COUNT") == "0"
                            and fixture.SHA.fullmatch(digest) is not None,
                            "native_execution_plan_refused:" +
                            plan.get("SENDMAIL_ACTION_REASON", "missing"))
            fixture.require(not sink.attempted.is_set() and not sink.unexpected.is_set(),
                            "preview_attempted_delivery")
            result = fixture.fields(*args, "--sendmail-apply", "--prepared-at",
                                    plan["SENDMAIL_ACTION_PREPARED_AT"],
                                    "--approve-sha256", digest,
                                    "--confirm", fixture.CONFIRM[action])
            fixture.require(result.get("SENDMAIL_ACTION_OUTCOME") == "command_completed"
                            and result.get("SENDMAIL_ACTION_COMMAND_COUNT") == "1"
                            and result.get("SENDMAIL_ACTION_DELIVERY_VERIFIED") == "no"
                            and result.get("SENDMAIL_ACTION_CONFIG_CHANGED") == "no"
                            and result.get("SENDMAIL_ACTION_SERVICE_CHANGED") == "no",
                            "native_execution_unconfirmed:" +
                            result.get("SENDMAIL_ACTION_OUTCOME", "missing"))
            fixture.require(sink.attempted.wait(3) and not sink.unexpected.is_set(),
                            "native_smtp_attempt_not_observed_or_unexpected")
        finally:
            sink.shutdown()
            thread.join(timeout=5)

    after = fixture.snapshot()
    fixture.require(after[other] == before[other], "other_queue_changed")
    fixture.require(queue_files(after[queue]) == queue_files(before[queue]),
                    "temporary_refusal_did_not_preserve_message")
    fixture.inventory(queue, 1)
    fixture.inventory(other, 1)
    print("NATIVE_SENDMAIL_" + queue.upper() + "_" + action.upper() +
          "=verified_smtp_attempt_451_other_queue_unchanged")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, AssertionError, ValueError, KeyError, fixture.subprocess.TimeoutExpired) as error:
        print("NATIVE_SENDMAIL_EXECUTION=failed:" +
              (str(error) if isinstance(error, AssertionError) else type(error).__name__),
              file=sys.stderr)
        sys.exit(2)
