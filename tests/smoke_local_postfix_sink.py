#!/usr/bin/env python3
"""GitHub Actions disposable-only SMTP sink for full local Postfix delivery.

This fixture sends precisely one small synthetic SMTP DATA message through the
already configured independent Postfix listener, and verifies its receipt at a
127.0.0.1-only fake outgoing SMTP endpoint. It has NO Internet socket,
Microsoft 365 token, credentials or real tenant data.
"""
import email.policy
from email.message import EmailMessage
from email.parser import BytesParser
import os
import re
import smtplib
import socketserver
import subprocess
import sys
import threading

SENDER = "alerts@example.org"
RECIPIENT = "ingress@example.org"
MARKER = "LMR365_LOCAL_POSTFIX_QUEUE_TO_SINK_FIXTURE"
MAX_BODY = 65536


class Sink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address):
        super(Sink, self).__init__(address, Handler)
        self.delivered = threading.Event()
        self.pending_sample = threading.Event()
        self.allow_accept = threading.Event()
        self.messages = []


class Handler(socketserver.StreamRequestHandler):
    def reply(self, message):
        self.wfile.write(message.encode("ascii") + "\r\n".encode("ascii"))
        self.wfile.flush()

    def handle(self):
        self.connection.settimeout(20)
        self.reply("220 localhost ESMTP disposable-ci")
        sender = None
        recipient = None
        while True:
            line = self.rfile.readline(4097)
            if not line or len(line) > 4096:
                return
            cmd = line.decode("ascii", "replace").strip()
            upper = cmd.upper()
            if upper.startswith("EHLO "):
                self.reply("250-localhost")
                self.reply("250 SIZE 65536")
            elif upper.startswith("HELO "):
                self.reply("250 localhost")
            elif upper.startswith("MAIL FROM:"):
                found = re.match(r"(?i)^MAIL FROM:\s*<([^>]+)>", cmd)
                if found is None or found.group(1).lower() != SENDER:
                    self.reply("550 unexpected-fixture-sender")
                else:
                    sender, recipient = SENDER, None
                    self.reply("250 sender-ok")
            elif upper.startswith("RCPT TO:"):
                found = re.match(r"(?i)^RCPT TO:\s*<([^>]+)>", cmd)
                if sender != SENDER or found is None or found.group(1).lower() != RECIPIENT:
                    self.reply("550 unexpected-fixture-recipient")
                else:
                    recipient = RECIPIENT
                    self.reply("250 recipient-ok")
            elif upper == "DATA":
                if sender != SENDER or recipient != RECIPIENT:
                    self.reply("554 invalid-fixture-envelope")
                    continue
                self.reply("354 finish-with-dot")
                chunks = []
                size = 0
                while True:
                    fragment = self.rfile.readline(8193)
                    if not fragment or len(fragment) > 8192:
                        return
                    if fragment in (b".\r\n", b".\n"):
                        break
                    if fragment.startswith(b".."):
                        fragment = fragment[1:]
                    size += len(fragment)
                    if size > MAX_BODY:
                        self.reply("552 synthetic-message-too-large")
                        return
                    chunks.append(fragment)
                self.server.messages.append((sender, recipient, b"".join(chunks)))
                # Keep the synthetic DATA transaction open while the product
                # reads the real active queue. Always release from main finally.
                self.server.pending_sample.set()
                if not self.server.allow_accept.wait(timeout=90):
                    return
                self.reply("250 queued-in-local-fixture")
                self.server.delivered.set()
                sender, recipient = None, None
            elif upper == "RSET":
                sender, recipient = None, None
                self.reply("250 reset")
            elif upper == "NOOP":
                self.reply("250 ok")
            elif upper == "QUIT":
                self.reply("221 bye")
                return
            else:
                self.reply("500 unsupported-fixture-command")


def main(args):
    if os.environ.get("GITHUB_ACTIONS") != "true" or not os.environ.get("RUNNER_TEMP"):
        raise RuntimeError("ephemeral_github_actions_runner_required")
    if len(args) != 2 or any(not value.isdigit() for value in args):
        raise ValueError("expected_inbound_and_sink_tcp_ports")
    inbound, sinkport = (int(value) for value in args)
    if any(not 1024 <= port <= 65535 for port in (inbound, sinkport)) or inbound == sinkport:
        raise ValueError("invalid_or_colliding_ports")
    if sinkport != 46601:
        raise ValueError("only_fixed_loopback_sink_port_is_permitted")

    message = EmailMessage()
    message["From"] = SENDER
    message["To"] = RECIPIENT
    message["Subject"] = "LinuxMailRelay365 local queue acceptance"
    message["Message-ID"] = "<lmr365-local-fixture@ci.invalid>"
    message.set_content(MARKER + "\n")

    with Sink(("127.0.0.1", sinkport)) as receiver:
        thread = threading.Thread(target=receiver.serve_forever, kwargs={"poll_interval": .1})
        thread.daemon = True
        thread.start()
        try:
            with smtplib.SMTP("127.0.0.1", inbound, timeout=15) as client:
                code, _ = client.ehlo("lmr365-local-ci.invalid")
                if code != 250:
                    raise AssertionError("local_sidecar_smtp_ehlo_failed")
                if client.sendmail(SENDER, [RECIPIENT], message.as_bytes()):
                    raise AssertionError("sidecar_refused_local_fixture_recipient")
            if not receiver.pending_sample.wait(timeout=50):
                raise AssertionError("local_postfix_sink_did_not_receive_message")
            try:
                query = subprocess.run(
                    ["sudo", "-n", "python3", "linux/inspect-mail-queue.py",
                     "--scope", "sidecar", "--messages"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    universal_newlines=True, timeout=70, check=False)
                if query.returncode != 0 or len(query.stdout) > 8192:
                    raise AssertionError("native_queue_message_inventory_failed")
                fields = query.stdout.splitlines()
                for expected in ("MAIL_ITEMS_VERSION=1", "MAIL_ITEMS_SCOPE=sidecar",
                                 "MAIL_ITEMS_RESULT=ok", "MAIL_ITEMS_TOTAL=1",
                                 "MAIL_ITEMS_LISTED=1", "MAIL_ITEMS_TRUNCATED=no",
                                 "MAIL_ITEMS_CHANGES_APPLIED=no", "MAIL_ITEMS_ATOMIC=no",
                                 "MAIL_ITEMS_DELIVERY_VERIFIED=no",
                                 "MAIL_ITEMS_REFERENCE_KIND=sample_ordinal_only"):
                    if fields.count(expected) != 1:
                        raise AssertionError("native_queue_inventory_receipt_inconsistent")
                rows = [line for line in fields if line.startswith("MAIL_ITEMS_ROW=")]
                if (len(fields) != 11 or len(rows) != 1 or not re.fullmatch(
                        r"MAIL_ITEMS_ROW=1\|active\|[0-9]+\|[1-9][0-9]*\|1\|not_applicable",
                        rows[0])):
                    raise AssertionError("native_active_queue_row_not_verified")
                if any(value in query.stdout for value in (SENDER, RECIPIENT, MARKER)):
                    raise AssertionError("native_queue_inventory_disclosed_private_data")
                print("LOCAL_POSTFIX_ACTIVE_MESSAGE_METADATA=verified_read_only")
            finally:
                receiver.allow_accept.set()
            if not receiver.delivered.wait(timeout=20):
                raise AssertionError("local_postfix_sink_did_not_accept_message")
        finally:
            receiver.allow_accept.set()
            receiver.shutdown()
            thread.join(timeout=5)
        if len(receiver.messages) != 1:
            raise AssertionError("unexpected_number_of_local_fixture_messages")
        envelope_from, envelope_to, raw_message = receiver.messages[0]
        if (envelope_from, envelope_to) != (SENDER, RECIPIENT):
            raise AssertionError("fixture_envelope_modified")
        parsed = BytesParser(policy=email.policy.default).parsebytes(raw_message)
        if str(parsed.get("From", "")).lower() != SENDER:
            raise AssertionError("fixture_header_from_mismatch")
        if str(parsed.get("To", "")).lower() != RECIPIENT:
            raise AssertionError("fixture_header_recipient_mismatch")
        if parsed.get("Message-ID") != "<lmr365-local-fixture@ci.invalid>":
            raise AssertionError("fixture_message_id_mismatch")
        if MARKER not in parsed.get_content():
            raise AssertionError("fixture_message_body_mismatch")
    print("LOCAL_POSTFIX_FULL_MESSAGE_DELIVERED_TO_LOOPBACK_SINK=yes")
    print("LOCAL_POSTFIX_QUEUE_TO_SMTP_SINK=verified")
    print("MICROSOFT365_SMTP_DELIVERY_VERIFIED=no")
    print("INTERNET_SMTP_TRANSMISSION_ATTEMPTED=no")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError, AssertionError, smtplib.SMTPException, subprocess.TimeoutExpired):
        print("LOCAL_POSTFIX_SINK_RESULT=failed", file=sys.stderr)
        sys.exit(2)
