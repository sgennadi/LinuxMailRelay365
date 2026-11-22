#!/usr/bin/env python3
"""Manual TLS/AUTH/MAIL FROM/RCPT TO *pre-DATA* test for isolated Postfix.

This opt-in local-only test sends no SMTP DATA, headers or body, never queues
mail, and does not contact Exchange directly. Mail addresses and password are
entered via hidden interactive prompts; none are passed on argv or printed.
Expected-negative RCPT tests require a permanent 5xx SMTP refusal. The test
proves only what the local SMTP daemon accepted before DATA, not remote
Microsoft 365 entitlement, transport delivery, DNS or inbox arrival.
Python 3.6+; no third-party modules.
"""
import argparse
import base64
import getpass
import re
import socket
import ssl
import sys

LOGIN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._@-]{2,63}\Z")
FQDN = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                  r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")
CA = re.compile(r"/[A-Za-z0-9_./-]{1,255}\Z")
MAILBOX = re.compile(
    r"\A(?![^@]*\.\.)(?:[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9_+-])?)@[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")


class Refused(Exception):
    pass


def validate(port, hostname, username, ca_file, sender, recipient):
    if not (port == 25 or 1024 <= port <= 65535):
        raise Refused("invalid_smtp_port")
    if len(hostname) > 253 or not FQDN.fullmatch(hostname):
        raise Refused("invalid_tls_dns_name")
    if not LOGIN.fullmatch(username):
        raise Refused("invalid_smtp_login")
    if ca_file and (not CA.fullmatch(ca_file) or ".." in ca_file.split("/")):
        raise Refused("invalid_ca_file_path")
    for addr in (sender, recipient):
        if (not isinstance(addr, str) or len(addr) > 254 or
                len(addr.split("@")[0]) > 64 or not MAILBOX.fullmatch(addr)):
            raise Refused("invalid_envelope_address")


def smtp_reply(reader):
    code = None
    lines = []
    for _ in range(40):
        line = reader.readline(2049)
        if not line or len(line) > 2048:
            raise Refused("malformed_smtp_reply")
        match = re.match(rb"^([0-9]{3})([- ])", line)
        if not match or (code is not None and code != match.group(1)):
            raise Refused("malformed_smtp_reply")
        code = match.group(1)
        lines.append(line[4:].decode("ascii", "replace").strip().upper())
        if match.group(2) == b" ":
            return int(code), lines
    raise Refused("malformed_smtp_reply")


def auth_request(username, password):
    if (not isinstance(password, str) or not 8 <= len(password) <= 256 or
            any(ord(x) < 33 or ord(x) > 126 for x in password)):
        raise Refused("invalid_password")
    raw = b"\0" + username.encode("ascii") + b"\0" + password.encode("ascii")
    return b"AUTH PLAIN " + base64.b64encode(raw) + b"\r\n"


def probe(port, hostname, username, ca_file, sender, recipient,
          expect_reject=False, password_provider=getpass.getpass):
    validate(port, hostname, username, ca_file, sender, recipient)
    plain = None
    tls = None
    reader = None
    try:
        plain = socket.create_connection(("127.0.0.1", port), timeout=9)
        plain.settimeout(9)
        reader = plain.makefile("rb")
        code, _ = smtp_reply(reader)
        if code != 220:
            raise Refused("no_smtp_banner")
        plain.sendall(b"EHLO lmr365-envelope-check.invalid\r\n")
        code, capabilities = smtp_reply(reader)
        if code != 250 or not any(x.startswith("STARTTLS") for x in capabilities):
            raise Refused("starttls_unavailable")
        if any(x == "AUTH" or x.startswith("AUTH ") for x in capabilities):
            raise Refused("auth_offered_before_tls")
        plain.sendall(b"STARTTLS\r\n")
        code, _ = smtp_reply(reader)
        if code != 220:
            raise Refused("starttls_refused")
        reader.close()
        reader = None
        context = ssl.create_default_context(cafile=ca_file or None)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        if hasattr(context, "minimum_version") and hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls = context.wrap_socket(plain, server_hostname=hostname)
        plain = None
        if tls.version() not in ("TLSv1.2", "TLSv1.3"):
            raise Refused("obsolete_tls")
        reader = tls.makefile("rb")
        tls.sendall(b"EHLO lmr365-envelope-check.invalid\r\n")
        code, capabilities = smtp_reply(reader)
        if code != 250 or not any("PLAIN" in x.split() for x in capabilities
                                  if x.startswith("AUTH ")):
            raise Refused("auth_plain_unavailable")
        request = auth_request(username, password_provider("SMTP password (hidden): "))
        tls.sendall(request)
        request = None
        code, _ = smtp_reply(reader)
        if code != 235:
            raise Refused("smtp_auth_refused")
        tls.sendall(b"MAIL FROM:<" + sender.encode("ascii") + b">\r\n")
        code, _ = smtp_reply(reader)
        if code != 250:
            raise Refused("mailfrom_not_accepted")
        tls.sendall(b"RCPT TO:<" + recipient.encode("ascii") + b">\r\n")
        code, _ = smtp_reply(reader)
        accepted = code in (250, 251)
        if expect_reject:
            if not 500 <= code <= 599:
                raise Refused("expected_permanent_rcpt_rejection")
        elif not accepted:
            raise Refused("rcpt_not_accepted")
        # SMTP RSET discards the envelope. No DATA command is ever sent.
        tls.sendall(b"RSET\r\n")
        if smtp_reply(reader)[0] != 250:
            raise Refused("rset_not_acknowledged")
        tls.sendall(b"QUIT\r\n")
        if smtp_reply(reader)[0] != 221:
            raise Refused("quit_not_acknowledged")
        return ("rcpt_rejected_as_expected" if expect_reject
                else "rcpt_accepted_without_data")
    except (OSError, ssl.SSLError, socket.timeout):
        raise Refused("smtp_tls_or_socket_failure")
    finally:
        if reader is not None:
            reader.close()
        if tls is not None:
            tls.close()
        if plain is not None:
            plain.close()


def output(status):
    print("SMTP_ENVELOPE_PREFLIGHT_VERSION=1")
    print("SMTP_ENVELOPE_PREFLIGHT_RESULT=" + status)
    print("SMTP_ENVELOPE_PREFLIGHT_DATA_SENT=no")
    print("SMTP_ENVELOPE_PREFLIGHT_QUEUE_CREATED=no")
    print("SMTP_ENVELOPE_PREFLIGHT_CREDENTIALS_LOGGED=no")
    print("SMTP_ENVELOPE_PREFLIGHT_MAIL_CONFIG_CHANGED=no")
    print("SMTP_ENVELOPE_PREFLIGHT_TENANT_DELIVERY_VERIFIED=no")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smtp-port", type=int, default=2525)
    parser.add_argument("--server-name", default="")
    parser.add_argument("--login", default="")
    parser.add_argument("--ca-file", default="")
    parser.add_argument("--expect-reject", action="store_true",
                        help="Require a permanent 5xx RCPT refusal; no DATA")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        output("self_test_passed")
        return 0
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        output("interactive_terminal_required")
        return 2
    try:
        sender = getpass.getpass("Test MAIL FROM (hidden): ")
        recipient = getpass.getpass("Test RCPT TO (hidden): ")
        validate(args.smtp_port, args.server_name, args.login, args.ca_file,
                 sender, recipient)
        status = probe(args.smtp_port, args.server_name, args.login,
                       args.ca_file, sender, recipient,
                       expect_reject=args.expect_reject)
    except (Refused, ValueError, EOFError, KeyboardInterrupt):
        output("refused_or_failed")
        return 2
    output(status)
    return 0


if __name__ == "__main__":
    sys.exit(main())
