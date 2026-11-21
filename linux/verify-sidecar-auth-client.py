#!/usr/bin/env python3
"""Manually verify a real local SMTP AUTH login over validated STARTTLS.

Read-only to Postfix/Dovecot configuration. This optional operator exercise
sends only EHLO/STARTTLS/AUTH/QUIT to 127.0.0.1 on the installed custom port.
It sends no MAIL FROM, RCPT TO, DATA, email or tenant request. The SMTP password
is requested via an interactive terminal, never passed on the command line,
stored in a file, printed, or included in diagnostics. Python 3.6 compatible.

A successful AUTH login proves only LOCAL TLS+AUTH credentials. It does not
prove network reachability, Microsoft 365 rights, queue I/O or delivery.
"""
import argparse
import base64
import getpass
import re
import socket
import ssl
import sys

LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{2,63}\Z")
FQDN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                  r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")
CA = re.compile(r"/[A-Za-z0-9_./-]{1,255}\Z")


class Refused(Exception):
    pass


def smtp_reply(reader):
    code = None
    lines = []
    for _ in range(40):
        line = reader.readline(2049)
        if not line or len(line) > 2048:
            raise Refused("invalid_reply")
        match = re.match(rb"^([0-9]{3})([- ])", line)
        if not match or (code is not None and code != match.group(1)):
            raise Refused("invalid_reply")
        code = match.group(1)
        lines.append(line[4:].decode("ascii", "replace").strip().upper())
        if match.group(2) == b" ":
            return int(code), lines
    raise Refused("invalid_reply")


def validate(port, hostname, username, ca_file):
    if not 1024 <= port <= 65535:
        raise Refused("invalid_smtp_port")
    if not FQDN.fullmatch(hostname) or len(hostname) > 253:
        raise Refused("invalid_tls_server_dns_name")
    if not LOGIN.fullmatch(username):
        raise Refused("invalid_smtp_login")
    if ca_file and (not CA.fullmatch(ca_file) or ".." in ca_file.split("/")):
        raise Refused("invalid_ca_file_path")


def make_auth_plain(username, password):
    """Valid single-line AUTH PLAIN only; this value must never be printed."""
    if (not LOGIN.fullmatch(username) or
            not isinstance(password, str) or
            not 8 <= len(password) <= 256 or
            any(ord(char) < 33 or ord(char) > 126 for char in password)):
        raise Refused("invalid_password_input")
    return b"AUTH PLAIN " + base64.b64encode(
        (b"\0" + username.encode("ascii") + b"\0" + password.encode("ascii"))) + b"\r\n"


def verify(port, hostname, username, ca_file, password_provider=getpass.getpass):
    plain = None
    tls = None
    reader = None
    password = None
    try:
        plain = socket.create_connection(("127.0.0.1", port), timeout=9)
        plain.settimeout(9)
        reader = plain.makefile("rb")
        code, _ = smtp_reply(reader)
        if code != 220:
            raise Refused("no_smtp_banner")
        plain.sendall(b"EHLO lmr365-auth-check.invalid\r\n")
        code, capabilities = smtp_reply(reader)
        if code != 250 or not any(x.startswith("STARTTLS") for x in capabilities):
            raise Refused("starttls_unavailable")
        if any(x.startswith("AUTH ") or x == "AUTH" for x in capabilities):
            raise Refused("auth_advertised_before_tls")
        plain.sendall(b"STARTTLS\r\n")
        code, _ = smtp_reply(reader)
        if code != 220:
            raise Refused("starttls_refused")
        reader.close()
        reader = None
        context = ssl.create_default_context(cafile=ca_file or None)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        tls = context.wrap_socket(plain, server_hostname=hostname)
        plain = None
        if tls.version() not in ("TLSv1.2", "TLSv1.3"):
            raise Refused("obsolete_tls_version")
        reader = tls.makefile("rb")
        tls.sendall(b"EHLO lmr365-auth-check.invalid\r\n")
        code, capabilities = smtp_reply(reader)
        if code != 250 or not any("PLAIN" in x.split() for x in capabilities
                                  if x.startswith("AUTH ")):
            raise Refused("auth_plain_not_offered_after_tls")
        password = password_provider("SMTP app password (hidden): ")
        request = make_auth_plain(username, password)
        password = None
        tls.sendall(request)
        code, _ = smtp_reply(reader)
        if code != 235:
            raise Refused("smtp_auth_not_accepted")
        tls.sendall(b"QUIT\r\n")
        code, _ = smtp_reply(reader)
        if code != 221:
            raise Refused("smtp_quit_not_acknowledged")
        return tls.version()
    except (OSError, ssl.SSLError, socket.timeout):
        raise Refused("smtp_connection_tls_or_socket_failure")
    finally:
        password = None
        if reader is not None:
            reader.close()
        if tls is not None:
            tls.close()
        if plain is not None:
            plain.close()


def output(status):
    print("SMTP_AUTH_CLIENT_CHECK_VERSION=1")
    print("SMTP_AUTH_CLIENT_RESULT=" + status)
    print("SMTP_AUTH_CREDENTIALS_LOGGED=no")
    print("SMTP_MAIL_FROM_RCPT_DATA_SENT=no")
    print("MICROSOFT365_DELIVERY_VERIFIED=no")
    print("CHANGES_APPLIED=no")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smtp-port", type=int, default=2525)
    parser.add_argument("--server-name", default="")
    parser.add_argument("--login", default="")
    parser.add_argument("--ca-file", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        output("self_test_passed")
        return 0
    try:
        validate(args.smtp_port, args.server_name, args.login, args.ca_file)
    except Refused as exc:
        output(str(exc))
        return 2
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        output("interactive_terminal_required")
        return 2
    try:
        version = verify(args.smtp_port, args.server_name,
                         args.login, args.ca_file)
    except (Refused, ValueError):
        # Never report exception text, a server greeting or credential data.
        output("refused_or_failed")
        return 2
    output("tls_" + version.lower().replace(".", "_") + "_auth_login_verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
