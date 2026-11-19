#!/usr/bin/env python3
"""Real SMTP AUTH/STARTTLS + before-queue From Guard into a 127.0.0.1 sink.

Run ONLY from the disposable Ubuntu GitHub Actions Postfix smoke, after
outbound routing has been forcefully isolated to 127.0.0.1:46601.
Uses *synthetic* sender, local recipient and disposable Dovecot password.
No Microsoft 365, Internet SMTP, token, real user message or queue edits.
"""
import email.policy
from email.parser import BytesParser
import importlib.util
import os
from pathlib import Path
import smtplib
import ssl
import sys
import threading

SENDER = "alice@example.org"
RECIPIENT = "ingress@example.org"
LOGIN = "lmr365-ci-b"
PASSWORD = "disposable-test-credential"
CA_PATH = "/etc/linuxmailrelay365-ci-smtp/next-cert.pem"
SINK_PORT = 46601
MARKER = "LMR365_REAL_SMTP_AUTH_FROM_GUARD_TO_LOOPBACK"
MSGID = "<lmr365-auth-fromguard-ci@ci.invalid>"


def require_disposable_fixture(args):
    if os.environ.get("GITHUB_ACTIONS") != "true" or not os.environ.get("RUNNER_TEMP"):
        raise ValueError("ephemeral_github_actions_required")
    if len(args) != 2 or not args[0].isdigit():
        raise ValueError("only_inbound_port_and_fixed_CA_allowed")
    port = int(args[0])
    if not 1024 <= port <= 65535 or port == SINK_PORT or args[1] != CA_PATH:
        raise ValueError("invalid_inbound_port_or_CA_path")
    if not Path(CA_PATH).is_file():
        raise ValueError("disposable_CA_missing")
    return port


def load_loopback_sink():
    script = Path(__file__).with_name("smoke_local_postfix_sink.py")
    spec = importlib.util.spec_from_file_location("lmr365_auth_loopback_sink", str(script))
    if spec is None or spec.loader is None:
        raise ValueError("local_loopback_sink_missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SENDER = SENDER
    module.RECIPIENT = RECIPIENT
    return module


def session(port, authenticate=True, password=PASSWORD):
    # CA certificate is checked. The server DNS identity is verified by the
    # separate real-TLS CI test, not bypassed in production.
    ctx = ssl.create_default_context(cafile=CA_PATH)
    ctx.check_hostname = False
    client = smtplib.SMTP("127.0.0.1", port, timeout=15)
    try:
        code, _ = client.ehlo("fromguard-disposable-ci.invalid")
        if code != 250 or not client.has_extn("starttls") or client.has_extn("auth"):
            raise AssertionError("starttls_required_and_no_pretls_auth")
        code, _ = client.starttls(context=ctx)
        if code != 220:
            raise AssertionError("starttls_failed")
        code, _ = client.ehlo("fromguard-disposable-ci.invalid")
        if code != 250 or not client.has_extn("auth"):
            raise AssertionError("auth_missing_after_starttls")
        if authenticate:
            client.login(LOGIN, password)
        return client
    except BaseException:
        client.close()
        raise


def test_no_plaintext_or_anonymous_submission(port):
    client = smtplib.SMTP("127.0.0.1", port, timeout=15)
    try:
        client.ehlo("auth-required-disposable-ci.invalid")
        if client.has_extn("auth") or not client.has_extn("starttls"):
            raise AssertionError("authentication_offered_before_tls")
        code, _ = client.mail(SENDER)
        if code < 400:
            raise AssertionError("plaintext_mail_was_accepted")
    finally:
        client.close()

    client = session(port, authenticate=False)
    try:
        code, _ = client.mail(SENDER)
        if code < 400:
            code, _ = client.rcpt(RECIPIENT)
        if code < 400:
            raise AssertionError("unauthenticated_envelope_accepted")
    finally:
        client.close()

    client = None
    try:
        client = session(port, password="incorrect-disposable-password")
    except smtplib.SMTPAuthenticationError:
        pass
    else:
        if client is not None:
            client.close()
        raise AssertionError("wrong_smtp_auth_password_accepted")


def attempt_envelope_spoof(port):
    client = session(port)
    try:
        code, _ = client.mail("spoof@example.org")
        if code < 400:
            code, _ = client.rcpt(RECIPIENT)
        if code < 500:
            raise AssertionError("unowned_envelope_sender_not_denied")
    finally:
        client.close()


def message(header_lines, body=MARKER):
    return ("\r\n".join(header_lines) + "\r\n\r\n" + body + "\r\n").encode("ascii")


def attempt_header(port, raw_message, should_accept):
    client = session(port)
    try:
        code, _ = client.mail(SENDER)
        if code != 250:
            raise AssertionError("owned_envelope_sender_rejected")
        code, _ = client.rcpt(RECIPIENT)
        if code != 250:
            raise AssertionError("synthetic_recipient_rejected")
        code, _ = client.data(raw_message)
        if should_accept and code != 250:
            raise AssertionError("owned_header_and_envelope_not_accepted")
        if not should_accept and code < 500:
            raise AssertionError("forged_header_not_rejected_before_queue")
    finally:
        client.close()


def run(port):
    sink = load_loopback_sink()
    # Explicit fixed loopback endpoint; it accepts only the one expected
    # sender/recipient, and records all successfully received fixture DATA.
    with sink.Sink(("127.0.0.1", SINK_PORT)) as receiver:
        thread = threading.Thread(target=receiver.serve_forever,
                                  kwargs={"poll_interval": .1}, daemon=True)
        thread.start()
        try:
            test_no_plaintext_or_anonymous_submission(port)
            attempt_envelope_spoof(port)
            headers = [
                ("From: billing@example.org", "wrong_from"),
                ("From: alice@example.org\r\nFrom: alice@example.org",
                 "duplicate_from"),
                ("From: alice@example.org\r\nSender: billing@example.org",
                 "wrong_sender"),
                ("From: alice@example.org\r\nReturn-Path: <billing@example.org>",
                 "forged_return_path"),
                ("From: alice@example.org\r\nResent-From: billing@example.org",
                 "resent_from"),
                ("From: Team: alice@example.org;", "group_from"),
                ("To: ingress@example.org", "missing_from"),
            ]
            for header, _label in headers:
                attempt_header(port, message([
                    header, "To: " + RECIPIENT, "Subject: negative-ci-test",
                    "Message-ID: " + MSGID
                ]), should_accept=False)
            attempt_header(port, message([
                "From: " + SENDER, "To: " + RECIPIENT,
                "Subject: approved-smtp-identity",
                "Message-ID: " + MSGID,
                "MIME-Version: 1.0",
                "Content-Type: text/plain; charset=utf-8",
            ]), should_accept=True)
            if not receiver.delivered.wait(timeout=40):
                raise AssertionError("local_sink_did_not_receive_approved_message")
        finally:
            receiver.shutdown()
            thread.join(timeout=5)

        if len(receiver.messages) != 1:
            raise AssertionError("unexpected_message_delivery_count")
        sender, recipient, raw = receiver.messages[0]
        if (sender, recipient) != (SENDER, RECIPIENT):
            raise AssertionError("delivered_envelope_identity_changed")
        parsed = BytesParser(policy=email.policy.default).parsebytes(raw)
        if (len(parsed.get_all("From", [])) != 1 or
                str(parsed["From"]).casefold() != SENDER or
                str(parsed["To"]).casefold() != RECIPIENT or
                parsed["Message-ID"] != MSGID or
                MARKER not in parsed.get_content()):
            raise AssertionError("delivered_message_does_not_match_approved_fixture")
    print("SMTP_AUTH_REAL_POSTFIX_FROM_GUARD_DENIALS=verified")
    print("SMTP_AUTH_REAL_POSTFIX_FROM_GUARD_POSITIVE_DATA=delivered_to_loopback_only")
    print("SMTP_AUTH_REAL_POSTFIX_UNOWNED_MAIL_FROM=denied")
    print("SMTP_AUTH_REAL_POSTFIX_FORGED_FROM_AND_SENDER=denied")
    print("SMTP_AUTH_LOCAL_SINK_MESSAGE_COUNT=1")
    print("MICROSOFT365_DELIVERY_VERIFIED=no")
    print("XOAUTH2_MULTI_MAILBOX_ENABLED=no")


def main(argv):
    run(require_disposable_fixture(argv))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError, AssertionError,
            smtplib.SMTPException, ssl.SSLError):
        # Do not emit usernames, credentials or exception content.
        print("SMTP_AUTH_FROM_GUARD_LOOPBACK_TEST=failed", file=sys.stderr)
        sys.exit(2)
