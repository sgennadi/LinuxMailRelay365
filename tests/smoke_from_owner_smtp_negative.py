#!/usr/bin/env python3
"""Negative *real SMTP DATA* tests for isolated Postfix+Dovecot From Milter.

Disposable GitHub Actions runner only. SMTP AUTH over validated STARTTLS.
Only intentionally REJECTED messages are sent; no success DATA is permitted,
no Exchange tenant mailbox or external delivery and no primary MTA change.
"""
import argparse
import os
import pathlib
import smtplib
import ssl
import subprocess
import sys
import time


def queue_fingerprint(config):
    result = subprocess.run(
        ["postqueue", "-c", config, "-j"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
    if result.returncode:
        raise AssertionError("isolated_postqueue_unavailable")
    import hashlib
    return hashlib.sha256(result.stdout).hexdigest()


def connection(port, ca, hostname):
    context = ssl.create_default_context(cafile=ca)
    smtp = smtplib.SMTP("127.0.0.1", port, timeout=12)
    try:
        code, _ = smtp.ehlo("from-owner-negative-ci.invalid")
        if code != 250 or not smtp.has_extn("starttls"):
            raise AssertionError("missing_private_starttls")
        # Use the verified test SAN for SNI/hostname, while routing via loopback.
        smtp._host = hostname
        smtp.starttls(context=context)
        smtp.ehlo("from-owner-negative-ci.invalid")
        if not smtp.has_extn("auth"):
            raise AssertionError("missing_smtp_auth_after_starttls")
        smtp.login("lmr365-ci-b", "disposable-test-credential")
        return smtp
    except BaseException:
        smtp.close()
        raise


def refused_header(port, ca, hostname, from_fields):
    smtp = connection(port, ca, hostname)
    try:
        code, _ = smtp.mail("alice@example.org")
        if code != 250:
            raise AssertionError("approved_envelope_not_accepted")
        code, _ = smtp.rcpt("recipient@example.org")
        if code != 250:
            raise AssertionError("synthetic_internal_recipient_not_accepted")
        lines = ["Subject: Isolated negative From test",
                 "To: recipient@example.org"] + from_fields + [
                 "", "CI negative test; this message MUST NOT be queued."]
        code, _ = smtp.data("\r\n".join(lines))
        if code < 500 or code >= 600:
            raise AssertionError("spoofed_header_not_rejected_5xx")
        print("FROM_GUARD_REAL_SMTP_DATA_SPOOF_REJECTED_5XX=yes")
    finally:
        try:
            smtp.quit()
        except (OSError, smtplib.SMTPException):
            smtp.close()


def tempfailed_missing_guard(port, ca, hostname):
    smtp = connection(port, ca, hostname)
    try:
        code, _ = smtp.mail("alice@example.org")
        if 400 <= code < 500:
            print("FROM_GUARD_ABSENT_TEMPFAIL_STAGE=MAIL")
            return
        if code != 250:
            raise AssertionError("missing_guard_unexpected_mail_response")
        code, _ = smtp.rcpt("recipient@example.org")
        if 400 <= code < 500:
            print("FROM_GUARD_ABSENT_TEMPFAIL_STAGE=RCPT")
            return
        if code != 250:
            raise AssertionError("missing_guard_unexpected_rcpt_response")
        msg = ("From: alice@example.org\r\n"
               "To: recipient@example.org\r\n"
               "Subject: Must temporary fail\r\n\r\n"
               "Never deliver this test message.")
        code, _ = smtp.data(msg)
        if not 400 <= code < 500:
            raise AssertionError("missing_guard_was_not_tempfailed")
        print("FROM_GUARD_ABSENT_TEMPFAIL_STAGE=DATA")
    finally:
        try:
            smtp.quit()
        except (OSError, smtplib.SMTPException):
            smtp.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--smtp-port", type=int, required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--hostname", default="lmr365-ci.example.test")
    parser.add_argument("--guard-down", action="store_true")
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or not os.environ.get("RUNNER_TEMP"):
        raise AssertionError("disposable_github_actions_runner_required")
    if not 1024 <= args.smtp_port <= 65535:
        raise AssertionError("invalid_isolated_smtp_port")
    if args.ca_file != "/etc/linuxmailrelay365-ci-smtp/next-cert.pem":
        raise AssertionError("fixture_certificate_required")
    if not pathlib.Path(args.ca_file).is_file():
        raise AssertionError("fixture_certificate_missing")
    conf = "/etc/linuxmailrelay365/sidecar-postfix"
    before = queue_fingerprint(conf)
    if args.guard_down:
        tempfailed_missing_guard(args.smtp_port, args.ca_file, args.hostname)
    else:
        for headers in (
            ["From: billing@example.org"],
            ["From: alice@example.org", "From: billing@example.org"],
            ["From: Alice <alice@example.org, billing@example.org>"],
            ["From: alice@example.org", "Resent-From: billing@example.org"],
        ):
            refused_header(args.smtp_port, args.ca_file, args.hostname, headers)
    after = queue_fingerprint(conf)
    if after != before:
        raise AssertionError("negative_smtp_data_changed_independent_queue")
    print("FROM_GUARD_NEGATIVE_SMTP_QUEUE_UNCHANGED=yes")
    print("MICROSOFT365_MESSAGE_DELIVERY_TESTED=no")
    return 0


if __name__ == "__main__":
    sys.exit(main())
