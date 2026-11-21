#!/usr/bin/env python3
"""Opt-in Postfix pipe delivery: one verified OAuth mailbox per envelope sender.

This script is NOT an SMTP login/authenticator. The isolated SMTP ingress must
already enforce SMTP AUTH + sender-login ownership + From-Guard Milter and
disable non-SMTP submissions. An exact static ingress audit is required before
each delivery; it cannot prove live Exchange Send As grants or inbox arrival.

Install together with audit-oauth-sender-map.py, audit-oauth-ingress.py,
m365_xoauth2_transport.py and m365_hardware_signer.py. Python 3.6+.
"""
import argparse
import grp
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys

RUNTIME_MAP = "/etc/linuxmailrelay365/oauth-runtime-senders.tsv"
AUDITOR = Path(__file__).with_name("audit-oauth-sender-map.py")
INGRESS = Path(__file__).with_name("audit-oauth-ingress.py")
TRANSPORT = Path(__file__).with_name("m365_xoauth2_transport.py")
MAX_MAIL_BYTES = 25 * 1024 * 1024
MAX_HEADER_BYTES = 128 * 1024
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
EX_TEMPFAIL = 75
EX_UNAVAILABLE = 69


class Denied(Exception):
    pass


class Unverified(Exception):
    pass


def load_source(path, name):
    if not path.is_file() or path.is_symlink():
        raise Unverified("required_guard_module_missing")
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise Unverified("guard_module_unavailable")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def require_service_account():
    try:
        user = __import__("pwd").getpwnam("m365mailer")
        group = grp.getgrnam("m365mailer")
    except KeyError:
        raise Unverified("dedicated_delivery_identity_missing")
    if user.pw_uid == 0 or os.geteuid() != user.pw_uid or os.getegid() != group.gr_gid:
        raise Denied("dedicated_delivery_identity_required")
    return group.gr_gid


def secure_runtime_map(auditor, gid, expected_sha):
    """Root:m365mailer 0640, no symlinks, pinned master.cf digest."""
    if not SHA.fullmatch(expected_sha):
        raise Denied("reviewed_sender_map_digest_required")
    raw = auditor.secure_read(RUNTIME_MAP, auditor.MAX_MAP, 0o640, gid)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise Unverified("sender_map_changed_since_route_approval")
    rows = auditor.parse_map(raw)
    if len(rows) > 64:
        raise Unverified("current_sender_login_limit_exceeded")
    for login, sender, mailbox, identity_path in rows:
        # No implicit Exchange Send As: each mailbox only owns its own From.
        if sender != mailbox:
            raise Denied("send_as_requires_separate_tenant_authorization")
        protected = auditor.secure_read(
            identity_path, auditor.MAX_IDENTITY, 0o640, gid)
        auditor.validate_identity(protected, mailbox)
    return rows


def ingress_ready(rows, auditor):
    """Defense-in-depth runtime check; trusted SMTP provenance is upstream."""
    module = load_source(INGRESS, "lmr365_ingress_guard")
    result = module.assess(rows, auditor)
    if result.get("OVERALL") != "ingress_config_consistent_not_live_verified":
        raise Unverified("smtp_auth_sender_and_header_guard_not_ready")
    return True


def single_header(message, auditor, expected):
    """Reject spoofed From, duplicate headers and message header confusion."""
    if not message or len(message) > MAX_MAIL_BYTES or b"\x00" in message:
        raise Denied("invalid_message_size_or_encoding")
    # The header must terminate within a fixed bound, regardless of body size.
    limit = message[:MAX_HEADER_BYTES + 4]
    positions = [p for p in (limit.find(b"\r\n\r\n"), limit.find(b"\n\n"))
                 if p >= 0]
    if not positions:
        raise Denied("unbounded_or_missing_message_header")
    boundary = min(positions)
    header_data = limit[:boundary + 4]
    if b"\r" in header_data.replace(b"\r\n", b""):
        raise Denied("invalid_carriage_return_in_headers")
    try:
        from email import policy
        from email.parser import BytesParser
        parsed = BytesParser(policy=policy.default).parsebytes(header_data,
                                                               headersonly=True)
        if parsed.defects:
            raise Denied("malformed_message_headers")
        names = [key.lower() for key, _ in parsed.raw_items()]
        if len(names) > 256:
            raise Denied("too_many_message_headers")
        if (names.count("from") != 1 or names.count("sender") > 1 or
                any(x in names for x in ("return-path", "resent-from",
                                         "resent-sender", "resent-to",
                                         "resent-date"))):
            raise Denied("invalid_sender_headers")
        if auditor.strict_header_address(parsed["From"]) != expected:
            raise Denied("rfc5322_from_not_owner")
        if names.count("sender") and \
                auditor.strict_header_address(parsed["Sender"]) != expected:
            raise Denied("rfc5322_sender_not_owner")
    except (TypeError, ValueError, UnicodeError, AttributeError):
        raise Denied("unparseable_message_headers")
    return True


def choose_identity(rows, sender, sasl_login):
    matches = [r for r in rows if r[1] == sender and r[0] == sasl_login]
    if len(matches) != 1:
        raise Denied("envelope_sender_not_owned_or_ambiguous")
    return matches[0]


def deliver(sender, recipient, sasl_login, sasl_method, map_hash, raw,
            auditor=None, ingress_checker=ingress_ready,
            transport=None, gid=None):
    auditor = auditor or load_source(AUDITOR, "lmr365_multi_policy")
    if not isinstance(sender, str) or not isinstance(recipient, str):
        raise Denied("invalid_envelope_arguments")
    if not auditor.EMAIL.fullmatch(sender) or not auditor.EMAIL.fullmatch(recipient):
        raise Denied("invalid_sender_or_recipient_address")
    sender = sender.casefold()
    if (not isinstance(sasl_login, str) or
            not isinstance(sasl_method, str) or
            not auditor.LOGIN.fullmatch(sasl_login) or
            sasl_method.upper() not in ('PLAIN', 'LOGIN')):
        raise Denied('verified_smtp_auth_session_required')
    sasl_login = sasl_login.casefold()
    if gid is None:
        gid = require_service_account()
    rows = secure_runtime_map(auditor, gid, map_hash)
    login, assigned_from, mailbox, path = choose_identity(rows, sender, sasl_login)
    if assigned_from != sender or mailbox != sender:
        raise Denied("route_not_self_mailbox")
    single_header(raw, auditor, sender)
    ingress_checker(rows, auditor)
    # Identity and local SHA check occur *before* any outbound network traffic.
    if transport is None:
        if str(TRANSPORT.parent) not in sys.path:
            sys.path.insert(0, str(TRANSPORT.parent))
        transport = load_source(TRANSPORT, "lmr365_oauth_transport")
    config = transport.load_config(path)
    if config.get("mailbox", "").casefold() != sender:
        raise Unverified("selected_identity_changed")
    token = transport.acquire_token(config)
    transport.send_smtp(config, recipient, raw, token)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipient", default="")
    parser.add_argument("--envelope-sender", default="")
    parser.add_argument("--sasl-login", default="")
    parser.add_argument("--sasl-method", default="")
    parser.add_argument("--expected-map-sha256", required=True)
    parser.add_argument("--check-only", action="store_true")
    opts = parser.parse_args(argv)
    try:
        gid = require_service_account()
        auditor = load_source(AUDITOR, "lmr365_multi_policy")
        rows = secure_runtime_map(auditor, gid, opts.expected_map_sha256)
        ingress_ready(rows, auditor)
        if opts.check_only:
            if opts.recipient or opts.envelope_sender or opts.sasl_login or opts.sasl_method:
                raise Denied("check_only_accepts_no_delivery_arguments")
            print("MULTI_MAILBOX_INGRESS=configuration_consistent_not_live_verified")
            print("MULTI_MAILBOX_IDENTITIES=" + str(len(set(r[2] for r in rows))))
            print("MULTI_MAILBOX_MESSAGES_SENT=no")
            return 0
        if not opts.recipient or not opts.envelope_sender:
            parser.error("Postfix pipe must supply one envelope sender and recipient")
        raw = sys.stdin.buffer.read(MAX_MAIL_BYTES + 1)
        deliver(opts.envelope_sender, opts.recipient,
                opts.sasl_login, opts.sasl_method, opts.expected_map_sha256, raw,
                auditor=auditor, gid=gid)
        print("2.0.0 SMTP submitted to Microsoft 365; inbox not verified")
        return 0
    except Denied as exc:
        print("5.7.1 " + str(exc), file=sys.stderr)
        return EX_UNAVAILABLE
    except Exception:
        # No SMTP response bodies, tokens, identities or messages in logs.
        print("4.3.0 Multi-mailbox dependency or Microsoft 365 submission unverified",
              file=sys.stderr)
        return EX_TEMPFAIL


if __name__ == "__main__":
    sys.exit(main())
