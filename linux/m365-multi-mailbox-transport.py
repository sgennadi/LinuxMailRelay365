#!/usr/bin/env python3
"""Opt-in Postfix pipe delivery: one verified OAuth mailbox per envelope sender.

This script is NOT an SMTP login/authenticator. The isolated SMTP ingress must
already enforce SMTP AUTH + sender-login ownership + From-Guard Milter and
disable non-SMTP submissions. A fresh, root-issued 120-second ingress
receipt is required before token acquisition; the unprivileged transport
never reads Dovecot password hashes. No inbox delivery proof is implied.

Install together with audit-oauth-sender-map.py, audit-oauth-ingress.py,
m365_xoauth2_transport.py and m365_hardware_signer.py. Python 3.6+.
"""
import argparse
import grp
import json
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys
import time

RUNTIME_MAP = "/etc/linuxmailrelay365/oauth-runtime-senders.tsv"
PROOF_FILE = "/etc/linuxmailrelay365/oauth-ingress-proof.json"
PROOF_TTL = 120
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


def config_metadata(path):
    """Public stat metadata, never root-only credential or Milter file bytes."""
    try:
        meta = Path(path).lstat()
    except OSError:
        raise Unverified("postfix_config_stat_unavailable")
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or \
            meta.st_nlink != 1 or meta.st_mode & 0o022:
        raise Unverified("postfix_config_changed_or_untrusted")
    return [meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns,
            meta.st_ctime_ns, meta.st_mode, meta.st_uid, meta.st_gid]


def decode_protected_ingress_receipt(raw):
    """Unprivileged consumer rejects ambiguous root-issued proof JSON."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Unverified("duplicate_privileged_ingress_receipt_key")
            result[key] = value
        return result

    def refuse_nonfinite(_):
        raise Unverified("nonfinite_privileged_ingress_receipt_value")

    value = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
                       parse_constant=refuse_nonfinite)
    if not isinstance(value, dict):
        raise Unverified("invalid_privileged_ingress_receipt_type")
    return value


def ingress_ready(rows, auditor):
    """Check a fresh privileged receipt, not root:dovecot SMTP password hashes.

    A short-lived root-managed audit proves the protected SMTP AUTH/Milter
    policy was consistent when the receipt was issued. Postfix itself must
    still enforce SMTP AUTH and From-Guard before queueing. No local user
    can force-refresh the receipt or use a stale receipt for token issuance.
    """
    try:
        service_gid = grp.getgrnam("m365mailer").gr_gid
        raw = auditor.secure_read(PROOF_FILE, 2048, 0o640, service_gid)
        receipt = decode_protected_ingress_receipt(raw)
        expected = {"version", "map_sha256", "issued_at", "expires_at",
                    "mailboxes", "main_meta", "master_meta", "ingress"}
        if (set(receipt) != expected or
                type(receipt["version"]) is not int or
                receipt["version"] != 1 or
                receipt["ingress"] != "root_static_audit_consistent_not_live_delivery"):
            raise Unverified("privileged_ingress_receipt_invalid")
        now = int(time.time())
        issued, expires = receipt["issued_at"], receipt["expires_at"]
        if (type(issued) is not int or type(expires) is not int or
                issued > now + 5 or now >= expires or expires - issued != PROOF_TTL or
                now < issued - 5):
            raise Unverified("privileged_ingress_receipt_expired")
        map_bytes = auditor.secure_read(RUNTIME_MAP, auditor.MAX_MAP, 0o640,
                                        service_gid)
        if (not isinstance(receipt["map_sha256"], str) or
                not SHA.fullmatch(receipt["map_sha256"]) or
                hashlib.sha256(map_bytes).hexdigest() != receipt["map_sha256"]):
            raise Unverified("privileged_ingress_receipt_map_changed")
        if (type(receipt["mailboxes"]) is not int or
                receipt["mailboxes"] != len(set(row[2] for row in rows))):
            raise Unverified("privileged_ingress_receipt_mailboxes_changed")
        conf = Path("/etc/linuxmailrelay365/sidecar-postfix")
        for field, path in (("main_meta", conf / "main.cf"),
                            ("master_meta", conf / "master.cf")):
            if receipt[field] != config_metadata(path):
                raise Unverified("privileged_ingress_receipt_postfix_changed")
        return True
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            auditor.Refused):
        raise Unverified("privileged_ingress_receipt_unavailable_or_invalid") from None


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



def require_privileged_acceptance_parent():
    """Only the root-owned acceptance manager may launch direct test mail.

    A compromised unprivileged account must not use --acceptance-test to
    bypass SMTP AUTH via arbitrary direct M365 submissions. The manager
    launches this one-shot process as root-owned runuser -> m365mailer.
    /proc inspection is Linux-only and fails closed on hidepid/unknown.
    """
    try:
        parent = os.getppid()
        if parent <= 1:
            raise Denied("direct_acceptance_requires_root_runuser")
        proc = Path("/proc") / str(parent)
        # Linux forbids a setuid non-root child from reading the root
        # parent's /proc/<pid>/exe under normal ptrace restrictions.
        # /proc/<pid>/status is readable; require the root-owned runuser
        # task name and all four root UIDs, refusing missing/ambiguous data.
        raw = (proc / "status").read_text(encoding="ascii")
        names = [line.split()[1:] for line in raw.splitlines()
                 if line.startswith("Name:")]
        uids = [line.split()[1:] for line in raw.splitlines()
                if line.startswith("Uid:")]
        if len(names) != 1 or names[0] != ["runuser"] or len(uids) != 1:
            raise Denied("direct_acceptance_requires_root_runuser")
        if len(uids[0]) != 4 or any(value != "0" for value in uids[0]):
            raise Denied("direct_acceptance_parent_not_root")
        return True
    except (OSError, UnicodeError, ValueError):
        raise Denied("direct_acceptance_parent_unverifiable") from None


def acceptance_single(request_data, expected_sha, auditor,
                      gid=None, ingress_checker=ingress_ready, transport=None):
    """One explicitly reviewed DIRECT M365 SMTP acceptance, not Postfix ingress.

    Root-only orchestration must reserve run ID before asking this unprivileged
    helper to submit. No caller-supplied headers or message body are accepted.
    """
    if not isinstance(request_data, bytes) or not 1 <= len(request_data) <= 4096:
        raise Denied("invalid_acceptance_request_size")
    def distinct_pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Denied("duplicated_acceptance_request_field")
            result[key] = value
        return result
    try:
        request = json.loads(request_data.decode("ascii"),
                             object_pairs_hook=distinct_pairs)
    except (UnicodeError, ValueError, TypeError):
        raise Denied("invalid_acceptance_request")
    if not isinstance(request, dict) or set(request) != {
            "sender", "recipient", "role", "run_id"}:
        raise Denied("invalid_acceptance_request_fields")
    sender, recipient = request["sender"], request["recipient"]
    role, run_id = request["role"], request["run_id"]
    if (not isinstance(sender, str) or not auditor.EMAIL.fullmatch(sender) or
            not isinstance(recipient, str) or not auditor.EMAIL.fullmatch(recipient) or
            role not in ("internal", "external") or
            not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id)):
        raise Denied("invalid_acceptance_sender_recipient_or_run_id")
    sender = sender.casefold()
    domain = sender.rsplit("@", 1)[1]
    recipient_domain = recipient.rsplit("@", 1)[1].casefold()
    if ((role == "internal" and recipient_domain != domain) or
            (role == "external" and recipient_domain == domain)):
        raise Denied("acceptance_recipient_role_does_not_match_sender_domain")
    if gid is None:
        gid = require_service_account()
    rows = secure_runtime_map(auditor, gid, expected_sha)
    selected = [row for row in rows if row[1] == sender and row[2] == sender]
    if len(selected) != 1:
        raise Denied("acceptance_sender_not_in_reviewed_runtime_map")
    ingress_checker(rows, auditor)
    if transport is None:
        if str(TRANSPORT.parent) not in sys.path:
            sys.path.insert(0, str(TRANSPORT.parent))
        transport = load_source(TRANSPORT, "lmr365_oauth_acceptance")
    config = transport.load_config(selected[0][3])
    if config.get("mailbox", "").casefold() != sender:
        raise Unverified("acceptance_selected_identity_changed")
    # Only the transport's built-in fixed test content is sent. No arbitrary
    # mail body, Sender, From, Bcc or attachment is accepted via this API.
    transport.submit_acceptance_message(config, {
        "recipient": recipient, "role": role, "run_id": run_id})
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipient", default="")
    parser.add_argument("--envelope-sender", default="")
    parser.add_argument("--sasl-login", default="")
    parser.add_argument("--sasl-method", default="")
    parser.add_argument("--expected-map-sha256", required=True)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--acceptance-test", action="store_true")
    opts = parser.parse_args(argv)
    try:
        gid = require_service_account()
        auditor = load_source(AUDITOR, "lmr365_multi_policy")
        if opts.acceptance_test:
            if (opts.check_only or opts.recipient or opts.envelope_sender or
                    opts.sasl_login or opts.sasl_method):
                raise Denied("acceptance_has_no_postfix_sender_arguments")
            require_privileged_acceptance_parent()
            acceptance_single(sys.stdin.buffer.read(4097),
                              opts.expected_map_sha256, auditor, gid=gid)
            print("2.0.0 Direct M365 SMTP acceptance; mailbox delivery unverified")
            return 0
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
