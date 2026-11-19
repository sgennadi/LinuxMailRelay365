#!/usr/bin/env python3
"""Fail-closed, privacy-safe, READ-ONLY multi-mailbox XOAUTH2 map audit.

No SMTP/Entra network, no token, no Postfix edits, no identity provisioning.
Does not activate multi-mailbox sending. Supports Python 3.6+ (RHEL 8).
"""
import argparse
import email.policy
from email.parser import BytesParser
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path

BASE = "/etc/linuxmailrelay365/"
IDENTITIES = BASE + "oauth-identities/"
HEADER = "smtp_login\tenvelope_from\tm365_mailbox\tidentity_config_path"
EMAIL = re.compile(r"\A[A-Za-z0-9._+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")
LOGIN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.@-]{2,63}\Z")
SAFE_PATH = re.compile(r"\A/etc/linuxmailrelay365/[A-Za-z0-9_./-]{1,240}\Z")
MAX_MAP, MAX_IDENTITY, MAX_ENTRIES = 65536, 8192, 256
MAX_OFFLINE_MESSAGE = 65536


class Refused(Exception):
    pass


def allowed_path(value, identity=False):
    if not isinstance(value, str) or not SAFE_PATH.fullmatch(value):
        raise Refused("invalid_absolute_path")
    if any(p in ("", ".", "..") for p in value.split("/")[1:]):
        raise Refused("unsafe_path_component")
    if identity:
        if not value.startswith(IDENTITIES) or not value.endswith(".json"):
            raise Refused("identity_path_outside_allowlist")
    elif not value.endswith(".tsv"):
        raise Refused("map_must_be_tsv")
    return value


def secure_read(path, limit, expected_mode, expected_group=None):
    """No symlinked parents or files; check root ownership and exact mode."""
    try:
        parent = Path("/")
        for segment in Path(path).parts[1:-1]:
            parent = parent / segment
            info = os.lstat(str(parent))
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise Refused("unsafe_parent_directory")
        before = os.lstat(path)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or
                stat.S_IMODE(before.st_mode) != expected_mode or
                before.st_size < 1 or before.st_size > limit or
                expected_group is not None and before.st_gid != expected_group):
            raise Refused("unsafe_file_permissions_or_size")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        try:
            after = os.fstat(fd)
            if (not stat.S_ISREG(after.st_mode) or
                    (after.st_ino, after.st_dev) != (before.st_ino, before.st_dev) or
                    after.st_uid != 0 or stat.S_IMODE(after.st_mode) != expected_mode or
                    expected_group is not None and after.st_gid != expected_group):
                raise Refused("file_changed_or_unsafe")
            raw = os.read(fd, limit + 1)
        finally:
            os.close(fd)
        if not raw or len(raw) > limit:
            raise Refused("file_too_large_or_empty")
        return raw
    except (OSError, ValueError):
        raise Refused("root_owned_input_not_readable")


def parse_map(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_MAP:
        raise Refused("invalid_map_size")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise Refused("invalid_map_encoding")
    if "\r" in text or "\0" in text:
        raise Refused("unsupported_control_character")
    lines = text.splitlines()
    if not lines or lines[0] != HEADER:
        raise Refused("wrong_map_header")
    if len(lines) < 2 or len(lines) - 1 > MAX_ENTRIES:
        raise Refused("invalid_map_entry_count")
    senders, identities, result = set(), {}, []
    for line in lines[1:]:
        if len(line) > 1024 or any(ord(c) < 32 for c in line if c != "\t"):
            raise Refused("invalid_map_row")
        columns = line.split("\t")
        if len(columns) != 4:
            raise Refused("invalid_map_row_columns")
        login, sender, mailbox, config_path = columns
        if (not LOGIN.fullmatch(login) or not EMAIL.fullmatch(sender) or
                not EMAIL.fullmatch(mailbox)):
            raise Refused("invalid_login_or_address")
        allowed_path(config_path, identity=True)
        login, sender, mailbox = login.casefold(), sender.casefold(), mailbox.casefold()
        if sender in senders:
            raise Refused("ambiguous_envelope_sender_owner")
        senders.add(sender)
        if mailbox in identities and identities[mailbox] != config_path:
            raise Refused("conflicting_identity_for_mailbox")
        identities[mailbox] = config_path
        result.append((login, sender, mailbox, config_path))
    return result


def validate_identity(raw, mailbox):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_IDENTITY:
        raise Refused("invalid_identity_size")
    try:
        identity = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise Refused("invalid_identity_json")
    if not isinstance(identity, dict):
        raise Refused("invalid_identity_object")
    if any(k in identity for k in ("password", "client_secret", "refresh_token", "access_token")):
        raise Refused("inline_credential_prohibited")
    try:
        tenant = str(uuid.UUID(identity["tenant_id"]))
        uuid.UUID(identity["client_id"])
    except (ValueError, TypeError, KeyError, AttributeError):
        raise Refused("invalid_identity_guid")
    if (not isinstance(identity.get("mailbox"), str) or
            not EMAIL.fullmatch(identity["mailbox"]) or
            identity["mailbox"].casefold() != mailbox):
        raise Refused("mailbox_identity_mismatch")
    if not isinstance(identity.get("certificate"), str) or not identity["certificate"]:
        raise Refused("missing_certificate_reference")
    if bool(identity.get("private_key")) == bool(identity.get("signer")):
        raise Refused("expected_one_signing_backend")
    return tenant



def strict_header_address(value):
    """Match the existing From Guard semantics (one mailbox, no groups)."""
    try:
        if value is None or value.defects or len(value.addresses) != 1:
            return None
        groups = value.groups
        if len(groups) != 1 or groups[0].display_name is not None:
            return None
        address = value.addresses[0].addr_spec
        if not isinstance(address, str) or not EMAIL.fullmatch(address):
            return None
        return address.casefold()
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return None


def authorize_offline(rows, authenticated_login, envelope_from, m365_mailbox,
                      raw_message):
    """Proof-of-policy simulation ONLY; not an SMTP AUTH or Exchange assertion.

    The login in this function is a *trusted test parameter*, not a value
    extracted from an SMTP session. Never call this to authorize real mail
    until the server-side authenticated identity is bound to the queue path.
    """
    if (not isinstance(authenticated_login, str) or
            not isinstance(envelope_from, str) or
            not isinstance(m365_mailbox, str)):
        raise Refused("invalid_sender_identity")
    login = authenticated_login.casefold()
    sender = envelope_from.casefold()
    mailbox = m365_mailbox.casefold()
    if (not LOGIN.fullmatch(login) or not EMAIL.fullmatch(sender) or
            not EMAIL.fullmatch(mailbox) or
            sum(1 for row in rows if row[:3] == (login, sender, mailbox)) != 1):
        raise Refused("sender_login_mailbox_mapping_denied")
    if (not isinstance(raw_message, bytes) or
            not 1 <= len(raw_message) <= MAX_OFFLINE_MESSAGE or
            b"\x00" in raw_message):
        raise Refused("invalid_message_size_or_encoding")
    try:
        message = BytesParser(policy=email.policy.default).parsebytes(
            raw_message, headersonly=True)
        if message.defects:
            raise Refused("malformed_message_headers")
        fields = list(message.raw_items())
        if len(fields) > 256:
            raise Refused("too_many_message_headers")
        count = {}
        for name, value in fields:
            low = name.lower()
            count[low] = count.get(low, 0) + 1
            if low in ("return-path", "resent-from", "resent-sender"):
                raise Refused("forged_or_resent_sender_headers")
            if low in ("from", "sender") and count[low] > 1:
                raise Refused("ambiguous_sender_headers")
        if count.get("from") != 1 or count.get("sender", 0) > 1:
            raise Refused("invalid_from_header_count")
        if strict_header_address(message["From"]) != sender:
            raise Refused("header_from_not_authorized_for_envelope")
        if count.get("sender", 0) == 1 and \
                strict_header_address(message["Sender"]) != sender:
            raise Refused("sender_header_not_authorized_for_envelope")
        return True
    except (TypeError, ValueError, UnicodeError, AttributeError):
        raise Refused("malformed_message_headers")



def select_planned_identity_offline(rows, authenticated_login, envelope_from,
                                    m365_mailbox, raw_message):
    """Plan an exact mailbox identity AFTER the synthetic sender checks.

    This is a pure in-memory policy check. It must never be used as live
    delivery authorization: the login is a caller-supplied fixture value,
    not a verified Postfix/Dovecot SASL identity.
    """
    if not authorize_offline(rows, authenticated_login, envelope_from,
                             m365_mailbox, raw_message):
        raise Refused("offline_policy_did_not_authorize")
    matches = [
        row[3] for row in rows
        if row[:3] == (authenticated_login.casefold(),
                       envelope_from.casefold(), m365_mailbox.casefold())
    ]
    if len(matches) != 1:
        raise Refused("ambiguous_planned_identity")
    return matches[0]


def simulate_policy(rows):
    """Deterministic positive and spoofing-negative tests, using no sockets."""
    tested = 0
    for login, sender, mailbox, identity_path in rows:
        message = ("From: <" + sender + ">\r\n"
                   "To: fixture@ci.invalid\r\n"
                   "Subject: local policy test\r\n\r\n"
                   "This message is not transmitted.\r\n").encode("ascii")
        if select_planned_identity_offline(rows, login, sender, mailbox,
                                           message) != identity_path:
            raise Refused("policy_simulation_wrong_oauth_identity")
        tested += 1
        # Sentinels are guaranteed DIFFERENT from this row's values, even
        # when the configured organization happens to use the test strings.
        bad_login = ("not-authorized-user" if login != "not-authorized-user"
                     else "denied-account")
        bad_sender = ("other@invalid.example" if sender != "other@invalid.example"
                      else "different@invalid.example")
        bad_mailbox = ("other@invalid.example" if mailbox != "other@invalid.example"
                       else "different@invalid.example")
        invalid = (
            (bad_login, sender, mailbox, message),
            (login, bad_sender, mailbox, message),
            (login, sender, bad_mailbox, message),
            (login, sender, mailbox, message.replace(
                ("From: <" + sender + ">").encode("ascii"),
                ("From: <" + bad_sender + ">").encode("ascii"))),
            (login, sender, mailbox, message.replace(
                b"Subject: local policy test\r\n",
                ("Sender: <" + bad_sender + ">\r\nSubject: local policy test\r\n").encode("ascii"))),
            (login, sender, mailbox, message.replace(
                b"Subject: local policy test\r\n",
                ("From: <" + bad_sender + ">\r\nSubject: local policy test\r\n").encode("ascii"))),
        )
        for bad_login, bad_sender, bad_mailbox, bad_message in invalid:
            try:
                authorize_offline(rows, bad_login, bad_sender, bad_mailbox,
                                  bad_message)
            except Refused:
                tested += 1
            else:
                raise Refused("policy_simulation_accepted_spoof")
    return tested

def audit(path, reader=secure_read, service_gid=None):
    allowed_path(path)
    if service_gid is None:
        try:
            import grp
            service_gid = grp.getgrnam("m365mailer").gr_gid
        except (KeyError, OSError):
            raise Refused("m365mailer_group_missing")
    raw = reader(path, MAX_MAP, 0o600, None)
    rows = parse_map(raw)
    simulation_cases = simulate_policy(rows)
    inspected = {}
    for login, sender, mailbox, identity_path in rows:
        if identity_path not in inspected:
            data = reader(identity_path, MAX_IDENTITY, 0o640, service_gid)
            inspected[identity_path] = (
                mailbox, validate_identity(data, mailbox), hashlib.sha256(data).hexdigest())
        elif inspected[identity_path][0] != mailbox:
            raise Refused("identity_reused_across_mailboxes")
    return dict(
        MAP_SHA256=hashlib.sha256(raw).hexdigest(),
        ENTRIES=len(rows),
        LOCAL_LOGINS=len(set(row[0] for row in rows)),
        MAILBOXES=len(set(row[2] for row in rows)),
        IDENTITIES=len(inspected),
        TENANTS=len(set(item[1] for item in inspected.values())),
        SENDAS_DIFFERENT_FROM=sum(row[1] != row[2] for row in rows),
        POLICY_SIMULATION_TEST_CASES=simulation_cases,
        EXISTING_FROM_GUARD_CAPACITY_COMPATIBLE=("yes" if len(rows) <= 64 else "no"))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only multi-mailbox sender policy audit")
    ap.add_argument("--map-path", required=True)
    args = ap.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Refused("root_required_for_root_only_map")
        report = audit(args.map_path)
        print("OAUTH_SENDER_MAP_RESULT=structural_review_only")
        for key in ("MAP_SHA256", "ENTRIES", "LOCAL_LOGINS", "MAILBOXES",
                    "IDENTITIES", "TENANTS", "SENDAS_DIFFERENT_FROM",
                    "POLICY_SIMULATION_TEST_CASES"):
            print("OAUTH_SENDER_MAP_" + key + "=" + str(report[key]))
        print("OAUTH_SENDER_MAP_POLICY_SIMULATION=passed_offline_only")
        print("OAUTH_SENDER_MAP_EXISTING_FROM_GUARD_CAPACITY_COMPATIBLE=" +
              report["EXISTING_FROM_GUARD_CAPACITY_COMPATIBLE"])
        for key in ("LOCAL_SMTP_LOGIN_VERIFIED", "ENVELOPE_AUTHORIZATION_ACTIVE",
                    "HEADER_FROM_GUARD_ACTIVE", "EXCHANGE_SENDAS_VERIFIED",
                    "CERTIFICATE_AND_SIGNER_VERIFIED"):
            print("OAUTH_SENDER_MAP_" + key + "=no")
        print("OAUTH_SENDER_MAP_POSTFIX_CHANGED=no")
        print("OAUTH_SENDER_MAP_MESSAGES_SENT=no")
        return 0
    except Refused as exc:
        print("OAUTH_SENDER_MAP_RESULT=refused", file=sys.stderr)
        print("OAUTH_SENDER_MAP_ERROR=" + str(exc), file=sys.stderr)
        print("OAUTH_SENDER_MAP_POSTFIX_CHANGED=no", file=sys.stderr)
        print("OAUTH_SENDER_MAP_MESSAGES_SENT=no", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
