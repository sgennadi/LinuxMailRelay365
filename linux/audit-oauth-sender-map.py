#!/usr/bin/env python3
"""Fail-closed, privacy-safe, READ-ONLY multi-mailbox XOAUTH2 map audit.

No SMTP/Entra network, no token, no Postfix edits, no identity provisioning.
Does not activate multi-mailbox sending. Supports Python 3.6+ (RHEL 8).
"""
import argparse
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
EMAIL = re.compile(r"\A[A-Za-z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")
LOGIN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\Z")
SAFE_PATH = re.compile(r"\A/etc/linuxmailrelay365/[A-Za-z0-9_./-]{1,240}\Z")
MAX_MAP, MAX_IDENTITY, MAX_ENTRIES = 65536, 8192, 256


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
        SENDAS_DIFFERENT_FROM=sum(row[1] != row[2] for row in rows))


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
                    "IDENTITIES", "TENANTS", "SENDAS_DIFFERENT_FROM"):
            print("OAUTH_SENDER_MAP_" + key + "=" + str(report[key]))
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
