#!/usr/bin/env python3
"""Read-only source/runtime multi-mailbox identity inventory (Python 3.6+).

No login authentication, signer operations, token requests, SMTP, changes,
or private-key reads. Only selected configuration metadata and public
certificate hashes are returned. The installed marker is not live acceptance.
"""
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import uuid


def sibling(name, alias):
    spec = importlib.util.spec_from_file_location(alias, str(Path(__file__).with_name(name)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = sibling("audit-oauth-sender-map.py", "inventory_sender_guard")
E = sibling("export-hardware-oauth-cert.py", "inventory_cert_guard")
BASE = Path("/etc/linuxmailrelay365")
IDENTITIES = BASE / "oauth-identities"
SOURCE = BASE / "oauth-senders.tsv"
RUNTIME = BASE / "oauth-runtime-senders.tsv"
MARKER = Path("/var/backups/linuxmailrelay365-multi-oauth/active.json")
CONF = BASE / "sidecar-postfix"
SHA = re.compile(r"[a-f0-9]{64}\Z")
LOGIN = re.compile(r"[a-z0-9][a-z0-9_.@-]{2,63}\Z")
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
MAILBOX = re.compile(r"[a-z0-9][a-z0-9._+%-]{0,62}@" + LABEL + r"(?:\." + LABEL + r")+\Z")


class Refused(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate_json_property")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def guid(value):
    need(isinstance(value, str), "invalid_guid")
    parsed = uuid.UUID(value)
    need(parsed.int != 0 and str(parsed) == value, "noncanonical_guid")
    return str(parsed)


def valid_mailbox(value):
    return isinstance(value, str) and len(value) <= 254 and ".." not in value and MAILBOX.fullmatch(value)


def read_optional(path, maximum, modes, gid=None):
    # A missing trusted parent is unavailable, not evidence of an empty map.
    E.trusted_directory(path.parent)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return E.secure_read(path, maximum, gid, modes=modes)


def public_certificate_sha(reference):
    need(isinstance(reference, str), "invalid_public_certificate_reference")
    path = Path(reference)
    need(path.parent == IDENTITIES and str(path) == reference and
         re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.(?:crt|pem|cer)", path.name),
         "public_certificate_outside_fixed_identity_root")
    E.trusted_directory(path.parent)
    # The PEM parser refuses any private key marker. We never follow the
    # identity's private_key or hardware key reference.
    raw = E.secure_read(path, E.MAX_PEM, modes=(0o640, 0o644))
    return digest(E.der_from_pem(raw))


def identity_row(login, sender, mailbox, path, gid):
    row = dict(login=login, sender=sender, mailbox=mailbox, tenant="", client="",
               identity_sha256="", certificate_sha256="", signer="unknown",
               status="unverified")
    try:
        filename = Path(path)
        need(filename.parent == IDENTITIES and str(filename) == path,
             "identity_outside_fixed_root")
        E.trusted_directory(filename.parent)
        raw = E.secure_read(filename, A.MAX_IDENTITY, gid, modes=(0o640,))
        data = decode(raw)
        A.validate_identity(raw, mailbox)
        signer = "hardware" if "signer" in data else "software"
        key = "signer" if signer == "hardware" else "private_key"
        need(set(data) == {"tenant_id", "client_id", "mailbox", "certificate", key},
             "unexpected_identity_fields")
        need((signer == "hardware" and isinstance(data[key], dict) and bool(data[key])) or
             (signer == "software" and isinstance(data[key], str) and bool(data[key])),
             "unverified_signer_reference")
        tenant, client = guid(data["tenant_id"]), guid(data["client_id"])
        row.update(tenant=tenant, client=client, identity_sha256=digest(raw), signer=signer,
                   status="certificate_unverified")
        row["certificate_sha256"] = public_certificate_sha(data["certificate"])
        row["status"] = "public_certificate_read"
    except (Refused, A.Refused, E.Refused, OSError, TypeError, ValueError, UnicodeError):
        pass
    return row


def map_snapshot(path, runtime, gid):
    empty = dict(status="unverified", sha256="", rows=[])
    try:
        raw = read_optional(path, A.MAX_MAP, (0o640,) if runtime else (0o600,),
                            gid if runtime else None)
        if raw is None:
            return dict(status="absent", sha256="", rows=[])
        rows = A.parse_map(raw)
        # Match the current runtime's exact sender/mailbox restrictions.
        need(1 <= len(rows) <= 64 and all(LOGIN.fullmatch(login) and
             valid_mailbox(sender) and valid_mailbox(mailbox) and sender == mailbox
             for login, sender, mailbox, _ in rows), "unsupported_sender_mapping")
        return dict(status="ok", sha256=digest(raw),
                    rows=[identity_row(*row, gid) for row in rows])
    except (Refused, A.Refused, E.Refused, OSError, TypeError, ValueError, UnicodeError):
        return empty


def marker_snapshot(runtime):
    try:
        raw = read_optional(MARKER, 4096, (0o600,))
        if raw is None:
            return "not_installed" if runtime["status"] == "absent" else "missing_marker"
        if runtime["status"] != "ok":
            return "mismatch" if runtime["status"] == "absent" else "unverified"
        marker = decode(raw)
        need(isinstance(marker, dict) and type(marker.get("version")) is int and
             marker["version"] == 1 and isinstance(marker.get("active"), dict) and
             set(marker["active"]) == {"main.cf", "master.cf"} and
             isinstance(marker.get("runtime_map_sha256"), str) and
             SHA.fullmatch(marker["runtime_map_sha256"]) and
             all(isinstance(v, str) and SHA.fullmatch(v)
                 for v in marker["active"].values()), "invalid_installed_marker")
        E.trusted_directory(CONF)
        current = {name: digest(E.secure_read(CONF / name, 1048576,
                    modes=(0o600, 0o640, 0o644))) for name in ("main.cf", "master.cf")}
        return "matches_marker" if (runtime["sha256"] == marker["runtime_map_sha256"]
                                    and current == marker["active"]) else "mismatch"
    except (Refused, E.Refused, OSError, TypeError, ValueError, UnicodeError):
        return "unverified"


def relation(source, runtime):
    a, b = source["status"], runtime["status"]
    if "unverified" in (a, b):
        return "unverified"
    if a == b == "ok":
        return "same" if source["sha256"] == runtime["sha256"] else "different"
    if a == b == "absent":
        return "neither"
    return "source_only" if a == "ok" else "runtime_only"


def sample(gid):
    source = map_snapshot(SOURCE, False, gid)
    runtime = map_snapshot(RUNTIME, True, gid)
    return dict(source=source, runtime=runtime, relation=relation(source, runtime),
                installed_binding=marker_snapshot(runtime))


def inventory(gid):
    first = sample(gid)
    # Double sample includes identities and public certificate bytes,
    # not just the source/runtime TSV file digests.
    need(sample(gid) == first, "inventory_changed_during_read")
    return first


def main():
    try:
        need(os.geteuid() == 0, "root_required")
        nonce = sys.stdin.buffer.read(65).decode("ascii")
        need(SHA.fullmatch(nonce), "invalid_inventory_nonce")
        gid = grp.getgrnam("m365mailer").gr_gid
        result = inventory(gid)
        result.update(version=1, nonce=nonce, changes=False, mail_sent=False,
                      private_key_read=False, signing_tested=False)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (Refused, A.Refused, E.Refused, KeyError, OSError, TypeError, ValueError, UnicodeError):
        print("MULTI_IDENTITY_INVENTORY=unverified")
        return 2


if __name__ == "__main__":
    sys.exit(main())
