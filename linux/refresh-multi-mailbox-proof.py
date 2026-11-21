#!/usr/bin/env python3
"""Root-only short-lived attestation for multi-mailbox Postfix SMTP ingress.

The unprivileged m365mailer transport MUST NOT read root:dovecot password
hashes or root:postfix From-Guard policy. This opt-in tool performs the
privileged static audit, and emits a bounded, root:m365mailer 0640 receipt.

A receipt expires after 120 seconds; it never proves SMTP client ownership,
M365 tenant permissions or inbox delivery, and cannot replace actual SMTP
smoke tests. No service start/stop/reload, mail or cloud network I/O.
Python 3.6+.
"""
import argparse
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

HERE = Path(__file__).parent
AUDITOR = HERE / "audit-oauth-sender-map.py"
INGRESS = HERE / "audit-oauth-ingress.py"
RUNTIME = Path("/etc/linuxmailrelay365/oauth-runtime-senders.tsv")
PROOF = Path("/etc/linuxmailrelay365/oauth-ingress-proof.json")
CONF = Path("/etc/linuxmailrelay365/sidecar-postfix")
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
LIFETIME = 120
CONFIRM = "REFRESH_PRIVILEGED_MULTI_INGRESS_PROOF"


class Refused(Exception):
    pass


def module(path, key):
    if path.is_symlink() or not path.is_file():
        raise Refused("required_audit_module_missing")
    spec = importlib.util.spec_from_file_location(key, str(path))
    if not spec or not spec.loader:
        raise Refused("invalid_audit_module")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def secure_dir(path):
    path = Path(path)
    while True:
        st = path.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused("unsafe_proof_parent")
        if path == path.parent:
            break
        path = path.parent


def file_meta(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or info.st_mode & 0o022):
        raise Refused("untrusted_postfix_configuration")
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid]


def inspect(map_sha, now=None, audit=None, ingress=None, reader=None,
            config_meta=None):
    if not isinstance(map_sha, str) or not SHA.fullmatch(map_sha):
        raise Refused("approved_runtime_map_sha_required")
    audit = audit or module(AUDITOR, "m365_proof_auditor")
    ingress = ingress or module(INGRESS, "m365_proof_ingress")
    gid = grp.getgrnam("m365mailer").gr_gid
    reader = reader or audit.secure_read
    data = reader(str(RUNTIME), audit.MAX_MAP, 0o640, gid)
    if hashlib.sha256(data).hexdigest() != map_sha:
        raise Refused("runtime_sender_map_changed")
    rows = audit.parse_map(data)
    if not rows or len(rows) > 64 or any(sender != mailbox for _, sender, mailbox, _ in rows):
        raise Refused("unsupported_send_as_or_sender_map")
    for _, _, mailbox, identity in rows:
        raw = reader(identity, audit.MAX_IDENTITY, 0o640, gid)
        audit.validate_identity(raw, mailbox)
    result = ingress.assess(rows, audit)
    if result.get("OVERALL") != "ingress_config_consistent_not_live_verified" or \
            result.get("SERVICES") != "all_report_active" or \
            result.get("FROM_GUARD_SHA_PIN") != "configured_pinned_only":
        raise Refused("smtp_ingress_not_proven_current")
    if (ingress.read_postconf("default_transport") != "m365multi:" or
            ingress.read_postconf("relay_transport") != "m365multi:" or
            ingress.read_postconf("m365multi_destination_recipient_limit") != "1" or
            ingress.read_postconf("m365multi_destination_concurrency_limit") != "2"):
        raise Refused("unverified_multi_transport_settings")
    # Postfix pipe must contain an exact pinned map SHA and the queue SASL
    # macros. Require an unambiguous single service definition; never try to
    # interpret arbitrary regex / alternate master.cf service overrides.
    master = CONF / "master.cf"
    with master.open("rb") as source:
        content = source.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024 or content.count(b"m365multi unix - n n - 2 pipe") != 1:
        raise Refused("missing_or_ambiguous_multi_pipe")
    marker = (
        " --recipient " + "$" + "{recipient}" +
        " --envelope-sender " + "$" + "{sender}" +
        " --sasl-login " + "$" + "{sasl_username}" +
        " --sasl-method " + "$" + "{sasl_method}" +
        " --expected-map-sha256 " + map_sha
    ).encode("ascii")
    if marker not in content or content.count(marker) != 1 or \
            b"flags=q user=m365mailer argv=/usr/bin/python3 " not in content:
        raise Refused("multi_pipe_not_bound_to_sasl_and_sender_map")
    config_meta = config_meta or file_meta
    issued = int(time.time()) if now is None else int(now)
    return {
        "version": 1,
        "map_sha256": map_sha,
        "issued_at": issued,
        "expires_at": issued + LIFETIME,
        "mailboxes": len(set(row[2] for row in rows)),
        "main_meta": config_meta(CONF / "main.cf"),
        "master_meta": config_meta(master),
        "ingress": "root_static_audit_consistent_not_live_delivery",
    }


def publish(payload, path=PROOF, group=None):
    if os.geteuid() != 0:
        raise Refused("root_required")
    gid = grp.getgrnam("m365mailer").gr_gid if group is None else group
    secure_dir(path.parent)
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(data) > 2048:
        raise Refused("oversized_ingress_proof")
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_nlink != 1 or info.st_gid != gid or
                stat.S_IMODE(info.st_mode) != 0o640):
            raise Refused("existing_ingress_proof_is_unsafe")
    fd, temp = tempfile.mkstemp(prefix=".m365-ingress-", dir=str(path.parent))
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.close(fd)
        fd = -1
        os.replace(temp, str(path))
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.lexists(temp):
            os.unlink(temp)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--map-sha256", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0 or args.confirm != CONFIRM:
            raise Refused("root_and_typed_confirmation_required")
        proof = inspect(args.map_sha256)
        publish(proof)
        print("MULTI_INGRESS_PROOF=refreshed_static_audit_only")
        print("MULTI_INGRESS_PROOF_EXPIRES_SECONDS=" + str(LIFETIME))
        print("MULTI_INGRESS_MAILBOXES=" + str(proof["mailboxes"]))
        print("MULTI_INGRESS_MESSAGES_SENT=no")
        print("MULTI_INGRESS_MTA_SERVICES_CHANGED=no")
        return 0
    except (Refused, OSError, ValueError, KeyError, TypeError, UnicodeError):
        print("MULTI_INGRESS_PROOF=refused_no_delivery_proof", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
