#!/usr/bin/env python3
"""Review two exact mapped/prepared software identities for Graph addKey.

No Graph requests, credential changes, Postfix writes or SMTP. Only an
explicitly approved proof request uses the existing private signing key.
Never print the short-lived proof except in the dedicated SSH receipt.
Python 3.6+.
"""
import base64
import grp
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

_spec = importlib.util.spec_from_file_location(
    "mailbox_addkey_inventory", str(Path(__file__).with_name("inspect-multi-mailbox-identities.py")))
I = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(I)
A, E = I.A, I.E
IDENTITIES, SOURCE, RUNTIME = I.IDENTITIES, I.SOURCE, I.RUNTIME
CANDIDATE = re.compile(r"mbx-[a-f0-9]{32}\.json\Z")
FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
CONFIRM = "ADD_REVIEWED_MAILBOX_PUBLIC_CERT"
Refused, need = I.Refused, I.need


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def request(raw):
    need(1 <= len(raw) <= 4096, "request_size")
    obj = I.decode(raw)
    need(isinstance(obj, dict) and set(obj) == {
        "action", "scope", "source_sha", "runtime_sha", "donor_mailbox", "donor_sha",
        "donor_cert_sha", "candidate_file", "nonce", "pair_sha", "object_id", "confirm"}
        and all(isinstance(v, str) for v in obj.values()), "request_fields")
    need(obj["action"] in ("inspect", "proof") and obj["scope"] in ("source", "runtime") and
         all(v == "" or I.SHA.fullmatch(v) for v in (obj["source_sha"], obj["runtime_sha"])) and
         bool(obj[obj["scope"] + "_sha"]) and
         I.valid_mailbox(obj["donor_mailbox"]) and
         all(I.SHA.fullmatch(obj[k]) for k in ("donor_sha", "donor_cert_sha", "nonce")) and
         CANDIDATE.fullmatch(obj["candidate_file"]), "request_context")
    if obj["action"] == "inspect":
        need(not any(obj[k] for k in ("pair_sha", "object_id", "confirm")), "inspect_approval")
    else:
        need(I.SHA.fullmatch(obj["pair_sha"]) and obj["confirm"] == CONFIRM, "proof_approval")
        I.guid(obj["object_id"])
    return obj


def maps(req, gid):
    rows = {}
    for scope, path, mode, group in (("source", SOURCE, 0o600, None),
                                    ("runtime", RUNTIME, 0o640, gid)):
        raw = I.read_optional(path, A.MAX_MAP, (mode,), group)
        need((I.digest(raw) if raw is not None else "") == req[scope + "_sha"],
             "map_changed_since_inventory")
        rows[scope] = A.parse_map(raw) if raw is not None else []
        need(len(rows[scope]) <= 64, "map_limit")
    return rows


def fixed_file(ref):
    need(isinstance(ref, str), "invalid_identity_reference")
    path = Path(ref)
    need(path.parent == IDENTITIES and str(path) == ref and FILE.fullmatch(path.name),
         "identity_reference_outside_fixed_root")
    return path


def identity(path, gid):
    E.trusted_directory(IDENTITIES)
    raw = E.secure_read(path, A.MAX_IDENTITY, gid, modes=(0o640,))
    item = I.decode(raw)
    need(isinstance(item, dict) and set(item) ==
         {"tenant_id", "client_id", "mailbox", "certificate", "private_key"},
         "software_identity_required")
    I.guid(item["tenant_id"])
    I.guid(item["client_id"])
    need(I.valid_mailbox(item["mailbox"]), "invalid_mailbox")
    A.validate_identity(raw, item["mailbox"])
    cert = fixed_file(item["certificate"])
    fixed_file(item["private_key"])
    need(cert.suffix in (".crt", ".pem", ".cer"), "invalid_public_certificate_filename")
    der = E.der_from_pem(E.secure_read(cert, E.MAX_PEM, modes=(0o640, 0o644)))
    return raw, item, der


def sample(req, gid):
    rows = maps(req, gid)
    matches = [row for row in rows[req["scope"]] if row[2] == req["donor_mailbox"]]
    need(len(matches) == 1 and matches[0][1] == req["donor_mailbox"], "donor_not_exactly_mapped")
    donor = fixed_file(matches[0][3])
    candidate = IDENTITIES / req["candidate_file"]
    need(donor != candidate, "same_identity")
    old_raw, old, old_der = identity(donor, gid)
    new_raw, new, new_der = identity(candidate, gid)
    need(old["mailbox"] == req["donor_mailbox"] and I.digest(old_raw) == req["donor_sha"] and
         I.digest(old_der) == req["donor_cert_sha"], "selected_donor_changed")
    need(old["tenant_id"] == new["tenant_id"] and old["client_id"] == new["client_id"],
         "different_entra_application")
    need(new["certificate"] == str(candidate.with_suffix(".crt")) and
         new["private_key"] == str(candidate.with_suffix(".key")),
         "candidate_not_prepared_identity")
    need(old["certificate"] != new["certificate"] and old["private_key"] != new["private_key"] and
         I.digest(old_der) != I.digest(new_der), "duplicate_certificate_or_key")
    need(not any(row[2] == new["mailbox"] or row[3] == str(candidate)
                 for scope_rows in rows.values() for row in scope_rows),
         "candidate_already_bound_use_separate_rotation")
    receipt = dict(version=1, status="public_pair", nonce=req["nonce"], scope=req["scope"],
                   source_sha=req["source_sha"], runtime_sha=req["runtime_sha"],
                   tenant=old["tenant_id"], client=old["client_id"],
                   donor_mailbox=old["mailbox"], candidate_mailbox=new["mailbox"],
                   candidate_file=candidate.name, donor_sha=I.digest(old_raw),
                   candidate_sha=I.digest(new_raw), donor_cert_sha=I.digest(old_der),
                   candidate_cert_sha=I.digest(new_der),
                   donor_der=base64.b64encode(old_der).decode("ascii"),
                   candidate_der=base64.b64encode(new_der).decode("ascii"),
                   changes=False, mail_sent=False, cloud_changed=False, private_key_exported=False)
    receipt["pair_sha"] = I.digest(encode(receipt))
    # The existing Graph proof implementation receives the exact pair.
    context = dict(active=old, active_sha=receipt["donor_sha"], stage_sha=receipt["candidate_sha"],
                   active_cert_sha=receipt["donor_cert_sha"],
                   candidate_cert_sha=receipt["candidate_cert_sha"], active_der=old_der,
                   root=IDENTITIES, group=gid)
    return receipt, context


def inspect(req, gid):
    first = sample(req, gid)
    need(sample(req, gid) == first, "identity_pair_changed_during_read")
    return first


def proof(req, gid):
    receipt, ctx = inspect(req, gid)
    need(receipt["pair_sha"] == req["pair_sha"], "pair_changed_since_approval")
    # Existing implementation validates the software key path and file mode,
    # then signs only a fixed audience/issuer/time-bound RS256 Graph JWT.
    jwt = E.make_proof(ctx, req["object_id"], receipt["donor_sha"], receipt["candidate_sha"],
                       receipt["donor_cert_sha"], receipt["candidate_cert_sha"])
    need(inspect(req, gid) == (receipt, ctx), "identity_pair_changed_after_signing")
    return jwt


def main():
    try:
        need(os.geteuid() == 0, "root_required")
        os.umask(0o077)
        req = request(sys.stdin.buffer.read(4097))
        gid = grp.getgrnam("m365mailer").gr_gid
        if req["action"] == "inspect":
            print(encode(inspect(req, gid)[0]).decode("ascii"))
        else:
            jwt = proof(req, gid)
            E.emit("PROOF_VERSION", "1")
            E.emit("PRIVATE_KEY_EXPORTED", "no")
            E.emit("ENTRA_CONTACTED", "no")
            E.emit("MAIL_SENT", "no")
            E.emit("PROOF_JWT", jwt)
        return 0
    except (Refused, A.Refused, E.Refused, OSError, KeyError, ValueError, TypeError, UnicodeError):
        print("MAILBOX_GRAPH_PAIR=refused_or_review_required")
        return 2


if __name__ == "__main__":
    sys.exit(main())
