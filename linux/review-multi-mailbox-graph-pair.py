#!/usr/bin/env python3
"""Review two exact mapped/prepared software or managed TPM identities for Graph addKey.

No Graph requests, credential changes, Postfix writes or SMTP. Only an
explicitly approved proof request uses the existing private signing key.
Never print the short-lived proof except in the dedicated SSH receipt.
Python 3.6+.
"""
import base64
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import pwd
import shutil
import stat
import sys
import tempfile
import time

_spec = importlib.util.spec_from_file_location(
    "mailbox_addkey_inventory", str(Path(__file__).with_name("inspect-multi-mailbox-identities.py")))
I = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(I)
A, E = I.A, I.E
_tpm_spec = importlib.util.spec_from_file_location(
    "mailbox_addkey_tpm", str(Path(__file__).with_name("manage-tpm-oauth-key.py")))
T = importlib.util.module_from_spec(_tpm_spec)
_tpm_spec.loader.exec_module(T)
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
    fields = {"tenant_id", "client_id", "mailbox", "certificate"}
    need(isinstance(item, dict) and set(item) in
         (fields | {"private_key"}, fields | {"signer"}), "unsupported_identity_schema")
    I.guid(item["tenant_id"])
    I.guid(item["client_id"])
    need(I.valid_mailbox(item["mailbox"]), "invalid_mailbox")
    A.validate_identity(raw, item["mailbox"])
    cert = fixed_file(item["certificate"])
    if "signer" in item:
        spec = item["signer"]
        need(isinstance(spec,dict) and set(spec)=={"type","provider","key_ref","provider_config"} and
             spec["type"]=="openssl-provider" and spec["provider"]=="tpm2" and
             isinstance(spec["key_ref"],str) and spec["key_ref"].startswith("handle:") and
             T.HANDLE.fullmatch(spec["key_ref"][7:]), "managed_tpm_signer_required")
        conf = fixed_file(spec["provider_config"])
        need(conf == path.with_suffix(".tpm2.cnf") and
             E.secure_read(conf,32768,gid,modes=(0o640,))==T.PROVIDER_TEMPLATE.encode("ascii"),
             "managed_tpm_provider_config_required")
        need(not os.path.lexists(str(path.with_suffix(".key"))), "unexpected_pem_key_for_tpm")
    else:
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
         ("signer" in new or new["private_key"] == str(candidate.with_suffix(".key"))),
         "candidate_not_prepared_identity")
    def reference(item):
        return item["signer"]["key_ref"] if "signer" in item else item["private_key"]
    need(old["certificate"] != new["certificate"] and reference(old) != reference(new) and
         I.digest(old_der) != I.digest(new_der), "duplicate_certificate_or_key")
    need(not any(row[2] == new["mailbox"] or row[3] == str(candidate)
                 for scope_rows in rows.values() for row in scope_rows),
         "candidate_already_bound_use_separate_rotation")
    receipt = dict(version=1, status="public_pair", nonce=req["nonce"], scope=req["scope"],
                   source_sha=req["source_sha"], runtime_sha=req["runtime_sha"],
                   tenant=old["tenant_id"], client=old["client_id"],
                   donor_mailbox=old["mailbox"], candidate_mailbox=new["mailbox"],
                   candidate_file=candidate.name,
                   donor_signer="hardware" if "signer" in old else "software",
                   candidate_signer="hardware" if "signer" in new else "software",
                   donor_sha=I.digest(old_raw),
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
                   root=IDENTITIES, group=gid, candidate=new, candidate_der=new_der)
    return receipt, context


def inspect(req, gid):
    first = sample(req, gid)
    need(sample(req, gid) == first, "identity_pair_changed_during_read")
    return first


def tpm_service_prefix(gid):
    account = pwd.getpwnam("m365mailer")
    need(account.pw_uid > 0 and gid > 0 and account.pw_gid == gid and
         grp.getgrnam("m365mailer").gr_gid == gid, "dedicated_service_account_required")
    runuser = shutil.which("runuser",path="/usr/sbin:/usr/bin:/sbin:/bin")
    need(bool(runuser), "service_runner_required")
    resolved = Path(runuser).resolve(strict=True)
    E.trusted_directory(resolved.parent)
    info = resolved.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and
         bool(info.st_mode & 0o111), "untrusted_service_runner")
    return [str(resolved),"-u","m365mailer","--"]


def tpm_proof(ctx, object_id, now=None):
    """Only a fixed Graph addKey JWT; no arbitrary signing interface."""
    need(E.GUID.fullmatch(object_id), "invalid_app_object_id")
    spec = ctx["active"]["signer"]
    prefix = tpm_service_prefix(ctx["group"])
    T.check_hardware()
    T.check_runtime_files()
    T.provider_ready()
    need(spec["key_ref"][7:] in T.read_capabilities(), "tpm_donor_handle_missing")
    current = int(time.time()) if now is None else int(now)
    header = dict(typ="JWT",alg="RS256",x5t=E.b64url(hashlib.sha1(ctx["active_der"]).digest()))
    payload = dict(aud=E.POP_AUDIENCE,iss=object_id,nbf=current-30,exp=current+570)
    signing = E.b64url(json.dumps(header,separators=(",",":")).encode("ascii")) + "." + \
              E.b64url(json.dumps(payload,separators=(",",":")).encode("ascii"))
    unsigned = signing.encode("ascii")
    openssl = str(T.COMMANDS["openssl"])
    sig = T.run_command(prefix+[openssl,"pkeyutl","-provider","base","-provider","tpm2",
        "-sign","-inkey",spec["key_ref"],"-rawin","-digest","sha256",
        "-pkeyopt","rsa_padding_mode:pkcs1"],input_data=unsigned,
        env=T.command_env(spec["provider_config"]),timeout=45,operation="tpm_graph_rs256_failed")
    need(128 <= len(sig) <= 1024,"tpm_graph_signature_invalid")
    # Verify against the reviewed DER, not a subsequently changed path.
    public = T.run_command([openssl,"x509","-inform","DER","-pubkey","-noout"],
        input_data=ctx["active_der"],operation="tpm_graph_public_certificate_invalid")
    need(b"BEGIN PUBLIC KEY" in public,"tpm_graph_public_key_invalid")
    with tempfile.TemporaryDirectory(prefix="lmr365-graph-rs256-") as folder:
        pub, signature = Path(folder)/"public.pem", Path(folder)/"signature.bin"
        pub.write_bytes(public)
        signature.write_bytes(sig)
        checked = T.run_command([openssl,"dgst","-sha256","-verify",str(pub),
            "-signature",str(signature),"-sigopt","rsa_padding_mode:pkcs1"],
            input_data=unsigned,operation="tpm_graph_certificate_mismatch")
        need(b"Verified OK" in checked,"tpm_graph_certificate_mismatch")
    return signing+"."+E.b64url(sig)


def candidate_tpm_proof(ctx):
    item = ctx["candidate"]
    if "signer" not in item:
        return
    tpm_service_prefix(ctx["group"])
    spec = item["signer"]
    T.check_hardware()
    T.check_runtime_files()
    T.provider_ready()
    handle = spec["key_ref"][7:]
    need(handle in T.read_capabilities(),"tpm_candidate_handle_missing")
    # Verify candidate's actual local PS256 key before adding its certificate.
    with tempfile.TemporaryDirectory(prefix="lmr365-graph-candidate-") as folder:
        T.verify_service_signature(dict(gid=ctx["group"],directory=ctx["root"],
            handle=handle,provider_config=Path(spec["provider_config"])),
            Path(item["certificate"]),Path(folder))


def proof(req, gid):
    receipt, ctx = inspect(req, gid)
    need(receipt["pair_sha"] == req["pair_sha"], "pair_changed_since_approval")
    # Preview is read-only. Only after exact approval sign the candidate
    # hardware challenge and the fixed Graph donor proof. No PEM fallback.
    candidate_tpm_proof(ctx)
    need(inspect(req,gid)==(receipt,ctx),"identity_pair_changed_before_signing")
    if "signer" in ctx["active"]:
        jwt = tpm_proof(ctx,req["object_id"])
    else:
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
    except (Refused, A.Refused, E.Refused, T.Refused, OSError, KeyError, ValueError, TypeError, UnicodeError):
        print("MAILBOX_GRAPH_PAIR=refused_or_review_required")
        return 2


if __name__ == "__main__":
    sys.exit(main())
