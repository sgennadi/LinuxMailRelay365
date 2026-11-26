#!/usr/bin/env python3
"""Prepare an initial certificate before creating a new Entra application.

No cloud calls here. Pending metadata and one-way creation claim are root-only.
Do not publish a usable identity JSON until an explicitly reviewed Client ID
is supplied by the GUI after native Graph verification. Python 3.6+.
"""
import base64
import fcntl
import grp
import importlib.util
import os
from pathlib import Path
import pwd
import shutil
import stat
import sys
import tempfile

_spec = importlib.util.spec_from_file_location(
    "new_app_tpm", str(Path(__file__).with_name("prepare-multi-mailbox-tpm.py")))
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)
P, T = H.P, H.T
I, A, E, need, Refused = P.I, P.A, P.E, P.need, P.Refused
PHRASES = {"stage": "STAGE_NEW_APP_CERTIFICATE", "claim": "CREATE_NEW_ENTRA_APP",
           "finalize": "BIND_VERIFIED_NEW_ENTRA_APP"}


def request(raw):
    need(1 <= len(raw) <= 4096, "request_size")
    obj = I.decode(raw)
    fields = {"action", "tenant", "mailbox", "days", "source_sha", "runtime_sha", "nonce",
              "approval", "client", "confirm"}
    need(isinstance(obj, dict) and set(obj) in (fields, fields | {"handle"}) and
         all(isinstance(v, str) for k, v in obj.items() if k != "days"), "request_fields")
    if "handle" in obj:
        need(T.HANDLE.fullmatch(obj["handle"]), "invalid_tpm_handle")
    need(obj["action"] in ("preview", "stage", "inspect", "claim", "finalize") and
         type(obj["days"]) is int and 4 <= obj["days"] <= 365 and
         I.valid_mailbox(obj["mailbox"]) and A.EMAIL.fullmatch(obj["mailbox"]) and
         I.SHA.fullmatch(obj["nonce"]) and
         all(not obj[k] or I.SHA.fullmatch(obj[k]) for k in ("source_sha", "runtime_sha")),
         "request_context")
    I.guid(obj["tenant"])
    if obj["action"] in PHRASES:
        need(obj["confirm"] == PHRASES[obj["action"]] and I.SHA.fullmatch(obj["approval"]),
             "approval_required")
    else:
        need(not obj["approval"] and not obj["confirm"], "read_only_request")
    if obj["action"] == "finalize":
        I.guid(obj["client"])
    else:
        need(not obj["client"], "unexpected_client_id")
    return obj


def basis(req):
    result = {k: req[k] for k in ("tenant", "mailbox", "days", "source_sha", "runtime_sha", "nonce")}
    # Legacy software pending records and receipts retain their exact schema.
    if "handle" in req:
        result["handle"] = req["handle"]
    return result


def locations(req):
    key, cert, identity = P.paths(req)
    stem = identity.stem
    return key, cert, identity, P.IDENTITIES / ("." + stem + ".pending"), P.IDENTITIES / ("." + stem + ".claim")


def tpm_paths(req):
    identity = P.paths(req)[2]
    return identity.with_suffix(".tpm2.cnf"), P.IDENTITIES / ("." + identity.stem + ".tpm-attempt")


def destinations(req):
    return locations(req) + tpm_paths(req)


def routes(req, gid):
    hashes = P.route_state(req, gid)
    need(hashes == [req["source_sha"], req["runtime_sha"]], "route_changed_since_inventory")
    return hashes


def preview(req, gid):
    need(all(P.missing(p) for p in destinations(req)), "pending_or_identity_destination_exists")
    if "handle" in req:
        state, version, handles = H.hardware(gid)
        need(req["handle"] not in handles, "tpm_handle_occupied_no_overwrite")
        evidence = dict(basis(req), version=1, directory=state, group=gid, openssl=version,
                        persistent_handles=sorted(handles),
                        provider_sha256=I.digest(T.PROVIDER_TEMPLATE.encode("ascii")))
        sha = I.digest(P.encode(evidence))
    else:
        local = P.plan(dict(basis(req), client="", approval="", confirm=""), gid)
        sha = local["plan_sha"]
    routes(req, gid)
    return receipt(req, "preview", sha, "", "", False, False)


def receipt(req, status, digest, cert_sha, der, claimed, changes):
    return dict(basis(req), version=1, status=status, approval_sha=digest,
                identity_file=P.paths(req)[2].name, app_name="LMR365-MBX-" + req["nonce"][:32],
                certificate_sha256=cert_sha, certificate_der=der, claimed=claimed,
                changes=changes, runtime_changed=False, cloud_changed=False, mail_sent=False,
                client=req["client"] if status == "finalized" else "")


def write_private(path, raw, work):
    temp = work / "metadata"
    temp.write_bytes(raw)
    P.publish(temp, path, 0, 0o600)


def stage(req, gid, service):
    review = preview(req, gid)
    need(review["approval_sha"] == req["approval"] and preview(req, gid) == review, "stale_stage_plan")
    key, cert, identity, pending, claim = locations(req)
    if P.missing(P.IDENTITIES):
        P.IDENTITIES.mkdir(mode=0o700)
        os.chown(str(P.IDENTITIES), 0, gid)
        os.chmod(str(P.IDENTITIES), 0o750)
        P.sync_dir(P.BASE)
    state = P.directory_state(gid)
    with tempfile.TemporaryDirectory(prefix=".new-app-", dir=str(P.IDENTITIES)) as folder:
        work = Path(folder)
        if "handle" in req:
            meta = stage_tpm(req, gid, state, work)
        else:
            sk, sc = work/"key", work/"cert"
            P.openssl(["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256",
                       "-days", str(req["days"]), "-subj", "/CN=LinuxMailRelay365-New-App",
                       "-keyout", str(sk), "-out", str(sc)], timeout=60)
            need(P.directory_state(gid) == state and not P.SELINUX.exists() and
                 all(P.missing(p) for p in destinations(req)), "destination_changed")
            routes(req, gid)
            P.publish(sk, key, gid, 0o640)
            P.publish(sc, cert, gid, 0o640)
            der = P.service_proof(service, key, cert, work)
            need(250 <= len(der) <= 8192 and I.public_certificate_sha(str(cert)) == I.digest(der),
                 "certificate_digest_mismatch")
            meta = dict(basis(req), version=1, certificate_sha256=I.digest(der),
                        key_sha256=I.digest(E.secure_read(key, 65536, gid, modes=(0o640,))))
        routes(req, gid)
        write_private(pending, P.encode(meta), work)
    return inspect(req, gid, service, status="staged", changes=True)


def stage_tpm(req, gid, state, work):
    key, cert, identity, pending, claim = locations(req)
    provider, attempt = tpm_paths(req)
    handle = req["handle"]
    need(P.directory_state(gid) == state and not P.SELINUX.exists() and
         all(P.missing(p) for p in destinations(req)), "destination_changed")
    routes(req, gid)
    need(handle not in T.read_capabilities(), "tpm_handle_occupied")
    # Durable reservation before the first TPM mutation. Even a lost reply
    # cannot make a second attempt with this recovery code safe.
    marker = P.encode(dict(basis(req), version=1, plan_sha=req["approval"]))
    write_private(attempt, marker, work)
    H.persist(handle, work)
    routes(req, gid)
    need(P.directory_state(gid) == state and not P.SELINUX.exists() and
         all(P.missing(p) for p in locations(req) + (provider,)) and
         E.secure_read(attempt, 4096, 0, modes=(0o600,)) == marker, "tpm_stage_changed")
    raw_provider = T.PROVIDER_TEMPLATE.encode("ascii")
    staged_provider = work/"provider"
    staged_provider.write_bytes(raw_provider)
    P.publish(staged_provider, provider, gid, 0o640)
    sc = work/"cert"
    T.run_command([str(T.COMMANDS["openssl"]), "req", "-new", "-x509", "-sha256",
                   "-days", str(req["days"]), "-subj", "/CN=LinuxMailRelay365-New-App-TPM2",
                   "-provider", "tpm2", "-provider", "default", "-propquery", "?provider=tpm2",
                   "-key", "handle:"+handle, "-out", str(sc)], env=T.command_env(provider),
                  timeout=95, operation="tpm_certificate_generation_failed")
    der = E.der_from_pem(sc.read_bytes())
    need(250 <= len(der) <= 8192, "tpm_public_certificate_invalid")
    P.publish(sc, cert, gid, 0o640)
    meta = dict(basis(req), version=1, certificate_sha256=I.digest(der),
                provider_sha256=I.digest(raw_provider), attempt_sha256=I.digest(marker))
    verify_tpm(req, gid, meta, work)
    routes(req, gid)
    return meta


def tpm_material(req, gid, meta):
    key, cert, identity, pending, claim = locations(req)
    provider, attempt = tpm_paths(req)
    need(P.missing(key) and P.missing(identity), "unexpected_pem_or_finalized_identity")
    raw = E.secure_read(provider, 32768, gid, modes=(0o640,))
    need(raw == T.PROVIDER_TEMPLATE.encode("ascii") and
         I.digest(raw) == meta["provider_sha256"], "tpm_provider_config_changed")
    marker = E.secure_read(attempt, 4096, 0, modes=(0o600,))
    item = I.decode(marker)
    need(isinstance(item, dict) and set(item) == set(basis(req)) | {"version","plan_sha"} and
         item["version"] == 1 and all(item[k] == v for k,v in basis(req).items()) and
         I.SHA.fullmatch(item["plan_sha"]) and I.digest(marker) == meta["attempt_sha256"],
         "tpm_attempt_evidence_changed")
    der = E.der_from_pem(E.secure_read(cert, E.MAX_PEM, gid, modes=(0o640,)))
    need(I.digest(der) == meta["certificate_sha256"], "staged_certificate_changed")
    need(req["handle"] in T.read_capabilities(), "staged_tpm_handle_missing")
    return der


def verify_tpm(req, gid, meta, work):
    der = tpm_material(req, gid, meta)
    T.check_hardware()
    T.check_runtime_files()
    T.provider_ready()
    cert = locations(req)[1]
    provider = tpm_paths(req)[0]
    P.openssl(["x509","-in",str(cert),"-checkend","3600","-noout"])
    T.verify_service_signature(dict(gid=gid,directory=P.IDENTITIES,handle=req["handle"],
                                   provider_config=provider),cert,work)
    need(tpm_material(req,gid,meta) == der,"tpm_stage_changed_after_signature")
    return der


def inspect(req, gid, service, status="staged", changes=False):
    need(not P.SELINUX.exists(), "selinux_policy_review_required")
    P.directory_state(gid)
    routes(req, gid)
    key, cert, identity, pending, claim = locations(req)
    need(P.missing(identity), "identity_already_finalized")
    raw = E.secure_read(pending, 4096, 0, modes=(0o600,))
    meta = I.decode(raw)
    digests = {"certificate_sha256"} | ({"provider_sha256", "attempt_sha256"} if "handle" in req else {"key_sha256"})
    need(isinstance(meta, dict) and set(meta) == set(basis(req)) | {"version"} | digests and
         meta["version"] == 1 and all(meta[k] == v for k, v in basis(req).items()),
         "pending_context_mismatch")
    need(all(isinstance(meta[k],str) and I.SHA.fullmatch(meta[k]) for k in digests),
         "pending_digest_invalid")
    # Verify local usability again, not merely stored hashes.
    with tempfile.TemporaryDirectory(prefix=".new-app-proof-", dir=str(P.IDENTITIES)) as folder:
        if "handle" in req:
            der = verify_tpm(req,gid,meta,Path(folder))
        else:
            need(all(P.missing(p) for p in tpm_paths(req)), "unexpected_tpm_stage")
            need(I.digest(E.secure_read(key, 65536, gid, modes=(0o640,))) == meta["key_sha256"],
                 "staged_key_changed")
            der = E.der_from_pem(E.secure_read(cert, E.MAX_PEM, gid, modes=(0o640,)))
            need(I.digest(der) == meta["certificate_sha256"], "staged_certificate_changed")
            need(P.service_proof(service, key, cert, Path(folder)) == der, "local_proof_changed")
    sha = I.digest(raw)
    claimed = not P.missing(claim)
    if claimed:
        need(E.secure_read(claim, 256, 0, modes=(0o600,)) ==
             P.encode(dict(version=1, stage_sha=sha)), "invalid_creation_claim")
    routes(req, gid)
    need(E.secure_read(pending, 4096, 0, modes=(0o600,)) == raw and
         I.public_certificate_sha(str(cert)) == meta["certificate_sha256"] and
         P.missing(identity), "staged_identity_changed")
    if "handle" in req:
        need(tpm_material(req,gid,meta) == der,"staged_tpm_identity_changed")
    else:
        need(I.digest(E.secure_read(key,65536,gid,modes=(0o640,))) == meta["key_sha256"] and
             all(P.missing(p) for p in tpm_paths(req)), "staged_key_changed")
    return receipt(req, status, sha, meta["certificate_sha256"],
                   base64.b64encode(der).decode("ascii"), claimed, changes)


def mutate(req, gid, service):
    action = req["action"]
    if action == "stage":
        return stage(req, gid, service)
    current = inspect(req, gid, service)
    need(current["approval_sha"] == req["approval"], "pending_stage_changed")
    key, cert, identity, pending, claim = locations(req)
    with tempfile.TemporaryDirectory(prefix=".new-app-commit-", dir=str(P.IDENTITIES)) as folder:
        work = Path(folder)
        if action == "claim":
            # A durable no-clobber marker BEFORE Graph POST. A lost response
            # never authorizes another create; resume by exact verified Client ID.
            need(not current["claimed"], "creation_already_claimed")
            write_private(claim, P.encode(dict(version=1, stage_sha=req["approval"])), work)
            return inspect(req, gid, service, status="claimed", changes=True)
        need(action == "finalize" and current["claimed"], "creation_claim_required")
        item = dict(tenant_id=req["tenant"],client_id=req["client"],mailbox=req["mailbox"],certificate=str(cert))
        if "handle" in req:
            item["signer"] = dict(type="openssl-provider",provider="tpm2",key_ref="handle:"+req["handle"],
                                  provider_config=str(tpm_paths(req)[0]))
        else:
            item["private_key"] = str(key)
        data = P.encode(item)
        A.validate_identity(data, req["mailbox"])
        routes(req, gid)
        staged = work/"identity"
        staged.write_bytes(data)
        P.publish(staged, identity, gid, 0o640)
        need(E.secure_read(identity, A.MAX_IDENTITY, gid, modes=(0o640,)) == data,
             "identity_readback_mismatch")
        row = I.identity_row("proof", req["mailbox"], req["mailbox"], str(identity), gid)
        need(row["status"] == "public_certificate_read" and
             row["certificate_sha256"] == current["certificate_sha256"] and row["client"] == req["client"] and
             row["signer"] == ("hardware" if "handle" in req else "software"),
             "identity_inventory_unverified")
        runuser = shutil.which("runuser", path=P.ENV["PATH"])
        need(bool(runuser), "runuser_required")
        P.execute([runuser, "-u", service, "--", "/usr/bin/test", "-r", str(identity)])
        routes(req, gid)
        # Keep root-only stage and claim as recovery evidence; never delete keys.
        return dict(current, status="finalized", client=req["client"], changes=True)


def run(req, gid, service="m365mailer"):
    need(pwd.getpwnam(service).pw_gid == gid, "service_group_changed")
    if req["action"] == "preview":
        result = preview(req, gid)
        need(preview(req, gid) == result, "preview_changed")
        return result
    if req["action"] == "inspect":
        return inspect(req, gid, service)
    hardware_guard = T.lock() if "handle" in req else None
    fd = None
    try:
        E.trusted_directory(P.LOCK.parent)
        fd = os.open(str(P.LOCK), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600, "unsafe_shared_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return mutate(req, gid, service)
    finally:
        if fd is not None:
            os.close(fd)
        if hardware_guard is not None:
            os.close(hardware_guard)


def main():
    try:
        need(os.geteuid() == 0, "root_required")
        os.umask(0o077)
        req = request(sys.stdin.buffer.read(4097))
        print(P.encode(run(req, grp.getgrnam("m365mailer").gr_gid)).decode("ascii"))
        return 0
    except (Refused, T.Refused, A.Refused, E.Refused, OSError, KeyError, TypeError, ValueError, UnicodeError):
        print("NEW_APP_IDENTITY=refused_or_review_required")
        return 2


if __name__ == "__main__":
    sys.exit(main())
