#!/usr/bin/env python3
"""Opt-in TPM2 key for a NEW, unbound mapped OAuth identity (Python 3.6+).

No PEM private key, TPM reset/eviction, Entra writes, SMTP, service or map
changes. Existing primary/sidecar provisioning is unchanged. A failed
persistent creation needs manual review; never automatically retry or remove.
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

HERE = Path(__file__).resolve().parent


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, str(HERE/filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P = module("prepare-multi-mailbox-identity.py", "mapped_tpm_prepare")
T = module("manage-tpm-oauth-key.py", "mapped_tpm_tools")
I, A, E, need, Refused = P.I, P.A, P.E, P.need, P.Refused
CONFIRM = "CREATE_UNBOUND_TPM2_OAUTH_IDENTITY"
REASONS = ("selinux_policy_review", "identity_directory_or_account", "tpm2_device_unavailable",
           "tpm2_tools_unavailable", "openssl_provider_unavailable", "service_tpm_access_unavailable",
           "persistent_inventory_unavailable", "no_free_handle")


def service_group():
    user = pwd.getpwnam("m365mailer")
    gid = grp.getgrnam("m365mailer").gr_gid
    need(user.pw_uid > 0 and gid > 0 and user.pw_gid == gid, "service_account_invalid")
    return gid


def hardware(gid, policy=None):
    """Read-only prerequisites; full destination policy is reviewed later."""
    try:
        if policy is None:
            policy = P.policy_snapshot([])
        P.require_policy(policy)
    except (Refused, E.Refused, OSError, ValueError):
        raise Refused("selinux_policy_review") from None
    try:
        state = P.directory_state(gid, policy)
    except (Refused, E.Refused, OSError, ValueError):
        raise Refused("identity_directory_or_account") from None
    try:
        T.check_hardware()
    except (T.Refused, OSError):
        raise Refused("tpm2_device_unavailable") from None
    try:
        T.check_runtime_files()
    except (T.Refused, OSError):
        raise Refused("tpm2_tools_unavailable") from None
    try:
        version = T.provider_ready()
    except (T.Refused, OSError):
        raise Refused("openssl_provider_unavailable") from None
    try:
        runuser = shutil.which("runuser", path=P.ENV["PATH"])
        need(bool(runuser), "service_tpm_access_unavailable")
        prefix = [runuser, "-u", "m365mailer", "--"]
        T.run_command(prefix + [str(T.COMMANDS["getcap"]), "properties-fixed"],
                      operation="service_tpm_access_unavailable", timeout=25)
        T.run_command(prefix + [str(T.COMMANDS["openssl"]), "list", "-providers", "-provider", "tpm2"],
                      operation="service_tpm_access_unavailable", timeout=25)
    except (T.Refused, OSError):
        raise Refused("service_tpm_access_unavailable") from None
    try:
        handles = T.read_capabilities()
    except (T.Refused, OSError):
        raise Refused("persistent_inventory_unavailable") from None
    try:
        P.require_policy(policy)
        need(P.directory_state(gid, policy) == state, "directory_changed")
    except (Refused, E.Refused, OSError, ValueError):
        raise Refused("selinux_policy_review") from None
    return state, version, handles


def free_handle(handles):
    # Same managed owner window as existing TPM provisioning.
    for index in range(65536):
        candidate = "0x8101{:04x}".format(index)
        if candidate not in handles:
            return candidate
    raise Refused("no_free_handle")


def discover(gid):
    try:
        state, version, handles = hardware(gid)
        return dict(version=1, available=True, reason="ready", handle=free_handle(handles),
                    changes=False, key_created=False)
    except Refused as exc:
        reason = str(exc)
        need(reason in REASONS, "unexpected_tpm_probe_error")
        return dict(version=1, available=False, reason=reason, handle="",
                    changes=False, key_created=False)


def parse(raw):
    need(1 <= len(raw) <= 8192, "request_size")
    obj = I.decode(raw)
    need(isinstance(obj, dict), "request_object")
    if obj == {"action":"discover"}:
        return obj
    need(set(obj) == {"action","identity","handle","confirm"} and
         obj["action"] in ("preview","apply") and isinstance(obj["handle"],str) and
         T.HANDLE.fullmatch(obj["handle"]), "request_fields")
    identity = P.request(P.encode(obj["identity"]))
    if obj["action"] == "preview":
        need(not identity["approval"] and not obj["confirm"], "preview_approval_forbidden")
    else:
        need(bool(identity["approval"]) and obj["confirm"] == CONFIRM, "tpm_approval_required")
    return dict(obj, identity=identity)


def locations(req):
    key, cert, identity = P.paths(req)
    return key, cert, identity, identity.with_suffix(".tpm2.cnf")


def attempt_path(req):
    return P.IDENTITIES / ("." + P.paths(req)[2].stem + ".tpm-attempt")


def destinations(req):
    return locations(req) + (attempt_path(req),)


def plan(job, gid, policy=None):
    req, handle = job["identity"], job["handle"]
    if policy is None:
        policy = P.policy_snapshot(list(destinations(req)))
    P.require_policy(policy)
    state, version, handles = hardware(gid, policy)
    need(handle not in handles, "tpm_handle_occupied_no_overwrite")
    hashes = P.route_state(req,gid)
    need(all(P.missing(p) for p in destinations(req)), "identity_destination_already_exists")
    evidence = dict(version=1, backend="tpm2", request={k:v for k,v in req.items()
                    if k not in ("approval","confirm")}, handle=handle,
                    directory=state, group=gid, openssl=version, handles=sorted(handles),
                    runtime_sha=hashes[1], provider_sha=I.digest(T.PROVIDER_TEMPLATE.encode("ascii")))
    if policy["mode"] != "inactive":
        evidence["selinux_policy"] = policy
    result = dict(version=1,status="preview",plan_sha=I.digest(P.encode(evidence)),
                source_sha=hashes[0],runtime_sha=hashes[1],nonce=req["nonce"],
                tenant=req["tenant"],client=req["client"],mailbox=req["mailbox"],days=req["days"],
                identity_file=locations(req)[2].name,changes=False,runtime_changed=False,
                cloud_changed=False,mail_sent=False,certificate_sha256="",certificate_der="")
    if policy["mode"] != "inactive":
        result.update(selinux_mode=policy["mode"], selinux_policy_sha=I.digest(P.encode(policy)))
    P.require_policy(policy)
    return result


def wrap(job, receipt, created):
    return dict(version=1, backend="tpm2", handle=job["handle"], identity=receipt,
                persistent_created=created, local_ps256_verified=created,
                hardware_attestation_verified=False, tpm_objects_removed=False, pem_key_created=False)


def sidecar_lock():
    E.trusted_directory(P.LOCK.parent)
    fd = os.open(str(P.LOCK), os.O_CREAT|os.O_RDWR|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
             stat.S_IMODE(st.st_mode)==0o600,"unsafe_sidecar_lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def persist(handle, scratch):
    # Only a fresh transient context may be passed to EvictControl. Never
    # pass a persistent handle as -c; that would remove an existing object.
    ctx, unique = scratch/"primary.ctx", scratch/"primary-unique.bin"
    pub1, pub2 = scratch/"new-public.pem", scratch/"persistent-public.pem"
    unique.write_bytes(b"\x20\x00"+os.urandom(32))
    env = T.command_env()
    T.run_command([str(T.COMMANDS["createprimary"]),"-C","o","-G","rsa2048:null:null","-g","sha256",
                   "-a",T.KEY_ATTRS,"-u",str(unique),"-c",str(ctx)],
                  env=env,timeout=150,operation="tpm_primary_key_creation_failed")
    need(handle not in T.read_capabilities(),"tpm_handle_occupied_after_creation")
    T.run_command([str(T.COMMANDS["readpublic"]),"-c",str(ctx),"-f","pem","-o",str(pub1)],
                  env=env,operation="new_tpm_key_public_unavailable")
    need(handle not in T.read_capabilities(),"tpm_handle_occupied_before_persistence")
    T.run_command([str(T.COMMANDS["evictcontrol"]),"-C","o","-c",str(ctx),handle],
                  env=env,timeout=45,operation="tpm_handle_persistence_failed")
    need(handle in T.read_capabilities(),"new_tpm_persistent_handle_not_visible")
    T.run_command([str(T.COMMANDS["readpublic"]),"-c",handle,"-f","pem","-o",str(pub2)],
                  env=env,operation="new_tpm_persistent_key_unreadable")
    need(pub1.read_bytes()==pub2.read_bytes(),"new_tpm_key_identity_mismatch")


def apply(job,gid):
    req,handle=job["identity"],job["handle"]
    need(job["confirm"]==CONFIRM and I.SHA.fullmatch(req["approval"]),"approval_required")
    hardware_guard=T.lock()
    guard=None
    started=False
    try:
        guard=sidecar_lock()
        policy=P.policy_snapshot(list(destinations(req)))
        review=plan(job,gid,policy)
        need(review["plan_sha"]==req["approval"] and plan(job,gid,policy)==review,"tpm_plan_changed")
        key,cert,identity,provider=locations(req)
        attempt=attempt_path(req)
        state=P.ensure_identity_directory(gid,policy)
        hashes=[review["source_sha"],review["runtime_sha"]]
        def unchanged():
            P.require_policy(policy)
            need(P.directory_state(gid,policy)==state and P.route_state(req,gid)==hashes,"identity_context_changed")
        unchanged()
        need(all(P.missing(p) for p in destinations(req)),"identity_destination_already_exists")
        with tempfile.TemporaryDirectory(prefix=".mapped-tpm-",dir=str(P.IDENTITIES)) as folder:
            scratch=Path(folder)
            need(handle not in T.read_capabilities(),"tpm_handle_occupied")
            # The attempt can persist a key even when the command response is
            # lost. Never free the handle automatically, even on failure.
            started=True
            marker=P.encode(dict(version=1,handle=handle,nonce=req["nonce"],plan_sha=req["approval"],
                                **{k:review[k] for k in ("selinux_mode","selinux_policy_sha") if k in review}))
            staged_attempt=scratch/"attempt"
            staged_attempt.write_bytes(marker)
            P.publish(staged_attempt,attempt,0,0o600,policy)
            need(E.secure_read(attempt,4096,0,modes=(0o600,))==marker,"tpm_attempt_marker_changed")
            unchanged()
            persist(handle,scratch)
            unchanged()
            need(E.secure_read(attempt,4096,0,modes=(0o600,))==marker and
                 all(P.missing(p) for p in locations(req)),"identity_destination_already_exists")
            staged_provider=scratch/"provider"
            staged_provider.write_bytes(T.PROVIDER_TEMPLATE.encode("ascii"))
            P.publish(staged_provider,provider,gid,0o640,policy)
            staged_cert=scratch/"cert"
            T.run_command([str(T.COMMANDS["openssl"]),"req","-new","-x509","-sha256","-days",str(req["days"]),
                           "-subj","/CN=LinuxMailRelay365-MultiMailbox-TPM2","-provider","tpm2","-provider","default",
                           "-propquery","?provider=tpm2","-key","handle:"+handle,"-out",str(staged_cert)],
                          env=T.command_env(provider),timeout=95,operation="tpm_certificate_generation_failed")
            der=E.der_from_pem(staged_cert.read_bytes())
            need(250<=len(der)<=8192,"tpm_public_certificate_invalid")
            P.publish(staged_cert,cert,gid,0o640,policy)
            T.verify_service_signature(dict(gid=gid,directory=P.IDENTITIES,handle=handle,
                                             provider_config=provider),cert,scratch)
            unchanged()
            need(P.missing(key) and P.missing(identity) and handle in T.read_capabilities() and
                 I.public_certificate_sha(str(cert))==I.digest(der) and
                 E.secure_read(provider,E.MAX_PEM,gid,modes=(0o640,))==T.PROVIDER_TEMPLATE.encode("ascii"),
                 "tpm_identity_evidence_changed")
            data=P.encode(dict(tenant_id=req["tenant"],client_id=req["client"],mailbox=req["mailbox"],
                certificate=str(cert),signer=dict(type="openssl-provider",provider="tpm2",
                    key_ref="handle:"+handle,provider_config=str(provider))))
            A.validate_identity(data,req["mailbox"])
            staged=scratch/"identity"
            staged.write_bytes(data)
            P.publish(staged,identity,gid,0o640,policy)
            need(E.secure_read(identity,A.MAX_IDENTITY,gid,modes=(0o640,))==data,"identity_readback_mismatch")
            row=I.identity_row("proof",req["mailbox"],req["mailbox"],str(identity),gid)
            need(row["status"]=="public_certificate_read" and row["signer"]=="hardware" and
                 row["certificate_sha256"]==I.digest(der),"identity_inventory_unverified")
            runuser=shutil.which("runuser",path=P.ENV["PATH"])
            need(bool(runuser),"runuser_required")
            P.execute([runuser,"-u","m365mailer","--","/usr/bin/test","-r",str(identity)])
            unchanged()
            need(P.missing(key) and E.secure_read(attempt,4096,0,modes=(0o600,))==marker,
                 "pem_key_or_attempt_marker_changed")
            return wrap(job,dict(review,status="prepared",changes=True,certificate_sha256=I.digest(der),
                                 certificate_der=base64.b64encode(der).decode("ascii")),True)
    except BaseException:
        if started:
            print("MAPPED_TPM_OUTCOME=inspect_handle_and_partial_files_no_auto_remove",file=sys.stderr,flush=True)
        raise
    finally:
        if guard is not None:
            os.close(guard)
        os.close(hardware_guard)


def main():
    try:
        need(os.geteuid()==0,"root_required")
        os.umask(0o077)
        job=parse(sys.stdin.buffer.read(8193))
        try:
            gid=service_group()
        except (KeyError,Refused):
            if job["action"]=="discover":
                print(P.encode(dict(version=1,available=False,reason="identity_directory_or_account",handle="",
                                    changes=False,key_created=False)).decode("ascii"))
                return 0
            raise
        if job["action"]=="discover":
            result=discover(gid)
        elif job["action"]=="preview":
            first=plan(job,gid)
            need(plan(job,gid)==first,"tpm_preview_changed")
            result=wrap(job,first,False)
        else:
            result=apply(job,gid)
        print(P.encode(result).decode("ascii"))
        return 0
    except (Refused,T.Refused,A.Refused,E.Refused,OSError,KeyError,TypeError,ValueError,UnicodeError):
        print("MAPPED_TPM_IDENTITY=refused_or_review_required")
        return 2


if __name__=="__main__":
    sys.exit(main())
