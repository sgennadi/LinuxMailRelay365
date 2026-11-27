#!/usr/bin/env python3
"""Installed primary PEM or managed persistent TPM2 runtime guard; no mail submission.

Use from a single-threaded trusted root CLI. Authentication is an observation,
not a delivery or SELinux execution-domain assertion. No persistent receipt.
"""
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
LIBEXEC = Path("/usr/local/libexec")
TRANSPORT = "m365_xoauth2_transport.py"
SIGNER = "m365_hardware_signer.py"
ACTIVE = "/etc/postfix/m365-oauth/app.json"
CONFIRM = "VERIFY_PRIMARY_MAILBOX_SMTP_AUTH"
SUCCESS = b"Microsoft 365 STARTTLS and SMTP AUTH XOAUTH2 verified; no message submitted\n"
ENV = {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C", "HOME":"/nonexistent"}
MAX_AGE = 90


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, str(HERE / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R = load("runtime_primary_route", "preview-primary-mailbox-route.py")
C = load("runtime_primary_pem", "manage-primary-oauth-rotation.py")
T = load("runtime_primary_tpm", "manage-tpm-oauth-key.py")


class Refused(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(value):
    return hashlib.sha256(R.encode(value)).hexdigest()


def exact_guid(value):
    try:
        result = str(uuid.UUID(value))
        need(result == value and uuid.UUID(result).int != 0, "invalid_selected_guid")
        return result
    except (TypeError, ValueError, AttributeError):
        raise Refused("invalid_selected_guid") from None


def system_executable(path):
    # The OS package trust is a host prerequisite, not a package attestation.
    resolved = Path(path).resolve(strict=True)
    need(str(resolved).startswith(("/usr/bin/","/usr/sbin/","/bin/","/sbin/")),
         "unexpected_system_executable")
    R.E.trusted_directory(resolved.parent)
    meta = resolved.lstat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
         not meta.st_mode & 0o022 and bool(meta.st_mode & 0o111),
         "untrusted_system_executable")
    return [str(resolved),meta.st_dev,meta.st_ino,meta.st_size,
            meta.st_mtime_ns,meta.st_ctime_ns,meta.st_mode]


def reject_import_artifacts(directory):
    # The installed pipe imports this sibling module. Do not approve an
    # alternative package or precompiled module in place of pinned source.
    for name in os.listdir(str(directory)):
        if name == "m365_hardware_signer" or (
                name.startswith("m365_hardware_signer.") and name != SIGNER):
            raise Refused("ambiguous_installed_signer_import")
    cache = directory / "__pycache__"
    if os.path.lexists(str(cache)):
        R.E.trusted_directory(cache)
        if any(name.startswith("m365_hardware_signer.") for name in os.listdir(str(cache))):
            raise Refused("installed_signer_bytecode_requires_review")


def read_active(group):
    root=Path(ACTIVE).parent
    R.E.trusted_directory(root)
    raw,identity=R.E.read_identity(Path(ACTIVE),root,group)
    def unique(pairs):
        result={}
        for key,value in pairs:
            need(key not in result,"duplicate_active_identity_field")
            result[key]=value
        return result
    need(json.loads(raw.decode("utf-8"),object_pairs_hook=unique)==identity,
         "active_identity_parse_mismatch")
    return raw,identity


def tpm_device_fingerprint(value):
    return [value.st_dev,value.st_ino,value.st_rdev,value.st_uid,value.st_gid,value.st_mode]


def service_privilege_drop(uid,gid,groups):
    need(os.geteuid()==0 and type(uid) is int and type(gid) is int and
         uid>0 and gid>0 and groups==[gid],"invalid_diagnostic_service_identity")
    def drop():
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        if (os.getresuid()!=(uid,uid,uid) or os.getresgid()!=(gid,gid,gid)
                or os.getgroups()):
            raise RuntimeError("incomplete_privilege_drop")
    return drop


# Fixed child program, no caller-provided source, shell, device path or
# TPM command. Open the resource manager in the same access mode as a TCTI,
# then immediately close it without reading, writing or issuing an ioctl.
# This is a service-credential access observation, NOT a postfix_pipe_t test.
TPM_OPEN_PROBE = r"""
import json,os,stat,sys
uid,gid=int(sys.argv[1]),int(sys.argv[2])
expected=json.loads(sys.argv[3])
if (os.getresuid()!=(uid,uid,uid) or os.getresgid()!=(gid,gid,gid)
        or os.getgroups()):
    raise SystemExit(1)
fd=os.open("/dev/tpmrm0",os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
    st=os.fstat(fd)
    actual=[st.st_dev,st.st_ino,st.st_rdev,st.st_uid,st.st_gid,st.st_mode]
    if not stat.S_ISCHR(st.st_mode) or actual!=expected:
        raise SystemExit(1)
finally:
    os.close(fd)
print("TPM_RESOURCE_MANAGER_OPEN_CLOSE_OK")
"""


def check_service_tpm_access(uid,gid,groups,expected,runner=subprocess.run):
    """Check actual service access without broadening group/device permissions."""
    drop=service_privilege_drop(uid,gid,groups)
    need(type(expected) is list and len(expected)==6 and
         all(type(value) is int and value>=0 for value in expected) and
         expected[3]==0 and stat.S_ISCHR(expected[5]) and not expected[5]&0o002,
         "invalid_tpm_resource_manager_fingerprint")
    try:
        before=T.DEVICE.lstat()
        need(tpm_device_fingerprint(before)==expected,"tpm_resource_manager_changed")
        python=system_executable("/usr/bin/python3")
        result=runner(["/usr/bin/python3","-I","-B","-c",TPM_OPEN_PROBE,
                       str(uid),str(gid),json.dumps(expected,separators=(",",":"))],
                      input=b"",stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                      timeout=10,check=False,env=dict(ENV),cwd="/",preexec_fn=drop)
        need(result.returncode==0 and result.stdout==b"TPM_RESOURCE_MANAGER_OPEN_CLOSE_OK\n"
             and not result.stderr,"tpm_service_device_access_requires_review")
        after=T.DEVICE.lstat()
        need(tpm_device_fingerprint(after)==expected and
             before.st_ctime_ns==after.st_ctime_ns and
             system_executable("/usr/bin/python3")==python,
             "tpm_resource_manager_changed")
    except (OSError,subprocess.SubprocessError):
        raise Refused("tpm_service_device_access_requires_review") from None


def tpm_public_evidence(handle,certificate):
    # No TPM key creation, eviction or export. Read only the public key
    # from the managed persistent handle, using the kernel resource manager.
    T.check_hardware()
    device=T.DEVICE.lstat()
    need(stat.S_ISCHR(device.st_mode) and device.st_uid==0 and not device.st_mode&0o002,
         "untrusted_tpm_resource_manager")
    binary=system_executable(str(T.COMMANDS["readpublic"]))
    with tempfile.TemporaryDirectory(prefix="lmr365-tpm-runtime-",dir="/run") as work:
        public=Path(work)/"public.pem"
        T.run_command([str(T.COMMANDS["readpublic"]),"-c",handle,
                       "-f","pem","-o",str(public)],timeout=35,
                      operation="managed_tpm_handle_unreadable")
        raw=R.E.secure_read(public,16384,modes=(0o600,0o640,0o644))
    expected=C.openssl(["x509","-pubkey","-noout","-in",certificate]).strip()
    need(bool(expected) and expected==raw.strip(),"tpm_handle_certificate_mismatch")
    C.openssl(["x509","-in",certificate,"-noout","-checkend","0"])
    need(system_executable(str(T.COMMANDS["readpublic"]))==binary,
         "tpm_readpublic_changed")
    after=T.DEVICE.lstat()
    need(tpm_device_fingerprint(after)==tpm_device_fingerprint(device),
         "tpm_resource_manager_changed")
    return {"public_key_sha256":hashlib.sha256(expected).hexdigest(),
            "device":tpm_device_fingerprint(device),"readpublic":binary}


def managed_tpm_snapshot(identity,group):
    root=Path(ACTIVE).parent
    need(set(identity)=={"tenant_id","client_id","mailbox","certificate","signer"},
         "unexpected_hardware_identity_fields")
    spec=identity["signer"]
    need(type(spec) is dict and set(spec)=={"type","provider","key_ref","provider_config"},
         "invalid_hardware_signer_fields")
    need(spec["type"]=="openssl-provider" and spec["provider"]=="tpm2",
         "only_managed_tpm2_provider_supported")
    reference=spec["key_ref"]
    need(type(reference) is str and reference.startswith("handle:") and
         T.HANDLE.fullmatch(reference[len("handle:"):]) is not None,
         "only_managed_persistent_tpm2_handle_supported")
    # Deliberately accept only the exact provisioner's standalone template;
    # arbitrary .include, module paths, PIN files and PKCS#11 dependencies
    # cannot be represented by the present runtime evidence contract.
    provider=str(root/"tpm2.cnf")
    certificate=str(root/"hardware-app.crt")
    need(spec["provider_config"]==provider and identity["certificate"]==certificate,
         "managed_tpm_reference_mismatch")
    config=R.E.secure_read(provider,32768,group)
    need(config==T.PROVIDER_TEMPLATE.encode("ascii"),"managed_tpm_provider_config_changed")
    cert=R.E.secure_read(certificate,R.E.MAX_PEM,modes=(0o640,0o644))
    der=R.E.der_from_pem(cert)
    public=tpm_public_evidence(reference[len("handle:"):],certificate)
    need(R.E.secure_read(provider,32768,group)==config and
         R.E.secure_read(certificate,R.E.MAX_PEM,modes=(0o640,0o644))==cert,
         "managed_tpm_dependencies_changed")
    return {"certificate_sha256":hashlib.sha256(der).hexdigest(),
            "certificate_file_sha256":hashlib.sha256(cert).hexdigest(),
            "hardware":{"provider":"tpm2","key_ref":reference,
                        "provider_config_sha256":hashlib.sha256(config).hexdigest(),
                        **public}}


def installed_snapshot(mailbox, tenant, client):
    try:
        need(os.geteuid() == 0, "root_required")
        R.parse(R.encode({"mailbox":mailbox,"nonce":"0"*64}))
        exact_guid(tenant)
        exact_guid(client)
        R.E.trusted_directory(HERE)
        R.E.trusted_directory(LIBEXEC)
        account = pwd.getpwnam("m365mailer")
        group = grp.getgrnam("m365mailer")
        groups = sorted(set(os.getgrouplist("m365mailer",account.pw_gid)))
        need(account.pw_name == "m365mailer" and account.pw_uid > 0 and
             account.pw_gid == group.gr_gid > 0 and groups == [group.gr_gid],
             "unsupported_service_account_or_groups")
        raw,identity=read_active(group.gr_gid)
        need(identity["tenant_id"] == tenant and identity["client_id"] == client and
             identity["mailbox"].lower() == mailbox,
             "selected_primary_identity_mismatch")
        inventory = R.E.active_inventory("primary")
        need(inventory["tenant"] == tenant and inventory["client"] == client and
             inventory["mailbox"] == mailbox and
             inventory["identity_sha"] == C.sha(raw),
             "active_identity_inventory_mismatch")
        if "signer" in identity:
            credentials=managed_tpm_snapshot(identity,group.gr_gid)
            need(credentials["certificate_sha256"]==inventory["certificate_sha"],
                 "active_tpm_certificate_inventory_mismatch")
            # Postfix pipe runs with a single selected group; a successful
            # root ReadPublic or runuser with supplementary groups cannot
            # establish that the exact transport credentials can open TPM.
            check_service_tpm_access(account.pw_uid,group.gr_gid,groups,
                                     credentials["hardware"]["device"])
            version=2
        else:
            active=C.current(group.gr_gid)
            need(active["raw"]==raw and active["identity"]==identity,
                 "active_pem_identity_changed")
            # Keep existing PEM v1 digest stable for existing backups.
            credentials={"certificate_sha256":inventory["certificate_sha"],
                         "certificate_file_sha256":active["cert_sha"],
                         "key_sha256":active["key_sha"]}
            version=1
        sources = {}
        for name in (TRANSPORT,SIGNER):
            bundled = R.E.secure_read(HERE/name,1048576,modes=(0o600,0o640,0o644,0o755))
            installed = R.E.secure_read(LIBEXEC/name,1048576,modes=(0o644,0o755))
            need(bundled == installed,"installed_runtime_version_mismatch")
            sources[name] = hashlib.sha256(installed).hexdigest()
        reject_import_artifacts(LIBEXEC)
        need(read_active(group.gr_gid)==(raw,identity),"active_identity_changed")
        need(R.E.active_inventory("primary")==inventory,"active_certificate_changed")
        return {"version":version,"mailbox":mailbox,"tenant":tenant,"client":client,
                "uid":account.pw_uid,"gid":group.gr_gid,"groups":groups,
                "identity_sha256":inventory["identity_sha"],**credentials,"sources":sources,
                "python":system_executable("/usr/bin/python3"),
                "openssl":system_executable("/usr/bin/openssl")}
    except Refused:
        raise
    except (R.E.Refused,C.Refused,T.Refused,OSError,KeyError,ValueError,TypeError,
            subprocess.SubprocessError):
        raise Refused("primary_runtime_not_verified") from None


def run_auth(state, runner=subprocess.run):
    uid,gid = state["uid"],state["gid"]
    drop=service_privilege_drop(uid,gid,state["groups"])
    # Same installed interpreter and transport as the proposed pipe.
    # Ignore inherited Python settings, disable user site and bytecode writes.
    args = ["/usr/bin/python3","-E","-s","-B",str(LIBEXEC/TRANSPORT),
            "--smtp-auth-check","--config",ACTIVE]
    try:
        result = runner(args,input=b"",stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                        timeout=120,check=False,env=dict(ENV),cwd="/",preexec_fn=drop)
    except (OSError,subprocess.SubprocessError):
        raise Refused("primary_smtp_auth_unavailable") from None
    need(result.returncode == 0 and result.stdout == SUCCESS and not result.stderr,
         "primary_smtp_auth_not_verified")


class RuntimeGuard:
    """Stable SHA plus a recent in-memory AUTH observation.

    Callers must hold the maintenance and rotation locks throughout.
    Any dependency drift poisons this instance; require a fresh review.
    """
    def __init__(self, tenant, client, confirmation, snapshot=installed_snapshot,
                 auth=run_auth, clock=time.monotonic, expected_sha=None):
        need(confirmation == CONFIRM, "explicit_smtp_auth_confirmation_required")
        self.tenant = exact_guid(tenant)
        self.client = exact_guid(client)
        self.snapshot = snapshot
        self.auth = auth
        self.clock = clock
        need(expected_sha is None or (type(expected_sha) is str and R.SHA.fullmatch(expected_sha) is not None),
             "invalid_expected_runtime_sha")
        self.bound = expected_sha
        self.checked_at = None
        self.failed = False

    def __call__(self, mailbox):
        need(not self.failed, "runtime_guard_requires_fresh_review")
        try:
            state = self.snapshot(mailbox,self.tenant,self.client)
            fingerprint = digest(state)
            if self.bound is not None:
                need(fingerprint == self.bound, "installed_runtime_changed")
            now = self.clock()
            if self.checked_at is not None:
                need(now >= self.checked_at, "invalid_auth_observation_clock")
            if self.checked_at is None or now-self.checked_at >= MAX_AGE:
                self.auth(state)
                need(digest(self.snapshot(mailbox,self.tenant,self.client)) == fingerprint,
                     "runtime_changed_during_smtp_auth")
                end = self.clock()
                need(end >= now, "invalid_auth_observation_clock")
                self.checked_at = end
            self.bound = fingerprint
            return fingerprint
        except Exception:
            self.failed = True
            raise


if __name__ == "__main__":
    raise SystemExit("Runtime guard library; use the separately approved offline review.")
