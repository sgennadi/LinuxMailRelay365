#!/usr/bin/env python3
"""Root-only TPM2 RSA key and public certificate preparation (Preview).

A TPM is modified ONLY with --apply, an unchanged SHA256 plan, and explicit
typed confirmation. Creates one new non-exportable primary RSA signing key
at a free owner persistent handle and one self-signed public X.509 certificate.
Never deletes/evicts an existing TPM object, exports a private key, updates
app.json, creates hardware-staged.json, changes Postfix or contacts Entra.

Requires TPM resource manager /dev/tpmrm0, OpenSSL >=3 with an installed tpm2
provider, tpm2-tools, and an unauthenticated owner hierarchy. Refuses rather
than downgrading OpenSSL, installing a provider or bypassing authorization.
Python 3.6+ so the preflight works on RHEL/Oracle/Rocky/Alma 8 as well.
"""
import argparse
import errno
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile

VERSION = "1"
CONFIRM = "CREATE_TPM2_OAUTH_KEY"
LOCK = Path("/run/linuxmailrelay365-hardware-oauth.lock")
DEVICE = Path("/dev/tpmrm0")
TPM_MAJOR = Path("/sys/class/tpm/tpm0/tpm_version_major")
TARGETS = {
    "sidecar": Path("/etc/linuxmailrelay365/sidecar-identity"),
    "primary": Path("/etc/postfix/m365-oauth"),
}
# Limited, application-chosen owner-handle window. Every candidate is checked
# against the live TPM; no handle is allocated or overwritten in preview.
HANDLE = re.compile(r"\A0x8101[a-f0-9]{4}\Z")
CAP_LINE = re.compile(r"^-\s*(0x81[a-fA-F0-9]{6})\s*$")
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
COMMANDS = {
    "getcap": Path("/usr/bin/tpm2_getcap"),
    "createprimary": Path("/usr/bin/tpm2_createprimary"),
    "evictcontrol": Path("/usr/bin/tpm2_evictcontrol"),
    "readpublic": Path("/usr/bin/tpm2_readpublic"),
    "openssl": Path("/usr/bin/openssl"),
}
MAX_IDENTITY = 32768
MAX_COMMAND_OUTPUT = 65536
KEY_ATTRS = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"
PROVIDER_TEMPLATE = """# Managed by LinuxMailRelay365 TPM2 provisioning.
# Hardware key is at an owner persistent handle; never a PEM private key.
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
tpm2 = tpm2_sect
[default_sect]
activate = 1
[tpm2_sect]
activate = 1
tcti = device:/dev/tpmrm0
"""


class Refused(Exception):
    pass


def emit(key, value):
    print("TPM_PROVISION_{}={}".format(key, value))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require_root():
    if os.geteuid() != 0:
        raise Refused("root_required")


def check_dir(path):
    """Check all ancestors; reject symlink/writable directory substitution."""
    item = Path(path)
    while True:
        try:
            info = item.lstat()
        except OSError:
            raise Refused("missing_root_owned_identity_directory")
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused("untrusted_identity_directory")
        if item == item.parent:
            break
        item = item.parent


def checked_file(path, gid=None):
    try:
        info = Path(path).lstat()
    except OSError:
        raise Refused("installed_identity_missing")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or (info.st_mode & 0o022) or info.st_size < 1 or
            info.st_size > MAX_IDENTITY or
            (gid is not None and (info.st_gid != gid or
                                  stat.S_IMODE(info.st_mode) != 0o640))):
        raise Refused("untrusted_installed_identity")
    return info


def read_checked(path, gid=None):
    before = checked_file(path, gid)
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            actual = os.fstat(stream.fileno())
            if (actual.st_ino != before.st_ino or actual.st_dev != before.st_dev or
                    actual.st_uid != before.st_uid or actual.st_gid != before.st_gid or
                    actual.st_size != before.st_size or
                    stat.S_IMODE(actual.st_mode) != stat.S_IMODE(before.st_mode) or
                    actual.st_nlink != 1):
                raise Refused("active_oauth_changed_during_review")
            raw = stream.read(MAX_IDENTITY + 1)
    except OSError:
        raise Refused("active_oauth_read_failed")
    if len(raw) != before.st_size:
        raise Refused("active_oauth_changed_during_review")
    return raw


def command_env(conf=None):
    env = {"LC_ALL": "C", "PATH": "/usr/bin:/bin",
           "HOME": "/nonexistent", "TPM2TOOLS_TCTI": "device:/dev/tpmrm0",
           "TPM2OPENSSL_TCTI": "device:/dev/tpmrm0",
           "OPENSSL_CONF": str(conf) if conf is not None else "/dev/null"}
    return env


def run_command(argv, *, input_data=None, env=None, timeout=60, operation="command_failed"):
    if not isinstance(argv, list) or not argv or \
            not all(isinstance(x, str) for x in argv):
        raise Refused("invalid_command")
    try:
        r = subprocess.run(argv, input=input_data, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, check=False,
                           timeout=timeout, env=command_env() if env is None else env)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused(operation)
    if r.returncode or len(r.stdout) > MAX_COMMAND_OUTPUT:
        raise Refused(operation)
    return r.stdout


def runtime_tool_metadata(meta):
    return [meta.st_dev,meta.st_ino,meta.st_mode,meta.st_uid,meta.st_gid,
            meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns]


def trusted_runtime_tool(tool):
    """Accept a native executable or the fixed distro TPM2 multicall alias.

    Never invoke the resolved binary instead of its original alias: tpm2
    selects the command from argv[0]. No PATH search or arbitrary symlink
    chain is allowed. Directory and executable trust are checked separately.
    """
    if tool not in COMMANDS.values() or tool.parent!=Path("/usr/bin"):
        raise Refused("unsafe_tpm2_or_openssl_utility")
    check_dir(tool.parent)
    try:
        before=tool.lstat()
        target=tool
        link=None
        if stat.S_ISLNK(before.st_mode):
            # tpm2-tools packages commonly install tpm2_* as symlinks to
            # the same multicall /usr/bin/tpm2 binary. The symlink's mode
            # is not a write-access grant; its owner and parent matter.
            if tool==COMMANDS["openssl"] or before.st_uid!=0:
                raise Refused("unsafe_tpm2_or_openssl_utility")
            link=os.readlink(str(tool))
            if link not in ("tpm2","/usr/bin/tpm2"):
                raise Refused("unsafe_tpm2_or_openssl_utility")
            target=Path("/usr/bin/tpm2")
        actual=target.lstat()
        if (not stat.S_ISREG(actual.st_mode) or actual.st_uid!=0 or
                actual.st_mode&0o6022 or not actual.st_mode&0o111):
            raise Refused("unsafe_tpm2_or_openssl_utility")
        evidence=[str(tool),runtime_tool_metadata(before),link,
                  str(target),runtime_tool_metadata(actual)]
        if (runtime_tool_metadata(tool.lstat())!=evidence[1] or
                runtime_tool_metadata(target.lstat())!=evidence[4] or
                (link is not None and os.readlink(str(tool))!=link)):
            raise Refused("tpm_runtime_utility_changed")
        return evidence
    except OSError:
        raise Refused("missing_tpm2_or_openssl_utility") from None


def check_runtime_files():
    return {name:trusted_runtime_tool(tool) for name,tool in sorted(COMMANDS.items())}


def read_capabilities():
    raw = run_command([str(COMMANDS["getcap"]), "handles-persistent"],
                      operation="tpm_persistent_inventory_failed", timeout=35)
    try:
        lines = raw.decode("ascii").strip().splitlines()
    except UnicodeError:
        raise Refused("tpm_inventory_unparseable")
    result = set()
    for line in lines:
        m = CAP_LINE.fullmatch(line.strip())
        if not m:
            raise Refused("tpm_inventory_unparseable")
        result.add(m.group(1).lower())
    return result


def provider_ready():
    version = run_command([str(COMMANDS["openssl"]), "version"],
                          operation="openssl_version_failed").decode("ascii", "replace")
    m = re.match(r"^OpenSSL\s+([0-9]+)\.", version)
    if not m or int(m.group(1)) < 3:
        raise Refused("openssl3_native_tpm2_provider_required")
    run_command([str(COMMANDS["openssl"]), "list", "-providers",
                 "-provider", "tpm2"],
                operation="tpm2_openssl_provider_missing")
    return version.strip().splitlines()[0][:150]


def check_hardware():
    try:
        dev = DEVICE.stat()
        major = TPM_MAJOR.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise Refused("tpm2_resource_manager_or_sysfs_missing")
    if not stat.S_ISCHR(dev.st_mode) or major != "2":
        raise Refused("real_tpm2_resource_manager_required")
    return major


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


def primary_device_fingerprint(meta):
    return [meta.st_dev,meta.st_ino,meta.st_rdev,meta.st_uid,meta.st_gid,meta.st_mode]


def primary_python_fingerprint():
    # Fixed OS interpreter, not PATH or user-supplied code.
    python=Path("/usr/bin/python3").resolve(strict=True)
    if python.parent!=Path("/usr/bin"):
        raise Refused("untrusted_primary_tpm_python")
    check_dir(python.parent)
    meta=python.lstat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022 or
            not meta.st_mode&0o111):
        raise Refused("untrusted_primary_tpm_python")
    return [str(python),meta.st_dev,meta.st_ino,meta.st_size,meta.st_mode,
            meta.st_mtime_ns,meta.st_ctime_ns]


def primary_service_device_evidence(gid,runner=subprocess.run):
    """Prove the primary pipe's restricted service UID/GID can open TPM.

    This performs no TPM command, not even ReadPublic. No group, permission,
    ACL or SELinux change. The child's actual SELinux domain is not the pipe.
    """
    require_root()
    try:
        account=pwd.getpwnam("m365mailer")
        uid=account.pw_uid
        groups=sorted(set(os.getgrouplist("m365mailer",account.pw_gid)))
        if (account.pw_name!="m365mailer" or uid<=0 or gid<=0 or
                account.pw_gid!=gid or groups!=[gid] or
                grp.getgrnam("m365mailer").gr_gid!=gid):
            raise Refused("unsupported_primary_tpm_service_account_or_groups")
        before=DEVICE.lstat()
        if (not stat.S_ISCHR(before.st_mode) or before.st_uid!=0 or
                before.st_mode&0o002):
            raise Refused("untrusted_primary_tpm_resource_manager")
        expected=primary_device_fingerprint(before)
        python=primary_python_fingerprint()
        def drop():
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            if (os.getresuid()!=(uid,uid,uid) or os.getresgid()!=(gid,gid,gid)
                    or os.getgroups()):
                raise RuntimeError("incomplete_privilege_drop")
        result=runner(["/usr/bin/python3","-I","-B","-c",TPM_OPEN_PROBE,
                       str(uid),str(gid),json.dumps(expected,separators=(",",":"))],
                      input=b"",stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                      timeout=10,check=False,
                      env={"LC_ALL":"C","PATH":"/usr/bin:/bin","HOME":"/nonexistent"},
                      cwd="/",preexec_fn=drop)
        if (result.returncode!=0 or result.stdout!=b"TPM_RESOURCE_MANAGER_OPEN_CLOSE_OK\n"
                or result.stderr):
            raise Refused("primary_tpm_service_device_access_requires_review")
        after=DEVICE.lstat()
        current=pwd.getpwnam("m365mailer")
        if (primary_device_fingerprint(after)!=expected or
                before.st_ctime_ns!=after.st_ctime_ns or
                primary_python_fingerprint()!=python or
                (current.pw_name,current.pw_uid,current.pw_gid)!=("m365mailer",uid,gid) or
                grp.getgrnam("m365mailer").gr_gid!=gid or
                sorted(set(os.getgrouplist("m365mailer",gid)))!=groups):
            raise Refused("primary_tpm_service_access_changed")
        return {"uid":uid,"gid":gid,"groups":groups,"device":expected,
                "device_ctime_ns":before.st_ctime_ns,"python":python}
    except (KeyError,OSError,subprocess.SubprocessError):
        raise Refused("primary_tpm_service_device_access_requires_review") from None


def check_empty_destination(path):
    if path.exists() or path.is_symlink():
        raise Refused("hardware_certificate_or_provider_config_already_exists")


def prepare(target, handle):
    """Read-only plan: never create keys/files or contact Entra."""
    if target not in TARGETS or not isinstance(handle, str) or not HANDLE.fullmatch(handle):
        raise Refused("unsupported_tpm2_target_or_handle")
    directory = TARGETS[target]
    check_dir(directory)
    require_root()
    check_hardware()
    utilities=check_runtime_files()
    try:
        gid = grp.getgrnam("m365mailer").gr_gid
        pwd.getpwnam("m365mailer")
    except KeyError:
        raise Refused("m365mailer_service_account_missing")
    # Only the primary Postfix route currently requires a single group.
    # Preserve the existing sidecar plan/privilege contract.
    access = primary_service_device_evidence(gid) if target == "primary" else None
    existing = directory / "app.json"
    # Never read private key material, and never follow a substituted
    # app.json symlink between lstat() and opening the reviewed identity.
    active_raw = read_checked(existing, gid)
    try:
        active = json.loads(active_raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise Refused("invalid_installed_identity")
    if not isinstance(active, dict) or not all(
            isinstance(active.get(k), str) and active.get(k)
            for k in ("tenant_id", "client_id", "mailbox", "certificate")):
        raise Refused("invalid_installed_identity")
    check_empty_destination(directory / "tpm2.cnf")
    check_empty_destination(directory / "hardware-app.crt")
    check_empty_destination(directory / "hardware-staged.json")
    version = provider_ready()
    handles = read_capabilities()
    if handle in handles:
        raise Refused("tpm_persistent_handle_occupied_no_overwrite")
    # ReadPublic is a second independent check; if TPM cannot distinguish an
    # unoccupied handle cleanly, fail rather than assuming it is available.
    # Occupancy is rechecked immediately before EvictControl as well.
    device = check_hardware()
    evidence = {"version": VERSION, "target": target, "handle": handle,
                "device": str(DEVICE), "tpm_major": device,
                "active_sha256": sha(active_raw),
                "persistent_handles": sorted(handles),
                "openssl_version": version, "group": gid,
                "provider_config_sha256": sha(PROVIDER_TEMPLATE.encode("ascii"))}
    if access is not None:
        if primary_service_device_evidence(gid) != access:
            raise Refused("primary_tpm_service_access_changed")
        if check_runtime_files()!=utilities:
            raise Refused("tpm_runtime_utility_changed")
        evidence["primary_service_access"] = access
        evidence["primary_runtime_utilities"] = utilities
    digest = sha(json.dumps(evidence, sort_keys=True,
                            separators=(",", ":")).encode("utf-8"))
    return {"sha": digest, "target": target, "handle": handle,
            "directory": directory, "gid": gid, "evidence": evidence}


def report(plan):
    emit("VERSION", VERSION)
    emit("TARGET", plan["target"])
    emit("HANDLE", plan["handle"])
    emit("PLAN_SHA256", plan["sha"])
    emit("HANDLE_FREE", "yes")
    emit("KEY_TYPE", "RSA2048_TPM2_PRIMARY_SIGNING")
    emit("OPENSSL3_PROVIDER_READY", "yes")
    emit("KEY_CREATED", "no")
    emit("CERTIFICATE_CREATED", "no")
    emit("ACTIVE_OAUTH_CHANGED", "no")
    emit("ENTRA_CONTACTED", "no")
    emit("MAIL_SENT", "no")
    emit("TPM_OBJECTS_REMOVED", "no")
    emit("READY_FOR_APPROVED_CREATION", "yes")


def lock():
    check_dir(LOCK.parent)
    fd = None
    try:
        fd = os.open(str(LOCK), os.O_RDWR | os.O_CREAT |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600):
            raise Refused("untrusted_hardware_oauth_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except (OSError, BlockingIOError):
        if fd is not None:
            os.close(fd)
        raise Refused("another_hardware_oauth_change_in_progress")
    except Exception:
        if fd is not None:
            os.close(fd)
        raise


def set_label_like_active(path, active):
    try:
        context = os.getxattr(str(active), "security.selinux",
                              follow_symlinks=False)
    except OSError as exc:
        # Non-SELinux filesystem; on Enforcing hosts preserve label.
        if exc.errno in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
            return
        raise Refused("selinux_label_read_failed")
    try:
        os.setxattr(str(path), "security.selinux", context,
                    follow_symlinks=False)
    except OSError:
        raise Refused("selinux_label_write_failed")


def write_exclusive(path, raw, gid, mode):
    fd = None
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchown(fd, 0, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as out:
            fd = None
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        set_label_like_active(path, path.parent / "app.json")
    finally:
        if fd is not None:
            os.close(fd)


def fsync_directory(directory):
    fd = os.open(str(directory), os.O_RDONLY |
                 getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_service_signature(plan, cert, scratch):
    """Actual provider signing as m365mailer; verify PS256 with public X.509."""
    group = plan["gid"]
    checked_file(cert)  # Certificate must be root owned and non-writable.
    pubkey = scratch / "public.pem"
    sigfile = scratch / "signature.bin"
    payload = b"LinuxMailRelay365 TPM2 local PS256 signing acceptance v1"
    runuser = next((p for p in
                    ("/usr/sbin/runuser", "/usr/bin/runuser", "/sbin/runuser")
                    if Path(p).is_file()), None)
    if runuser is None:
        raise Refused("service_user_runner_missing")
    conf = plan.get("provider_config", plan["directory"] / "tpm2.cnf")
    env = command_env(conf)
    sig = run_command([runuser, "-u", "m365mailer", "--",
                       str(COMMANDS["openssl"]), "pkeyutl",
                       "-provider", "base", "-provider", "tpm2",
                       "-sign", "-inkey", "handle:" + plan["handle"],
                       "-rawin", "-digest", "sha256",
                       "-pkeyopt", "rsa_padding_mode:pss",
                       "-pkeyopt", "rsa_pss_saltlen:32"],
                      input_data=payload, env=env, timeout=75,
                      operation="tpm_ps256_service_account_sign_failed")
    if not 128 <= len(sig) <= 512:
        raise Refused("tpm_ps256_signature_invalid")
    sigfile.write_bytes(sig)
    sigfile.chmod(0o600)
    public = run_command([str(COMMANDS["openssl"]), "x509",
                          "-in", str(cert), "-pubkey", "-noout"],
                         env=command_env(conf),
                         operation="tpm_public_certificate_invalid")
    if b"BEGIN PUBLIC KEY" not in public:
        raise Refused("tpm_public_certificate_invalid")
    pubkey.write_bytes(public)
    pubkey.chmod(0o600)
    checked = run_command([str(COMMANDS["openssl"]), "dgst",
                           "-sha256", "-verify", str(pubkey),
                           "-signature", str(sigfile),
                           "-sigopt", "rsa_padding_mode:pss",
                           "-sigopt", "rsa_pss_saltlen:32"],
                          input_data=payload, env=command_env(conf),
                          operation="tpm_certificate_public_key_mismatch")
    if b"Verified OK" not in checked:
        raise Refused("tpm_certificate_public_key_mismatch")


def verify_primary_creation_access(plan):
    if plan["target"]!="primary":
        return
    if primary_service_device_evidence(plan["gid"])!=plan["evidence"].get("primary_service_access"):
        raise Refused("primary_tpm_service_access_changed")
    if check_runtime_files()!=plan["evidence"].get("primary_runtime_utilities"):
        raise Refused("tpm_runtime_utility_changed")


def apply(target, handle, approved_sha, confirmation):
    """Changes real TPM state. Never evicts an existing persistent object."""
    require_root()
    if confirmation != CONFIRM or not SHA.fullmatch(approved_sha or ""):
        raise Refused("explicit_approval_and_plan_sha_required")
    guard = lock()
    persisted = False
    certificate_published = False
    try:
        plan = prepare(target, handle)
        if plan["sha"] != approved_sha:
            raise Refused("tpm_creation_plan_changed_reapprove")
        # No activation of an existing token/key; every attempt must start
        # from the exact reviewed handle inventory and active identity.
        if prepare(target, handle)["sha"] != approved_sha:
            raise Refused("tpm_creation_plan_changed_reapprove")
        with tempfile.TemporaryDirectory(prefix="lmr365-tpm2-", dir="/tmp") as work:
            scratch = Path(work)
            ctx = scratch / "primary.ctx"
            # TPM primary keys are deterministic for the same seed/template.
            # Mix fresh uniqueness into TPMT_PUBLIC.unique to obtain a new
            # cryptographic identity without exporting any TPM private key.
            # TPM2B_PUBLIC_KEY_RSA: 16-bit LE length + 32 random bytes.
            unique = scratch / "primary-unique.bin"
            unique.write_bytes(b"\x20\x00" + os.urandom(32))
            unique.chmod(0o600)
            pub1 = scratch / "new-public.pem"
            pub2 = scratch / "persistent-public.pem"
            env = command_env()
            verify_primary_creation_access(plan)
            run_command([str(COMMANDS["createprimary"]), "-C", "o",
                         "-G", "rsa2048:null:null", "-g", "sha256",
                         "-a", KEY_ATTRS, "-u", str(unique),
                         "-c", str(ctx)], env=env, timeout=150,
                        operation="tpm_primary_key_creation_failed")
            # Two checks before persistence, with the cross-component lock.
            if handle in read_capabilities():
                raise Refused("tpm_handle_occupied_after_creation")
            run_command([str(COMMANDS["readpublic"]), "-c", str(ctx),
                         "-f", "pem", "-o", str(pub1)], env=env,
                        operation="new_tpm_key_public_unavailable")
            if handle in read_capabilities():
                raise Refused("tpm_handle_occupied_before_persistence")
            verify_primary_creation_access(plan)
            # IMPORTANT: with -c a transient context we only persist; never
            # pass a persistent -c handle (which would EVICT an existing key).
            run_command([str(COMMANDS["evictcontrol"]), "-C", "o",
                         "-c", str(ctx), handle], env=env, timeout=45,
                        operation="tpm_handle_persistence_failed")
            persisted = True
            if handle not in read_capabilities():
                raise Refused("new_tpm_persistent_handle_not_visible")
            run_command([str(COMMANDS["readpublic"]), "-c", handle,
                         "-f", "pem", "-o", str(pub2)], env=env,
                        operation="new_tpm_persistent_key_unreadable")
            if pub1.read_bytes() != pub2.read_bytes():
                raise Refused("new_tpm_key_identity_mismatch")
            provider_path = plan["directory"] / "tpm2.cnf"
            cert_path = plan["directory"] / "hardware-app.crt"
            check_empty_destination(provider_path)
            check_empty_destination(cert_path)
            write_exclusive(provider_path, PROVIDER_TEMPLATE.encode("ascii"),
                            plan["gid"], 0o640)
            # Generate a self-signed public cert with the *hardware* key.
            # No PEM private key or key-auth file is created or printed.
            cert_tmp = scratch / "public-cert.pem"
            run_command([str(COMMANDS["openssl"]), "req", "-new", "-x509",
                         "-sha256", "-days", "365", "-subj",
                         "/CN=LinuxMailRelay365 Hardware OAuth",
                         "-provider", "tpm2", "-provider", "default",
                         "-propquery", "?provider=tpm2",
                         "-key", "handle:" + handle,
                         "-out", str(cert_tmp)],
                        env=command_env(provider_path), timeout=95,
                        operation="tpm_hardware_certificate_generation_failed")
            raw_cert = cert_tmp.read_bytes()
            if (b"-----BEGIN CERTIFICATE-----" not in raw_cert or
                    len(raw_cert) > MAX_IDENTITY):
                raise Refused("tpm_public_certificate_invalid")
            write_exclusive(cert_path, raw_cert, plan["gid"], 0o644)
            certificate_published = True
            verify_service_signature(plan, cert_path, scratch)
            # Provenance is not the same as attestation: only a signature
            # from the configured TPM provider and certificate is proven.
            fsync_directory(plan["directory"])
            emit("VERSION", VERSION)
            emit("TARGET", target)
            emit("HANDLE", handle)
            emit("PERSISTENT_KEY_CREATED", "yes")
            emit("CERTIFICATE_CREATED", "yes")
            emit("CERTIFICATE_SHA256", sha(raw_cert))
            emit("SERVICE_ACCOUNT_PS256_VERIFIED", "yes")
            emit("HARDWARE_ATTESTATION_VERIFIED", "no")
            emit("STAGED_IDENTITY_CREATED", "no")
            emit("ACTIVE_OAUTH_CHANGED", "no")
            emit("ENTRA_CONTACTED", "no")
            emit("MAIL_SENT", "no")
            emit("TPM_OBJECTS_REMOVED", "no")
            emit("NEXT", "review_hardware_oauth_candidate_stage")
    except Exception:
        # A persistent key is never silently removed: doing so could delete
        # a key which another process now uses. Fail closed, never retry at
        # the same handle without a fresh reviewed plan and manual inspection.
        emit("KEY_MAY_EXIST", "yes" if persisted else "unknown")
        emit("CERTIFICATE_MAY_EXIST", "yes" if certificate_published else "unknown")
        emit("RECOVERY", "inspect_selected_handle_and_root_owned_files_no_auto_evict")
        raise
    finally:
        os.close(guard)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--handle", required=True)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approve-sha256", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    try:
        if bool(args.plan) == bool(args.apply):
            raise Refused("select_plan_or_apply")
        if args.plan and (args.approve_sha256 or args.confirm):
            raise Refused("approval_forbidden_in_readonly_mode")
        if args.plan:
            report(prepare(args.target, args.handle))
        else:
            apply(args.target, args.handle, args.approve_sha256, args.confirm)
        return 0
    except Refused as exc:
        emit("ERROR", str(exc))
        return 2
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        emit("ERROR", "unexpected_tpm_provisioning_io_failure")
        return 2


if __name__ == "__main__":
    sys.exit(main())
