#!/usr/bin/env python3
"""Disposable KVM+swtpm acceptance of real kernel TPM2 access and provisioning.

The emulator is not physical hardware or attestation. Only the CI guest's
new device and identity are used. No production permission changes, mail,
Entra, SELinux policy changes or removal of persistent TPM objects.
"""
import grp
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess

HERE=Path(__file__).resolve().parent
MARKER=Path("/run/lmr365-disposable-vtpm-vm")
BOOT=Path("/proc/sys/kernel/random/boot_id")
IDENTITY=Path("/etc/postfix/m365-oauth")
DEVICE=Path("/dev/tpmrm0")
ACCOUNT="m365mailer"
HANDLE="0x81010001"
ENV={"LC_ALL":"C","PATH":"/usr/sbin:/usr/bin:/sbin:/bin"}

def need(condition,reason):
    if not condition:
        raise RuntimeError(reason)

def command(*args,timeout=60):
    return subprocess.run(list(args),check=True,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,timeout=timeout,env=ENV).stdout

def disposable():
    need(os.geteuid()==0 and os.environ.get("GITHUB_ACTIONS")=="true" and
         os.environ.get("LMR365_KVM_VTPM_GUEST")=="true","disposable_vtpm_guest_only")
    st=MARKER.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
         stat.S_IMODE(st.st_mode)==0o600 and MARKER.read_bytes()==BOOT.read_bytes(),
         "vtpm_boot_bound_marker_required")
    need(command("/usr/bin/hostname","-s").strip()==b"rocky-selinux-ci" and
         Path("/proc/1/comm").read_text().strip()=="systemd" and
         Path("/sys/fs/selinux/enforce").read_text().strip()=="1" and
         any(line in ("ID=rocky",'ID="rocky"') for line in
             Path("/etc/os-release").read_text().splitlines()),
         "rocky_enforcing_guest_required")

def absent_account():
    for lookup in (pwd.getpwnam,grp.getgrnam):
        try:
            lookup(ACCOUNT)
        except KeyError:
            continue
        raise RuntimeError("existing_vtpm_service_account")

def device_identity(st):
    return st.st_dev,st.st_ino,st.st_rdev

def check_device(original):
    disposable()
    current=DEVICE.lstat()
    need(stat.S_ISCHR(current.st_mode) and
         device_identity(current)==device_identity(original),"vtpm_device_changed")
    return current

def set_fixture_mode(original,gid,mode):
    check_device(original)
    os.chown(str(DEVICE),0,gid,follow_symlinks=False)
    os.chmod(str(DEVICE),mode)
    observed=check_device(original)
    need((observed.st_uid,observed.st_gid,stat.S_IMODE(observed.st_mode))==(0,gid,mode),
         "vtpm_fixture_permissions_unverified")

def check_postfix_scope():
    """Rocky 9 active baseline or Rocky 10 strictly stopped primary queue."""
    disposable()
    release=dict(line.split("=",1) for line in Path("/etc/os-release").read_text().splitlines()
                 if "=" in line)
    version=release.get("VERSION_ID","").strip('"')
    need(command("/usr/sbin/postconf","-h","inet_interfaces").strip()==b"loopback-only",
         "fixture_postfix_scope_unverified")
    if version=="9.9":
        need(command("/usr/sbin/postqueue","-j").strip()==b"","vtpm_queue_changed")
        return "running_empty_native_queue"
    need(version=="10.3","unsupported_vtpm_guest_version")
    spec=importlib.util.spec_from_file_location("fixture_vtpm_queue_guard",
        str(HERE/"inspect-conditional-postfix-activation.py"))
    P=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)
    for name,expected in (("config_directory",P.CONFIG),("queue_directory",P.QUEUE),
                          ("multi_instance_enable","no"),("multi_instance_directories",""),
                          ("mail_owner","postfix"),("relayhost","")):
        need(command("/usr/sbin/postconf","-x","-h",name).decode("ascii").strip()==expected,
             "fixture_postfix_scope_unverified")
    P.stopped_units()
    P.no_postfix_processes()
    fd=P.open_directory(P.QUEUE,strict=False)
    try:
        P.empty_queue(fd)
    finally:
        os.close(fd)
    P.stopped_units()
    P.no_postfix_processes()
    need(P.tpm_pipe_sandbox()=="private_devices_without_bind",
         "stock_rocky10_tpm_sandbox_not_verified")
    print("LMR365_VM_VTPM_NATIVE_SANDBOX=private_devices_without_bind",flush=True)
    return "stopped_empty_native_queue"


def main():
    disposable()
    os.umask(0o077)
    need(os.environ.get("LMR365_VTPM_PROVIDER_PACKAGE") in ("present","unavailable"),
         "provider_inventory_unverified")
    spec=importlib.util.spec_from_file_location("fixture_tpm_product",str(HERE/"manage-tpm-oauth-key.py"))
    T=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(T)
    need(T.DEVICE==DEVICE and T.TARGETS["primary"]==IDENTITY and T.check_hardware()=="2",
         "native_tpm2_resource_manager_required")
    # Fixed native executable metadata, before calling the product guard.
    # This logs no config, secrets, certificate or TPM private material.
    for name,path in sorted(T.COMMANDS.items()):
        meta=path.lstat()
        target=os.readlink(str(path)) if stat.S_ISLNK(meta.st_mode) else "-"
        print("LMR365_VM_VTPM_TOOL "+name+" mode="+oct(meta.st_mode)+
              " uid="+str(meta.st_uid)+" link="+repr(target),flush=True)
    T.check_runtime_files()
    print("LMR365_VM_VTPM_UTILITIES=verified_native_executables",flush=True)
    need(T.read_capabilities()==set(),"vtpm_persistent_inventory_not_empty")
    need(not os.path.lexists(str(IDENTITY)),"existing_vtpm_identity")
    postfix_scope=check_postfix_scope()
    print("LMR365_VM_VTPM_POSTFIX_SCOPE="+postfix_scope,flush=True)
    absent_account()
    original=DEVICE.lstat()
    need(stat.S_ISCHR(original.st_mode) and
         set(os.listxattr(str(DEVICE),follow_symlinks=False))=={"security.selinux"},
         "vtpm_device_metadata_not_supported")
    label=os.getxattr(str(DEVICE),"security.selinux",follow_symlinks=False)
    command("/usr/sbin/useradd","--system","--user-group","--home-dir","/nonexistent",
            "--shell","/sbin/nologin",ACCOUNT)
    account=pwd.getpwnam(ACCOUNT)
    gid=grp.getgrnam(ACCOUNT).gr_gid
    need(account.pw_uid>0 and gid>0 and account.pw_gid==gid and
         sorted(set(os.getgrouplist(ACCOUNT,gid)))==[gid],"fixture_account_unverified")
    IDENTITY.mkdir(mode=0o750)
    os.chown(str(IDENTITY),0,gid)
    IDENTITY.chmod(0o750)
    app=IDENTITY/"app.json"
    raw=(json.dumps({"tenant_id":"11111111-1111-1111-1111-111111111111",
         "client_id":"22222222-2222-2222-2222-222222222222",
         "mailbox":"fixture@example.invalid","certificate":str(IDENTITY/"app.crt"),
         "private_key":str(IDENTITY/"app.key")})+"\n").encode("ascii")
    app.write_bytes(raw)
    os.chown(str(app),0,gid)
    app.chmod(0o640)
    command("/usr/sbin/restorecon","-F",str(IDENTITY),str(app))
    completed=False
    try:
        # Only this newly booted emulator's DAC permissions are varied.
        # The real product never modifies device ownership or permissions.
        set_fixture_mode(original,0,0o600)
        try:
            T.prepare("primary",HANDLE)
        except T.Refused as error:
            need(str(error)=="primary_tpm_service_device_access_requires_review",
                 "unexpected_vtpm_denial")
        else:
            raise RuntimeError("denied_vtpm_prepare_was_accepted")
        need(T.read_capabilities()==set() and app.read_bytes()==raw and
             sorted(p.name for p in IDENTITY.iterdir())==["app.json"],
             "denied_vtpm_prepare_changed_state")
        print("LMR365_VM_VTPM_DENIAL=refused_before_key_creation",flush=True)
        set_fixture_mode(original,gid,0o660)
        evidence=T.primary_service_device_evidence(gid)
        need(evidence["uid"]==account.pw_uid and evidence["groups"]==[gid] and
             T.primary_service_device_evidence(gid)==evidence,
             "vtpm_service_access_unverified")
        print("LMR365_VM_VTPM_OPEN=verified_exact_service_credentials",flush=True)
        if os.environ["LMR365_VTPM_PROVIDER_PACKAGE"]=="present":
            # Use the actual product provider and provisioning function. No
            # fake signer, socket TCTI override, or PEM fallback.
            T.provider_ready()
            print("LMR365_VM_VTPM_PROVIDER=native_openssl3_provider",flush=True)
            plan=T.prepare("primary",HANDLE)
            need(plan["evidence"]["primary_service_access"]==evidence,
                 "vtpm_plan_access_unbound")
            T.apply("primary",HANDLE,plan["sha"],T.CONFIRM)
            need(T.read_capabilities()=={HANDLE} and app.read_bytes()==raw and
                 sorted(p.name for p in IDENTITY.iterdir())==
                 ["app.json","hardware-app.crt","tpm2.cnf"],
                 "vtpm_provisioning_evidence_unverified")
            need((IDENTITY/"tpm2.cnf").read_bytes()==T.PROVIDER_TEMPLATE.encode("ascii"),
                 "vtpm_provider_config_unverified")
            print("LMR365_VM_VTPM_PS256=verified_emulated_tpm_certificate",flush=True)
        else:
            need(T.read_capabilities()==set(),"vtpm_unavailable_provider_changed_state")
            print("LMR365_VM_VTPM_PROVIDER=unavailable_in_configured_repos",flush=True)
            print("LMR365_VM_VTPM_PS256=not_tested",flush=True)
        completed=True
    finally:
        # Restore device DAC only if it is still the exact disposable device.
        check_device(original)
        os.chown(str(DEVICE),original.st_uid,original.st_gid,follow_symlinks=False)
        os.chmod(str(DEVICE),stat.S_IMODE(original.st_mode))
        after=check_device(original)
        need((after.st_uid,after.st_gid,after.st_mode)==
             (original.st_uid,original.st_gid,original.st_mode) and
             os.getxattr(str(DEVICE),"security.selinux",follow_symlinks=False)==label,
             "vtpm_fixture_device_restore_unverified")
    if completed:
        for name in ("app.json","hardware-app.crt","tpm2.cnf"):
            path=IDENTITY/name
            if path.exists():
                path.unlink()
        IDENTITY.rmdir()
        command("/usr/sbin/userdel",ACCOUNT)
        try:
            grp.getgrnam(ACCOUNT)
        except KeyError:
            pass
        else:
            command("/usr/sbin/groupdel",ACCOUNT)
        absent_account()
        need(check_postfix_scope()==postfix_scope,"vtpm_queue_or_service_changed")
        disposable()
        MARKER.unlink()
        print("LMR365_VM_VTPM_DEVICE=original_metadata_restored",flush=True)
        print("LMR365_VM_VTPM_PHYSICAL_HARDWARE=no",flush=True)
        print("LMR365_VM_VTPM_PIPE_DOMAIN_TESTED=no",flush=True)
        print("LMR365_VM_VTPM_CLOUD_OR_MAIL_TESTED=no",flush=True)

if __name__=="__main__":
    main()
