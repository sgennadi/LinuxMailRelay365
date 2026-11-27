#!/usr/bin/env python3
"""Additional native TPM2 signing acceptance inside the disposable Rocky 10 pipe.

Requires the earlier successful virtual TPM test, never attaches hardware.
No external SMTP or token exchange, no policy or SELinux label change to the
TPM device. On failure the runner discards the whole guest.
"""
import importlib.util
import json
import os
from pathlib import Path
import stat
import uuid
import pwd
import grp

HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,str(HERE/file))
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

F=load("tpm_pipe_fixture","rocky_vm_primary_pipe_enforcing.py")
T=load("tpm_pipe_provisioner","manage-tpm-oauth-key.py")
P=load("tpm_pipe_native_guard","inspect-conditional-postfix-activation.py")
W=F.W
need=F.need
command=F.command
HANDLE="0x81010002"
DEVICE=Path("/dev/tpmrm0")
NAMES=("main.cf","master.cf")

def native(name):
    return command("/usr/sbin/postconf","-x","-h",name).decode("ascii").strip()

def stopped(queue):
    F.disposable()
    P.stopped_units()
    P.no_postfix_processes()
    P.empty_queue(queue)

def snapshot(config):
    return tuple(P.T.config_file(config,name,0) for name in NAMES)

def policy_matches():
    for name in NAMES:
        command("/usr/sbin/matchpathcon","-V",P.CONFIG+"/"+name)

def main():
    F.disposable()
    need("VERSION_ID=\"10.3\"" in Path("/etc/os-release").read_text().splitlines(),
         "rocky10_pipe_fixture_required")
    os.umask(0o077)
    expected={"config_directory":P.CONFIG,"queue_directory":P.QUEUE,
              "data_directory":"/var/lib/postfix","mail_owner":"postfix",
              "multi_instance_enable":"no","multi_instance_directories":"",
              "inet_interfaces":"loopback-only","relayhost":"","transport_maps":""}
    need(all(native(k)==v for k,v in expected.items()),"unexpected_native_scope")
    need(native("default_transport") in ("smtp","smtp:") and
         native("relay_transport") in ("relay","relay:","smtp","smtp:"),
         "unexpected_native_transports")
    need(command("/usr/bin/systemctl","is-active","postfix.service").strip()==b"active" and
         not command("/usr/sbin/postqueue","-j").strip(),"active_empty_baseline_required")
    need(T.read_capabilities()=={"0x81010001"} and T.check_hardware()=="2",
         "previous_virtual_tpm_test_required")
    F.absent_account()
    need(all(not os.path.lexists(str(path)) for path in
         (F.IDENTITY,F.PRODUCT,F.SIGNER,F.WORKER)),"unexpected_existing_identity")
    original=DEVICE.lstat()
    need(stat.S_ISCHR(original.st_mode) and original.st_uid==0 and
         set(os.listxattr(str(DEVICE),follow_symlinks=False))=={"security.selinux"},
         "unexpected_device")
    label=os.getxattr(str(DEVICE),"security.selinux",follow_symlinks=False)
    def device():
        F.disposable()
        s=DEVICE.lstat()
        need(stat.S_ISCHR(s.st_mode) and
             (s.st_dev,s.st_ino,s.st_rdev)==(original.st_dev,original.st_ino,original.st_rdev),
             "fixture_device_changed")
        return s
    command("/usr/bin/systemctl","stop","postfix.service")
    config=P.open_directory(P.CONFIG)
    queue=P.open_directory(P.QUEUE,strict=False)
    try:
        stopped(queue)
        # Establish the policy-matched fixture baseline; no production paths.
        command("/usr/sbin/restorecon","-F",P.CONFIG+"/main.cf",P.CONFIG+"/master.cf")
        policy_matches()
        baseline=snapshot(config)
        for _,meta in baseline:
            P.T.valid_meta(meta,True)
        command("/usr/sbin/useradd","--system","--user-group","--home-dir","/nonexistent",
                "--shell","/sbin/nologin",F.ACCOUNT)
        account=pwd.getpwnam(F.ACCOUNT)
        gid=grp.getgrnam(F.ACCOUNT).gr_gid
        need(account.pw_uid>0 and gid>0 and account.pw_gid==gid,"fixture_account")
        F.IDENTITY.mkdir(mode=0o750)
        os.chown(str(F.IDENTITY),0,gid)
        F.IDENTITY.chmod(0o750)
        app=F.IDENTITY/"app.json"
        # Provisioning reads identity metadata only; never create a PEM key.
        raw={"tenant_id":"11111111-1111-1111-1111-111111111111",
             "client_id":"22222222-2222-2222-2222-222222222222",
             "mailbox":W.MAILBOX,"certificate":str(F.IDENTITY/"unused.crt"),
             "private_key":str(F.IDENTITY/"unused.key")}
        app.write_text(json.dumps(raw),encoding="ascii")
        os.chown(str(app),0,gid)
        app.chmod(0o640)
        command("/usr/sbin/restorecon","-F",str(F.IDENTITY),str(app))
        for source,target,mode in (("m365_xoauth2_transport.py",F.PRODUCT,"0755"),
            ("m365_hardware_signer.py",F.SIGNER,"0644"),
            ("rocky_vm_primary_pipe_worker.py",F.WORKER,"0755")):
            command("/usr/bin/install","-o","root","-g","root","-m",mode,str(HERE/source),str(target))
            command("/usr/sbin/restorecon","-F",str(target))
            need(target.read_bytes()==(HERE/source).read_bytes(),"fixture_source_changed")
        device()
        os.chown(str(DEVICE),0,gid,follow_symlinks=False)
        os.chmod(str(DEVICE),0o660)
        try:
            current=device()
            need((current.st_uid,current.st_gid,stat.S_IMODE(current.st_mode))==(0,gid,0o660),
                 "device_dac_unverified")
            plan=T.prepare("primary",HANDLE)
            T.apply("primary",HANDLE,plan["sha"],T.CONFIRM)
            need(T.read_capabilities()=={"0x81010001",HANDLE},"persistent_handle_unverified")
            raw.pop("private_key")
            raw["certificate"]=str(F.IDENTITY/"hardware-app.crt")
            raw["signer"]={"type":"openssl-provider","provider":"tpm2",
                           "key_ref":"handle:"+HANDLE,
                           "provider_config":str(F.IDENTITY/"tpm2.cnf")}
            app.write_text(json.dumps(raw),encoding="ascii")
            need(sorted(p.name for p in F.IDENTITY.iterdir())==
                 ["app.json","hardware-app.crt","tpm2.cnf"],"unexpected_pem_material")
            nonce,other=uuid.uuid4().hex,uuid.uuid4().hex
            need(nonce!=other,"duplicate_nonce")
            # All nonlocal mail in this isolated guest is routed only to the
            # fixture, whose strict envelope/nonce refuses anything else.
            for setting in ("default_transport = m365xoauth2:","relay_transport = m365xoauth2:",
                            "m365xoauth2_destination_recipient_limit = 1"):
                command("/usr/sbin/postconf","-e",setting)
            master=baseline[1][0]
            need(b"m365xoauth2" not in master,"existing_pipe")
            candidate=master+(b"" if master.endswith(b"\n") else b"\n")+(
                "m365xoauth2 unix - n n - 2 pipe\n"
                "  flags=q user=m365mailer argv=/usr/bin/python3 "+str(F.WORKER)+
                " --nonce "+nonce+" --network-nonce "+other+" --uid "+str(account.pw_uid)+
                " --gid "+str(gid)+" --tpm-handle "+HANDLE+" --recipient ${recipient}\n").encode("ascii")
            stopped(queue)
            P.T.atomic_write(config,"master.cf",candidate,baseline[1][1],0,True)
            command("/usr/sbin/restorecon","-F",P.CONFIG+"/main.cf")
            policy_matches()
            edited=snapshot(config)
            need(edited[1][0]==candidate and native("default_transport")=="m365xoauth2:" and
                 native("relay_transport")=="m365xoauth2:" and
                 all(native(k)==v for k,v in expected.items()),"fixture_route_unverified")
            daemon=native("daemon_directory")
            need(daemon=="/usr/libexec/postfix","unexpected_daemon")
            command("/usr/sbin/postfix","check")
            stopped(queue)
            need(snapshot(config)==edited,"fixture_config_changed")
            command("/usr/bin/systemctl","start","postfix.service")
            need(command("/usr/bin/systemctl","is-active","postfix.service").strip()==b"active",
                 "fixture_postfix_start")
            qid=F.submit_fixture(nonce,daemon,tpm=True)
            F.disposable()
            print("LMR365_TPM_PIPE_DOMAIN=postfix_pipe_t",flush=True)
            print("LMR365_TPM_PIPE_PS256=verified_native_provider",flush=True)
            print("LMR365_TPM_PIPE_QUEUE=correlated_and_empty",flush=True)
            print("LMR365_TPM_PIPE_QUEUE_ID="+qid,flush=True)
            command("/usr/bin/systemctl","stop","postfix.service")
            stopped(queue)
            need(snapshot(config)==edited,"fixture_changed_before_restore")
            for i,name in enumerate(NAMES):
                P.T.atomic_write(config,name,baseline[i][0],baseline[i][1],0,True)
            stopped(queue)
            need(snapshot(config)==baseline,"fixture_restore_changed")
            policy_matches()
        finally:
            device()
            os.chown(str(DEVICE),original.st_uid,original.st_gid,follow_symlinks=False)
            os.chmod(str(DEVICE),stat.S_IMODE(original.st_mode))
            after=device()
            need((after.st_uid,after.st_gid,after.st_mode)==
                 (original.st_uid,original.st_gid,original.st_mode) and
                 os.getxattr(str(DEVICE),"security.selinux",follow_symlinks=False)==label,
                 "fixture_device_restore_failed")
            print("LMR365_TPM_PIPE_DEVICE=original_metadata_restored",flush=True)
        for path in (app,F.IDENTITY/"hardware-app.crt",F.IDENTITY/"tpm2.cnf",
                     F.PRODUCT,F.SIGNER,F.WORKER):
            path.unlink()
        F.IDENTITY.rmdir()
        command("/usr/sbin/userdel",F.ACCOUNT)
        try:
            grp.getgrnam(F.ACCOUNT)
        except KeyError:
            pass
        else:
            command("/usr/sbin/groupdel",F.ACCOUNT)
        F.absent_account()
        stopped(queue)
        command("/usr/bin/systemctl","start","postfix.service")
        need(command("/usr/bin/systemctl","is-active","postfix.service").strip()==b"active" and
             not command("/usr/sbin/postqueue","-j").strip() and snapshot(config)==baseline and
             all(native(k)==v for k,v in expected.items()),"baseline_not_restored")
        F.disposable()
        F.MARKER.unlink()
        print("LMR365_TPM_PIPE_BASELINE=restored",flush=True)
        print("LMR365_TPM_PIPE_CLOUD_TESTED=no",flush=True)
    finally:
        os.close(queue)
        os.close(config)

if __name__=="__main__":
    main()
