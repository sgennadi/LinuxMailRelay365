#!/usr/bin/env python3
"""Additional native TPM2 signing acceptance inside the disposable Rocky 10 pipe.

Requires the earlier successful virtual TPM test, never attaches hardware.
No external SMTP or token exchange, no policy or SELinux label change to the
TPM device. On failure the runner discards the whole guest.
"""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import stat
import re
import subprocess
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

# Only for this disposable, swtpm-backed VM. A bind of the one resource
# manager plus its cgroup permission is narrower than PrivateDevices=no,
# but affects the whole Postfix service, not just the pipe. No production
# policy or product code may infer authorization from this experiment.
UNIT_PROPERTIES=("PrivateDevices","DevicePolicy","DeviceAllow","BindPaths",
    "BindReadOnlyPaths","ProtectSystem","NoNewPrivileges","SystemCallFilter",
    "RootDirectory","RootImage","InaccessiblePaths","PrivateMounts","DropInPaths")
RUNTIME_DIR=Path("/run/systemd/system/postfix.service.d")
DROPIN=RUNTIME_DIR/"99-lmr365-disposable-tpm.conf"
DROPIN_BYTES=b"[Service]\nBindPaths=/dev/tpmrm0:/dev/tpmrm0\nDeviceAllow=/dev/tpmrm0 rw\n"

def unit_snapshot():
    F.disposable()
    raw=command("/usr/bin/systemctl","show","--all","postfix.service",
                *("-p"+name for name in UNIT_PROPERTIES)).decode("utf-8","strict")
    rows={}
    for line in raw.splitlines():
        key,sep,value=line.partition("=")
        need(sep and key in UNIT_PROPERTIES and key not in rows and len(value)<=8192,
             "unit_property_unverified")
        rows[key]=value
    need(set(rows)==set(UNIT_PROPERTIES),"unit_property_missing")
    return rows

def validate_unit_scope(before,after):
    for key in UNIT_PROPERTIES:
        if key not in ("BindPaths","DeviceAllow","DropInPaths"):
            need(after[key]==before[key],"unexpected_unit_hardening_change")
    need(after["PrivateDevices"]=="yes" and after["DevicePolicy"]=="closed",
         "private_device_policy_changed")
    # Native systemd renders the one bind with an optional destination and
    # rbind/norbind option. No extra devices or unrelated binds are accepted.
    need(after["BindPaths"] in ("/dev/tpmrm0","/dev/tpmrm0:/dev/tpmrm0",
        "/dev/tpmrm0:/dev/tpmrm0:rbind","/dev/tpmrm0:/dev/tpmrm0:norbind"),
        "device_bind_scope_unverified")
    need(after["DeviceAllow"].split()==["/dev/tpmrm0","rw"],"device_allow_scope_unverified")
    need(set(after["DropInPaths"].split())==set(before["DropInPaths"].split())|{str(DROPIN)},
         "unexpected_dropin_change")

@contextmanager
def scoped_fixture_device(queue):
    stopped(queue)
    before=unit_snapshot()
    need(before["PrivateDevices"]=="yes" and before["DevicePolicy"]=="closed" and
         not any(before[key] for key in ("BindPaths","BindReadOnlyPaths","DeviceAllow",
             "RootDirectory","RootImage","InaccessiblePaths")),"unexpected_unit_baseline")
    for parent in (Path("/run"),Path("/run/systemd"),Path("/run/systemd/system")):
        st=parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,
             "unsafe_runtime_parent")
    created_dir=False
    if not os.path.lexists(RUNTIME_DIR):
        RUNTIME_DIR.mkdir(mode=0o755)
        created_dir=True
    st=RUNTIME_DIR.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,
         "unsafe_runtime_dropin_directory")
    fd=os.open(DROPIN,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    owned=os.fstat(fd)
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(DROPIN_BYTES)
            out.flush()
            os.fsync(out.fileno())
        command("/usr/bin/systemctl","daemon-reload")
        validate_unit_scope(before,unit_snapshot())
        print("LMR365_TPM_PIPE_UNIT_SCOPE=one_device_private_devices_preserved",flush=True)
        yield
    finally:
        # Stop the fixture even if its test mail is deferred. Never restart
        # or clear a failed queue automatically. The guest will be discarded.
        F.disposable()
        try:
            command("/usr/bin/systemctl","stop","postfix.service")
            P.stopped_units()
            P.no_postfix_processes()
        finally:
            current=DROPIN.lstat()
            need(stat.S_ISREG(current.st_mode) and current.st_uid==0 and current.st_nlink==1 and
                 (current.st_dev,current.st_ino)==(owned.st_dev,owned.st_ino),
                 "fixture_dropin_identity_changed")
            DROPIN.unlink()
            if created_dir:
                RUNTIME_DIR.rmdir()
            command("/usr/bin/systemctl","daemon-reload")
            need(unit_snapshot()==before,"unit_hardening_baseline_not_restored")
            print("LMR365_TPM_PIPE_UNIT_BASELINE=restored",flush=True)

def service_device_diagnostics():
    """Read-only evidence from the actual master process, not a namespace entry."""
    F.disposable()
    props=("MainPID","PrivateDevices","PrivateMounts","DevicePolicy","DeviceAllow",
           "RootDirectory","RootImage","InaccessiblePaths","BindPaths","BindReadOnlyPaths",
           "ProtectSystem","NoNewPrivileges","SystemCallFilter")
    try:
        raw=command("/usr/bin/systemctl","show","postfix.service",
                    *("-p"+name for name in props)).decode("utf-8","strict")
        rows={}
        for line in raw.splitlines():
            key,sep,value=line.partition("=")
            if sep and key in props and key not in rows and len(value)<=8192:
                rows[key]=value
        for name in ("PrivateDevices","PrivateMounts","DevicePolicy","NoNewPrivileges","ProtectSystem"):
            value=rows.get(name,"")
            if re.fullmatch(r"[A-Za-z0-9_-]{1,40}",value):
                print("LMR365_TPM_PIPE_SYSTEMD="+name+"="+value,flush=True)
        for name in ("RootDirectory","RootImage","InaccessiblePaths","BindPaths",
                     "BindReadOnlyPaths","DeviceAllow","SystemCallFilter"):
            if name in rows:
                value=rows[name]
                # Do not disclose arbitrary configured paths or command data.
                print("LMR365_TPM_PIPE_SYSTEMD="+name+"="+
                      ("set" if value else "empty"),flush=True)
        pid=int(rows.get("MainPID","0"))
        need(pid>1,"master_pid_unverified")
        proc=Path("/proc")/str(pid)
        need((proc/"exe").resolve()==Path("/usr/libexec/postfix/master") and
             b":postfix_master_t:" in (proc/"attr/current").read_bytes(),
             "master_identity_unverified")
        hostns=os.readlink("/proc/self/ns/mnt")
        masterns=os.readlink(str(proc/"ns/mnt"))
        print("LMR365_TPM_PIPE_MASTER_MOUNT_NAMESPACE="+
              ("same" if hostns==masterns else "separate"),flush=True)
        try:
            visible=(proc/"root/dev/tpmrm0").lstat()
            host=DEVICE.lstat()
            state=("same_character_device" if stat.S_ISCHR(visible.st_mode) and
                   (visible.st_dev,visible.st_ino,visible.st_rdev)==
                   (host.st_dev,host.st_ino,host.st_rdev) else "different_device")
        except FileNotFoundError:
            state="absent"
        except OSError:
            state="unverified"
        # Verify master identity again before accepting the snapshot.
        need(command("/usr/bin/systemctl","show","postfix.service","-pMainPID","--value").strip()==
             str(pid).encode("ascii") and (proc/"exe").resolve()==Path("/usr/libexec/postfix/master"),
             "master_changed")
        print("LMR365_TPM_PIPE_MASTER_DEVICE="+state,flush=True)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
        print("LMR365_TPM_PIPE_MASTER_DEVICE=unverified",flush=True)

def failure_diagnostics():
    # Disposable boot-bound guest only. Report fixed native metadata and
    # AVC records concerning the actual pipe domain; no message/secret dump.
    F.disposable()
    for path in ("/dev/tpmrm0",str(F.IDENTITY),str(F.IDENTITY/"app.json"),
                 str(F.IDENTITY/"hardware-app.crt"),str(F.IDENTITY/"tpm2.cnf")):
        try:
            value=command("/usr/bin/stat","-c","%a %u %g %C",path).decode("ascii").strip()
            if re.fullmatch(r"[0-7]+ [0-9]+ [0-9]+ [A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_.,:-]+",value):
                print("LMR365_TPM_PIPE_METADATA="+path+" "+value,flush=True)
        except (OSError,ValueError,subprocess.SubprocessError):
            print("LMR365_TPM_PIPE_METADATA_UNVERIFIED="+path,flush=True)
    service_device_diagnostics()
    count=0
    for argv in (("/usr/sbin/ausearch","-m","AVC,USER_AVC","-ts","recent","--raw"),
                 ("/usr/bin/journalctl","-b","-k","--no-pager","-n","1000")):
        try:
            raw=command(*argv,timeout=15).decode("utf-8","replace")
        except (OSError,subprocess.SubprocessError):
            continue
        for line in raw.splitlines():
            if "avc:" not in line.lower() or "postfix_pipe_t:" not in line:
                continue
            # Extract only permission names, source/target type, and object
            # class; omit paths, process arguments and raw audit text.
            perms=re.search(r"avc:\s+denied\s+\{\s*([a-z_ ]+)\s*\}",line,re.I)
            source=re.search(r"\bscontext=[^:\s]+:[^:\s]+:([A-Za-z0-9_]+):",line)
            target=re.search(r"\btcontext=[^:\s]+:[^:\s]+:([A-Za-z0-9_]+):",line)
            cls=re.search(r"\btclass=([A-Za-z0-9_]+)\b",line)
            if perms and source and target and cls and source[1]=="postfix_pipe_t":
                print("LMR365_TPM_PIPE_AVC="+source[1]+":"+target[1]+":"+cls[1]+":"+
                      ",".join(perms[1].split()),flush=True)
                count+=1
                if count>=30:
                    break
        if count>=30:
            break
    print("LMR365_TPM_PIPE_AVC_COUNT="+str(count),flush=True)

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
            with scoped_fixture_device(queue):
                command("/usr/bin/systemctl","start","postfix.service")
                need(command("/usr/bin/systemctl","is-active","postfix.service").strip()==b"active",
                     "fixture_postfix_start")
                service_device_diagnostics()
                try:
                    qid=F.submit_fixture(nonce,daemon,tpm=True)
                except Exception:
                    failure_diagnostics()
                    raise
            F.disposable()
            print("LMR365_TPM_PIPE_DOMAIN=postfix_pipe_t",flush=True)
            print("LMR365_TPM_PIPE_PS256=verified_native_provider",flush=True)
            print("LMR365_TPM_PIPE_QUEUE=correlated_and_empty",flush=True)
            print("LMR365_TPM_PIPE_QUEUE_ID="+qid,flush=True)
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
