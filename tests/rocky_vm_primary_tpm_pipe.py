#!/usr/bin/env python3
"""Additional native TPM2 signing acceptance inside the disposable Rocky 10 pipe.

Requires the earlier successful virtual TPM test, never attaches hardware.
No external SMTP or token exchange, no policy or SELinux label change to the
TPM device. On failure the runner discards the whole guest.
"""
from contextlib import contextmanager, nullcontext
import importlib.util
import json
import os
from pathlib import Path
import stat
import re
import shlex
import subprocess
import time
import tempfile
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
    "RootDirectory","RootImage","InaccessiblePaths","PrivateMounts","DropInPaths",
    "TemporaryFileSystem")
# D-Bus exposes arrays even when systemctl show omits an empty list.
# Read the typed property rather than interpreting missing output as empty.
UNIT_ARRAYS={
    "DeviceAllow":("Service","a(ss)",2),
    "BindPaths":("Service","a(ssbt)",4),
    "BindReadOnlyPaths":("Service","a(ssbt)",4),
    "InaccessiblePaths":("Service","as",1),
    "TemporaryFileSystem":("Service","a(ss)",2),
    "DropInPaths":("Unit","as",1),
}
RUNTIME_DIR=Path("/run/systemd/system/postfix.service.d")
DROPIN=RUNTIME_DIR/"99-lmr365-disposable-tpm.conf"
DROPIN_BYTES=b"[Service]\nBindPaths=/dev/tpmrm0:/dev/tpmrm0\nDeviceAllow=/dev/tpmrm0 rw\n"

def unit_array(name):
    interface,signature,width=UNIT_ARRAYS[name]
    raw=command("/usr/bin/busctl","--system","--no-pager","get-property",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1/unit/postfix_2eservice",
                "org.freedesktop.systemd1."+interface,name).decode("utf-8","strict")
    need(len(raw)<=16384 and len(raw.splitlines())==1,"unit_array_unverified:"+name)
    tokens=shlex.split(raw)
    need(len(tokens)>=2 and tokens[0]==signature and
         re.fullmatch(r"(?:0|[1-9][0-9]{0,3})",tokens[1]),"unit_array_type_unverified:"+name)
    count=int(tokens[1])
    need(count<=128 and len(tokens)==2+count*width and
         all("\\" not in token and not any(ord(c)<32 for c in token)
             for token in tokens[2:]),"unit_array_count_unverified:"+name)
    return tuple(tuple(tokens[i:i+width]) for i in range(2,len(tokens),width))

def unit_snapshot():
    F.disposable()
    scalar=tuple(name for name in UNIT_PROPERTIES if name not in UNIT_ARRAYS)
    raw=command("/usr/bin/systemctl","show","--all","postfix.service",
                *("-p"+name for name in scalar)).decode("utf-8","strict")
    rows={}
    for line in raw.splitlines():
        key,sep,value=line.partition("=")
        need(sep and key in scalar and key not in rows and len(value)<=8192,
             "unit_property_unverified")
        rows[key]=value
    need(set(rows)==set(scalar),"unit_property_missing:"+",".join(sorted(set(scalar)-set(rows))))
    for name in UNIT_ARRAYS:
        rows[name]=unit_array(name)
    return rows

def validate_unit_scope(before,after):
    for key in UNIT_PROPERTIES:
        if key not in ("BindPaths","DeviceAllow","DropInPaths"):
            need(after[key]==before[key],"unexpected_unit_hardening_change:"+key)
    need(after["PrivateDevices"]=="yes" and after["DevicePolicy"]=="closed",
         "private_device_policy_changed")
    need(after["BindPaths"] in (
        (("/dev/tpmrm0","/dev/tpmrm0","false","0"),),
        (("/dev/tpmrm0","/dev/tpmrm0","false","16384"),)),
        "device_bind_scope_unverified")
    need(after["DeviceAllow"]==(("/dev/tpmrm0","rw"),),"device_allow_scope_unverified")
    need(set(after["DropInPaths"])==set(before["DropInPaths"])|{(str(DROPIN),)},
         "unexpected_dropin_change")

@contextmanager
def scoped_fixture_device(queue):
    stopped(queue)
    before=unit_snapshot()
    need(before["PrivateDevices"]=="yes" and before["DevicePolicy"]=="closed" and
         not any(before[key] for key in ("BindPaths","BindReadOnlyPaths","DeviceAllow",
             "RootDirectory","RootImage","InaccessiblePaths","TemporaryFileSystem")),"unexpected_unit_baseline")
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

def policy_rule_evidence():
    """Read the installed binary SELinux policy without modifying it.

    A matching TE rule may be conditional or restricted by constraints.
    Rule presence is not an authorization, and no rule is ever installed.
    Query the actual device and service /dev directory types separately.
    """
    F.disposable()
    try:
        raw=command("/usr/bin/systemctl","show","postfix.service",
                    "-pMainPID","--value").decode("ascii").strip()
        need(re.fullmatch(r"[1-9][0-9]{0,9}",raw) is not None and int(raw)>1,
             "policy_master_pid_unverified")
        proc=Path("/proc")/raw
        need((proc/"exe").resolve()==Path("/usr/libexec/postfix/master") and
             b":postfix_master_t:" in (proc/"attr/current").read_bytes(),
             "policy_master_identity_unverified")
        def label_type(path):
            label=os.getxattr(str(path),"security.selinux",follow_symlinks=False).rstrip(b"\0").decode("ascii")
            fields=label.split(":",3)
            need(len(fields)==4 and re.fullmatch(r"[A-Za-z0-9_]+_t",fields[2]) is not None,
                 "policy_object_type_unverified")
            return fields[2]
        target=label_type(DEVICE)
        directory=label_type(proc/"root/dev")
        need(command("/usr/bin/systemctl","show","postfix.service","-pMainPID","--value").strip()==raw.encode("ascii"),
             "policy_master_changed")
        print("LMR365_TPM_PIPE_POLICY_DEVICE_TYPE="+target,flush=True)
        print("LMR365_TPM_PIPE_POLICY_DEV_DIRECTORY_TYPE="+directory,flush=True)
        # Search the live policy image, not an arbitrary policy path or
        # module from the host. Do not use audit2allow or change dontaudit.
        policy=Path("/sys/fs/selinux/policy")
        need(policy.is_file(),"live_policy_unavailable")
        for kind,cls,permissions in ((directory,"dir",("search","getattr")),
                (target,"chr_file",("getattr","open","read","write","ioctl"))):
            for perm in permissions:
                for rule,option in (("allow","--allow"),("dontaudit","--dontaudit")):
                    state="unverified"
                    try:
                        result=command("/usr/bin/sesearch",option,"-s","postfix_pipe_t",
                                       "-t",kind,"-c",cls,"-p",perm,str(policy),
                                       timeout=12).decode("utf-8","strict")
                        rows=[line.strip() for line in result.splitlines() if line.strip()]
                        if len(result)<=32768 and len(rows)<=128 and all(
                                line.startswith(rule+" ") for line in rows):
                            state="rule_present" if rows else "no_matching_rule"
                    except (OSError,ValueError,UnicodeError,subprocess.SubprocessError):
                        pass
                    print("LMR365_TPM_PIPE_POLICY_RULE="+rule+":"+kind+":"+cls+":"+perm+":"+state,
                          flush=True)
    except (OSError,ValueError,RuntimeError,UnicodeError,subprocess.SubprocessError):
        print("LMR365_TPM_PIPE_POLICY_EVIDENCE=unverified",flush=True)

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
    policy_rule_evidence()
    count=0
    for argv in (("/usr/sbin/ausearch","-m","AVC,USER_AVC","-ts","recent","--raw"),
                 ("/usr/bin/journalctl","-b","-k","--no-pager","-n","1000")):
        try:
            raw=command(*argv,timeout=15).decode("utf-8","replace")
        except (OSError,subprocess.SubprocessError):
            continue
        for line in raw.splitlines():
            if "avc:" not in line.lower() or not any(
                    kind+":" in line for kind in ("postfix_pipe_t",W.BROKER_DOMAIN)):
                continue
            # Extract only permission names, source/target type, and object
            # class; omit paths, process arguments and raw audit text.
            perms=re.search(r"avc:\s+denied\s+\{\s*([a-z_ ]+)\s*\}",line,re.I)
            source=re.search(r"\bscontext=[^:\s]+:[^:\s]+:([A-Za-z0-9_]+):",line)
            target=re.search(r"\btcontext=[^:\s]+:[^:\s]+:([A-Za-z0-9_]+):",line)
            cls=re.search(r"\btclass=([A-Za-z0-9_]+)\b",line)
            if perms and source and target and cls and source[1] in ("postfix_pipe_t",W.BROKER_DOMAIN):
                print("LMR365_TPM_PIPE_AVC="+source[1]+":"+target[1]+":"+cls[1]+":"+
                      ",".join(perms[1].split()),flush=True)
                count+=1
                if count>=30:
                    break
        if count>=30:
            break
    print("LMR365_TPM_PIPE_AVC_COUNT="+str(count),flush=True)

BROKER_UNIT="lmr365-disposable-tpm-broker.service"
BROKER_USER="lmr365signer"

BROKER_DOMAIN=W.BROKER_DOMAIN
BROKER_MODULE="lmr365_fixture_signer"
BROKER_EXEC=Path("/usr/local/libexec/lmr365-disposable-signer-python")

# Candidate policy for the disposable VM only. Runtime read/execute
# interfaces are not a reviewed production permission set.
BROKER_TE="""policy_module(lmr365_fixture_signer, 1.0.0)

gen_require(`
    type init_t;
    type postfix_pipe_t;
    type postfix_etc_t;
    class process2 { nnp_transition nosuid_transition };
')

type lmr365_fixture_signer_t;
type lmr365_fixture_signer_exec_t;
init_daemon_domain(lmr365_fixture_signer_t, lmr365_fixture_signer_exec_t)
allow init_t lmr365_fixture_signer_t:process2 { nnp_transition nosuid_transition };

type lmr365_fixture_signer_tmp_t;
files_tmp_file(lmr365_fixture_signer_tmp_t)
manage_dirs_pattern(lmr365_fixture_signer_t, lmr365_fixture_signer_tmp_t, lmr365_fixture_signer_tmp_t)
manage_files_pattern(lmr365_fixture_signer_t, lmr365_fixture_signer_tmp_t, lmr365_fixture_signer_tmp_t)
files_tmp_filetrans(lmr365_fixture_signer_t, lmr365_fixture_signer_tmp_t, { dir file })

allow lmr365_fixture_signer_t self:process { fork sigchld signal signull sigkill };
allow lmr365_fixture_signer_t self:fifo_file rw_fifo_file_perms;
allow lmr365_fixture_signer_t self:unix_stream_socket create_stream_socket_perms;
allow lmr365_fixture_signer_t self:dir search_dir_perms;
allow lmr365_fixture_signer_t self:file read_file_perms;
allow lmr365_fixture_signer_t self:lnk_file read_lnk_file_perms;
allow postfix_pipe_t lmr365_fixture_signer_t:unix_stream_socket connectto;

allow lmr365_fixture_signer_t postfix_etc_t:dir search_dir_perms;
allow lmr365_fixture_signer_t postfix_etc_t:file read_file_perms;
libs_use_ld_so(lmr365_fixture_signer_t)
libs_use_shared_libs(lmr365_fixture_signer_t)
corecmd_exec_bin(lmr365_fixture_signer_t)
files_read_usr_files(lmr365_fixture_signer_t)
files_read_etc_files(lmr365_fixture_signer_t)
auth_read_passwd(lmr365_fixture_signer_t)
init_use_fds(lmr365_fixture_signer_t)
logging_send_syslog_msg(lmr365_fixture_signer_t)
kernel_read_system_state(lmr365_fixture_signer_t)
kernel_read_kernel_sysctls(lmr365_fixture_signer_t)
selinux_get_enforce_mode(lmr365_fixture_signer_t)
dev_rw_null(lmr365_fixture_signer_t)
dev_read_urand(lmr365_fixture_signer_t)
dev_rw_tpm(lmr365_fixture_signer_t)
miscfiles_read_localization(lmr365_fixture_signer_t)
"""


def broker_policy_inventory():
    raw=command("/usr/sbin/semodule","-lfull",timeout=90).decode("ascii","strict")
    rows=tuple(sorted(tuple(line.split()) for line in raw.splitlines() if line.strip()))
    need(bool(rows) and all(len(row) in (3,4) and row[0].isdigit() for row in rows),
         "broker_policy_inventory_unverified")
    return rows


@contextmanager
def broker_policy_scope(queue):
    stopped(queue)
    need(os.environ.get("LMR365_KVM_TPM_BROKER_ACCEPTANCE")=="true" and
         'VERSION_ID="10.3"' in Path("/etc/os-release").read_text().splitlines(),
         "broker_policy_disposable_rocky10_only")
    before=broker_policy_inventory()
    need(not any(row[1]==BROKER_MODULE for row in before) and
         not os.path.lexists(BROKER_EXEC),"existing_broker_policy_or_entrypoint")
    # Copy the native interpreter, never relabel the distro Python or Postfix.
    source=Path("/usr/bin/python3").resolve(strict=True)
    st=source.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o6022,
         "broker_python_entrypoint_untrusted")
    created=False
    entered=False
    try:
        with tempfile.TemporaryDirectory(prefix="lmr365-fixture-policy-",dir="/run") as work:
            te=Path(work)/(BROKER_MODULE+".te")
            te.write_text(BROKER_TE,encoding="ascii")
            try:
                command("/usr/bin/make","-C",work,"-f","/usr/share/selinux/devel/Makefile",
                        BROKER_MODULE+".pp",timeout=120)
            except subprocess.CalledProcessError:
                print("LMR365_TPM_BROKER_POLICY_BUILD=failed",flush=True)
                raise
            command("/usr/sbin/semodule","-X","400","-i",str(te.with_suffix(".pp")),timeout=120)
        after=broker_policy_inventory()
        added=tuple(row for row in after if row not in before)
        need(len(added)==1 and added[0][:2]==("400",BROKER_MODULE) and
             all(row in after for row in before),"broker_policy_install_unverified")
        F.disposable()
        created=True
        command("/usr/bin/install","-o","root","-g","root","-m","0755",str(source),str(BROKER_EXEC))
        need(BROKER_EXEC.read_bytes()==source.read_bytes(),"broker_entrypoint_changed")
        command("/usr/bin/chcon","-t","lmr365_fixture_signer_exec_t",str(BROKER_EXEC))
        need(os.getxattr(BROKER_EXEC,"security.selinux").split(b":")[2]==b"lmr365_fixture_signer_exec_t",
             "broker_entrypoint_label_unverified")
        print("LMR365_TPM_BROKER_POLICY=fixture_module_loaded",flush=True)
        entered=True
        yield
    finally:
        F.disposable()
        # Never unload a policy while its service still has a live process.
        if entered:
            pid=command("/usr/bin/systemctl","show","-pMainPID","--value",BROKER_UNIT).strip()
            need(pid==b"0","broker_service_not_stopped_before_policy_removal")
        if created and os.path.lexists(BROKER_EXEC):
            BROKER_EXEC.unlink()
        now=broker_policy_inventory()
        if any(row[1]==BROKER_MODULE for row in now):
            command("/usr/sbin/semodule","-X","400","-r",BROKER_MODULE,timeout=120)
        need(broker_policy_inventory()==before,"broker_policy_baseline_not_restored")
        F.disposable()
        print("LMR365_TPM_BROKER_POLICY=original_inventory_restored",flush=True)


BROKER_STAGES=("identity","hostname","enforcing","domain","request_nonce","self_sign","listen",
               "peer","request","sign","reply")
BROKER_STATUS_PROPERTIES=("LoadState","ActiveState","SubState","Result","MainPID",
                          "ExecMainPID","ExecMainCode","ExecMainStatus")


def broker_rows():
    raw=command("/usr/bin/journalctl","--no-pager","-u",BROKER_UNIT,
                "-o","json","-n","100",timeout=10)
    need(len(raw)<=1048576,"broker_journal_too_large")
    rows=[json.loads(line) for line in raw.splitlines()]
    need(all(type(row) is dict for row in rows),"broker_journal_row_unverified")
    return rows


def broker_receipt(pid,uid,expected):
    return sum(row.get("_SYSTEMD_UNIT")==BROKER_UNIT and row.get("_PID")==str(pid) and
               row.get("_UID")==str(uid) and row.get("MESSAGE")==expected
               for row in broker_rows())==1


def broker_status():
    raw=command("/usr/bin/systemctl","show",BROKER_UNIT,
                *("-p"+key for key in BROKER_STATUS_PROPERTIES)).decode("ascii","strict")
    rows={}
    for line in raw.splitlines():
        key,sep,value=line.partition("=")
        need(sep and key in BROKER_STATUS_PROPERTIES and key not in rows and
             re.fullmatch(r"[A-Za-z0-9_-]{1,40}",value),"broker_status_unverified")
        rows[key]=value
    need(set(rows)==set(BROKER_STATUS_PROPERTIES),"broker_status_missing")
    return rows


def broker_start_diagnostics(nonce,uid,pid):
    # Read-only, bounded classifications. Never print unit arguments, raw
    # journal text, environment, credential paths or the nonce.
    F.disposable()
    try:
        status=broker_status()
        for key,value in status.items():
            if key not in ("MainPID","ExecMainPID"):
                print("LMR365_TPM_BROKER_STATUS="+key+"="+value,flush=True)
        pid=int(status["ExecMainPID"]) if int(status["ExecMainPID"])>1 else pid
        print("LMR365_TPM_BROKER_PID="+("observed" if pid>1 else "absent"),flush=True)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
        print("LMR365_TPM_BROKER_STATUS=unverified",flush=True)
    try:
        rows=[row for row in broker_rows() if row.get("_SYSTEMD_UNIT")==BROKER_UNIT]
        for expected,label in (("LMR365_TPM_BROKER_READY="+nonce,"ready"),
                ("LMR365_TPM_BROKER_SELF_PS256="+nonce,"self_signature"),
                ("LMR365_TPM_BROKER_PS256="+nonce,"signature")):
            matches=[row for row in rows if row.get("MESSAGE")==expected]
            valid=sum(row.get("_PID")==str(pid) and row.get("_UID")==str(uid) for row in matches)
            print("LMR365_TPM_BROKER_JOURNAL="+label+":rows_"+str(len(matches))+
                  "_exact_peer_"+str(valid),flush=True)
        for stage in BROKER_STAGES:
            matches=[row for row in rows if row.get("MESSAGE")=="LMR365_TPM_BROKER_FAIL="+stage]
            if matches:
                valid=sum(row.get("_PID")==str(pid) and row.get("_UID")==str(uid) for row in matches)
                print("LMR365_TPM_BROKER_JOURNAL=failure_"+stage+":rows_"+str(len(matches))+
                      "_exact_peer_"+str(valid),flush=True)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
        print("LMR365_TPM_BROKER_JOURNAL=unverified",flush=True)


@contextmanager
def broker_credentials(queue,pipe_uid,pipe_gid):
    """Separate TPM DAC group from the existing read-only identity group."""
    stopped(queue)
    for lookup in (pwd.getpwnam,grp.getgrnam):
        try:
            lookup(BROKER_USER)
        except KeyError:
            continue
        raise RuntimeError("existing_broker_user_or_group")
    need(pwd.getpwnam(F.ACCOUNT).pw_uid==pipe_uid and
         grp.getgrnam(F.ACCOUNT).gr_gid==pipe_gid and
         set(os.getgrouplist(F.ACCOUNT,pipe_gid))=={pipe_gid},
         "broker_pipe_account_unverified")
    original=DEVICE.lstat()
    label=os.getxattr(DEVICE,"security.selinux",follow_symlinks=False)
    need(stat.S_ISCHR(original.st_mode) and
         (original.st_uid,original.st_gid,stat.S_IMODE(original.st_mode))==(0,pipe_gid,0o660),
         "broker_device_dac_baseline")
    def checked_device():
        F.disposable()
        st=DEVICE.lstat()
        need(stat.S_ISCHR(st.st_mode) and
             (st.st_dev,st.st_ino,st.st_rdev)==(original.st_dev,original.st_ino,original.st_rdev) and
             os.getxattr(DEVICE,"security.selinux",follow_symlinks=False)==label,
             "broker_device_identity_changed")
        return st
    command("/usr/sbin/useradd","--system","--user-group","--groups",F.ACCOUNT,
            "--home-dir","/nonexistent","--shell","/sbin/nologin",BROKER_USER)
    try:
        account=pwd.getpwnam(BROKER_USER)
        signer_gid=grp.getgrnam(BROKER_USER).gr_gid
        need(account.pw_uid>0 and account.pw_uid!=pipe_uid and signer_gid>0 and
             signer_gid!=pipe_gid and account.pw_gid==signer_gid and
             set(os.getgrouplist(BROKER_USER,signer_gid))=={signer_gid,pipe_gid} and
             set(os.getgrouplist(F.ACCOUNT,pipe_gid))=={pipe_gid} and
             not grp.getgrnam(BROKER_USER).gr_mem,
             "broker_separate_group_unverified")
        # Provision first with the existing identity group; only the signer
        # gets access to the emulator device during the IPC test.
        checked_device()
        os.chown(DEVICE,0,signer_gid,follow_symlinks=False)
        try:
            current=checked_device()
            need((current.st_uid,current.st_gid,stat.S_IMODE(current.st_mode))==
                 (0,signer_gid,0o660),"broker_separate_tpm_dac_unverified")
            print("LMR365_TPM_BROKER_DAC=dedicated_signer_group",flush=True)
            yield account.pw_uid,signer_gid
        finally:
            checked_device()
            os.chown(DEVICE,original.st_uid,original.st_gid,follow_symlinks=False)
            current=checked_device()
            need((current.st_uid,current.st_gid,current.st_mode)==
                 (original.st_uid,original.st_gid,original.st_mode),"broker_group_restore_failed")
            print("LMR365_TPM_BROKER_DAC=provisioning_group_restored",flush=True)
    finally:
        command("/usr/sbin/userdel",BROKER_USER)
        try:
            grp.getgrnam(BROKER_USER)
        except KeyError:
            pass
        else:
            command("/usr/sbin/groupdel",BROKER_USER)
        for lookup in (pwd.getpwnam,grp.getgrnam):
            try:
                lookup(BROKER_USER)
            except KeyError:
                continue
            raise RuntimeError("broker_account_cleanup_unverified")
        need(set(os.getgrouplist(F.ACCOUNT,pipe_gid))=={pipe_gid},"broker_pipe_group_changed")


def broker_process_credentials(proc,uid,signer_gid,pipe_gid):
    raw=(proc/"status").read_text(encoding="ascii")
    rows={}
    for line in raw.splitlines():
        key,sep,value=line.partition(":")
        if sep and key in ("Uid","Gid","Groups"):
            need(key not in rows and all(token.isdigit() for token in value.split()),
                 "broker_process_credentials_unverified")
            rows[key]=tuple(map(int,value.split()))
    need(set(rows)=={"Uid","Gid","Groups"} and rows["Uid"]==(uid,)*4 and
         rows["Gid"]==(signer_gid,)*4 and set(rows["Groups"])|{signer_gid}=={signer_gid,pipe_gid},
         "broker_process_credentials_unverified")


@contextmanager
def broker_scope(queue,nonce,pipe_uid,gid):
    stopped(queue)
    before=unit_snapshot()
    need(before["PrivateDevices"]=="yes" and before["DevicePolicy"]=="closed" and
         not any(before[key] for key in ("BindPaths","BindReadOnlyPaths","DeviceAllow",
                    "RootDirectory","RootImage","TemporaryFileSystem")),"broker_postfix_baseline")
    with broker_credentials(queue,pipe_uid,gid) as (uid,signer_gid):
        props=("User="+BROKER_USER,"Group="+BROKER_USER,"SupplementaryGroups="+F.ACCOUNT,"PrivateDevices=yes",
               "DevicePolicy=closed","DeviceAllow=/dev/tpmrm0 rw",
               "BindPaths=/dev/tpmrm0:/dev/tpmrm0","NoNewPrivileges=yes",
               "ProtectSystem=strict","ProtectHome=yes","PrivateTmp=yes",
               "RestrictAddressFamilies=AF_UNIX","CapabilityBoundingSet=",
               "RuntimeMaxSec=280","UMask=0077",
               "SELinuxContext=system_u:system_r:"+BROKER_DOMAIN+":s0")
        pid=0
        try:
            command("/usr/bin/systemd-run","--unit="+BROKER_UNIT,"--service-type=exec",
                    *("--property="+prop for prop in props),
                    str(BROKER_EXEC),"-I","-B",str(F.WORKER),"--broker-server",
                    "--nonce",nonce,"--uid",str(uid),"--gid",str(signer_gid),
                    "--pipe-uid",str(pipe_uid),"--pipe-gid",str(gid))
            until=time.monotonic()+85
            domain=""
            while time.monotonic()<until:
                status=broker_status()
                need(status["MainPID"].isdigit(),"broker_pid_unverified")
                pid=int(status["MainPID"])
                if status["ActiveState"] in ("failed","inactive"):
                    break
                if pid>1 and broker_receipt(pid,uid,"LMR365_TPM_BROKER_READY="+nonce):
                    proc=Path("/proc")/str(pid)
                    need((proc/"exe").resolve()==BROKER_EXEC,
                         "broker_executable_unverified")
                    fields=(proc/"attr/current").read_bytes().rstrip(b"\0\n").decode("ascii").split(":",3)
                    need(len(fields)==4 and fields[2]==BROKER_DOMAIN,"broker_domain_unverified")
                    domain=fields[2]
                    broker_process_credentials(proc,uid,signer_gid,gid)
                    visible=(proc/"root/dev/tpmrm0").lstat()
                    host=DEVICE.lstat()
                    need(stat.S_ISCHR(visible.st_mode) and
                         (visible.st_dev,visible.st_ino,visible.st_rdev)==
                         (host.st_dev,host.st_ino,host.st_rdev),"broker_device_unverified")
                    break
                time.sleep(.25)
            need(pid>1 and bool(domain),"broker_ready_unverified")
            print("LMR365_TPM_BROKER_DOMAIN="+domain,flush=True)
            print("LMR365_TPM_BROKER_DEVICE=same_character_device",flush=True)
            print("LMR365_TPM_BROKER_GROUPS=verified_actual_process",flush=True)
            need(broker_receipt(pid,uid,"LMR365_TPM_BROKER_SELF_PS256="+nonce),
                 "broker_service_self_signing_unverified")
            print("LMR365_TPM_BROKER_SELF_SIGN=verified_fixed_fixture",flush=True)
            need(unit_snapshot()==before,"broker_changed_postfix_sandbox")
            yield pid,uid,domain,signer_gid
            need(broker_receipt(pid,uid,"LMR365_TPM_BROKER_PS256="+nonce),
                 "broker_service_signing_receipt_unverified")
            need(unit_snapshot()==before,"broker_changed_postfix_sandbox")
            print("LMR365_TPM_BROKER_SERVICE_PS256=verified_fixed_fixture",flush=True)
        except Exception:
            broker_start_diagnostics(nonce,uid,pid)
            failure_diagnostics()
            raise
        finally:
            F.disposable()
            # The fixture never clears a failed queue or restarts Postfix.
            try:
                command("/usr/bin/systemctl","stop",BROKER_UNIT)
                need(command("/usr/bin/systemctl","show","-pMainPID","--value",BROKER_UNIT).strip()==b"0",
                     "broker_service_not_stopped")
            finally:
                need(unit_snapshot()==before,"broker_changed_postfix_sandbox")


def broker_link_evidence(master,broker_info):
    """Read actual process namespace and active TE policy; no access grant."""
    F.disposable()
    try:
        pid,uid,domain,signer_gid=broker_info
        signer=Path("/proc")/str(pid)
        need(broker_status()["MainPID"]==str(pid) and
             (signer/"exe").resolve()==BROKER_EXEC and
             (master/"exe").resolve()==Path("/usr/libexec/postfix/master"),
             "broker_link_process_unverified")
        fields=(signer/"attr/current").read_bytes().rstrip(b"\0\n").decode("ascii").split(":",3)
        need(len(fields)==4 and fields[2]==domain and re.fullmatch(r"[A-Za-z0-9_]+_t",domain),
             "broker_link_domain_unverified")
        left=os.readlink(master/"ns/net")
        right=os.readlink(signer/"ns/net")
        print("LMR365_TPM_BROKER_NET_NAMESPACE="+("same" if left==right else "different"),flush=True)
        policy=Path("/sys/fs/selinux/policy")
        need(policy.is_file(),"broker_live_policy_unavailable")
        for source,target,cls,permissions in (
                ("postfix_pipe_t",domain,"unix_stream_socket",("connectto",)),
                ("postfix_pipe_t","postfix_pipe_t","unix_stream_socket",("create","connect","read","write")),
                (domain,domain,"unix_stream_socket",("create","bind","listen","accept","read","write"))):
            for perm in permissions:
                for rule in ("allow","dontaudit"):
                    state="unverified"
                    try:
                        raw=command("/usr/bin/sesearch","--"+rule,"-s",source,"-t",target,
                                    "-c",cls,"-p",perm,str(policy),timeout=12).decode("utf-8","strict")
                        rows=[line.strip() for line in raw.splitlines() if line.strip()]
                        if len(raw)<=32768 and len(rows)<=128 and all(
                                line.startswith(rule+" ") for line in rows):
                            state="rule_present" if rows else "no_matching_rule"
                    except (OSError,ValueError,UnicodeError,subprocess.SubprocessError):
                        pass
                    print("LMR365_TPM_BROKER_IPC_POLICY="+rule+":"+source+":"+target+
                          ":"+cls+":"+perm+":"+state,flush=True)
    except (OSError,ValueError,RuntimeError,UnicodeError,subprocess.SubprocessError):
        print("LMR365_TPM_BROKER_IPC_EVIDENCE=unverified",flush=True)


def main():
    F.disposable()
    broker=os.environ.get("LMR365_KVM_TPM_BROKER_ACCEPTANCE")=="true"
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
            scope=broker_scope(queue,nonce,account.pw_uid,gid) if broker else nullcontext(None)
            with (broker_policy_scope(queue) if broker else nullcontext()), scope as broker_info:
                broker_args=(" --broker-pid "+str(broker_info[0])+" --broker-uid "+str(broker_info[1])+
                             " --broker-domain "+broker_info[2]+" --broker-gid "+str(broker_info[3])) if broker else " --tpm-handle "+HANDLE
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
                    " --gid "+str(gid)+broker_args+" --recipient ${recipient}\n").encode("ascii")
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
                with (nullcontext() if broker else scoped_fixture_device(queue)):
                    command("/usr/bin/systemctl","start","postfix.service")
                    need(command("/usr/bin/systemctl","is-active","postfix.service").strip()==b"active",
                         "fixture_postfix_start")
                    service_device_diagnostics()
                    if broker:
                        # Verify the host TPM is still absent from the stock master.
                        value=command("/usr/bin/systemctl","show","postfix.service","-pMainPID","--value").strip()
                        need(value.isdigit() and int(value)>1,"broker_postfix_pid_unverified")
                        proc=Path("/proc")/value.decode("ascii")
                        need((proc/"exe").resolve()==Path("/usr/libexec/postfix/master") and
                             b":postfix_master_t:" in (proc/"attr/current").read_bytes(),
                             "broker_postfix_master_unverified")
                        need(not os.path.lexists(proc/"root/dev/tpmrm0"),"broker_exposed_tpm_to_postfix")
                        print("LMR365_TPM_BROKER_POSTFIX_DEVICE=absent",flush=True)
                        # A namespace mismatch or absent TE rule is diagnostic
                        # only. Keep the actual authenticated pipe test mandatory.
                        broker_link_evidence(proc,broker_info)
                    try:
                        qid=F.submit_fixture(nonce,daemon,tpm=not broker,broker=broker)
                    except Exception:
                        failure_diagnostics()
                        if broker:
                            # Emit fixed service stage codes only; no raw journal.
                            for stage in BROKER_STAGES:
                                if broker_receipt(broker_info[0],broker_info[1],"LMR365_TPM_BROKER_FAIL="+stage):
                                    print("LMR365_TPM_BROKER_FAILURE="+stage,flush=True)
                        raise
            F.disposable()
            print("LMR365_TPM_PIPE_DOMAIN=postfix_pipe_t",flush=True)
            if broker:
                command("/usr/bin/systemctl","stop","postfix.service")
                print("LMR365_TPM_BROKER_PIPE=verified_fixed_fixture",flush=True)
                print("LMR365_TPM_BROKER_POSTFIX_SANDBOX=unchanged",flush=True)
            else:
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
