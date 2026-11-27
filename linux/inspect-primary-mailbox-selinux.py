#!/usr/bin/env python3
"""Read-only primary Postfix XOAUTH2 SELinux readiness, not write approval.

Check exact file-context policy and live metadata, including the active
certificate and key/provider references, without reading private key bytes.
No relabel, boolean changes, package installation, service control or network.
The diagnostic does not establish Postfix pipe-domain access.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import signal
import stat
import sys
import json

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,str(HERE/file))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

A=load("primary_label_runtime","primary-mailbox-runtime.py")
P=load("primary_label_native","inspect-conditional-postfix-activation.py")
T=P.T
ROOT="/etc/postfix/m365-oauth"
FIXED={
    "config_directory":("/etc/postfix","dir"),
    "main_cf":("/etc/postfix/main.cf","file"),
    "master_cf":("/etc/postfix/master.cf","file"),
    "queue_directory":("/var/spool/postfix","dir"),
    "identity_directory":(ROOT,"dir"),
    "identity_config":(ROOT+"/app.json","file"),
    "transport":("/usr/local/libexec/m365_xoauth2_transport.py","file"),
    "signer":("/usr/local/libexec/m365_hardware_signer.py","file"),
    "recovery_parent":("/var/lib","dir")
}
DYNAMIC=("active_certificate","active_key_or_provider")
CONFIG=("config_directory","main_cf","master_cf")
GENERIC={"default_t","unlabeled_t","file_t","etc_t","usr_t"}
PORTS={443:"http_port_t",587:"smtp_port_t"}

def need(condition,reason):
    if not condition:
        raise ValueError(reason)

def mode():
    try:
        value=Path("/sys/fs/selinux/enforce").read_text(encoding="ascii").strip()
        return {"0":"permissive","1":"enforcing"}.get(value,"unverified")
    except FileNotFoundError:
        return "inactive_or_unavailable"
    except (OSError,UnicodeError):
        return "unverified"

def metadata(st):
    return [st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,
            st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns]

def policy_label(path,kind,command):
    raw=command("matchpathcon",["-N","-n","-m",kind,path])
    lines=raw.splitlines()
    need(len(lines)==1 and lines[0]==lines[0].strip(),"policy_label_unverified")
    label=T.checked_label(lines[0].encode("ascii"))
    return T.label_bytes(label).rstrip(b"\0")

def sample_path(path,kind,command=P.system_command,uid=0):
    parent,name=os.path.split(path)
    fd=None
    try:
        # Traverse fixed directories without following symlinks; spool
        # ancestors can be distribution-owned rather than root-owned.
        fd=P.open_directory(parent,strict=False)
        first=os.stat(name,dir_fd=fd,follow_symlinks=False)
        need((stat.S_ISDIR(first.st_mode) if kind=="dir" else
              stat.S_ISREG(first.st_mode) and first.st_nlink==1),
             "unexpected_object_type")
        need(first.st_uid==uid and not first.st_mode&0o022,
             "unsafe_object_metadata")
        flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
        if kind=="dir":
            flags|=os.O_DIRECTORY
        handle=os.open(name,flags,dir_fd=fd)
        try:
            before=os.fstat(handle)
            need(metadata(before)==metadata(first),"object_changed")
            actual=T.file_label(handle)
            expected=policy_label(path,kind,command)
            need(metadata(os.fstat(handle))==metadata(before)==
                 metadata(os.stat(name,dir_fd=fd,follow_symlinks=False)) and
                 T.file_label(handle)==actual,"metadata_changed")
            if actual is None:
                return "label_missing",None
            actual_raw=T.label_bytes(actual).rstrip(b"\0")
            if actual_raw!=expected:
                return "policy_mismatch",None
            evidence={"label":actual,"metadata":metadata(before)}
            if actual_raw.decode("ascii").split(":")[2] in GENERIC:
                return "policy_match_generic",evidence
            return "policy_match",evidence
        finally:
            os.close(handle)
    except FileNotFoundError:
        return "missing",None
    except (OSError,ValueError,UnicodeError,P.Refused):
        return "unverified",None
    finally:
        if fd is not None:
            os.close(fd)

def credential_paths(identity):
    """Resolve fixed-directory references only; never load key/provider bytes."""
    def fixed(value):
        need(type(value) is str and str(Path(value).parent)==ROOT and
             re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",Path(value).name) is not None,
             "unexpected_credential_reference")
        need(value==ROOT+"/"+Path(value).name,"noncanonical_credential_reference")
        return (value,"file")
    cert=fixed(identity["certificate"])
    if "signer" not in identity:
        need(set(identity)=={"tenant_id","client_id","mailbox","certificate","private_key"},
             "unexpected_identity_fields")
        return "pem",dict(active_certificate=cert,active_key_or_provider=fixed(identity["private_key"]))
    spec=identity["signer"]
    need(set(identity)=={"tenant_id","client_id","mailbox","certificate","signer"} and
         type(spec) is dict and set(spec)=={"type","provider","key_ref","provider_config"} and
         spec["type"]=="openssl-provider","unexpected_hardware_identity")
    provider=fixed(spec["provider_config"])
    # Blob and PKCS#11 dependency trees are not completely represented by
    # these two file checks. Report the scope explicitly, never ready.
    if (spec["provider"]=="tpm2" and type(spec["key_ref"]) is str and
            spec["key_ref"].startswith("handle:") and
            A.T.HANDLE.fullmatch(spec["key_ref"][7:]) and
            provider[0]==ROOT+"/tpm2.cnf" and cert[0]==ROOT+"/hardware-app.crt"):
        identity_mode="managed_tpm2_reference"
    else:
        identity_mode="custom_hardware"
    return identity_mode,dict(active_certificate=cert,active_key_or_provider=provider)

def port_matches(raw,include_generic=False):
    need(type(raw) is str and len(raw)<=131072,"port_policy_unverified")
    lines=[line.strip() for line in raw.splitlines() if line.strip()]
    need(bool(lines) and lines[0].split()==["SELinux","Port","Type","Proto","Port","Number"],
         "port_policy_header_unverified")
    matches={port:set() for port in PORTS}
    for line in lines[1:]:
        match=re.fullmatch(r"([A-Za-z0-9_]+)\s+(tcp|udp|sctp|dccp)\s+(.+)",line)
        need(match is not None,"port_policy_row_unverified")
        label,protocol,values=match.groups()
        for value in values.split(","):
            interval=re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?",value.strip())
            need(interval is not None,"port_policy_range_unverified")
            lo,hi=int(interval[1]),int(interval[2] or interval[1])
            need(0<=lo<=hi<=65535,"port_policy_range_unverified")
            # The stock high-reserved interval is a generic fallback,
            # not a second specific assignment of SMTP Submission. Do not
            # disregard a custom hi_reserved_port_t single port or range.
            generic=(label in ("reserved_port_t","unreserved_port_t","port_t") or
                     (label=="hi_reserved_port_t" and (lo,hi)==(512,1023)))
            if protocol=="tcp" and (include_generic or not generic):
                for port in PORTS:
                    if lo<=port<=hi:
                        matches[port].add(label)
    return matches


def port_states(raw):
    return {str(port):"expected_type" if labels=={PORTS[port]} else
            "no_specific_type" if not labels else "different_or_ambiguous_type"
            for port,labels in port_matches(raw).items()}

def collect(nonce,mode_reader=mode,command=P.system_command,sampler=sample_path,
            active_reader=A.read_active):
    observed=mode_reader()
    labels=dict.fromkeys(tuple(FIXED)+DYNAMIC,"not_checked")
    ports=dict.fromkeys(map(str,PORTS),"not_checked")
    identity="not_checked"
    config_sha=None
    status="inactive_or_unverified"
    if observed in ("enforcing","permissive"):
        def sample():
            paths=dict(FIXED)
            try:
                group=A.grp.getgrnam("m365mailer").gr_gid
                raw,data=active_reader(group)
                kind,credentials=credential_paths(data)
                paths.update(credentials)
                active_sha=A.C.sha(raw)
            except (OSError,ValueError,KeyError,TypeError,A.Refused,A.R.E.Refused):
                kind,active_sha="unverified",None
            # Postfix's normal spool directory may be postfix-owned.
            try:
                queue_uid=A.pwd.getpwnam("postfix").pw_uid
            except KeyError:
                queue_uid=None
            results={}
            for name,(path,file_kind) in paths.items():
                if name=="queue_directory":
                    # Accept root or the exact postfix account; no other owner.
                    try:
                        owner=os.lstat(path).st_uid
                        need(owner in (0,queue_uid),"unexpected_queue_owner")
                    except (OSError,ValueError):
                        results[name]=("unverified",None)
                        continue
                else:
                    owner=0
                results[name]=sampler(path,file_kind,command,owner)
            return kind,active_sha,results
        first=sample()
        second=sample()
        need(first==second and mode_reader()==observed,"selinux_observation_changed")
        identity,_,results=first
        for name,(state,_) in results.items():
            labels[name]=state
        try:
            raw=command("semanage",["port","-l"])
            ports=port_states(raw)
            need(command("semanage",["port","-l"])==raw,"port_policy_changed")
        except (OSError,ValueError,P.Refused):
            ports=dict.fromkeys(map(str,PORTS),"unverified")
        need(mode_reader()==observed and sample()==first,"selinux_observation_changed")
        if all(labels[name]=="policy_match" for name in CONFIG):
            config_sha=A.digest({name:results[name][1] for name in CONFIG})
        # Policy match for generic runtime/recovery paths can be entirely
        # normal, but is not evidence of permission in postfix_pipe_t.
        status="manual_runtime_review_required" if (
            observed=="enforcing" and config_sha is not None and
            identity in ("pem","managed_tpm2_reference") and
            all(state in ("policy_match","policy_match_generic") for state in labels.values()) and
            all(state=="expected_type" for state in ports.values())
        ) else "policy_or_mode_review_required"
    return {"version":1,"nonce":nonce,"status":status,"mode":observed,
            "identity":identity,"labels":labels,"ports":ports,"config_metadata_sha256":config_sha,
            "write_allowed":False,"runtime_verified":False,"changes_applied":False,
            "mail_sent":False,"network_attempted":False}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument("--nonce",required=True)
    args=parser.parse_args(argv)
    try:
        need(os.geteuid()==0 and A.R.SHA.fullmatch(args.nonce),"invalid_probe_context")
        A.R.E.trusted_directory(HERE)
        def expired(*_):
            raise TimeoutError("readiness_deadline")
        signal.signal(signal.SIGALRM,expired)
        signal.alarm(180)
        print(json.dumps(collect(args.nonce),sort_keys=True))
        return 0
    except Exception:
        print('{"status":"unverified"}')
        return 2
    finally:
        signal.alarm(0)

if __name__=="__main__":
    sys.exit(main())
