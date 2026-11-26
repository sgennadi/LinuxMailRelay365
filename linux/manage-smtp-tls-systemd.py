#!/usr/bin/env python3
"""Explicit systemd unit preview and installation interface."""
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def digest(plan):
    return hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def main():
    p=argparse.ArgumentParser()
    p.add_argument("action",choices=("preview","install","status","enable-recovery","disable-timer","stop-timer","enable-timer","start-timer","renew-now","preview-uninstall","uninstall"))
    p.add_argument("--plan-sha")
    p.add_argument("--confirm")
    a=p.parse_args()
    if os.geteuid()!=0:
        p.error("root required")
    planner=load("plan-smtp-tls-systemd")
    source=Path(__file__).resolve().parent/"systemd"
    target=Path("/etc/systemd/system")
    systemctl=load("smtp-tls-postfix").trusted_binary("/usr/bin/systemctl")
    def run(*args):
        return subprocess.run([systemctl]+list(args),stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=90,
            env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
    if a.action in ("preview-uninstall","uninstall"):
        plan=planner.preview_uninstall(source,target)
        if a.action=="preview-uninstall":
            print(json.dumps(dict(plan=plan,plan_sha256=digest(plan))))
            return 0
        if a.confirm!="UNINSTALL_TLS_UNITS" or a.plan_sha!=digest(plan):
            p.error("explicit confirmation and matching plan required")
        root=Path("/etc/postfix/lmr365-smtp-tls")
        import fcntl
        import stat
        for directory in [root]+list(root.parents):
            st=directory.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
                raise ValueError("unsafe lock directory")
        fd=os.open(str(root/"acme-renewal.lock"),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o077:
                raise ValueError("unsafe lock")
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with load("smtp-tls-transaction").deployment_lock(root):
                def inactive():
                    for name in ("initial-deployment.json","deployment.json"):
                        path=root/name
                        if path.exists() and json.loads(path.read_text()).get("phase") not in ("verified","rolled_back"):
                            raise ValueError("unfinished TLS transaction")
                    pf=load("smtp-tls-postfix").Postfix()
                    if "/lmr365-smtp-tls/" in pf.run(pf.postconf,"-n") or "/lmr365-smtp-tls/" in pf.run(pf.postconf,"-P"):
                        raise ValueError("detach managed TLS before removing recovery units")
                    for unit in planner.UNITS:
                        r=run("show",unit,"--property=ActiveState","--value")
                        if r.returncode or r.stdout.strip()!=b"inactive":
                            raise ValueError("unit must be inactive: "+unit)
                        r=run("is-enabled",unit)
                        if r.stdout.strip() not in (b"disabled",b"static",b"not-found"):
                            raise ValueError("unit must be disabled: "+unit)
                def reload_units():
                    if run("daemon-reload").returncode:
                        raise RuntimeError("daemon-reload failed")
                removed=load("uninstall-smtp-tls-systemd").uninstall(source,target,plan,planner.preview_uninstall,inactive,reload_units)
            print(json.dumps(dict(removed=removed)))
            return 0
        finally:
            os.close(fd)
    if a.action=="status":
        for unit in planner.UNITS:
            result=run("show",unit,"--property=LoadState,ActiveState,UnitFileState,NextElapseUSecRealtime")
            print(json.dumps({"unit":unit,"exit":result.returncode,"properties":result.stdout.decode("utf-8","replace").splitlines()}))
        return 0
    if a.action in ("enable-timer","start-timer","renew-now"):
        if a.confirm!="MANAGE_TLS_UNITS":
            p.error("explicit confirmation required")
        if any(u["status"]!="unchanged" for u in planner.preview(source,target)["units"]):
            raise ValueError("installed units do not match package")
        root=Path("/etc/postfix/lmr365-smtp-tls")
        with load("smtp-tls-transaction").deployment_lock(root):
            for name in ("initial-deployment.json","deployment.json"):
                path=root/name
                if path.exists() and json.loads(path.read_text()).get("phase") not in ("verified","rolled_back"):
                    raise ValueError("unfinished TLS transaction")
            data=load("smtp-tls-renewal-profile").load()
            gen=load("smtp-tls-generation")
            load("smtp-tls-validate-generation").validate(root,gen.current(root),data["domain"],data["ca_file"],gen,load("check-smtp-relay-certificate"))
            load("smtp-tls-postfix").Postfix().check()
            for unit in ("linuxmailrelay365-smtp-tls-initial-recovery.service","linuxmailrelay365-smtp-tls-prestart.service"):
                if run("is-enabled",unit).returncode:
                    raise ValueError("recovery units must be enabled")
        timer="linuxmailrelay365-smtp-acme-renew.timer"
        if a.action=="enable-timer":
            result=run("enable","--now",timer)
        elif a.action=="start-timer":
            result=run("start",timer)
        else:
            result=run("--no-block","start","linuxmailrelay365-smtp-acme-renew.service")
        print(json.dumps({"action":a.action,"exit":result.returncode,"completion_verified":False}))
        return result.returncode
    if a.action in ("enable-recovery","disable-timer","stop-timer"):
        if a.confirm!="MANAGE_TLS_UNITS":
            p.error("explicit confirmation required")
        timer="linuxmailrelay365-smtp-acme-renew.timer"
        if a.action=="enable-recovery":
            plan=planner.preview(source,target)
            if any(u["status"]!="unchanged" for u in plan["units"]):
                raise ValueError("installed units do not match package")
            root=Path("/etc/postfix/lmr365-smtp-tls")
            with load("smtp-tls-transaction").deployment_lock(root):
                for name in ("initial-deployment.json","deployment.json"):
                    path=root/name
                    if path.exists() and json.loads(path.read_text()).get("phase") not in ("verified","rolled_back"):
                        raise ValueError("unfinished TLS transaction")
                load("smtp-tls-postfix").Postfix().check()
                result=run("enable","linuxmailrelay365-smtp-tls-initial-recovery.service","linuxmailrelay365-smtp-tls-prestart.service")
        else:
            result=run("disable","--now",timer) if a.action=="disable-timer" else run("stop",timer)
        print(json.dumps({"action":a.action,"exit":result.returncode}))
        return result.returncode
    plan=planner.preview(source,target)
    if a.action=="preview":
        print(json.dumps(dict(plan=plan,plan_sha256=digest(plan))))
        return 0
    if a.confirm!="INSTALL_TLS_UNITS" or a.plan_sha!=digest(plan):
        p.error("explicit confirmation and matching plan required")
    def reload():
        if run("daemon-reload").returncode:
            raise RuntimeError("daemon-reload failed")
    created=load("install-smtp-tls-systemd").install(source,target,plan,planner.preview,reload)
    print(json.dumps(dict(created=created,timer_started=False)))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
