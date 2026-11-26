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
    p.add_argument("action",choices=("preview","install","status","enable-recovery","disable-timer","stop-timer"))
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
    if a.action=="status":
        for unit in planner.UNITS:
            result=run("show",unit,"--property=LoadState,ActiveState,UnitFileState,NextElapseUSecRealtime")
            print(json.dumps({"unit":unit,"exit":result.returncode,"properties":result.stdout.decode("utf-8","replace").splitlines()}))
        return 0
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
