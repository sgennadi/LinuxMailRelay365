#!/usr/bin/env python3
"""Explicit isolated staging challenge test; temporarily changes public DNS."""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).resolve().with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def snapshot(name):
    try:
        r=subprocess.run(["/usr/bin/dig","@1.1.1.1","_acme-challenge."+name,"TXT","+noall","+comments","+answer","+time=3","+tries=1"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8)
        output=r.stdout.decode("ascii","replace")
        if r.returncode or not re.search(r"status: (NOERROR|NXDOMAIN),",output):
            return None
        return sorted(line.split(None,4)[4] for line in output.splitlines()
            if len(line.split(None,4))==5 and line.split(None,4)[2:4]==["IN","TXT"])
    except (OSError,subprocess.SubprocessError):
        return None

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--provider",choices=("dns-azure","dns-cloudflare","dns-google","dns-route53","dns-rfc2136"),required=True)
    for field in ("name","domain","email","credentials","confirm"):
        p.add_argument("--"+field,required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="TEST_PUBLIC_DNS_CHALLENGE":
        p.error("root and explicit DNS change confirmation required")
    ok=False
    before=None
    attempted=False
    cleanup=load("check-smtp-acme-txt-cleanup")
    try:
        load("check-smtp-acme-credentials").inspect(a.provider,a.credentials)
        os.umask(0o077)
        env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"}
        with tempfile.TemporaryDirectory(prefix="lmr365-acme-test-",dir="/var/tmp") as root:
            env["HOME"]=root
            if a.provider=="dns-route53":
                env.update(AWS_SHARED_CREDENTIALS_FILE=a.credentials,AWS_CONFIG_FILE="/dev/null",AWS_PROFILE="default",AWS_EC2_METADATA_DISABLED="true")
            args=load("plan-smtp-acme-challenge-test").command(a.provider,a.name,a.domain,"https://acme-staging-v02.api.letsencrypt.org/directory",a.email,a.credentials,root)
            load("issue-smtp-acme-cloudflare").trusted(args[0])
            before=snapshot(a.name)
            attempted=True
            r=subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600,env=env)
            ok=r.returncode==0
    except Exception:
        pass
    comparison=cleanup.compare(before,snapshot(a.name) if attempted else None)
    print(json.dumps(dict(version=1,status="passed" if ok else "failed",dns_challenge_verified=ok,txt_cleanup_verified=False,txt_snapshot=comparison,production_certificate_modified=False,postfix_modified=False)))
    return 0 if ok else 1
if __name__=="__main__":
    raise SystemExit(main())
