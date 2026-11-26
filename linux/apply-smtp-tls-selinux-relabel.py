#!/usr/bin/env python3
"""Explicitly restore default SELinux contexts on one managed TLS generation."""
import argparse
import importlib.util
import json
import os
import subprocess
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).resolve().with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--generation",required=True)
    p.add_argument("--confirm",required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="RESTORE_TLS_CONTEXTS":
        p.error("root and explicit confirmation required")
    root=Path("/etc/postfix/lmr365-smtp-tls")
    report=dict(version=1,status="failed",access_verified=False)
    try:
        gen=load("smtp-tls-generation")
        with load("smtp-tls-transaction").deployment_lock(root):
            name=gen.current(root)
            if name!=a.generation:
                raise ValueError("active generation changed")
            gen.validate(root,name)
            pf=load("smtp-tls-postfix")
            env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"}
            mode=subprocess.check_output([pf.trusted_binary("/usr/sbin/getenforce")],env=env,timeout=10).strip()
            if mode not in (b"Enforcing",b"Permissive"):
                raise ValueError("SELinux not active")
            paths=[root,root/name]+[root/name/x for x in ("client-chain.pem","fullchain.pem","key.pem")]
            binary=pf.trusted_binary("/usr/sbin/restorecon")
            r=subprocess.run([binary,"-v"]+[str(x) for x in paths],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,env=env)
            if r.returncode:
                raise RuntimeError("restorecon failed")
            match=pf.trusted_binary("/usr/sbin/matchpathcon")
            for path in paths:
                expected=subprocess.check_output([match,"-n",str(path)],env=env,timeout=10).strip()
                actual=os.getxattr(str(path),"security.selinux").rstrip(b"\x00")
                if actual!=expected:
                    raise ValueError("context mismatch")
            report["status"]="contexts_verified"
    except Exception:
        report["status"]="failed_or_partial"
    print(json.dumps(report,sort_keys=True))
    return 0 if report["status"]=="contexts_verified" else 1
if __name__=="__main__":
    raise SystemExit(main())
