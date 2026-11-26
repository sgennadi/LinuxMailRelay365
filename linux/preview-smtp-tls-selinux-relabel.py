#!/usr/bin/env python3
"""Preview SELinux relabeling of managed TLS files; never apply changes."""
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
    report={"version":1,"apply_supported":False,"access_verified":False,"status":"unverified","changes":[]}
    try:
        if os.geteuid()!=0:
            raise ValueError("root required")
        root=Path("/etc/postfix/lmr365-smtp-tls")
        gen=load("smtp-tls-generation")
        with load("smtp-tls-transaction").deployment_lock(root):
            name=gen.current(root)
            gen.validate(root,name)
            pf=load("smtp-tls-postfix")
            env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"}
            mode=subprocess.check_output([pf.trusted_binary("/usr/sbin/getenforce")],env=env,timeout=10).strip()
            if mode==b"Disabled":
                report["status"]="not_applicable"
            elif mode in (b"Enforcing",b"Permissive"):
                paths=[root,root/name]+[root/name/x for x in ("client-chain.pem","fullchain.pem","key.pem")]
                r=subprocess.run([pf.trusted_binary("/usr/sbin/restorecon"),"-n","-v"]+[str(x) for x in paths],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env=env)
                report["status"]="preview" if r.returncode==0 else "failed"
                report["changes"]=r.stdout.decode("utf-8","replace").splitlines()[:100]
    except Exception:
        report["status"]="unverified"
    print(json.dumps(report,sort_keys=True))
    return 0 if report["status"] in ("preview","not_applicable") else 1
if __name__=="__main__":
    raise SystemExit(main())
