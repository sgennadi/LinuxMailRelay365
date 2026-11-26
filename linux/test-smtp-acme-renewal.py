#!/usr/bin/env python3
"""Preview ACME renewal test; refuse configured hooks before running dry-run."""
import argparse
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
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--confirm",required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="TEST_ACME_RENEWAL":
        p.error("root and explicit confirmation required")
    profile=load("smtp-tls-renewal-profile")
    profile.load()
    data=json.loads(profile.PROFILE.read_text())
    name=data["lineage"]
    base=profile.BASE
    conf=profile.trusted(base/"renewal"/(name+".conf"))
    if conf.stat().st_size>65536:
        raise ValueError("renewal configuration too large")
    for line in conf.read_text().splitlines():
        line=line.strip()
        if not line or line.startswith(("#",";","[")):
            continue
        key,sep,value=line.partition("=")
        if not sep:
            raise ValueError("unsupported renewal configuration syntax")
        if "hook" in key.lower():
            raise ValueError("configured hooks require manual review")
    if (base/"cli.ini").exists():
        raise ValueError("custom global ACME configuration requires manual review")
    certbot=load("smtp-tls-postfix").trusted_binary("/usr/bin/certbot")
    result=subprocess.run([certbot,"renew","--dry-run","--non-interactive","--no-directory-hooks",
        "--cert-name",name,"--config-dir",str(base),"--work-dir",str(base.parent/"work"),
        "--logs-dir",str(base.parent/"logs")],timeout=1800,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
    print(json.dumps({"test_renewal_exit":result.returncode,"activation_requested":False}))
    return result.returncode
if __name__=="__main__":
    raise SystemExit(main())
