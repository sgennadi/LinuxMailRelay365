#!/usr/bin/env python3
"""Read-only SELinux diagnostics for managed Postfix TLS."""
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

def probe(binary,*args):
    try:
        binary=load("smtp-tls-postfix").trusted_invocation(binary)
        r=subprocess.run([binary]+list(args),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
        return r.returncode,r.stdout.decode("utf-8","replace").strip()
    except Exception:
        return None,""

def main():
    root=Path("/etc/postfix/lmr365-smtp-tls")
    rc,mode=probe("/usr/sbin/getenforce")
    report={"version":1,"mode":mode.lower() if rc==0 and mode in ("Enforcing","Permissive","Disabled") else "unknown","paths":[],"access_verified":False}
    if report["mode"] in ("enforcing","permissive"):
        try:
            gen=load("smtp-tls-generation")
            name=gen.current(root)
            gen.validate(root,name)
            for path in (root,root/name,root/name/"client-chain.pem",root/name/"fullchain.pem",root/name/"key.pem"):
                code,expected=probe("/usr/sbin/matchpathcon","-n",str(path))
                try:
                    actual=os.getxattr(str(path),"security.selinux").decode("ascii").rstrip("\x00")
                except (OSError,UnicodeError):
                    actual=None
                report["paths"].append(dict(path=str(path),actual=actual,expected=expected if code==0 else None,status="matches" if actual and code==0 and actual==expected else "review"))
        except Exception:
            report["generation_status"]="unverified"
    print(json.dumps(report,sort_keys=True))
if __name__=="__main__":
    main()
