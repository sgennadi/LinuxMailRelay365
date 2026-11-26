#!/usr/bin/env python3
"""Read-only ACME capability discovery. Does not execute third-party plugins."""
import json
import os
import stat
import subprocess
from pathlib import Path

PROVIDERS=("azure","cloudflare","route53","google","rfc2136")

def trusted(path):
    try:
        resolved=Path(path).resolve(strict=True)
        for p in [resolved]+list(resolved.parents):
            st=p.stat()
            if st.st_uid!=0 or st.st_mode & 0o022:
                return False
        return stat.S_ISREG(resolved.stat().st_mode) and os.access(str(resolved),os.X_OK)
    except (OSError,RuntimeError):
        return False

def run(binary,args):
    try:
        p=subprocess.run([binary]+args,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=15,
            env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
        return p.stdout.decode("utf-8","replace")[:65536] if p.returncode==0 else None
    except (OSError,subprocess.SubprocessError):
        return None

def inventory():
    binary=next((p for p in ("/usr/bin/certbot","/usr/local/bin/certbot") if trusted(p)),None)
    version=run(binary,["--version"]) if binary else None
    # Package presence is evidence only, not proof of plugin operability.
    rpm=trusted("/usr/bin/rpm")
    dpkg=trusted("/usr/bin/dpkg-query")
    rows=[]
    for provider in PROVIDERS:
        found=[]
        for tool,args in (
            ("/usr/bin/rpm",["-q","python3-certbot-dns-"+provider]),
            ("/usr/bin/dpkg-query",["-W","-f=${Status}","python3-certbot-dns-"+provider])):
            if (tool.endswith("/rpm") and rpm) or (tool.endswith("/dpkg-query") and dpkg):
                value=run(tool,args)
                if value and (tool.endswith("/rpm") or value.strip()=="install ok installed"):
                    found.append(tool.rsplit("/",1)[-1])
        rows.append({"provider":"dns-"+provider,"package_evidence":found,
                     "plugin_operability":"unverified"})
    return {"certbot_path":binary,"version":version.strip() if version else None,
            "providers":rows,"manual_dns":"candidate" if version else "unverified",
            "issuance_supported":False}

if __name__=="__main__":
    print(json.dumps(inventory()))
