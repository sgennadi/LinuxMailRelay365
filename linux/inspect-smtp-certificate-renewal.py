#!/usr/bin/env python3
"""Read-only Certbot renewal readiness; never executes hooks or reads DNS secrets."""
import json
import os
import re
import stat
import subprocess
from pathlib import Path

ROOT=Path("/etc/letsencrypt/renewal")
SAFE_DNS={"dns-azure","dns-cloudflare","dns-route53","dns-google","dns-rfc2136"}

def classify(text):
    section=False
    values={}
    for line in text.splitlines():
        line=line.strip()
        if line.startswith("["):
            section=line=="[renewalparams]"
        elif section and "=" in line and not line.startswith("#"):
            key,value=map(str.strip,line.split("=",1))
            if key in values:
                return "ambiguous"
            values[key]=value
    auth=values.get("authenticator","")
    if auth=="manual":
        return "manual_hook_unverified" if values.get("manual_auth_hook") else "manual"
    if auth in SAFE_DNS:
        return "dns_plugin_configured"
    if auth in ("webroot","standalone","nginx","apache"):
        return "http_validation_configured"
    return "unknown"

def timer_state():
    result={}
    for unit in ("certbot.timer","certbot-renew.timer","snap.certbot.renew.timer"):
        try:
            p=subprocess.run(["/usr/bin/systemctl","show",unit,
                "--property=LoadState,ActiveState,UnitFileState"],
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
            fields=dict(line.split("=",1) for line in p.stdout.decode().splitlines() if "=" in line)
            result[unit]=fields if p.returncode==0 else {}
        except (OSError,ValueError,subprocess.SubprocessError):
            result[unit]={}
    return result

def inventory():
    rows=[]
    if ROOT.is_dir() and not ROOT.is_symlink():
        for path in sorted(ROOT.glob("*.conf"))[:128]:
            try:
                st=path.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022 or st.st_size>65536:
                    raise ValueError("untrusted config")
                mode=classify(path.read_text(encoding="utf-8"))
            except (OSError,ValueError):
                mode="unverified"
            rows.append({"lineage":path.stem,"renewal_method":mode,
                         "renewal_test":"not_run"})
    return {"lineages":rows,"timers":timer_state(),"automatic_renewal_verified":False}

if __name__=="__main__":
    if os.geteuid()!=0:
        raise SystemExit("root required")
    print(json.dumps(inventory()))
