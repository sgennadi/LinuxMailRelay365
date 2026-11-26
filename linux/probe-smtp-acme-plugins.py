#!/usr/bin/env python3
"""Inspect registered Certbot authenticators without issuing certificates."""
import json
import os
import re
import stat
import subprocess
from pathlib import Path

PROVIDERS=("dns-cloudflare","dns-azure","dns-google","dns-route53","dns-rfc2136")

def parse(output):
    names=set(re.findall(r"^\*\s+([a-z0-9_-]+)\s*$",output,re.M))
    return {name:{"registered":name in names,"credentials_verified":False,
                  "issuance_verified":False} for name in PROVIDERS}

def main():
    binary=Path("/usr/bin/certbot").resolve(strict=True)
    for path in [binary]+list(binary.parents):
        st=path.lstat()
        if st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("untrusted Certbot path")
    if not stat.S_ISREG(binary.stat().st_mode):
        raise ValueError("invalid Certbot executable")
    result=subprocess.run([str(binary),"plugins","--authenticators"],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,
        env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","HOME":"/root"})
    if result.returncode:
        print(json.dumps({"status":"probe_failed","providers":{}}))
        return 1
    print(json.dumps({"status":"completed","providers":parse(result.stdout.decode("utf-8","replace"))}))
    return 0

if __name__=="__main__":
    try:
        raise SystemExit(main())
    except (OSError,ValueError,subprocess.SubprocessError):
        print(json.dumps({"status":"probe_failed","providers":{}}))
        raise SystemExit(1)
