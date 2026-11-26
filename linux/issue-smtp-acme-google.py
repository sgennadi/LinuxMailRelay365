#!/usr/bin/env python3
"""Explicit Google DNS-01 issuance into isolated Certbot state.
Does not activate Postfix TLS or claim Exchange Online compatibility.
"""
import argparse
import os
import re
import stat
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

ROOT=Path("/var/lib/linuxmailrelay365/smtp-acme")

def dns(name):
    if len(name)>253 or "." not in name or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
        for p in name.split(".")):
        raise ValueError("invalid DNS name")
    return name

def trusted(path, secret=False):
    path=Path(path)
    if not path.is_absolute() or path.resolve(strict=True)!=path:
        raise ValueError("absolute non-symlink path required")
    for p in [path]+list(path.parents):
        st=p.lstat()
        if st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("untrusted path")
    st=path.stat()
    if not stat.S_ISREG(st.st_mode) or (secret and st.st_mode & 0o077):
        raise ValueError("unsafe file")
    return str(path)

def command(name, domain, server, email, credentials):
    name=dns(name)
    domain=dns(domain)
    if name!=domain and not name.endswith("."+domain):
        raise ValueError("outside selected domain")
    u=urlsplit(server)
    if u.scheme!="https" or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError("invalid ACME directory")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email):
        raise ValueError("invalid account email")
    return ["/usr/bin/certbot","certonly","--non-interactive","--agree-tos",
        "--email",email,"--server",server,"--dns-google",
        "--dns-google-credentials",credentials,"--cert-name",name,
        "--config-dir",str(ROOT/"config"),"--work-dir",str(ROOT/"work"),
        "--logs-dir",str(ROOT/"logs"),"--domains",name,"--keep-until-expiring"]

def main():
    p=argparse.ArgumentParser()
    for field in ("name","domain","server","email","credentials"):
        p.add_argument("--"+field,required=True)
    p.add_argument("--confirm",required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="ISSUE_CERTIFICATE":
        p.error("root and explicit issuance confirmation required")
    try:
        trusted("/usr/bin/certbot")
        credentials=trusted(a.credentials,True)
        args=command(a.name,a.domain,a.server,a.email,credentials)
        os.umask(0o077)
        for directory in (ROOT,ROOT/"config",ROOT/"work",ROOT/"logs"):
            directory.mkdir(mode=0o700,parents=True,exist_ok=True)
            for parent in [directory]+list(directory.parents):
                st=parent.lstat()
                if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
                    raise ValueError("unsafe ACME directory")
            if directory.stat().st_mode & 0o077:
                raise ValueError("ACME state must be private")
        result=subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            timeout=600,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","HOME":"/root"})
        if result.returncode:
            raise ValueError("issuance failed")
        print("ACME_ISSUANCE=completed_unverified")
        return 0
    except (OSError,ValueError,subprocess.SubprocessError):
        print("ACME_ISSUANCE=failed")
        return 1

if __name__=="__main__":
    raise SystemExit(main())
