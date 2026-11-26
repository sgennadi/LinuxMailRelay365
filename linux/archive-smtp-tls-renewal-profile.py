#!/usr/bin/env python3
"""Archive a renewal profile after stopping scheduled renewal."""
import argparse
import fcntl
import hashlib
import importlib.util
import os
import stat
import subprocess
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--expected-sha",required=True)
    p.add_argument("--confirm",required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="ARCHIVE_RENEWAL_PROFILE":
        p.error("root and explicit confirmation required")
    profile=load("smtp-tls-renewal-profile")
    path=profile.trusted(profile.PROFILE,True)
    root=path.parent
    systemctl=load("smtp-tls-postfix").trusted_binary("/usr/bin/systemctl")
    def run(*args):
        return subprocess.run([systemctl]+list(args),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
    fd=os.open(str(root/"acme-renewal.lock"),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o077:
            raise ValueError("unsafe lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with load("smtp-tls-transaction").deployment_lock(root):
            for unit in ("linuxmailrelay365-smtp-acme-renew.timer","linuxmailrelay365-smtp-acme-renew.service"):
                r=run("show",unit,"--property=ActiveState","--value")
                if r.returncode or r.stdout.strip()!=b"inactive":
                    raise ValueError("stop renewal timer and service first")
            r=run("is-enabled","linuxmailrelay365-smtp-acme-renew.timer")
            if r.stdout.strip()!=b"disabled":
                raise ValueError("disable renewal timer first")
            data=profile.trusted(path,True).read_bytes()
            digest=hashlib.sha256(data).hexdigest()
            if digest!=a.expected_sha:
                raise ValueError("profile changed")
            archive=root/("renewal-profile-disabled-"+digest+".json")
            os.link(str(path),str(archive))
            d=os.open(str(root),os.O_RDONLY|os.O_DIRECTORY)
            try:
                os.fsync(d)
                path.unlink()
                os.fsync(d)
            finally: os.close(d)
        print("RENEWAL_PROFILE=archived")
        return 0
    finally: os.close(fd)
if __name__=="__main__":
    raise SystemExit(main())
