#!/usr/bin/env python3
"""Restore an archived renewal profile without enabling the timer."""
import argparse
import hashlib
import importlib.util
import os
import re
from pathlib import Path
def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sha",required=True)
    p.add_argument("--confirm",required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="RESTORE_RENEWAL_PROFILE" or not re.fullmatch(r"[a-f0-9]{64}",a.sha):
        p.error("root, archive digest and confirmation required")
    profile=load("smtp-tls-renewal-profile")
    root=profile.PROFILE.parent
    with load("smtp-tls-transaction").deployment_lock(root):
        archive=profile.trusted(root/("renewal-profile-disabled-"+a.sha+".json"),True)
        if archive.stat().st_size>16384 or hashlib.sha256(archive.read_bytes()).hexdigest()!=a.sha:
            raise ValueError("archive digest mismatch")
        data=profile.load(archive)
        checker=load("check-smtp-relay-certificate")
        checker.inspect(data["cert"],data["chain"],data["domain"],data["ca_file"],data["privkey"])
        gen=load("smtp-tls-generation")
        load("smtp-tls-validate-generation").validate(root,gen.current(root),data["domain"],data["ca_file"],gen,checker)
        load("smtp-tls-postfix").Postfix().check()
        os.link(str(archive),str(profile.PROFILE))
        fd=os.open(str(root),os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    print("RENEWAL_PROFILE=restored; timer not enabled")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
