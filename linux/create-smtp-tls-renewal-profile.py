#!/usr/bin/env python3
"""Create a validated renewal profile without replacing an existing profile."""
import argparse
import hashlib
import subprocess
import importlib.util
import json
import os
import tempfile
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def main():
    p=argparse.ArgumentParser()
    for field in ("lineage","domain","ca-file","confirm"):
        p.add_argument("--"+field,required=True)
    p.add_argument("--replace-sha")
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!=("EDIT_RENEWAL_PROFILE" if a.replace_sha else "CREATE_RENEWAL_PROFILE"):
        p.error("root and explicit confirmation required")
    profile=load("smtp-tls-renewal-profile")
    root=profile.PROFILE.parent
    with load("smtp-tls-transaction").deployment_lock(root):
        fd,tmp=tempfile.mkstemp(prefix=".renewal-profile-",dir=str(root))
        try:
            with os.fdopen(fd,"w") as f:
                json.dump(dict(version=1,lineage=a.lineage,domain=a.domain,ca_file=a.ca_file),f)
                f.flush()
                os.fsync(f.fileno())
            data=profile.load(Path(tmp))
            load("check-smtp-relay-certificate").inspect(data["cert"],data["chain"],data["domain"],data["ca_file"],data["privkey"])
            load("smtp-tls-postfix").Postfix().check()
            if a.replace_sha:
                old=profile.trusted(profile.PROFILE,True).read_bytes()
                digest=hashlib.sha256(old).hexdigest()
                if digest!=a.replace_sha:
                    raise ValueError("profile changed")
                systemctl=load("smtp-tls-postfix").trusted_binary("/usr/bin/systemctl")
                for unit in ("linuxmailrelay365-smtp-acme-renew.timer","linuxmailrelay365-smtp-acme-renew.service"):
                    r=subprocess.run([systemctl,"show",unit,"--property=ActiveState","--value"],stdout=subprocess.PIPE,timeout=30)
                    if r.returncode or r.stdout.strip()!=b"inactive":
                        raise ValueError("stop renewal first")
                r=subprocess.run([systemctl,"is-enabled","linuxmailrelay365-smtp-acme-renew.timer"],stdout=subprocess.PIPE,timeout=30)
                if r.stdout.strip()!=b"disabled":
                    raise ValueError("disable timer first")
                gen=load("smtp-tls-generation")
                load("smtp-tls-validate-generation").validate(root,gen.current(root),data["domain"],data["ca_file"],gen,load("check-smtp-relay-certificate"))
                archive=root/("renewal-profile-disabled-"+digest+".json")
                os.link(str(profile.PROFILE),str(archive))
                d=os.open(str(root),os.O_RDONLY|os.O_DIRECTORY)
                try: os.fsync(d)
                finally: os.close(d)
                os.replace(tmp,str(profile.PROFILE))
            else:
                os.link(tmp,str(profile.PROFILE))
            d=os.open(str(root),os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(d)
            finally: os.close(d)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
    print("RENEWAL_PROFILE="+("edited" if a.replace_sha else "created"))
    return 0
if __name__=="__main__":
    raise SystemExit(main())
