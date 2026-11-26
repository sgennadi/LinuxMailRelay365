#!/usr/bin/env python3
"""Create a validated renewal profile without replacing an existing profile."""
import argparse
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
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="CREATE_RENEWAL_PROFILE":
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
            os.link(tmp,str(profile.PROFILE))
            d=os.open(str(root),os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(d)
            finally: os.close(d)
        finally:
            os.unlink(tmp)
    print("RENEWAL_PROFILE=created")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
