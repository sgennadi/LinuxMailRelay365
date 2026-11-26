#!/usr/bin/env python3
"""Stage a validated certificate/key pair without changing Postfix."""
import argparse
import hashlib
import importlib.util
import os
import stat
import tempfile
from pathlib import Path

ROOT=Path("/etc/postfix/lmr365-smtp-tls")

def stage(cert,chain,key,name,ca):
    if os.geteuid()!=0:
        raise ValueError("root required")
    os.umask(0o077)
    ROOT.mkdir(mode=0o700,exist_ok=True)
    for p in [ROOT]+list(ROOT.parents):
        st=p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe destination")
    if ROOT.stat().st_mode & 0o077:
        raise ValueError("private directory required")
    spec=importlib.util.spec_from_file_location("checker",str(Path(__file__).with_name("check-smtp-relay-certificate.py")))
    checker=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    with tempfile.TemporaryDirectory(dir=str(ROOT),prefix=".stage-") as tmp:
        tmp=Path(tmp)
        for source,label in ((cert,"cert.pem"),(chain,"chain.pem"),(key,"key.pem")):
            fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,"rb") as f:
                st=os.fstat(f.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022 or (label=="key.pem" and st.st_mode & 0o077):
                    raise ValueError("unsafe source")
                data=f.read(1048577)
                if not data or len(data)>1048576:
                    raise ValueError("invalid source size")
            (tmp/label).write_bytes(data)
        checker.inspect(str(tmp/"cert.pem"),str(tmp/"chain.pem"),name,ca,str(tmp/"key.pem"))
        bundle=(tmp/"cert.pem").read_bytes().rstrip()+b"\n"+(tmp/"chain.pem").read_bytes()
        fingerprint=hashlib.sha256(bundle).hexdigest()
        # Publish a complete immutable-by-convention generation, never overwrite.
        dest=ROOT/("candidate-"+fingerprint)
        dest.mkdir(mode=0o700)
        try:
            for label,data in (("fullchain.pem",bundle),("key.pem",(tmp/"key.pem").read_bytes())):
                with (dest/label).open("xb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
            for directory in (dest,ROOT):
                fd=os.open(str(directory),os.O_RDONLY|os.O_DIRECTORY)
                try: os.fsync(fd)
                finally: os.close(fd)
        except BaseException:
            for label in ("fullchain.pem","key.pem"):
                try: (dest/label).unlink()
                except FileNotFoundError: pass
            dest.rmdir()
            raise
        return dest.name

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for field in ("cert","chain","key","name","ca"):
        p.add_argument("--"+field,required=True)
    a=p.parse_args()
    try:
        print("STAGED="+stage(a.cert,a.chain,a.key,a.name,a.ca))
    except Exception:
        print("STAGING=refused")
        raise SystemExit(1)
