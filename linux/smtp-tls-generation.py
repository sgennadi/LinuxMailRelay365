#!/usr/bin/env python3
"""Atomic generation pointer primitive; not a Postfix deployment command."""
import os
import re
import stat
import uuid
from pathlib import Path

GEN=re.compile(r"candidate-[a-f0-9]{64}")

def validate(root,name):
    if not isinstance(name,str) or not GEN.fullmatch(name):
        raise ValueError("invalid generation")
    for p in [root]+list(root.parents)+[root/name]:
        st=p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe directory")
    for label in ("fullchain.pem","key.pem"):
        st=(root/name/label).lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o077 or not st.st_size:
            raise ValueError("unsafe generation file")

def current(root):
    try:
        name=os.readlink(str(root/"active"))
    except FileNotFoundError:
        return None
    validate(root,name)
    return name

def switch(root,name,expected):
    """Caller must hold the deployment lock and validate TLS before switching."""
    root=Path(root)
    validate(root,name)
    if current(root)!=expected:
        raise ValueError("active generation changed")
    tmp=root/(".active-"+uuid.uuid4().hex)
    try:
        os.symlink(name,str(tmp))
        os.replace(str(tmp),str(root/"active"))
        fd=os.open(str(root),os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    return expected
