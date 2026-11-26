"""Internal durable transaction journal for SMTP TLS activation."""
import os
import stat
import json
import fcntl
import tempfile
import re
from contextlib import contextmanager
from pathlib import Path

GEN=re.compile(r"candidate-[a-f0-9]{64}")

@contextmanager
def deployment_lock(root):
    root=Path(root)
    for p in [root]+list(root.parents):
        st=p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe deployment directory")
    fd=os.open(str(root/"deployment.lock"),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o077 or st.st_nlink!=1:
            raise ValueError("unsafe lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)

def sync(root):
    fd=os.open(str(root),os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def record(root,previous,candidate,phase):
    """Caller holds deployment_lock. No key or certificate data in journal."""
    root=Path(root)
    if previous is not None and not GEN.fullmatch(previous):
        raise ValueError("invalid previous generation")
    if not GEN.fullmatch(candidate) or phase not in ("prepared","switched","verified","rollback_required","rolled_back"):
        raise ValueError("invalid transaction")
    fd,path=tempfile.mkstemp(prefix=".journal-",dir=str(root))
    try:
        with os.fdopen(fd,"w") as f:
            json.dump(dict(version=1,previous=previous,candidate=candidate,phase=phase),f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(path,str(root/"deployment.json"))
        sync(root)
    finally:
        if os.path.exists(path):
            os.unlink(path)
