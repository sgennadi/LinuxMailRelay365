"""Guarded unit upgrade. Caller holds locks and verifies inactive services."""
import hashlib
import os
import stat
import tempfile
from pathlib import Path

def digest(data):
    return hashlib.sha256(data).hexdigest()

def publish(path,data,expected,mode=0o644):
    fd,tmp=tempfile.mkstemp(prefix=".lmr365-update-",dir=str(path.parent))
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(data)
            os.fchmod(f.fileno(),mode)
            f.flush()
            os.fsync(f.fileno())
        if expected is None:
            os.link(tmp,str(path))
        else:
            st=path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022 or digest(path.read_bytes())!=expected:
                raise ValueError("unit changed")
            os.replace(tmp,str(path))
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def sync(target):
    fd=os.open(str(target),os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def update(source,previous,target,plan,preview,assert_inactive,reload):
    if os.geteuid()!=0:
        raise ValueError("root required")
    source,previous,target=map(Path,(source,previous,target))
    for directory in [target]+list(target.parents):
        st=directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe target")
    if plan!=preview(source,previous,target) or plan["conflict"]:
        raise ValueError("update plan changed or conflicts exist")
    assert_inactive()
    changed=[]
    try:
        for u in plan["units"]:
            if u["status"] not in ("create","update"):
                continue
            path=target/u["name"]
            data=(source/u["name"]).read_bytes()
            if digest(data)!=u["sha256"]:
                raise ValueError("new package changed")
            old=None
            mode=0o644
            if u["status"]=="update":
                old=path.read_bytes()
                mode=stat.S_IMODE(path.lstat().st_mode)
                if digest(old)!=u["previous_sha256"]:
                    raise ValueError("old unit changed")
            publish(path,data,None if old is None else digest(old),mode)
            changed.append((path,old,u["sha256"],mode))
        sync(target)
        reload()
    except Exception:
        for path,old,expected,mode in reversed(changed):
            if old is None:
                if not stat.S_ISREG(path.lstat().st_mode) or digest(path.read_bytes())!=expected:
                    raise ValueError("unit changed during rollback")
                path.unlink()
            else:
                publish(path,old,expected,mode)
        sync(target)
        reload()
        raise
    return [str(x[0]) for x in changed]
