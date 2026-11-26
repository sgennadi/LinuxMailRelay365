"""Conservative unit removal; caller holds ACME and deployment locks."""
import hashlib
import os
import stat
from pathlib import Path

def uninstall(source,target,plan,preview,assert_inactive,reload):
    if os.geteuid()!=0:
        raise ValueError("root required")
    target=Path(target)
    for directory in [target]+list(target.parents):
        st=directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe unit directory")
    if plan!=preview(source,target) or plan["conflict"]:
        raise ValueError("uninstall plan changed or conflicts exist")
    assert_inactive()
    removed=[]
    try:
        for unit in plan["units"]:
            if unit["status"]!="remove":
                continue
            path=target/unit["name"]
            st=path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
                raise ValueError("unsafe unit")
            data=path.read_bytes()
            if hashlib.sha256(data).hexdigest()!=unit["sha256"]:
                raise ValueError("unit changed")
            path.unlink()
            removed.append((path,data,stat.S_IMODE(st.st_mode)))
        sync(target)
        reload()
    except Exception:
        for path,data,mode in removed:
            fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
            with os.fdopen(fd,"wb") as f:
                f.write(data)
                os.fchmod(f.fileno(),mode)
                f.flush()
                os.fsync(f.fileno())
        sync(target)
        reload()
        raise
    return [str(p) for p,_,_ in removed]

def sync(path):
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
