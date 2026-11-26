"""Install approved unit files without overwriting existing files."""
import hashlib
import os
import stat
import tempfile
from pathlib import Path

def install(source,target,plan,preview,reload):
    if os.geteuid()!=0:
        raise ValueError("root required")
    source,target=Path(source),Path(target)
    for directory in [target]+list(target.parents):
        st=directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("untrusted target directory")
    if plan!=preview(source,target) or plan["conflict"]:
        raise ValueError("installation plan changed or conflicts exist")
    created=[]
    try:
        for unit in plan["units"]:
            if unit["status"]!="create":
                continue
            data=(source/unit["name"]).read_bytes()
            if hashlib.sha256(data).hexdigest()!=unit["sha256"]:
                raise ValueError("packaged unit changed")
            dst=target/unit["name"]
            fd,tmp=tempfile.mkstemp(prefix=".lmr365-",dir=str(target))
            try:
                with os.fdopen(fd,"wb") as f:
                    f.write(data)
                    os.fchmod(f.fileno(),0o644)
                    f.flush()
                    os.fsync(f.fileno())
                os.link(tmp,str(dst))
                created.append((dst,dst.lstat().st_ino))
            finally:
                os.unlink(tmp)
        sync(target)
        reload()
    except Exception:
        for dst,inode in reversed(created):
            if dst.lstat().st_ino!=inode:
                raise ValueError("unit changed during installation; manual recovery required")
            dst.unlink()
        sync(target)
        reload()
        raise
    return [str(p) for p,_ in created]

def sync(path):
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
