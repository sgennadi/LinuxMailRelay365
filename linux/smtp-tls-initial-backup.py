"""Internal initial TLS configuration backup primitive."""
import hashlib
import os
import stat
import json
import tempfile
from pathlib import Path

def backup(root, source=Path("/etc/postfix/main.cf")):
    root=Path(root)
    for p in [root]+list(root.parents):
        st=p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe backup directory")
    if root.stat().st_mode & 0o077:
        raise ValueError("backup directory must be private")
    fd=os.open(str(source),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe configuration")
        data=f.read(8388609)
        if len(data)>8388608:
            raise ValueError("configuration too large")
    dest=Path(tempfile.mkdtemp(prefix="initial-backup-",dir=str(root)))
    meta={"sha256":hashlib.sha256(data).hexdigest(),"mode":stat.S_IMODE(st.st_mode),"uid":st.st_uid,"gid":st.st_gid}
    for name,content in (("main.cf",data),("manifest.json",json.dumps(meta).encode("ascii"))):
        with (dest/name).open("xb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
    for p in (dest,root):
        fd=os.open(str(p),os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    return dest

def verify(dest):
    dest=Path(dest)
    meta=json.loads((dest/"manifest.json").read_text())
    data=(dest/"main.cf").read_bytes()
    if hashlib.sha256(data).hexdigest()!=meta["sha256"]:
        raise ValueError("backup digest mismatch")
    return data,meta
