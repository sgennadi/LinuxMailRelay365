"""Internal initial TLS configuration backup primitive."""
import hashlib
import os
import stat
import json
import re
import tempfile
from pathlib import Path

def private_directory(path):
    path=Path(path)
    for item in [path]+list(path.parents):
        st=item.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe backup directory")
    if path.lstat().st_mode & 0o077:
        raise ValueError("backup directory must be private")


def read_private(path,limit):
    path=Path(path)
    private_directory(path.parent)
    fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        st=os.fstat(f.fileno())
        if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1
                or st.st_mode & 0o7077 or st.st_size>limit):
            raise ValueError("unsafe private backup file")
        data=f.read(limit+1)
        if len(data)>limit:
            raise ValueError("backup file too large")
        return data


def strict_object(pairs):
    value={}
    for key,item in pairs:
        if key in value:
            raise ValueError("duplicate backup or journal field")
        value[key]=item
    return value


def metadata(meta):
    if (not isinstance(meta,dict) or set(meta)!={"sha256","uid","gid","mode"}
            or not isinstance(meta["sha256"],str) or not re.fullmatch(r"[a-f0-9]{64}",meta["sha256"])
            or type(meta["uid"]) is not int or meta["uid"]!=0
            or type(meta["gid"]) is not int or not 0<=meta["gid"]<2**32-1
            or type(meta["mode"]) is not int or not 0<=meta["mode"]<=0o777 or meta["mode"] & 0o022):
        raise ValueError("invalid backup metadata")
    return meta


def backup(root, source=Path("/etc/postfix/main.cf")):
    root=Path(root)
    private_directory(root)
    fd=os.open(str(source),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o7022:
            raise ValueError("unsafe configuration")
        data=f.read(8388609)
        if len(data)>8388608:
            raise ValueError("configuration too large")
    dest=Path(tempfile.mkdtemp(prefix="initial-backup-",dir=str(root)))
    meta={"sha256":hashlib.sha256(data).hexdigest(),"mode":stat.S_IMODE(st.st_mode),"uid":st.st_uid,"gid":st.st_gid}
    for name,content in (("main.cf",data),("manifest.json",json.dumps(meta).encode("ascii"))):
        fd=os.open(str(dest/name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as f:
            os.fchmod(f.fileno(),0o600)
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
    meta=metadata(json.loads(read_private(dest/"manifest.json",16384),object_pairs_hook=strict_object))
    data=read_private(dest/"main.cf",8388608)
    if hashlib.sha256(data).hexdigest()!=meta["sha256"]:
        raise ValueError("backup digest mismatch")
    return data,meta

def verify_for_journal(dest,original,candidate,build):
    if (not all(isinstance(v,str) and re.fullmatch(r"[a-f0-9]{64}",v) for v in (original,candidate))
            or original==candidate):
        raise ValueError("invalid journal configuration hashes")
    data,meta=verify(dest)
    if meta["sha256"]!=original or hashlib.sha256(build(data)).hexdigest()!=candidate:
        raise ValueError("backup differs from the journaled TLS-only change")
    return data,meta

def restore(dest, expected_current_sha256, target=Path("/etc/postfix/main.cf")):
    """Caller holds deployment lock; external editors must be excluded separately."""
    data,meta=verify(dest)
    replace_config(data,expected_current_sha256,target,meta)


def replace_config(data, expected_current_sha256, target=Path("/etc/postfix/main.cf"), meta=None):
    """Atomically replace configuration; caller holds deployment lock."""
    target=Path(target)
    if not isinstance(data,bytes) or len(data)>8388608:
        raise ValueError("invalid candidate size")
    for p in target.parents:
        st=p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe configuration directory")
    fd=os.open(str(target),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o7022:
            raise ValueError("unsafe configuration")
        current=f.read(8388609)
        if len(current)>8388608 or hashlib.sha256(current).hexdigest()!=expected_current_sha256:
            raise ValueError("configuration changed; manual recovery required")
        attrs={name:os.getxattr(f.fileno(),name) for name in os.listxattr(f.fileno())}
    if meta is None:
        meta={"uid":st.st_uid,"gid":st.st_gid,"mode":stat.S_IMODE(st.st_mode)}
    if meta["uid"]!=0 or meta["mode"] & 0o7022:
        raise ValueError("unsafe backup metadata")
    fd,tmp=tempfile.mkstemp(prefix=".lmr365-restore-",dir=str(target.parent))
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(data)
            f.flush()
            os.fchown(f.fileno(),meta["uid"],meta["gid"])
            os.fchmod(f.fileno(),meta["mode"])
            for name,value in attrs.items():
                os.setxattr(f.fileno(),name,value)
            os.fsync(f.fileno())
        latest=target.lstat()
        if (latest.st_dev,latest.st_ino,latest.st_mtime_ns,latest.st_ctime_ns)!=(st.st_dev,st.st_ino,st.st_mtime_ns,st.st_ctime_ns):
            raise ValueError("configuration changed during restore")
        os.replace(tmp,str(target))
        fd=os.open(str(target.parent),os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
