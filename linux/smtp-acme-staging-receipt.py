"""Single-use, boot-local staging evidence. Caller holds the shared ACME lock."""
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path

PATH=Path("/run/lmr365-acme-staging-receipt.json")
TTL=900


def binding(req,stamp):
    return hashlib.sha256(json.dumps({"request":dict(req,environment="production"),
        "credential_identity":list(stamp)},sort_keys=True,separators=(",",":")).encode()).hexdigest()


def clear(path=PATH):
    # Caller checks /run and holds the common lock. Never follow a link.
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def issue(req,stamp,path=PATH,clock=time.monotonic):
    token=secrets.token_hex(32)
    data={"version":1,"token":token,"binding":binding(req,stamp),"expires":clock()+TTL}
    clear(path)
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as stream:
        os.fchmod(stream.fileno(),0o600)
        json.dump(data,stream,allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    return token


def consume(req,stamp,token,path=PATH,clock=time.monotonic):
    if not isinstance(token,str) or not re.fullmatch(r"[a-f0-9]{64}",token):
        raise ValueError("staging evidence required")
    fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as stream:
        st=os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o7077:
            raise ValueError("unsafe staging evidence")
        raw=stream.read(4097)
    if len(raw)>4096:
        raise ValueError("invalid staging evidence")
    data=json.loads(raw)
    now=clock()
    if (set(data)!={"version","token","binding","expires"} or data["version"]!=1
            or not isinstance(data["token"],str) or not isinstance(data["binding"],str)
            or type(data["expires"]) not in (float,int) or not now<data["expires"]<=now+TTL
            or not hmac.compare_digest(data["token"],token)
            or not hmac.compare_digest(data["binding"],binding(req,stamp))):
        raise ValueError("staging evidence expired or changed")
    # Consume before any production request, including a failed attempt.
    path.unlink()
