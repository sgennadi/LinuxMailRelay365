"""Durable initial configuration journal. Caller holds deployment lock."""
import os
import json
import re
import tempfile
from pathlib import Path

PHASES=("prepared","switched","verified","rollback_required","rolled_back")

def record(root,phase,backup,original,candidate,bootstrap_generation=None):
    root=Path(root)
    backup=Path(backup)
    if backup.parent!=root or not re.fullmatch(r"initial-backup-[a-zA-Z0-9_]+",backup.name):
        raise ValueError("invalid backup reference")
    if phase not in PHASES or not all(re.fullmatch(r"[a-f0-9]{64}",v) for v in (original,candidate)):
        raise ValueError("invalid journal state")
    if bootstrap_generation is not None and not re.fullmatch(r"candidate-[a-f0-9]{64}",bootstrap_generation):
        raise ValueError("invalid bootstrap generation")
    state=dict(version=1,phase=phase,backup=backup.name,
               original_sha256=original,candidate_sha256=candidate)
    if bootstrap_generation is not None:
        state["bootstrap_generation"]=bootstrap_generation
    fd,tmp=tempfile.mkstemp(prefix=".initial-journal-",dir=str(root))
    try:
        with os.fdopen(fd,"w") as f:
            json.dump(state,f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp,str(root/"initial-deployment.json"))
        fd=os.open(str(root),os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def recover(root,state,read,restore,check,reload,write):
    import hashlib
    if state.get("version")!=1 or state.get("phase") not in PHASES:
        raise ValueError("unknown initial transaction")
    original=state["original_sha256"]
    candidate=state["candidate_sha256"]
    name=state["backup"]
    if not re.fullmatch(r"initial-backup-[a-zA-Z0-9_]+",name) or not all(re.fullmatch(r"[a-f0-9]{64}",v) for v in (original,candidate)):
        raise ValueError("invalid journal")
    backup=Path(root)/name
    current=hashlib.sha256(read()).hexdigest()
    if state["phase"] in ("verified","rolled_back"):
        if current!=(candidate if state["phase"]=="verified" else original):
            raise ValueError("configuration drift")
        return "unchanged"
    if current not in (original,candidate):
        raise ValueError("unexpected configuration")
    write("rollback_required",backup,original,candidate)
    if current==candidate:
        restore(backup,candidate)
    if hashlib.sha256(read()).hexdigest()!=original:
        raise ValueError("restore verification failed")
    check()
    reload()
    write("rolled_back",backup,original,candidate)
    return "restored"
