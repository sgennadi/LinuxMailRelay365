"""Read a root-owned renewal profile and resolve isolated ACME lineage files."""
import json
import os
import re
import stat
from pathlib import Path

BASE=Path("/var/lib/linuxmailrelay365/smtp-acme/config")
PROFILE=Path("/etc/postfix/lmr365-smtp-tls/renewal-profile.json")

def trusted(path,private=False):
    for p in [path]+list(path.parents):
        st=p.lstat()
        if st.st_uid!=0 or st.st_mode & 0o022 or stat.S_ISLNK(st.st_mode):
            raise ValueError("unsafe renewal path")
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or (private and st.st_mode & 0o077):
        raise ValueError("unsafe renewal file")
    return path

def load(profile=PROFILE,base=BASE):
    profile=trusted(Path(profile),True)
    if profile.stat().st_size>16384:
        raise ValueError("profile too large")
    data=json.loads(profile.read_text())
    if set(data)!=set(("version","lineage","domain","ca_file")) or data["version"]!=1:
        raise ValueError("invalid renewal profile")
    name=data["lineage"]
    domain=data["domain"]
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}",name) or ".." in name:
        raise ValueError("invalid lineage")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}",domain) or ".." in domain:
        raise ValueError("invalid domain")
    base=Path(base)
    archive=base/"archive"/name
    files={}
    versions=set()
    for label in ("cert","chain","privkey"):
        path=(base/"live"/name/(label+".pem")).resolve(strict=True)
        match=re.fullmatch(label+r"([0-9]+)\.pem",path.name)
        if path.parent!=archive or not match:
            raise ValueError("unexpected ACME archive target")
        versions.add(match.group(1))
        files[label]=str(trusted(path,label=="privkey"))
    if len(versions)!=1:
        raise ValueError("inconsistent ACME generation")
    ca=Path(data["ca_file"])
    if not ca.is_absolute():
        raise ValueError("absolute CA path required")
    files.update(domain=domain,ca_file=str(trusted(ca.resolve(strict=True))))
    return files
