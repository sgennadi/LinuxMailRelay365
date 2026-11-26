#!/usr/bin/env python3
"""Bounded, read-only inventory of standard ACME certificate locations."""
import json
import os
import stat
from pathlib import Path
import subprocess

LIVE=Path("/etc/letsencrypt/live")
ARCHIVE=Path("/etc/letsencrypt/archive")

def trusted_file(path, lineage, secret=False):
    resolved=path.resolve(strict=True)
    expected=(ARCHIVE/lineage).resolve(strict=True)
    if resolved.parent != expected:
        raise ValueError("unexpected certificate location")
    for parent in [resolved]+list(resolved.parents):
        st=parent.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("untrusted ownership or permissions")
    st=resolved.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > 1048576:
        raise ValueError("invalid file")
    if secret and st.st_mode & 0o077:
        raise ValueError("private key permissions")
    return str(resolved)

def inventory():
    result=[]
    if not LIVE.is_dir():
        return result
    for directory in sorted(LIVE.iterdir())[:128]:
        if directory.is_symlink() or not directory.is_dir():
            continue
        try:
            cert=trusted_file(directory/"cert.pem",directory.name)
            chain=trusted_file(directory/"chain.pem",directory.name)
            key=trusted_file(directory/"privkey.pem",directory.name,True)
            metadata=subprocess.check_output(
                ["/usr/bin/openssl","x509","-in",cert,"-noout",
                 "-subject","-issuer","-dates","-fingerprint","-sha256"],
                stderr=subprocess.DEVNULL,timeout=10).decode("utf-8")
            result.append(dict(lineage=directory.name,certificate=cert,
                chain=chain,key_path=key,metadata=metadata,
                eligibility="unverified",renewal="unverified"))
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
            result.append(dict(lineage=directory.name,eligibility="unverified",
                               status="inspection_refused"))
    return result

if __name__=="__main__":
    if os.geteuid()!=0:
        raise SystemExit("root required")
    print(json.dumps({"certificates":inventory(),"apply_supported":False}))
