"""Restore candidate contexts before switching active SMTP TLS generation."""
import os
import subprocess
from pathlib import Path

def prepare(root,name,gen,trusted):
    gen.validate(root,name)
    if not Path("/sys/fs/selinux/enforce").exists():
        if Path("/sys/fs/selinux").is_mount():
            raise RuntimeError("SELinux mode unknown")
        return "not_detected"
    env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"}
    mode=subprocess.check_output([trusted("/usr/sbin/getenforce")],env=env,timeout=10).strip()
    if mode not in (b"Enforcing",b"Permissive"):
        raise RuntimeError("SELinux mode inconsistent")
    paths=[root/name]+[root/name/x for x in ("client-chain.pem","fullchain.pem","key.pem")]
    subprocess.check_call([trusted("/usr/sbin/restorecon")]+[str(x) for x in paths],env=env,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    match=trusted("/usr/sbin/matchpathcon")
    for path in paths:
        expected=subprocess.check_output([match,"-n",str(path)],env=env,timeout=10).strip()
        if os.getxattr(str(path),"security.selinux").rstrip(b"\x00")!=expected:
            raise RuntimeError("candidate SELinux context mismatch")
    return "contexts_verified"
