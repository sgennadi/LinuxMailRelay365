"""Restore candidate contexts before switching active SMTP TLS generation."""
import os
import stat
import re
import subprocess
from pathlib import Path

def context(value):
    fields=value.split(b":",3)
    if len(fields)!=4 or any(not re.fullmatch(rb"[A-Za-z0-9_]+", part) for part in fields[:3]) \
            or not re.fullmatch(rb"[A-Za-z0-9_.:,-]+", fields[3]):
        raise ValueError("unrecognized SELinux context")
    return fields

def private_identity(path,directory=False):
    st=path.lstat()
    expected_kind=stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_kind(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o077 \
            or (not directory and st.st_nlink!=1):
        raise ValueError("unsafe managed SELinux target")
    return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink)

def restore_candidate_contexts(root,name,gen,trusted,env):
    # The generation has already been validated; repeat before any relabel.
    gen.validate(root,name)
    private_identity(root,True)
    paths=[root/name]+[root/name/x for x in ("client-chain.pem","fullchain.pem","key.pem")]
    match=trusted("/usr/sbin/matchpathcon")
    restore=trusted("/usr/sbin/restorecon")
    def observe(path):
        identity=private_identity(path,path==root/name)
        expected=subprocess.check_output([match,"-n",str(path)],env=env,timeout=10).strip()
        actual=os.getxattr(str(path),"security.selinux",follow_symlinks=False).rstrip(b"\x00")
        expected_fields,actual_fields=context(expected),context(actual)
        # Never automatically change an MLS/MCS range, even on staged files.
        if expected_fields[3]!=actual_fields[3]:
            raise ValueError("SELinux range mismatch requires manual review")
        return identity,expected,actual
    before={path:observe(path) for path in paths}
    for path,(identity,expected,actual) in before.items():
        if observe(path)!=(identity,expected,actual):
            raise ValueError("SELinux target changed during preparation")
        if actual!=expected:
            # Restore full policy-default identity, not just the type.
            # Scope is exactly one private candidate, no recursion or symlinks.
            subprocess.check_call([restore,"-F",str(path)],env=env,timeout=30,
                                  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for path,(identity,expected,_) in before.items():
        current,new_expected,actual=observe(path)
        if current!=identity or new_expected!=expected or actual!=expected:
            raise RuntimeError("candidate SELinux context mismatch")
    gen.validate(root,name)

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
    restore_candidate_contexts(root,name,gen,trusted,env)
    if subprocess.check_output([trusted("/usr/sbin/getenforce")],env=env,timeout=10).strip()!=mode:
        raise RuntimeError("SELinux mode changed")
    return "contexts_verified"
