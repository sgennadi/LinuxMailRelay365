"""System Postfix adapter for managed SMTP TLS renewal."""
import os
import stat
import subprocess
from pathlib import Path

EXPECTED="/etc/postfix/lmr365-smtp-tls/active/client-chain.pem"

def trusted_binary(path):
    p=Path(path).resolve(strict=True)
    for item in [p]+list(p.parents):
        st=item.stat()
        if st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("untrusted executable")
    if not stat.S_ISREG(p.stat().st_mode) or not os.access(str(p),os.X_OK):
        raise ValueError("invalid executable")
    return str(p)

def trusted_invocation(path):
    """Validate the executable but preserve its invocation name.

    SELinux tools can be symlinked multi-call binaries (restorecon/setfiles).
    Resolving argv[0] changes their behavior. Keep the caller's absolute
    path after checking both the lexical path and resolved executable.
    """
    requested=Path(path)
    if not requested.is_absolute() or ".." in requested.parts:
        raise ValueError("absolute trusted invocation required")
    for item in [requested]+list(requested.parents):
        st=item.lstat()
        if st.st_uid!=0 or (not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022):
            raise ValueError("untrusted invocation path")
        if item!=requested:
            target=item.stat()
            if not stat.S_ISDIR(target.st_mode) or target.st_uid!=0 or target.st_mode & 0o022:
                raise ValueError("untrusted invocation directory")
    trusted_binary(str(requested))
    return str(requested)

class Postfix:
    def __init__(self):
        if os.geteuid()!=0:
            raise ValueError("root required")
        self.postfix=trusted_binary("/usr/sbin/postfix")
        self.postconf=trusted_binary("/usr/sbin/postconf")

    def run(self,binary,*args):
        result=subprocess.run([binary]+list(args),stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=60,
            env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
        if result.returncode:
            raise RuntimeError("Postfix command failed: "+args[0])
        return result.stdout.decode("utf-8","strict").strip()

    def verify_managed(self):
        if self.run(self.postconf,"-h","config_directory")!="/etc/postfix":
            raise ValueError("unsupported configuration directory")
        if self.run(self.postconf,"-h","smtp_tls_chain_files")!=EXPECTED:
            raise ValueError("SMTP TLS chain is not managed")
        if self.run(self.postconf,"-h","multi_instance_directories"):
            raise ValueError("multi-instance deployment requires manual review")
        overrides=self.run(self.postconf,"-P")
        for line in overrides.splitlines():
            if "/smtp_tls_" in line or "/smtp_use_tls" in line or "/smtp_enforce_tls" in line:
                raise ValueError("service TLS overrides require manual review")

    def check(self):
        self.verify_managed()
        self.run(self.postfix,"check")

    def reload(self):
        self.verify_managed()
        self.run(self.postfix,"status")
        self.run(self.postfix,"reload")
