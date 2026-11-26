#!/usr/bin/env python3
"""Preview ACME renewal test; refuse configured hooks before running dry-run."""
import argparse
import fcntl
import stat
import importlib.util
import json
import os
import subprocess
from pathlib import Path
def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--confirm",required=True)
    mode=p.add_mutually_exclusive_group()
    mode.add_argument("--live",action="store_true")
    mode.add_argument("--force",action="store_true")
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!=("FORCE_ACME_RENEWAL" if a.force else "RUN_ACME_RENEWAL" if a.live else "TEST_ACME_RENEWAL"):
        p.error("root and explicit confirmation required")
    root=Path("/etc/postfix/lmr365-smtp-tls")
    for directory in [root]+list(root.parents):
        st=directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe renewal lock directory")
    fd=os.open(str(root/"acme-renewal.lock"),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o077:
            raise ValueError("unsafe renewal lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return run_renewal(a)
    finally:
        os.close(fd)

def run_renewal(a):
    profile=load("smtp-tls-renewal-profile")
    profile.load()
    data=json.loads(profile.PROFILE.read_text())
    name=data["lineage"]
    base=profile.BASE
    conf=profile.trusted(base/"renewal"/(name+".conf"))
    if conf.stat().st_size>65536:
        raise ValueError("renewal configuration too large")
    authenticator=None
    for line in conf.read_text().splitlines():
        line=line.strip()
        if not line or line.startswith(("#",";","[")):
            continue
        key,sep,value=line.partition("=")
        if not sep:
            raise ValueError("unsupported renewal configuration syntax")
        if key.strip()=="authenticator":
            if authenticator is not None:
                raise ValueError("ambiguous authenticator")
            authenticator=value.strip()
        if "hook" in key.lower():
            raise ValueError("configured hooks require manual review")
    if (base/"cli.ini").exists():
        raise ValueError("custom global ACME configuration requires manual review")
    certbot=load("smtp-tls-postfix").trusted_binary("/usr/bin/certbot")
    env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","HOME":"/root"}
    if authenticator=="dns-route53":
        credentials=Path("/etc/postfix/lmr365-smtp-tls/aws-credentials")
        load("check-smtp-acme-credentials").inspect(authenticator,credentials)
        env.update(AWS_SHARED_CREDENTIALS_FILE=str(credentials),AWS_CONFIG_FILE="/dev/null",AWS_PROFILE="default",AWS_EC2_METADATA_DISABLED="true")
    result=subprocess.run([certbot,"renew"]+(["--force-renewal"] if a.force else [] if a.live else ["--dry-run"])+["--non-interactive","--no-directory-hooks",
        "--cert-name",name,"--config-dir",str(base),"--work-dir",str(base.parent/"work"),
        "--logs-dir",str(base.parent/"logs")],timeout=1800,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        env=env)
    print(json.dumps({"renewal_exit":result.returncode,"dry_run":not (a.live or a.force),"forced":a.force,"activation_requested":False}))
    if result.returncode==0 and (a.force or a.live):
        import sys
        activation=subprocess.run([sys.executable,str(Path(__file__).resolve().with_name("manage-smtp-tls-process-renewal.py")),"--profile","--confirm","PROCESS_RENEWED_TLS"],timeout=300)
        print(json.dumps({"activation_exit":activation.returncode,"exchange_acceptance":"unverified"}))
        return activation.returncode
    return result.returncode
if __name__=="__main__":
    raise SystemExit(main())
