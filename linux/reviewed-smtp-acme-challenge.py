#!/usr/bin/env python3
"""Explicit isolated staging DNS-01 challenge. No production certificate or MTA changes."""
import fcntl
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

CONFIRM="TEST_PUBLIC_DNS_CHALLENGE"
STAGING="https://acme-staging-v02.api.letsencrypt.org/directory"
ENV={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"}


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+".py"))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_snapshot(raw,owner,kind):
    if len(raw)>262144:
        raise ValueError("oversized DNS response")
    lines=raw.decode("ascii","strict").splitlines()
    statuses=re.findall(r"\bstatus: (NOERROR|NXDOMAIN),","\n".join(lines))
    if len(statuses)!=1:
        raise ValueError("unverified DNS response")
    values=[]
    for line in lines:
        if not line.strip() or line.startswith(";"):
            continue
        fields=line.split(None,4)
        # Refuse aliases, unexpected answers, or a delegated challenge.
        if (len(fields)!=5 or fields[0].lower()!=owner.lower()+"."
                or not fields[1].isdigit() or fields[2]!="IN" or fields[3]!=kind):
            raise ValueError("unexpected DNS answer")
        values.append(fields[4])
    if len(values)>64 or (statuses[0]=="NXDOMAIN" and values):
        raise ValueError("ambiguous DNS response")
    return sorted(values)


def snapshot(dig,owner,runner=subprocess.run):
    try:
        for kind in ("CNAME","NS","TXT"):
            result=runner([dig,"-r","@1.1.1.1",owner+".",kind,"+noall","+comments","+answer",
                           "+time=3","+tries=1"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          env=ENV,timeout=6)
            if result.returncode:
                return None
            values=parse_snapshot(result.stdout,owner,kind)
            if kind=="TXT":
                return values
            if values:
                return None
    except (OSError,ValueError,subprocess.SubprocessError):
        return None


def credential_identity(path):
    st=Path(path).lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o7077
            or not 0<st.st_size<=65536):
        raise ValueError("unsafe credential file")
    return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_size,st.st_mtime_ns,st.st_ctime_ns)


def validate_envelope(envelope,reviewer):
    if (not isinstance(envelope,dict) or set(envelope)!={"request","confirm","review_sha256"}
            or envelope["confirm"]!=CONFIRM or not isinstance(envelope["review_sha256"],str)
            or not re.fullmatch(r"[a-f0-9]{64}",envelope["review_sha256"])):
        raise ValueError("explicit reviewed confirmation required")
    req,plan=reviewer.normalize(envelope["request"])
    if req["environment"]!="staging":
        raise ValueError("staging only")
    return req,plan


def execute(envelope,reviewer=None,snapshot_fn=None,runner=subprocess.run,identity=credential_identity,
            trusted=None,command=None):
    reviewer=reviewer or load("review-smtp-acme-issuance")
    req,plan=validate_envelope(envelope,reviewer)
    report=dict(version=1,status="refused",accepted_domain=req["accepted_domain"],
                certificate_name=req["certificate_name"],provider=req["provider"],
                ca_directory=STAGING,challenge=plan["challenge"],
                review_sha256=envelope["review_sha256"],attempted=False,
                dns_challenge_verified=False,txt_cleanup_verified=False,
                txt_snapshot={"status":"unverified","txt_cleanup_verified":False},
                production_certificate_modified=False,postfix_modified=False,
                exchange_acceptance_verified=False)
    before=None
    try:
        stamp=identity(req["credentials_path"])
        fresh=reviewer.review(req)
        if (not fresh.get("local_preflight_passed") or fresh.get("review_sha256")!=envelope["review_sha256"]
                or identity(req["credentials_path"])!=stamp):
            raise ValueError("local review changed")
        trusted=trusted or load("smtp-tls-postfix").trusted_invocation
        certbot=trusted("/usr/bin/certbot")
        dig=trusted("/usr/bin/dig")
        observe=snapshot_fn or (lambda: snapshot(dig,plan["challenge"]))
        before=observe()
        if before is None:
            report["status"]="baseline_unverified"
            return report
        # Existing TXT may be another in-progress validation. Do not
        # manipulate it or run a concurrent challenge on that owner.
        if before:
            report["status"]="existing_txt_requires_review"
            return report
        builder=command or load("plan-smtp-acme-challenge-test").command
        with tempfile.TemporaryDirectory(prefix="lmr365-acme-staging-",dir="/var/tmp") as root:
            env=dict(ENV,HOME=root)
            if req["provider"]=="dns-route53":
                env.update(AWS_SHARED_CREDENTIALS_FILE=req["credentials_path"],AWS_CONFIG_FILE="/dev/null",
                           AWS_PROFILE="default",AWS_EC2_METADATA_DISABLED="true")
            args=builder(req["provider"],req["certificate_name"],req["accepted_domain"],STAGING,
                         req["email"],req["credentials_path"],root)
            args[0]=certbot
            args.extend(["--config","/dev/null","--no-directory-hooks"])
            if identity(req["credentials_path"])!=stamp:
                raise ValueError("credential changed")
            report["attempted"]=True
            try:
                result=runner(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600,env=env)
                report["status"]="passed" if result.returncode==0 else "failed"
                report["dns_challenge_verified"]=result.returncode==0
            except (OSError,subprocess.SubprocessError):
                report["status"]="outcome_unverified"
    except Exception:
        if report["attempted"]:
            report["status"]="outcome_unverified"
    finally:
        if report["attempted"]:
            try:
                after=observe()
                report["txt_snapshot"]=load("check-smtp-acme-txt-cleanup").compare(before,after)
            except Exception:
                pass
    return report


def main():
    fd=None
    try:
        if os.geteuid()!=0:
            raise ValueError("root required")
        os.umask(0o077)
        raw=sys.stdin.buffer.read(12289)
        if len(raw)>12288:
            raise ValueError("request too large")
        envelope=json.loads(raw)
        st=Path("/run").lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe lock directory")
        fd=os.open("/run/lmr365-acme-staging-challenge.lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o7077:
            raise ValueError("unsafe staging lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(execute(envelope),sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"version":1,"status":"refused","attempted":False}))
        return 1
    finally:
        if fd is not None:
            os.close(fd)


if __name__=="__main__":
    raise SystemExit(main())
