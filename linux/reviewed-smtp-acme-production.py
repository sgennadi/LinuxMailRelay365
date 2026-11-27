#!/usr/bin/env python3
"""New production ACME evaluation lineage; never activates or stages Postfix."""
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

ROOT=Path("/var/lib/linuxmailrelay365/smtp-acme-evaluation")
PRODUCTION="https://acme-v02.api.letsencrypt.org/directory"
CONFIRM="ISSUE_PRODUCTION_FOR_EVALUATION"


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+".py"))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def directory(path,private=False):
    for parent in [path]+list(path.parents):
        st=parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe evaluation directory")
    if private and path.lstat().st_mode & 0o077:
        raise ValueError("evaluation directory is not private")


def reserve(name):
    # Called only after fresh preflight and an empty observed DNS baseline.
    # Never overwrite or automatically delete an uncertain issuance lineage.
    for path in (ROOT.parent,ROOT):
        directory(path.parent)
        path.mkdir(mode=0o700,exist_ok=True)
        directory(path,private=(path==ROOT))
    dest=ROOT/name
    dest.mkdir(mode=0o700)
    directory(dest,True)
    return dest


def command(req,root,certbot,challenge):
    adapter=load("issue-smtp-acme-"+req["provider"][4:])
    args=adapter.command(req["certificate_name"],req["accepted_domain"],PRODUCTION,
                         req["email"],req["credentials_path"])
    args[0]=certbot
    for flag,folder in (("--config-dir","config"),("--work-dir","work"),("--logs-dir","logs")):
        args[args.index(flag)+1]=str(root/folder)
    args.remove("--keep-until-expiring")
    args.extend(["--config","/dev/null","--no-directory-hooks"])
    env=dict(challenge.ENV,HOME=str(root))
    if req["provider"]=="dns-route53":
        env.update(AWS_SHARED_CREDENTIALS_FILE=req["credentials_path"],AWS_CONFIG_FILE="/dev/null",
                   AWS_PROFILE="default",AWS_EC2_METADATA_DISABLED="true")
    return args,env


def lineage(root,name):
    live=root/"config"/"live"/name
    archive=root/"config"/"archive"/name
    directory(root,True)
    directory(live)
    directory(archive)
    paths={}
    versions=set()
    for label in ("cert","chain","privkey"):
        pointer=live/(label+".pem")
        st=pointer.lstat()
        if not stat.S_ISLNK(st.st_mode) or st.st_uid!=0:
            raise ValueError("unsafe lineage pointer")
        target=pointer.resolve(strict=True)
        match=re.fullmatch(label+r"([1-9][0-9]*)\.pem",target.name)
        if target.parent!=archive or not match:
            raise ValueError("unexpected lineage target")
        st=target.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o7022
                or (label=="privkey" and st.st_mode & 0o077) or not 0<st.st_size<=1048576):
            raise ValueError("unsafe lineage file")
        versions.add(match.group(1))
        paths[label]=str(target)
    if len(versions)!=1:
        raise ValueError("mixed lineage versions")
    return paths


def evaluate(root,name,checker=None):
    checker=checker or load("check-smtp-relay-certificate")
    paths=lineage(root,name)
    cert,chain,key=(paths[k] for k in ("cert","chain","privkey"))
    ca=checker.resolve_ca_bundle("auto")
    openssl=checker.openssl
    openssl("x509","-in",cert,"-noout","-checkend","0")
    openssl("verify","-verify_hostname",name,"-CAfile",ca,"-untrusted",chain,cert)
    if openssl("x509","-in",cert,"-pubkey","-noout").strip()!=openssl("pkey","-in",key,"-passin","pass:","-pubout").strip():
        raise ValueError("certificate key mismatch")
    fingerprint=openssl("x509","-in",cert,"-noout","-fingerprint","-sha256").decode("ascii").strip()
    match=re.fullmatch(r"[^=\n]+=([A-Fa-f0-9]{2}(?::[A-Fa-f0-9]{2}){31})",fingerprint)
    if not match:
        raise ValueError("unrecognized certificate fingerprint")
    extensions=openssl("x509","-in",cert,"-noout","-ext","extendedKeyUsage").decode("ascii")
    eku=re.search(r"X509v3 Extended Key Usage:[^\n]*\n([^\n]+)",extensions)
    explicit=bool(eku and any(x.strip() in ("TLS Web Client Authentication","1.3.6.1.5.5.7.3.2") for x in eku.group(1).split(",")))
    purpose="passed"
    try:
        openssl("verify","-purpose","sslclient","-CAfile",ca,"-untrusted",chain,cert)
    except (OSError,subprocess.SubprocessError):
        purpose="refused_or_unverified"
    return dict(certificate_sha256=match.group(1).replace(":","").lower(),client_auth_eku="explicit" if explicit else "not_explicit",
                local_sslclient=purpose,local_chain_name_key_verified=True)


def execute(envelope,reviewer=None,challenge=None,runner=subprocess.run,allocate=reserve,inspect=evaluate,
            observe=None,trusted=None,identity=None,expected_identity=None):
    reviewer=reviewer or load("review-smtp-acme-issuance")
    challenge=challenge or load("reviewed-smtp-acme-challenge")
    if (not isinstance(envelope,dict) or set(envelope)!={"request","confirm","review_sha256"}
            or envelope["confirm"]!=CONFIRM or not isinstance(envelope["review_sha256"],str)
            or not re.fullmatch(r"[a-f0-9]{64}",envelope["review_sha256"])):
        raise ValueError("explicit production confirmation required")
    req,plan=reviewer.normalize(envelope["request"])
    if req["environment"]!="production":
        raise ValueError("production only")
    report=dict(version=1,status="refused",accepted_domain=req["accepted_domain"],
                certificate_name=req["certificate_name"],provider=req["provider"],ca_directory=PRODUCTION,
                review_sha256=envelope["review_sha256"],attempted=False,state_reserved=False,
                certificate_issued=False,local_chain_name_key_verified=False,local_sslclient="unverified",
                client_auth_eku="unverified",certificate_sha256=None,evaluation_path=None,
                txt_cleanup_verified=False,txt_snapshot={"status":"unverified","txt_cleanup_verified":False},
                postfix_modified=False,activation_supported=False,exchange_acceptance_verified=False)
    before=None
    try:
        identity=identity or challenge.credential_identity
        stamp=identity(req["credentials_path"])
        if expected_identity is not None and stamp!=expected_identity:
            return report
        fresh=reviewer.review(req)
        if (not fresh.get("local_preflight_passed") or fresh.get("review_sha256")!=envelope["review_sha256"]
                or identity(req["credentials_path"])!=stamp):
            return report
        trusted=trusted or load("smtp-tls-postfix").trusted_invocation
        certbot=trusted("/usr/bin/certbot")
        dig=trusted("/usr/bin/dig")
        observe=observe or (lambda:challenge.snapshot(dig,plan["challenge"]))
        before=observe()
        if before is None:
            report["status"]="baseline_unverified"
            return report
        if before:
            report["status"]="existing_txt_requires_review"
            return report
        try:
            root=allocate(req["certificate_name"])
        except FileExistsError:
            report["status"]="evaluation_exists"
            return report
        report.update(state_reserved=True,evaluation_path=str(root))
        args,env=command(req,root,certbot,challenge)
        if identity(req["credentials_path"])!=stamp:
            return report
        report["attempted"]=True
        result=runner(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600,env=env)
        if result.returncode:
            report["status"]="failed"
            return report
        report["status"]="issued_unverified"
        # A zero exit alone is not proof of readable certificate material.
        report.update(inspect(root,req["certificate_name"]))
        report.update(status="evaluation_complete",certificate_issued=True)
    except Exception:
        if report["attempted"] and report["status"]!="issued_unverified":
            report["status"]="outcome_unverified"
    finally:
        if report["attempted"]:
            try:
                report["txt_snapshot"]=load("check-smtp-acme-txt-cleanup").compare(before,observe())
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
        # Same lock as the reviewed staging operation; other ACME clients
        # and hosts must be excluded by the operator.
        import fcntl
        directory(Path("/run"))
        fd=os.open("/run/lmr365-acme-staging-challenge.lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o7077:
            raise ValueError("unsafe ACME lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        envelope=json.loads(raw)
        if not isinstance(envelope,dict):
            raise ValueError("invalid envelope")
        token=envelope.pop("staging_receipt",None)
        if set(envelope)!={"request","confirm","review_sha256"} or envelope["confirm"]!=CONFIRM:
            raise ValueError("explicit production confirmation required")
        reviewer=load("review-smtp-acme-issuance")
        req,_=reviewer.normalize(envelope["request"])
        if req["environment"]!="production":
            raise ValueError("production only")
        challenge=load("reviewed-smtp-acme-challenge")
        stamp=challenge.credential_identity(req["credentials_path"])
        load("smtp-acme-staging-receipt").consume(req,stamp,token)
        print(json.dumps(execute(envelope,reviewer=reviewer,challenge=challenge,
                                 expected_identity=stamp),sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"version":1,"status":"refused","attempted":False}))
        return 1
    finally:
        if fd is not None:
            os.close(fd)


if __name__=="__main__":
    raise SystemExit(main())
