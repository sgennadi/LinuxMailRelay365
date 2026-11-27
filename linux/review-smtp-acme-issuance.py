#!/usr/bin/env python3
"""Local ACME issuance readiness review. No DNS writes, issuance or activation."""
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PROVIDERS=("dns-azure","dns-cloudflare","dns-route53","dns-google","dns-rfc2136")
SERVERS={"staging":"https://acme-staging-v02.api.letsencrypt.org/directory",
         "production":"https://acme-v02.api.letsencrypt.org/directory"}
KEYS={"accepted_domain","certificate_name","provider","environment","email","credentials_path"}


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+".py"))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalize(req):
    if not isinstance(req,dict) or set(req)!=KEYS or any(not isinstance(v,str) for v in req.values()):
        raise ValueError("invalid request")
    plan=load("plan-smtp-certificate-acme").plan(req)
    if req["provider"] not in PROVIDERS or req["environment"] not in SERVERS:
        raise ValueError("unsupported provider or environment")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+%-]{0,63}@[A-Za-z0-9.-]{1,253}",req["email"]):
        raise ValueError("invalid contact email")
    load("plan-smtp-certificate-acme").dns(req["email"].rsplit("@",1)[1])
    path=req["credentials_path"]
    if not re.fullmatch(r"/[A-Za-z0-9_./-]{1,1023}",path) or str(Path(path))!=path or ".." in Path(path).parts:
        raise ValueError("invalid credential path")
    return dict(req,accepted_domain=plan["accepted_domain"],certificate_name=plan["certificate_name"]),plan


def plugins():
    result=subprocess.run(["/usr/bin/python3","-I","-B",str(Path(__file__).with_name("probe-smtp-acme-plugins.py"))],
                          stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=75)
    if result.returncode or len(result.stdout)>16384:
        return {"status":"probe_failed"}
    return json.loads(result.stdout)


def review(req,check=None,probe=plugins):
    req,plan=normalize(req)
    report=dict(version=1,status="local_review_complete",accepted_domain=req["accepted_domain"],
                certificate_name=req["certificate_name"],provider=req["provider"],
                environment=req["environment"],ca_directory=SERVERS[req["environment"]],
                challenge=plan["challenge"],credential_file="unverified",plugin="unverified",
                local_preflight_passed=False,api_permissions_verified=False,
                dns_ownership_verified=False,ca_client_tls_verified=False,
                accepted_domain_verified=False,issuance_supported=False,
                dns_modified=False,certificate_issued=False,postfix_modified=False)
    check=check or load("check-smtp-acme-credentials").inspect
    try:
        result=check(req["provider"],req["credentials_path"])
        if result.get("file_preflight_passed") is True and result.get("api_permissions_verified") is False:
            report["credential_file"]="local_structure_passed"
        else:
            report["credential_file"]="refused"
    except Exception:
        # Parser errors can include the original credential line. Never emit them.
        report["credential_file"]="refused"
    try:
        inventory=probe()
        if inventory.get("status")=="completed":
            registered=inventory.get("providers",{}).get(req["provider"],{}).get("registered")
            if type(registered) is bool:
                report["plugin"]="registered" if registered else "not_registered"
    except Exception:
        pass
    report["local_preflight_passed"]=(report["credential_file"]=="local_structure_passed" and report["plugin"]=="registered")
    # Review identifier, not an authorization or a credential-content hash.
    report["review_sha256"]=hashlib.sha256(json.dumps(report,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return report


def main():
    try:
        if os.geteuid()!=0:
            raise ValueError("root required")
        raw=sys.stdin.buffer.read(8193)
        if len(raw)>8192:
            raise ValueError("request too large")
        print(json.dumps(review(json.loads(raw)),sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"version":1,"status":"refused","issuance_supported":False,
                          "dns_modified":False,"certificate_issued":False,"postfix_modified":False}))
        return 1


if __name__=="__main__":
    raise SystemExit(main())
