#!/usr/bin/env python3
"""Explicit issuance dispatcher; never activates a certificate."""
import argparse
import json
import os
import subprocess
from pathlib import Path

PROVIDERS={"dns-azure":"azure","dns-cloudflare":"cloudflare","dns-google":"google","dns-route53":"route53","dns-rfc2136":"rfc2136"}

def command(provider, name, domain, server, email, credentials):
    adapter=Path(__file__).resolve().with_name("issue-smtp-acme-"+PROVIDERS[provider]+".py")
    return ["/usr/bin/python3",str(adapter),"--name",name,"--domain",domain,
            "--server",server,"--email",email,"--credentials",credentials,
            "--confirm","ISSUE_CERTIFICATE"]

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--provider",choices=sorted(PROVIDERS),required=True)
    for field in ("name","domain","server","email","credentials","confirm"):
        p.add_argument("--"+field,required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="ISSUE_CERTIFICATE":
        p.error("root and explicit confirmation required")
    try:
        probe=subprocess.run(["/usr/bin/python3",str(Path(__file__).resolve().with_name("probe-smtp-acme-plugins.py"))],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=75)
        if probe.returncode or not json.loads(probe.stdout.decode("utf-8")).get("providers",{}).get(a.provider,{}).get("registered"):
            raise ValueError("plugin unavailable")
        result=subprocess.run(command(a.provider,a.name,a.domain,a.server,a.email,a.credentials),
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=660)
        ok=result.returncode==0 and b"ACME_ISSUANCE=completed_unverified" in result.stdout.splitlines()
        print(json.dumps(dict(version=1,status="completed_unverified" if ok else "failed",
            provider=a.provider,certificate_validated=False,postfix_modified=False,exchange_acceptance_verified=False)))
        return 0 if ok else 1
    except (OSError,ValueError,subprocess.SubprocessError):
        print(json.dumps(dict(version=1,status="failed",postfix_modified=False)))
        return 1
if __name__=="__main__":
    raise SystemExit(main())
