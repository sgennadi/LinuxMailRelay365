#!/usr/bin/env python3
"""Classify public DNS delegation evidence, never infer credentials."""
import argparse
import json
import re
import subprocess

def classify(names):
    hints=set()
    for name in names:
        n=name.lower().rstrip(".")
        if n.endswith(".ns.cloudflare.com"):
            hints.add("dns-cloudflare")
        elif re.search(r"\.azure-dns\.(com|net|org|info)$",n):
            hints.add("dns-azure")
        elif re.search(r"\.awsdns-[0-9]+\.(com|net|org|co\.uk)$",n):
            hints.add("dns-route53")
        elif n.endswith(".googledomains.com"):
            hints.add("dns-google")
        else:
            hints.add("unknown")
    return next(iter(hints)) if len(hints)==1 else "unknown"

def discover(domain,query):
    if len(domain)>253 or "." not in domain or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",x) for x in domain.split(".")):
        raise ValueError("invalid domain")
    labels=domain.split(".")
    for i in range(len(labels)-1):
        zone=".".join(labels[i:])
        names=query(zone)
        if names:
            return dict(zone=zone,nameservers=names,provider_hint=classify(names),
                        credentials_verified=False,challenge_delegation_verified=False)
    return dict(zone=None,nameservers=[],provider_hint="unknown",credentials_verified=False,challenge_delegation_verified=False)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("domain")
    a=p.parse_args()
    def query(zone):
        r=subprocess.run(["/usr/bin/dig","@1.1.1.1",zone,"NS","+short","+time=3","+tries=1"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
        if r.returncode:
            raise ValueError("DNS query failed")
        return sorted(set(x.lower() for x in r.stdout.decode("ascii").splitlines() if re.fullmatch(r"[a-zA-Z0-9.-]+\.",x)))
    print(json.dumps(discover(a.domain.lower(),query)))
if __name__=="__main__":
    main()
