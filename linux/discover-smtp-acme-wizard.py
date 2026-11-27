#!/usr/bin/env python3
"""Bounded public DNS and registered plugin discovery; no issuance or DNS writes."""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import time
from pathlib import Path


def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).resolve().with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def parse_answer(raw,zone,kind):
    if len(raw)>262144:
        raise ValueError("DNS response too large")
    output=raw.decode("ascii","strict")
    status=re.search(r"\bstatus: (NOERROR|NXDOMAIN),",output)
    if not status:
        raise ValueError("public DNS query failed")
    values=[]
    for line in output.splitlines():
        fields=line.split()
        if len(fields)==5 and fields[0].lower().rstrip(".")==zone.lower().rstrip(".") and fields[2]=="IN" and fields[3]==kind:
            name=fields[4].lower().rstrip(".")
            if len(name)>253 or not all(re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?",x) for x in name.split(".")):
                raise ValueError("unrecognized DNS target")
            values.append(name+".")
    if len(values)>64 or (status.group(1)=="NXDOMAIN" and values):
        raise ValueError("inconsistent DNS response")
    return sorted(set(values))


def make_query(dig,runner=subprocess.run,clock=time.monotonic):
    deadline=clock()+55
    remaining=24
    cache={}
    def query(zone,kind):
        nonlocal remaining
        zone=zone.lower().rstrip(".")
        if (kind not in ("NS","CNAME") or len(zone)>253 or
                not all(re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?",x) for x in zone.split("."))):
            raise ValueError("invalid DNS query")
        key=(zone,kind)
        if key in cache:
            return cache[key]
        left=deadline-clock()
        if remaining<=0 or left<=0:
            raise ValueError("DNS discovery budget exhausted")
        remaining-=1
        r=runner([dig,"-r","@1.1.1.1",zone+".",kind,"+noall","+comments","+answer","+time=3","+tries=1"],
                 stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=min(6,left),
                 env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
        if r.returncode:
            raise ValueError("public DNS query failed")
        cache[key]=parse_answer(r.stdout,zone,kind)
        return cache[key]
    return query


def inspect(name,domain,query,plugins):
    request=load("plan-smtp-certificate-acme").plan(dict(accepted_domain=domain,certificate_name=name,provider="manual"))
    name=request["certificate_name"]
    discovery=load("discover-smtp-public-dns")
    def discover(zone):
        return discovery.discover(zone,lambda n:query(n,"NS"))
    dns=discover(name)
    delegation=load("inspect-smtp-acme-delegation").inspect(name,query,discover)
    # A separate NS delegation at the challenge owner can exist without
    # a CNAME. Do not recommend the parent provider automatically in that case.
    direct_ns=query(delegation["challenge"],"NS")
    delegation["challenge_nameservers"]=direct_ns
    if direct_ns:
        delegation["delegated"]=True
    recommendation=load("recommend-smtp-acme-provider").recommend(dns,delegation,plugins)
    return dict(version=1,status="completed",request=request,dns=dns,delegation=delegation,
                plugins=plugins,recommendation=recommendation,public_resolver="1.1.1.1",
                automatic_issuance_allowed=False,postfix_modified=False)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--name",required=True)
    p.add_argument("--domain",required=True)
    a=p.parse_args()
    if os.geteuid()!=0:
        raise ValueError("root required for local plugin inventory")
    load("plan-smtp-certificate-acme").plan(dict(accepted_domain=a.domain,certificate_name=a.name,provider="manual"))
    dig=load("smtp-tls-postfix").trusted_invocation("/usr/bin/dig")
    try:
        r=subprocess.run(["/usr/bin/python3","-I","-B",str(Path(__file__).resolve().with_name("probe-smtp-acme-plugins.py"))],
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=75)
        plugins=json.loads(r.stdout.decode("utf-8")) if not r.returncode and len(r.stdout)<=16384 else {"status":"probe_failed"}
    except (OSError,ValueError,subprocess.SubprocessError):
        plugins={"status":"probe_failed"}
    print(json.dumps(inspect(a.name,a.domain,make_query(dig),plugins)))


if __name__=="__main__":
    try:
        main()
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print(json.dumps(dict(version=1,status="discovery_failed",automatic_issuance_allowed=False,postfix_modified=False)))
        raise SystemExit(1)
