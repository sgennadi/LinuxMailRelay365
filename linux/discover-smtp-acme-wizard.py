#!/usr/bin/env python3
"""JSON discovery interface for the certificate wizard; no issuance."""
import argparse
import importlib.util
import json
import re
import subprocess
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).resolve().with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--name",required=True)
    p.add_argument("--domain",required=True)
    a=p.parse_args()
    planner=load("plan-smtp-certificate-acme")
    request=planner.plan(dict(accepted_domain=a.domain,certificate_name=a.name,provider="manual"))
    name=request["certificate_name"]
    def query(zone,kind):
        r=subprocess.run(["/usr/bin/dig","@1.1.1.1",zone,kind,"+noall","+comments","+answer","+time=3","+tries=1"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
        output=r.stdout.decode("ascii","replace")
        if r.returncode or not re.search(r"status: (NOERROR|NXDOMAIN),",output):
            raise ValueError("public DNS query failed")
        values=[]
        for line in output.splitlines():
            fields=line.split()
            if len(fields)==5 and fields[0].lower().rstrip(".")==zone.lower().rstrip(".") and fields[2]=="IN" and fields[3]==kind:
                values.append(fields[4])
        return sorted(set(values))
    discovery=load("discover-smtp-public-dns")
    def discover(zone):
        return discovery.discover(zone,lambda n:query(n,"NS"))
    dns=discover(name)
    delegation=load("inspect-smtp-acme-delegation").inspect(name,query,discover)
    r=subprocess.run(["/usr/bin/python3",str(Path(__file__).resolve().with_name("probe-smtp-acme-plugins.py"))],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=75)
    plugins=json.loads(r.stdout.decode("utf-8")) if not r.returncode else {"status":"probe_failed"}
    recommendation=load("recommend-smtp-acme-provider").recommend(dns,delegation,plugins)
    print(json.dumps(dict(version=1,status="completed",request=request,dns=dns,delegation=delegation,plugins=plugins,recommendation=recommendation)))
if __name__=="__main__":
    try:
        main()
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):
        print(json.dumps(dict(version=1,status="discovery_failed",automatic_issuance_allowed=False)))
        raise SystemExit(1)
