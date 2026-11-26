#!/usr/bin/env python3
"""Explicit initial managed TLS deployment. Requires a preselected active generation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path

ROOT=Path("/etc/postfix/lmr365-smtp-tls")
CONFIG=Path("/etc/postfix/main.cf")

def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def main():
    p=argparse.ArgumentParser()
    for name in ("original-sha","candidate-sha","generation","domain","ca-file","confirm"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="INITIAL_TLS_DEPLOYMENT":
        p.error("root and explicit confirmation required")
    try:
        tx=load("smtp-tls-transaction")
        gen=load("smtp-tls-generation")
        backup=load("smtp-tls-initial-backup")
        candidate=load("smtp-tls-initial-candidate")
        journal=load("smtp-tls-initial-journal")
        deploy=load("smtp-tls-initial-deploy")
        planner=load("plan-smtp-tls-initial")
        checker=load("check-smtp-relay-certificate")
        pf=load("smtp-tls-postfix").Postfix()
        def read():
            return CONFIG.read_bytes()
        def preflight():
            planner.plan(lambda key:pf.run(pf.postconf,"-h",key),pf.run(pf.postconf,"-P"))
            pf.run(pf.postfix,"status")
        def validate():
            if gen.current(ROOT)!=a.generation:
                raise ValueError("active generation mismatch")
            path=ROOT/a.generation/"client-chain.pem"
            checker.inspect(str(path),str(path),a.domain,a.ca_file,str(path))
        def reload():
            pf.run(pf.postfix,"check")
            pf.run(pf.postfix,"reload")
        with tx.deployment_lock(ROOT):
            for name in ("initial-deployment.json","deployment.json"):
                path=ROOT/name
                if path.exists() and json.loads(path.read_text()).get("phase") not in ("verified","rolled_back"):
                    raise ValueError("unfinished transaction")
            result=deploy.deploy(a.original_sha,a.candidate_sha,read,candidate.build,
                lambda:backup.backup(ROOT),backup.replace_config,backup.restore,
                preflight,validate,pf.check,reload,lambda *args:journal.record(ROOT,*args))
        print("INITIAL_TLS="+result)
        return 0
    except Exception:
        print("INITIAL_TLS=failed; inspect transaction journal")
        return 1

if __name__=="__main__":
    raise SystemExit(main())
