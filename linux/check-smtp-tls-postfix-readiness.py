#!/usr/bin/env python3
"""Inspect Postfix TLS readiness without sending mail or claiming remote acceptance."""
import importlib.util
import json
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).resolve().with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def main():
    report=dict(version=1,configuration_verified=False,generation_verified=False,
                service_running=False,postfix_key_access_verified=False,
                exchange_acceptance_verified=False,mail_sent=False)
    try:
        root=Path("/etc/postfix/lmr365-smtp-tls")
        gen=load("smtp-tls-generation")
        pf=load("smtp-tls-postfix").Postfix()
        with load("smtp-tls-transaction").deployment_lock(root):
            name=gen.current(root)
            gen.validate(root,name)
            report["generation_verified"]=True
            pf.verify_managed()
            report["configuration_verified"]=True
            pf.run(pf.postfix,"status")
            report["service_running"]=True
    except Exception:
        pass
    report["status"]="local_ready" if all(report[k] for k in ("configuration_verified","generation_verified","service_running")) else "review_required"
    print(json.dumps(report,sort_keys=True))
    return 0 if report["status"]=="local_ready" else 1
if __name__=="__main__":
    raise SystemExit(main())
