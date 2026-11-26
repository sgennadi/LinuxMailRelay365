#!/usr/bin/env python3
"""Explicit managed renewal activation/recovery entry point."""
import argparse
import importlib.util
import os
from pathlib import Path

ROOT=Path("/etc/postfix/lmr365-smtp-tls")

def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).with_name(name+".py")))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    p=argparse.ArgumentParser()
    p.add_argument("action",choices=("activate","recover","recover-before-start"))
    p.add_argument("--candidate")
    p.add_argument("--domain")
    p.add_argument("--ca-file")
    p.add_argument("--confirm",required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="MANAGED_TLS_TRANSACTION":
        p.error("root and explicit confirmation required")
    try:
        generation=load("smtp-tls-generation")
        transaction=load("smtp-tls-transaction")
        activation=load("smtp-tls-activate")
        postfix=load("smtp-tls-postfix").Postfix()
        postfix.verify_managed()
        if a.action=="recover-before-start":
            result=activation.recover(ROOT,generation,transaction,postfix.check,lambda: None)
        elif a.action=="recover":
            result=activation.recover(ROOT,generation,transaction,postfix.check,postfix.reload)
        else:
            if not all((a.candidate,a.domain,a.ca_file)):
                raise ValueError("candidate, domain and trust store required")
            checker=load("check-smtp-relay-certificate")
            def validate(name):
                path=ROOT/name/"client-chain.pem"
                checker.inspect(str(path),str(path),a.domain,a.ca_file,str(path))
            result=activation.activate(ROOT,a.candidate,generation,transaction,
                postfix.check,postfix.reload,validate)
        print("TLS_TRANSACTION="+result)
        print("EXCHANGE_ACCEPTANCE=unverified")
        return 0
    except Exception:
        print("TLS_TRANSACTION=failed; inspect deployment journal")
        return 1

if __name__=="__main__":
    raise SystemExit(main())
