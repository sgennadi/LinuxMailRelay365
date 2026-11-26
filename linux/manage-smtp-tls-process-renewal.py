#!/usr/bin/env python3
"""Process explicitly selected renewed TLS material."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
ROOT=Path("/etc/postfix/lmr365-smtp-tls")
def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--profile",action="store_true")
    p.add_argument("--confirm",required=True)
    for field in ("cert","chain","key","domain","ca-file"):
        p.add_argument("--"+field)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="PROCESS_RENEWED_TLS":
        p.error("root and explicit confirmation required")
    if a.profile:
        if any((a.cert,a.chain,a.key,a.domain,a.ca_file)):
            p.error("profile and explicit paths are mutually exclusive")
        data=load("smtp-tls-renewal-profile").load()
        a.cert,a.chain,a.key,a.domain,a.ca_file=(data[k] for k in ("cert","chain","privkey","domain","ca_file"))
    elif not all((a.cert,a.chain,a.key,a.domain,a.ca_file)):
        p.error("certificate parameters required")
    gen=load("smtp-tls-generation")
    tx=load("smtp-tls-transaction")
    pf=load("smtp-tls-postfix").Postfix()
    checker=load("check-smtp-relay-certificate")
    validator=load("smtp-tls-validate-generation")
    def validate(name):
        return validator.validate(ROOT,name,a.domain,a.ca_file,gen,checker)
    def activate(name):
        return load("smtp-tls-activate").activate(ROOT,name,gen,tx,pf.check,pf.reload,validate)
    pf.check()
    result=load("smtp-tls-process-renewal").process(a.cert,a.chain,a.key,a.domain,a.ca_file,
        load("stage-smtp-relay-certificate").stage,lambda:gen.current(ROOT),validate,activate)
    print(json.dumps(result))
    return 0
if __name__=="__main__":
    raise SystemExit(main())
