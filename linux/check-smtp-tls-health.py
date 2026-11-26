#!/usr/bin/env python3
"""Read-only managed SMTP TLS health report."""
import argparse
import sys
import importlib.util
import json
import subprocess
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).resolve().with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--journal-alerts',action='store_true')
    args=parser.parse_args()
    root=Path("/etc/postfix/lmr365-smtp-tls")
    report={"version":1,"exchange_acceptance_verified":False,"checks":{}}
    checks=report["checks"]
    try:
        gen=load("smtp-tls-generation")
        active=gen.current(root)
        gen.validate(root,active)
        checks["generation"]={"status":"passed","name":active}
        cert=root/active/"fullchain.pem"
        openssl=load("smtp-tls-postfix").trusted_binary("/usr/bin/openssl")
        for days in (0,7,30):
            r=subprocess.run([openssl,"x509","-in",str(cert),"-noout","-checkend",str(days*86400)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
            checks["valid_for_"+str(days)+"_days"]={"status":"passed" if r.returncode==0 else "failed"}
    except Exception:
        checks["generation"]={"status":"failed"}
    try:
        load("smtp-tls-postfix").Postfix().verify_managed()
        checks["postfix_binding"]={"status":"passed"}
    except Exception:
        checks["postfix_binding"]={"status":"failed"}
    try:
        systemctl=load("smtp-tls-postfix").trusted_binary("/usr/bin/systemctl")
        for kind in ("timer","service"):
            unit="linuxmailrelay365-smtp-acme-renew."+kind
            r=subprocess.run([systemctl,"show",unit,"--property=LoadState,ActiveState,UnitFileState,Result,NextElapseUSecRealtime,ExecMainStatus"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15)
            checks[kind]={"status":"observed" if r.returncode==0 else "unavailable","properties":dict(line.split("=",1) for line in r.stdout.decode("utf-8","replace").splitlines() if "=" in line)}
    except Exception:
        checks["systemd"]={"status":"unavailable"}
    report['alerts']=load('smtp-tls-health-alerts').alerts(report)
    print(json.dumps(report,sort_keys=True))
    if args.journal_alerts:
        for alert in report['alerts']:
            priority=2 if alert['severity']=='critical' else 4
            print('<{}>SMTP TLS: {}'.format(priority,alert['code']),file=sys.stderr)
if __name__=="__main__":
    main()
