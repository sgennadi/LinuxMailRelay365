#!/usr/bin/env python3
"""Read-only recent SELinux AVC diagnostics; never generate policy."""
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

def main():
    report=dict(version=1,status="unverified",matching_denials=0,access_verified=False)
    try:
        if os.geteuid()!=0:
            raise ValueError("root required")
        spec=importlib.util.spec_from_file_location("postfix",str(Path(__file__).resolve().with_name("smtp-tls-postfix.py")))
        m=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        binary=m.trusted_binary("/usr/sbin/ausearch")
        r=subprocess.run([binary,"-m","AVC,USER_AVC","-ts","today","--raw"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
        if r.returncode==0:
            events=set()
            for line in r.stdout.decode("utf-8","replace").splitlines():
                if not re.search(r"avc:\s+denied",line,re.I):
                    continue
                if not re.search(r"scontext=[^\s]*:postfix_[^\s]*|comm=\"(?:smtp|smtpd|postfix)\"|lmr365-smtp-tls",line):
                    continue
                event=re.search(r"msg=audit\(([^)]+)\)",line)
                if event:
                    events.add(event.group(1))
            report.update(status="observed",matching_denials=len(events))
        elif r.returncode==1:
            report["status"]="no_matches_or_audit_unavailable"
    except Exception:
        pass
    print(json.dumps(report,sort_keys=True))
if __name__=="__main__":
    main()
