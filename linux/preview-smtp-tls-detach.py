#!/usr/bin/env python3
"""Read-only preview of managed TLS detachment."""
import importlib.util
import hashlib
import json
import os
import re
from pathlib import Path
ROOT=Path("/etc/postfix/lmr365-smtp-tls")
def load(name):
    spec=importlib.util.spec_from_file_location(name,str(Path(__file__).with_name(name+".py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
def main():
    if os.geteuid()!=0:
        raise ValueError("root required")
    with load("smtp-tls-transaction").deployment_lock(ROOT):
        state=json.loads((ROOT/"initial-deployment.json").read_text())
        if state.get("version")!=1 or state.get("phase")!="verified":
            raise ValueError("verified initial deployment required")
        name=state["backup"]
        if not re.fullmatch(r"initial-backup-[a-zA-Z0-9_]+",name):
            raise ValueError("invalid backup reference")
        previous,meta=load("smtp-tls-initial-backup").verify(ROOT/name)
        if hashlib.sha256(previous).hexdigest()!=state["original_sha256"]:
            raise ValueError("backup does not match initial transaction")
        pf=load("smtp-tls-postfix").Postfix()
        pf.verify_managed()
        original=Path("/etc/postfix/main.cf").read_bytes()
        plan=load("plan-smtp-tls-detach").preview(original,previous)
        plan.update(backup=name,alternative_route_verified=False,
                    apply_supported=False)
        print(json.dumps(plan,sort_keys=True))
    return 0
if __name__=="__main__":
    raise SystemExit(main())
