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
    p.add_argument("--recover",action="store_true")
    p.add_argument("--before-start",action="store_true")
    p.add_argument("--confirm",required=True)
    for name in ("original-sha","candidate-sha","generation","domain","ca-file"):
        p.add_argument("--"+name)
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
            fd=os.open(str(CONFIG),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            import stat
            with os.fdopen(fd,"rb") as stream:
                st=os.fstat(stream.fileno())
                if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1
                        or st.st_mode & 0o7022 or st.st_size>8388608):
                    raise ValueError("unsafe main.cf")
                data=stream.read(8388609)
                if len(data)>8388608:
                    raise ValueError("configuration too large")
                return data
        def preflight():
            planner.plan_postfix(pf)
            pf.run(pf.postfix,"status")
        def validate():
            if gen.current(ROOT)!=a.generation:
                raise ValueError("active generation mismatch")
            result=load("smtp-tls-validate-generation").validate(ROOT,a.generation,a.domain,a.ca_file,gen,checker)
            if result.get("status")!="local_checks_passed":
                raise ValueError("candidate TLS validation refused")
        def reload():
            pf.run(pf.postfix,"check")
            pf.run(pf.postfix,"reload")
        def journal_read(path):
            return json.loads(backup.read_private(path,16384),object_pairs_hook=backup.strict_object)
        with tx.deployment_lock(ROOT):
            backup.private_directory(ROOT)
            if a.recover:
                path=ROOT/"initial-deployment.json"
                if not os.path.lexists(path):
                    print("INITIAL_TLS=no_transaction")
                    return 0
                state=journal_read(path)
                if state.get("version")!=1 or state.get("phase") not in journal.PHASES:
                    raise ValueError("invalid initial recovery journal")
                if state["phase"] not in ("verified","rolled_back"):
                    # Refuse a pending recovery before changing any journal
                    # or configuration if the original backup is not proven.
                    import re
                    name=state.get("backup")
                    if not isinstance(name,str) or not re.fullmatch(r"initial-backup-[A-Za-z0-9_]+",name):
                        raise ValueError("invalid backup reference")
                    backup.verify_for_journal(ROOT/name,state.get("original_sha256"),state.get("candidate_sha256"),candidate.build)
                    if os.path.lexists(ROOT/"deployment.json"):
                        raise ValueError("overlapping deployment transaction")
                def restore_verified(saved,expected):
                    data,meta=backup.verify_for_journal(saved,state["original_sha256"],state["candidate_sha256"],candidate.build)
                    backup.replace_config(data,expected,CONFIG,meta)
                result=journal.recover(ROOT,state,read,restore_verified,
                    lambda:pf.run(pf.postfix,"check"),lambda:None if a.before_start else reload(),
                    lambda *args:journal.record(ROOT,*args,bootstrap_generation=state.get("bootstrap_generation")))
                print("INITIAL_TLS="+result)
                return 0
            if a.before_start or not all((a.original_sha,a.candidate_sha,a.generation,a.domain,a.ca_file)):
                raise ValueError("deployment arguments required")
            for name in ("initial-deployment.json","deployment.json"):
                path=ROOT/name
                if os.path.lexists(path) and journal_read(path).get("phase") not in ("verified","rolled_back"):
                    raise ValueError("unfinished transaction")
            def restore_initial(saved,expected):
                data,meta=backup.verify_for_journal(saved,a.original_sha,a.candidate_sha,candidate.build)
                backup.replace_config(data,expected,CONFIG,meta)
            result=deploy.deploy(a.original_sha,a.candidate_sha,read,candidate.build,
                lambda:backup.backup(ROOT),backup.replace_config,restore_initial,
                preflight,validate,pf.check,reload,lambda *args:journal.record(ROOT,*args))
        print("INITIAL_TLS="+result)
        return 0
    except Exception:
        print("INITIAL_TLS=failed; inspect transaction journal")
        return 1

if __name__=="__main__":
    raise SystemExit(main())
