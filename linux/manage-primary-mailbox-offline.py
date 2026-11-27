#!/usr/bin/env python3
"""Experimental offline primary single-mailbox XOAUTH2 review only."""
import argparse
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,str(HERE/filename))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


X=load("primary_mailbox_transaction","primary-mailbox-transaction.py")
O=load("primary_mailbox_maintenance","manage-conditional-postfix-offline.py")
A=load("primary_mailbox_runtime","primary-mailbox-runtime.py")


def review_host(config,queue,mailbox,tenant,client,confirmation):
    identity=O.mail_identity()
    def maintenance():
        O.maintenance(config,queue,identity)
    maintenance()
    runtime=A.RuntimeGuard(tenant,client,confirmation)
    revision,info,_=X.review(config,0,mailbox,maintenance,runtime)
    maintenance()
    X.need(runtime(mailbox)==info["runtime_sha256"],"runtime_review_changed")
    maintenance()
    return revision,info["runtime_sha256"]


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review",action="store_true",required=True)
    parser.add_argument("--mailbox",required=True)
    parser.add_argument("--tenant-id",required=True)
    parser.add_argument("--client-id",required=True)
    parser.add_argument("--confirm",required=True)
    parser.add_argument("--maintenance-confirmation",required=True)
    args=parser.parse_args(argv)
    fds=[]
    def expired(*_):
        raise A.Refused("offline_review_timeout")
    try:
        A.need(os.geteuid()==0 and args.maintenance_confirmation==O.MAINTENANCE,
               "root_and_exclusive_maintenance_required")
        A.need(args.confirm==A.CONFIRM,"explicit_smtp_auth_confirmation_required")
        A.exact_guid(args.tenant_id)
        A.exact_guid(args.client_id)
        X.R.parse(X.R.encode({"mailbox":args.mailbox,"nonce":"0"*64}))
        A.R.E.trusted_directory(HERE)
        os.umask(0o077)
        signal.signal(signal.SIGALRM,expired)
        signal.alarm(300)
        fds.append(O.route_lock())
        fds.append(A.C.lock())
        for path in (O.P.CONFIG,O.P.QUEUE):
            fds.append(O.P.open_directory(path,strict=path!=O.P.QUEUE))
        revision,runtime=review_host(fds[-2],fds[-1],args.mailbox,args.tenant_id,
                                    args.client_id,args.confirm)
        print("PRIMARY_MAILBOX_OFFLINE_STATUS=reviewed_experimental")
        print("PRIMARY_MAILBOX_OFFLINE_SHA256="+revision)
        print("PRIMARY_MAILBOX_OFFLINE_RUNTIME_SHA256="+runtime)
        print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=observed")
        return 0
    except (A.Refused,A.C.Refused,A.R.E.Refused,X.Refused,X.R.E.Refused,
            O.Refused,O.P.Refused,O.T.Refused,O.M.Refused,
            OSError,ValueError,TypeError,KeyError,RuntimeError,subprocess.SubprocessError):
        # Never relay exceptions carrying config or authentication material.
        print("PRIMARY_MAILBOX_OFFLINE_STATUS=refused_or_unverified")
        print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=unverified")
        return 2
    finally:
        signal.alarm(0)
        for fd in reversed(fds):
            os.close(fd)
        print("PRIMARY_MAILBOX_OFFLINE_POSTFIX_CHANGED=no")
        print("PRIMARY_MAILBOX_OFFLINE_SERVICE_STARTED=no")
        print("PRIMARY_MAILBOX_OFFLINE_MAIL_SUBMITTED=no")
        print("PRIMARY_MAILBOX_OFFLINE_QUEUE_MODIFIED=no")


if __name__=="__main__":
    sys.exit(main())
