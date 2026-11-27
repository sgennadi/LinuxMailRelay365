#!/usr/bin/env python3
"""Experimental offline primary single-mailbox XOAUTH2 review/apply/recovery.

Only a stopped default single Postfix instance with empty queues is supported.
Exclusive maintenance is mandatory; no service control or message submission.
The administrator must prevent concurrent config/credential changes, starts,
submissions and OS/runtime updates. No SELinux-labelled or ACL files.
"""
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
RECOVERY_PARENT="/var/lib"
SCOPE={"config_directory":O.P.CONFIG,"queue_directory":O.P.QUEUE,
       "multi_instance_enable":"no","multi_instance_directories":"",
       "mail_owner":"postfix"}


def verify_scope(config):
    # An empty fixed spool is not evidence that a nonstandard instance has
    # an empty queue. Bind the expanded settings to the actual directory.
    before=X.snapshot(config,0)
    result=X.R.command("postconf",("-c",O.P.CONFIG,"-x",*SCOPE.keys()))
    X.need(result.returncode==0 and not result.stderr.strip() and
           len(result.stdout)<=65536,"native_maintenance_scope_unverified")
    observed=X.R.parameter_map(result.stdout.decode("utf-8","strict"))
    X.need(observed==SCOPE and X.snapshot(config,0)==before,
           "unsupported_postfix_instance_or_spool")


def host_guard(config,queue,parent=None):
    identity=O.mail_identity()
    def maintenance():
        O.maintenance(config,queue,identity)
        verify_scope(config)
        if parent is not None:
            O.same_directory(parent,RECOVERY_PARENT)
            O.M.check_directory(parent,0)
        # The native query must not be the last maintenance observation.
        O.maintenance(config,queue,identity)
    return maintenance


def read_native():
    return X.R.native_snapshot(X.R.ROOT)


def review_host(config,queue,mailbox,tenant,client,confirmation):
    maintenance=host_guard(config,queue)
    maintenance()
    runtime=A.RuntimeGuard(tenant,client,confirmation)
    revision,info,_=X.review(config,0,mailbox,maintenance,runtime)
    maintenance()
    X.need(runtime(mailbox)==info["runtime_sha256"],"runtime_review_changed")
    maintenance()
    return revision,info["runtime_sha256"]


def apply_host(config,queue,parent,mailbox,tenant,client,reviewed,confirmation,auth_confirmation):
    X.need(confirmation==X.APPLY and X.sha(reviewed),"typed_reviewed_apply_required")
    maintenance=host_guard(config,queue,parent)
    maintenance()
    # A new guard is created for every CLI invocation. No persisted AUTH
    # receipt or previous GUI success can authorize this operation.
    runtime=A.RuntimeGuard(tenant,client,auth_confirmation)
    def fresh():
        return X.review(config,0,mailbox,maintenance,runtime)
    return X.apply(config,parent,reviewed,0,confirmation,maintenance,fresh,
                   read_native,runtime)


def restore_host(config,queue,parent,revision,confirmation):
    X.need(confirmation==X.RESTORE and X.sha(revision),"typed_restore_confirmation_required")
    maintenance=host_guard(config,queue,parent)
    maintenance()
    # Recovery deliberately does not require a functioning OAuth identity,
    # working network, or a token. It restores only a verified exact pair.
    return X.restore(config,parent,revision,0,confirmation,maintenance,read_native)


def inspect_backup_host(config,queue,parent,revision):
    maintenance=host_guard(config,queue,parent)
    maintenance()
    info,files=X.load_backup(parent,revision,0)
    phase=X.phase(config,0,info,files)
    if phase in ("before","after"):
        X.verify(config,0,info,files,phase,maintenance,read_native)
    else:
        # A mixed pair can be recognized, not considered ready to run.
        maintenance()
        X.need(phase=="pipe_only" and X.phase(config,0,info,files)==phase,
               "recovery_phase_changed")
    return phase


def parse_request(args):
    A.need(args.maintenance_confirmation==O.MAINTENANCE,
           "explicit_exclusive_maintenance_required")
    if args.restore is not None or args.inspect_backup is not None:
        backup=args.restore if args.restore is not None else args.inspect_backup
        A.need(X.sha(backup) and args.expected_sha256 is None and
               all(v is None for v in (args.mailbox,args.tenant_id,args.client_id,args.auth_confirmation)),
               "invalid_recovery_request")
        A.need(args.confirm==(X.RESTORE if args.restore is not None else None),
               "invalid_recovery_confirmation")
        return
    A.exact_guid(args.tenant_id)
    A.exact_guid(args.client_id)
    X.R.parse(X.R.encode({"mailbox":args.mailbox,"nonce":"0"*64}))
    if args.apply:
        A.need(X.sha(args.expected_sha256) and args.confirm==X.APPLY and
               args.auth_confirmation==A.CONFIRM,"invalid_apply_approval")
    else:
        A.need(args.confirm==A.CONFIRM and args.expected_sha256 is None and
               args.auth_confirmation is None,"invalid_review_approval")


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--review",action="store_true")
    modes.add_argument("--apply",action="store_true")
    modes.add_argument("--restore",metavar="BACKUP_SHA256")
    modes.add_argument("--inspect-backup",metavar="BACKUP_SHA256")
    parser.add_argument("--mailbox")
    parser.add_argument("--tenant-id")
    parser.add_argument("--client-id")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--confirm")
    parser.add_argument("--auth-confirmation")
    parser.add_argument("--maintenance-confirmation",required=True)
    args=parser.parse_args(argv)
    fds=[]
    attempted=False
    def expired(*_):
        raise A.Refused("offline_operation_timeout")
    try:
        A.need(os.geteuid()==0,"root_required")
        parse_request(args)
        A.R.E.trusted_directory(HERE)
        os.umask(0o077)
        signal.signal(signal.SIGALRM,expired)
        signal.alarm(480)
        fds.append(O.route_lock())
        fds.append(A.C.lock())
        for path in (RECOVERY_PARENT,O.P.CONFIG,O.P.QUEUE):
            fds.append(O.P.open_directory(path,strict=path!=O.P.QUEUE))
        parent,config,queue=fds[-3:]
        if args.review:
            revision,runtime=review_host(config,queue,args.mailbox,args.tenant_id,
                                         args.client_id,args.confirm)
            print("PRIMARY_MAILBOX_OFFLINE_STATUS=reviewed_experimental")
            print("PRIMARY_MAILBOX_OFFLINE_SHA256="+revision)
            print("PRIMARY_MAILBOX_OFFLINE_RUNTIME_SHA256="+runtime)
            print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=observed")
            print("PRIMARY_MAILBOX_OFFLINE_POSTFIX_CHANGED=no")
        elif args.apply:
            attempted=True
            revision=apply_host(config,queue,parent,args.mailbox,args.tenant_id,
                                args.client_id,args.expected_sha256,args.confirm,args.auth_confirmation)
            print("PRIMARY_MAILBOX_OFFLINE_STATUS=applied_offline_not_started")
            print("PRIMARY_MAILBOX_OFFLINE_BACKUP_SHA256="+revision)
            print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=observed")
            print("PRIMARY_MAILBOX_OFFLINE_POSTFIX_CHANGED=yes")
        elif args.restore is not None:
            attempted=True
            revision=restore_host(config,queue,parent,args.restore,args.confirm)
            print("PRIMARY_MAILBOX_OFFLINE_STATUS=restored_offline_not_started")
            print("PRIMARY_MAILBOX_OFFLINE_BACKUP_SHA256="+revision)
            print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=not_attempted")
            print("PRIMARY_MAILBOX_OFFLINE_POSTFIX_CHANGED=restored")
        else:
            phase=inspect_backup_host(config,queue,parent,args.inspect_backup)
            print("PRIMARY_MAILBOX_OFFLINE_STATUS=backup_phase_observed")
            print("PRIMARY_MAILBOX_OFFLINE_BACKUP_SHA256="+args.inspect_backup)
            print("PRIMARY_MAILBOX_OFFLINE_PHASE="+phase)
            print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=not_attempted")
            print("PRIMARY_MAILBOX_OFFLINE_POSTFIX_CHANGED=no")
        return 0
    except X.T.RollbackRequired:
        print("PRIMARY_MAILBOX_OFFLINE_STATUS=manual_recovery_required")
        print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=unverified")
        print("PRIMARY_MAILBOX_OFFLINE_POSTFIX_CHANGED=inspect_recovery")
    except (A.Refused,A.C.Refused,A.R.E.Refused,X.Refused,X.R.E.Refused,
            O.Refused,O.P.Refused,O.T.Refused,O.M.Refused,
            OSError,ValueError,TypeError,KeyError,RuntimeError,subprocess.SubprocessError):
        # No raw exception, token, config contents or SMTP transcript.
        print("PRIMARY_MAILBOX_OFFLINE_STATUS=refused_or_unverified")
        print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=unverified")
        print("PRIMARY_MAILBOX_OFFLINE_POSTFIX_CHANGED="+("inspect_recovery" if attempted else "no"))
    finally:
        signal.alarm(0)
        for fd in reversed(fds):
            os.close(fd)
        print("PRIMARY_MAILBOX_OFFLINE_SERVICE_STARTED=no")
        print("PRIMARY_MAILBOX_OFFLINE_MAIL_SUBMITTED=no")
        # We do not mutate queues, but a refused maintenance check does not
        # establish queue contents or absence of external activity.
        print("PRIMARY_MAILBOX_OFFLINE_QUEUE_MODIFIED=no")
    if attempted:
        recovery=args.expected_sha256 if args.apply else args.restore
        if X.sha(recovery):
            # A retained identifier does not assert that backup creation
            # completed. Inspect before taking further action.
            print("PRIMARY_MAILBOX_OFFLINE_RECOVERY_SHA256="+recovery)
    return 2


if __name__=="__main__":
    sys.exit(main())
