#!/usr/bin/env python3
"""Experimental primary single-mailbox XOAUTH2 review/apply/recovery/start.

Only a default single Postfix instance is supported. Exclusive maintenance,
initially stopped Postfix and empty queues are mandatory. Only the explicit
start operation controls the service; no automatic stop, rollback after
start, or message submission. No SELinux-labelled or ACL files.
"""
import argparse
import importlib.util
import os
import re
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
START="START_REVIEWED_PRIMARY_MAILBOX_ROUTE"
SCOPE={"config_directory":O.P.CONFIG,"queue_directory":O.P.QUEUE,
       "multi_instance_enable":"no","multi_instance_directories":"",
       "mail_owner":"postfix"}


def verify_scope(config,selinux=None):
    # An empty fixed spool is not evidence that a nonstandard instance has
    # an empty queue. Bind the expanded settings to the actual directory.
    before=X.snapshot(config,0) if selinux is None else X.snapshot(config,0,selinux)
    result=X.R.command("postconf",("-c",O.P.CONFIG,"-x",*SCOPE.keys()))
    X.need(result.returncode==0 and not result.stderr.strip() and
           len(result.stdout)<=65536,"native_maintenance_scope_unverified")
    observed=X.R.parameter_map(result.stdout.decode("utf-8","strict"))
    after=X.snapshot(config,0) if selinux is None else X.snapshot(config,0,selinux)
    X.need(observed==SCOPE and after==before,"unsupported_postfix_instance_or_spool")


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


def native_selinux_mode():
    try:
        raw=Path("/sys/fs/selinux/enforce").read_text(encoding="ascii").strip()
    except (OSError,UnicodeError):
        return "unverified"
    return {"0":"permissive","1":"enforcing"}.get(raw,"unverified")


def native_selinux_label(path,kind,command=O.P.system_command):
    # Exact primary paths only. Recovery paths are derived from a validated
    # transaction digest, never from an arbitrary user-provided filename.
    base="/var/lib/"+X.BASE
    dirs={"/etc/postfix","/var/lib",base}
    files={"/etc/postfix/"+name for name in X.NAMES}
    allowed=(kind=="dir" and (path in dirs or
             re.fullmatch(re.escape(base)+r"/[a-f0-9]{64}",path))) or (
             kind=="file" and (path in files or
             re.fullmatch(re.escape(base)+r"/[a-f0-9]{64}/(?:"+
                "|".join(re.escape(name) for name in X.FILES+(X.MANIFEST,))+r")",path)))
    X.need(bool(allowed),"unsupported_selinux_policy_path")
    raw=command("matchpathcon",["-N","-n","-m",kind,path])
    lines=raw.splitlines()
    X.need(len(lines)==1 and lines[0]==lines[0].strip(),"selinux_policy_label_unverified")
    value=X.T.checked_label(lines[0].encode("ascii")+b"\0")
    X.normalized_label(value)
    return value


def native_selinux_offline(config,queue,parent):
    """Native stopped-host adapter for disposable Enforcing acceptance only.

    Not reachable through main(), the GUI, or any ordinary Apply operation.
    Both existing workflow locks and exclusive maintenance are the caller's
    responsibility. No service control, policy edit or automatic relabel.
    """
    X.need(os.geteuid()==0 and native_selinux_mode()=="enforcing",
           "native_enforcing_required")
    identity=O.mail_identity()
    def stopped():
        O.same_directory(config,O.P.CONFIG)
        O.same_directory(queue,O.P.QUEUE)
        O.same_directory(parent,RECOVERY_PARENT)
        O.M.check_directory(config,0)
        O.M.check_directory(parent,0)
        X.need(native_selinux_mode()=="enforcing" and O.mail_identity()==identity,
               "native_selinux_maintenance_changed")
        O.P.stopped_units()
        O.P.no_postfix_processes()
        O.P.empty_queue(queue)
    stopped()
    policy=X.SelinuxPolicy(config,parent,0,native_selinux_mode,native_selinux_label)
    def guard():
        stopped()
        verify_scope(config,policy)
        stopped()
        X.need(policy.evidence()==policy.initial,"native_selinux_context_changed")
    guard()
    return policy,guard


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


def verify_applied_host(config,queue,parent,revision,mailbox,tenant,client,confirmation):
    """Reverify the applied pair and original runtime without starting Postfix."""
    X.need(X.sha(revision) and confirmation==A.CONFIRM,"explicit_applied_auth_review_required")
    maintenance=host_guard(config,queue,parent)
    maintenance()
    info,files=X.load_backup(parent,revision,0)
    X.need(info["mailbox"]==mailbox,"backup_mailbox_mismatch")
    # Refuse before/pipe_only/foreign states before any authentication.
    X.verify(config,0,info,files,"after",maintenance,read_native)
    runtime=A.RuntimeGuard(tenant,client,confirmation,expected_sha=info["runtime_sha256"])
    X.need(runtime(mailbox)==info["runtime_sha256"],"applied_runtime_changed")
    X.verify(config,0,info,files,"after",maintenance,read_native)
    X.need(runtime(mailbox)==info["runtime_sha256"],"applied_runtime_changed")
    maintenance()
    X.need(X.phase(config,0,info,files)=="after","applied_configuration_changed")
    return info["runtime_sha256"]


def native_postfix(action):
    # "check" may repair metadata; it is not a read-only command.
    X.need(action in ("check","status"),"unexpected_native_action")
    adapter=load("primary_mailbox_postfix_adapter","smtp-tls-postfix.py")
    binary=adapter.trusted_invocation("/usr/sbin/postfix")
    result=subprocess.run([binary,"-c",O.P.CONFIG,action],input=b"",
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                          timeout=60 if action=="check" else 20,
                          env=O.P.SYSTEM_ENV,check=False)
    X.need(result.returncode==0,"native_postfix_"+action+"_unverified")


def native_start():
    result=subprocess.run([O.P.trusted_tool("systemctl"),"start","postfix.service"],
                          input=b"",stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                          timeout=60,env=O.P.SYSTEM_ENV,check=False)
    X.need(result.returncode==0,"postfix_start_unverified")


def running_status():
    raw=O.P.system_command("systemctl",["show","postfix.service",
                           "--property=LoadState","--property=ActiveState"])
    X.need(O.P.key_values(raw,("LoadState","ActiveState"))==
           {"LoadState":"loaded","ActiveState":"active"},"postfix_unit_not_active")
    raw=O.P.system_command("systemctl",["list-units","--all","--type=service",
                           "--no-legend","--no-pager","--plain","postfix*.service"])
    seen=set()
    for line in raw.splitlines():
        fields=line.split()
        X.need(len(fields)>=4 and fields[0].endswith(".service") and fields[0] not in seen,
               "unexpected_postfix_unit_inventory")
        seen.add(fields[0])
        if fields[0] not in ("postfix.service","postfix@-.service"):
            X.need(fields[2:4]==["inactive","dead"],"other_postfix_unit_not_stopped")
    X.need("postfix.service" in seen,"missing_primary_postfix_unit")
    native_postfix("status")


def start_applied_host(config,queue,parent,revision,mailbox,tenant,client,
                       confirmation,auth_confirmation,mark_check,mark_start,
                       checker=native_postfix,starter=native_start):
    """No automatic stop or file rollback once a service start is attempted."""
    X.need(confirmation==START and auth_confirmation==A.CONFIRM and X.sha(revision),
           "explicit_reviewed_start_required")
    maintenance=host_guard(config,queue,parent)
    maintenance()
    identity=O.mail_identity()
    info,files=X.load_backup(parent,revision,0)
    X.need(info["mailbox"]==mailbox,"backup_mailbox_mismatch")
    X.verify(config,0,info,files,"after",maintenance,read_native)
    runtime=A.RuntimeGuard(tenant,client,auth_confirmation,expected_sha=info["runtime_sha256"])
    X.need(runtime(mailbox)==info["runtime_sha256"],"applied_runtime_changed")
    X.verify(config,0,info,files,"after",maintenance,read_native)
    mark_check()
    checker("check")
    X.verify(config,0,info,files,"after",maintenance,read_native)
    X.need(runtime(mailbox)==info["runtime_sha256"],"applied_runtime_changed")
    X.verify(config,0,info,files,"after",maintenance,read_native)
    maintenance()
    X.need(O.mail_identity()==identity and X.phase(config,0,info,files)=="after",
           "configuration_or_identity_changed_before_start")
    mark_start()
    starter()
    # The stopped-instance and empty-queue guard no longer applies. Do not
    # claim that no external submission or queue activity could have occurred.
    def running_guard():
        O.same_directory(config,O.P.CONFIG)
        O.same_directory(queue,O.P.QUEUE)
        O.same_directory(parent,RECOVERY_PARENT)
        O.M.check_directory(config,0)
        O.M.check_directory(parent,0)
        X.need(O.mail_identity()==identity and not os.listxattr(config) and
               not os.path.exists("/sys/fs/selinux/enforce"),"running_host_context_changed")
        verify_scope(config)
        running_status()
    X.verify(config,0,info,files,"after",running_guard,read_native)
    # Do not authenticate again after the service may accept mail. Observe
    # the exact installed runtime, not an old cached AUTH result.
    X.need(A.digest(A.installed_snapshot(mailbox,tenant,client))==info["runtime_sha256"],
           "runtime_changed_after_start")
    running_guard()
    X.need(X.phase(config,0,info,files)=="after","configuration_changed_after_start")
    return info["runtime_sha256"]


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
    if args.start is not None:
        A.need(X.sha(args.start) and args.confirm==START and
               args.expected_sha256 is None and args.auth_confirmation==A.CONFIRM,
               "invalid_start_approval")
    elif args.verify_applied is not None:
        A.need(X.sha(args.verify_applied) and args.confirm==A.CONFIRM and
               args.expected_sha256 is None and args.auth_confirmation is None,
               "invalid_applied_verification_approval")
    elif args.apply:
        A.need(X.sha(args.expected_sha256) and args.confirm==X.APPLY and
               args.auth_confirmation==A.CONFIRM,"invalid_apply_approval")
    else:
        A.need(args.confirm==A.CONFIRM and args.expected_sha256 is None and
               args.auth_confirmation is None,"invalid_review_approval")


# Only explicit internal refusal codes are exported, never raw exceptions.
# This is informational, review-only, and cannot authorize any action.
REVIEW_GUIDANCE={
    "unsupported_service_account_or_groups":"service_account_review",
    "tpm_service_device_access_requires_review":"tpm_device_access_review",
    "tpm_resource_manager_changed":"tpm_device_changed",
    "invalid_tpm_resource_manager_fingerprint":"tpm_device_metadata_review",
    "selinux_metadata_restore_not_implemented":"selinux_offline_blocked",
    "extended_directory_metadata_unsupported":"extended_metadata_review",
}

def review_guidance(error):
    if type(error) not in (A.Refused,O.Refused):
        return None
    return REVIEW_GUIDANCE.get(str(error))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--review",action="store_true")
    modes.add_argument("--apply",action="store_true")
    modes.add_argument("--restore",metavar="BACKUP_SHA256")
    modes.add_argument("--inspect-backup",metavar="BACKUP_SHA256")
    modes.add_argument("--verify-applied",metavar="BACKUP_SHA256")
    modes.add_argument("--start",metavar="BACKUP_SHA256")
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
    check_attempted=False
    start_attempted=False
    start_verified=False
    def mark_check():
        nonlocal check_attempted
        check_attempted=True
    def mark_start():
        nonlocal start_attempted
        start_attempted=True
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
        elif args.start is not None:
            runtime=start_applied_host(config,queue,parent,args.start,args.mailbox,
                                       args.tenant_id,args.client_id,args.confirm,args.auth_confirmation,
                                       mark_check,mark_start)
            start_verified=True
            print("PRIMARY_MAILBOX_OFFLINE_STATUS=started_running_observed")
            print("PRIMARY_MAILBOX_OFFLINE_BACKUP_SHA256="+args.start)
            print("PRIMARY_MAILBOX_OFFLINE_RUNTIME_SHA256="+runtime)
            print("PRIMARY_MAILBOX_OFFLINE_PHASE=after")
            print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=observed")
            print("PRIMARY_MAILBOX_OFFLINE_POSTFIX_CHANGED=no")
        elif args.verify_applied is not None:
            runtime=verify_applied_host(config,queue,parent,args.verify_applied,args.mailbox,
                                        args.tenant_id,args.client_id,args.confirm)
            print("PRIMARY_MAILBOX_OFFLINE_STATUS=applied_runtime_reverified_not_started")
            print("PRIMARY_MAILBOX_OFFLINE_BACKUP_SHA256="+args.verify_applied)
            print("PRIMARY_MAILBOX_OFFLINE_RUNTIME_SHA256="+runtime)
            print("PRIMARY_MAILBOX_OFFLINE_PHASE=after")
            print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=observed")
            print("PRIMARY_MAILBOX_OFFLINE_POSTFIX_CHANGED=no")
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
            OSError,ValueError,TypeError,KeyError,RuntimeError,subprocess.SubprocessError) as error:
        # No raw exception, token, config contents or SMTP transcript.
        print("PRIMARY_MAILBOX_OFFLINE_STATUS="+("start_outcome_unverified" if start_attempted else
              "native_check_outcome_unverified" if check_attempted else "refused_or_unverified"))
        print("PRIMARY_MAILBOX_OFFLINE_SMTP_AUTH=unverified")
        print("PRIMARY_MAILBOX_OFFLINE_POSTFIX_CHANGED="+("inspect_recovery" if attempted or check_attempted else "no"))
        if args.review and not attempted and not check_attempted and not start_attempted:
            guidance=review_guidance(error)
            if guidance is not None:
                print("PRIMARY_MAILBOX_OFFLINE_REVIEW_GUIDANCE="+guidance)
    finally:
        signal.alarm(0)
        for fd in reversed(fds):
            os.close(fd)
        print("PRIMARY_MAILBOX_OFFLINE_SERVICE_STARTED="+("observed_running" if start_verified else
              "unverified" if start_attempted else "no"))
        print("PRIMARY_MAILBOX_OFFLINE_MAIL_SUBMITTED="+("not_verified" if start_attempted else "no"))
        # Native check may repair metadata. Once start is attempted, external
        # mail/queue activity cannot be ruled out even on timeout or failure.
        print("PRIMARY_MAILBOX_OFFLINE_QUEUE_MODIFIED="+("not_verified" if check_attempted or start_attempted else "no"))
    if attempted or args.start is not None:
        recovery=args.start if args.start is not None else args.expected_sha256 if args.apply else args.restore
        if X.sha(recovery):
            # A retained identifier does not assert that backup creation
            # completed. Inspect before taking further action.
            print("PRIMARY_MAILBOX_OFFLINE_RECOVERY_SHA256="+recovery)
    return 2


if __name__=="__main__":
    sys.exit(main())
