#!/usr/bin/env python3
"""Native SELinux v2 primary Postfix transaction acceptance, disposable VM ONLY.

No real credentials, SMTP AUTH, message submission, service startup with the
candidate, policy installation or weakening. The disposable fixture may normalize the
original two configuration labels to exact installed policy before review.
Synthetic auth is an explicit
test dependency, never part of the manager's production CLI.
"""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys

HERE=Path(__file__).resolve().parent
MARKER=Path("/run/lmr365-disposable-primary-mailbox-vm")
BOOT=Path("/proc/sys/kernel/random/boot_id")
MAIL="lmr365-fixture@example.invalid"

def need(ok,reason):
    if not ok:
        raise RuntimeError(reason)

def command(*args):
    return subprocess.run(list(args),check=True,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,timeout=60,
                          env={"LC_ALL":"C","PATH":"/usr/sbin:/usr/bin:/sbin:/bin"}).stdout

def prepare_fixture_labels(C,config,queue,parent):
    """CI-only baseline preparation; never called by the product manager."""
    X,O=C.X,C.O
    O.same_directory(config,O.P.CONFIG)
    O.same_directory(queue,O.P.QUEUE)
    O.same_directory(parent,C.RECOVERY_PARENT)
    O.P.stopped_units()
    O.P.no_postfix_processes()
    O.P.empty_queue(queue)
    need(C.native_selinux_mode()=="enforcing","enforcing_fixture_required")
    before=tuple(X.T.config_file(config,name,0) for name in X.NAMES)
    expected=tuple(C.native_selinux_label("/etc/postfix/"+name,"file") for name in X.NAMES)
    mismatched=[]
    for name,(_,meta),label in zip(X.NAMES,before,expected):
        actual=X.normalized_label(meta["selinux"])
        desired=X.normalized_label(label)
        # Context strings contain no configuration values or identity data.
        print("LMR365_PRIMARY_VM_FIXTURE_LABEL "+name+" actual="+actual.decode("ascii")+
              " expected="+desired.decode("ascii"),flush=True)
        if actual!=desired:
            mismatched.append(name)
    if mismatched:
        # Prove the original refusal before changing even the lab fixture.
        try:
            C.native_selinux_offline(config,queue,parent)
        except X.Refused as error:
            need(str(error)=="selinux_label_policy_mismatch","unexpected_fixture_guard_refusal")
        else:
            raise RuntimeError("mismatched_label_was_accepted")
        need(tuple(X.T.config_file(config,name,0) for name in X.NAMES)==before and
             not (Path(C.RECOVERY_PARENT)/X.BASE).exists(),
             "refused_review_changed_original_configuration")
        print("LMR365_PRIMARY_VM_LABEL_MISMATCH=refused_without_write",flush=True)
        # Normalize only the known test files to installed policy.
        command("/usr/sbin/restorecon","-F",*["/etc/postfix/"+name for name in mismatched])
    else:
        print("LMR365_PRIMARY_VM_LABEL_MISMATCH=not_present",flush=True)
    after=tuple(X.T.config_file(config,name,0) for name in X.NAMES)
    for (old_data,old_meta),(new_data,new_meta),label in zip(before,after,expected):
        need(old_data==new_data and
             {k:v for k,v in old_meta.items() if k!="selinux"}==
             {k:v for k,v in new_meta.items() if k!="selinux"},
             "fixture_normalization_changed_bytes_or_permissions")
        X.same_label(new_meta["selinux"],label)
    O.P.stopped_units()
    O.P.no_postfix_processes()
    O.P.empty_queue(queue)
    need(C.native_selinux_mode()=="enforcing","fixture_enforcement_changed")
    print("LMR365_PRIMARY_VM_FIXTURE_POLICY=exact_context_baseline",flush=True)


def main():
    need(os.geteuid()==0 and os.environ.get("GITHUB_ACTIONS")=="true",
         "disposable_vm_only")
    st=MARKER.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
         stat.S_IMODE(st.st_mode)==0o600 and MARKER.read_bytes()==BOOT.read_bytes(),
         "boot_bound_marker_required")
    need(Path("/proc/1/comm").read_text().strip()=="systemd" and
         command("/usr/bin/hostname","-s").strip()==b"rocky-selinux-ci" and
         Path("/sys/fs/selinux/enforce").read_text().strip()=="1",
         "native_enforcing_guest_required")
    need("ID=\"rocky\"" in Path("/etc/os-release").read_text().splitlines() or
         "ID=rocky" in Path("/etc/os-release").read_text().splitlines(),"rocky_required")
    spec=importlib.util.spec_from_file_location("primary_native_vm_manager",
        str(HERE/"manage-primary-mailbox-offline.py"))
    C=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(C)
    X,O=C.X,C.O
    C.A.R.E.trusted_directory(HERE)
    need(not (Path("/var/lib")/X.BASE).exists(),"unexpected_existing_recovery_tree")
    need(not Path("/etc/postfix/m365-oauth/app.json").exists(),"real_identity_present")
    need(command("/usr/sbin/postqueue","-j").strip()==b"","queue_not_empty")
    need(command("/usr/sbin/postconf","-h","inet_interfaces").strip()==b"loopback-only",
         "loopback_only_required")
    need(command("/usr/bin/systemctl","is-active","postfix.service").strip()==b"active",
         "baseline_service_required")
    os.umask(0o077)
    fds=[]
    revision=None
    completed=False
    try:
        fds.append(O.route_lock())
        fds.append(C.A.C.lock())
        command("/usr/bin/systemctl","stop","postfix.service")
        for path in (C.RECOVERY_PARENT,O.P.CONFIG,O.P.QUEUE):
            fds.append(O.P.open_directory(path,strict=path!=O.P.QUEUE))
        parent,config,queue=fds[-3:]
        prepare_fixture_labels(C,config,queue,parent)
        # Only fixed, non-secret maintenance scope parameters in a disposable
        # VM. Keep native whitespace visible to diagnose version differences.
        scope=C.X.R.command("postconf",("-c",O.P.CONFIG,"-x",*C.SCOPE.keys()))
        need(scope.returncode==0 and not scope.stderr.strip() and
             len(scope.stdout)<=4096,"native_fixture_scope_unverified")
        print("LMR365_PRIMARY_VM_SCOPE_OUTPUT="+repr(scope.stdout),flush=True)
        need(C.X.R.parameter_map(scope.stdout.decode("utf-8","strict"))==C.SCOPE,
             "native_fixture_scope_mismatch")
        policy,guard=C.native_selinux_offline(config,queue,parent)
        baseline=X.snapshot(config,0,policy)
        native=C.read_native()
        def fixture_identity(mailbox):
            need(mailbox==MAIL,"unexpected_fixture_mailbox")
            return ("mailbox_matches","b"*64,"c"*64)
        def fixture_auth(mailbox):
            need(mailbox==MAIL,"unexpected_fixture_mailbox")
            return "a"*64
        def fresh():
            return X.review(config,0,MAIL,guard,fixture_auth,
                            identity_reader=fixture_identity,selinux=policy)
        revision,info,files=fresh()
        need(info["version"]==2 and info["native_before_sha256"]==X.digest(native),
             "native_review_mismatch")
        print("LMR365_PRIMARY_VM_REVIEW=native_policy_and_postconf",flush=True)
        need(X.apply(config,parent,revision,0,X.APPLY,guard,fresh,C.read_native,
                     fixture_auth,selinux=policy)==revision,"native_apply_failed")
        X.verify(config,0,info,files,"after",guard,C.read_native,selinux=policy)
        after=X.snapshot(config,0,policy)
        need(all(after[i][1]==baseline[i][1] for i in range(2)),
             "native_configuration_labels_changed")
        need(X.load_backup(parent,revision,0,policy)==(info,files),
             "native_private_recovery_not_verified")
        print("LMR365_PRIMARY_VM_APPLY=verified_native_labels",flush=True)
        print("LMR365_PRIMARY_VM_BACKUP=verified_native_private_labels",flush=True)
        # No service is started while the OAuth fixture route is installed.
        need(X.restore(config,parent,revision,0,X.RESTORE,guard,C.read_native,
                       selinux=policy)==revision,"native_restore_failed")
        need(X.snapshot(config,0,policy)==baseline and C.read_native()==native,
             "native_restore_mismatch")
        need(X.restore(config,parent,revision,0,X.RESTORE,guard,C.read_native,
                       selinux=policy)==revision,"native_restore_not_idempotent")
        guard()
        print("LMR365_PRIMARY_VM_RESTORE=exact_bytes_metadata_and_native",flush=True)
        completed=True
    finally:
        for fd in reversed(fds):
            os.close(fd)
        # On uncertainty never start with the candidate or perform a blind
        # rollback. The disposable VM is discarded by the outer runner.
        if completed:
            command("/usr/bin/systemctl","start","postfix.service")
            need(command("/usr/bin/systemctl","is-active","postfix.service").strip()==b"active",
                 "baseline_service_restart_failed")
            need(command("/usr/sbin/postqueue","-j").strip()==b"","queue_changed")
            need(Path("/sys/fs/selinux/enforce").read_text().strip()=="1","enforcement_changed")
            MARKER.unlink()
    print("LMR365_PRIMARY_VM_BASELINE=running_restored")
    print("LMR365_PRIMARY_VM_REAL_OAUTH_AUTH=no")
    print("LMR365_PRIMARY_VM_REAL_PIPE_DELIVERY=no")

if __name__=="__main__":
    main()
