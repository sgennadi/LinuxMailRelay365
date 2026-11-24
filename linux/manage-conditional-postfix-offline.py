#!/usr/bin/env python3
"""Experimental, explicitly approved offline sender-map Apply/Restore.

Never stops/starts/reloads a service, installs a package, changes listeners,
sends mail, changes queues or changes an existing map. Requires the operator
to prevent all concurrent submissions, configuration changes and service
starts during maintenance. Only a conservative existing STARTTLS/no-AUTH
Postfix configuration is eligible. Not a production release.
"""
import argparse
import fcntl
import grp
import importlib.util
import os
import pathlib
import pwd
import re
import signal
import stat
import subprocess
import sys

_spec = importlib.util.spec_from_file_location(
    "conditional_preflight", str(pathlib.Path(__file__).with_name(
        "inspect-conditional-postfix-activation.py")))
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)
T, M = P.T, P.M
Refused = M.Refused
MAINTENANCE = "I_HAVE_PREVENTED_CONCURRENT_MAIL_AND_CONFIG_CHANGES"
LOCK = "/run/linuxmailrelay365-postfix-route.lock"


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def sha(value):
    return type(value) is str and M.HEX.fullmatch(value) is not None


def route_lock():
    directory = P.open_directory("/run")
    try:
        fd = os.open(os.path.basename(LOCK), os.O_RDWR | os.O_CREAT |
                     os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     0o600, dir_fd=directory)
        try:
            meta = os.fstat(fd)
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
                 meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o600,
                 "untrusted_route_lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(directory)


def mail_identity():
    account = pwd.getpwnam("postfix")
    group = grp.getgrnam("postfix")
    need(account.pw_uid != 0 and account.pw_gid != 0 and
         group.gr_gid == account.pw_gid, "unverified_postfix_account")
    return account.pw_uid, group.gr_gid


def same_directory(fd, path):
    now = os.stat(path, follow_symlinks=False)
    current = os.fstat(fd)
    need(stat.S_ISDIR(now.st_mode) and
         (now.st_dev, now.st_ino) == (current.st_dev, current.st_ino),
         "maintenance_directory_replaced")


def maintenance(config, queue, identity):
    # The transaction currently refuses all extended attributes rather than
    # accidentally discarding ACLs or security labels. SELinux support must
    # be implemented and verified before allowing writes on those hosts.
    need(not os.path.exists("/sys/fs/selinux/enforce"),
         "selinux_metadata_restore_not_implemented")
    same_directory(config, P.CONFIG)
    same_directory(queue, P.QUEUE)
    M.check_directory(config, 0)
    need(not os.listxattr(config), "extended_directory_metadata_unsupported")
    need(mail_identity() == identity, "postfix_account_changed")
    P.stopped_units()
    P.no_postfix_processes()
    P.empty_queue(queue)


def review_digest(evidence, identity):
    return M.digest(M.canonical({"format": "LMR365-OFFLINE-APPLY-V1",
                                "preflight": evidence,
                                "postfix_uid": identity[0],
                                "postfix_gid": identity[1]}))


def native_unprivileged(arguments, identity, data=None):
    uid, gid = identity
    def drop_privileges():
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    try:
        result = subprocess.run(
            [M.trusted_postfix_tool("postmap")] + arguments,
            input=data if data is not None else b"",
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=P.SYSTEM_ENV, timeout=15, check=False,
            preexec_fn=drop_privileges)
    except (OSError, subprocess.SubprocessError):
        raise Refused("native_unprivileged_map_lookup_failed")
    need(len(result.stdout) <= M.MAX_BYTES, "native_lookup_oversized")
    return result.returncode, result.stdout


def verify_active_map(spec, rules, identity, runner=native_unprivileged):
    # Only the exact manager-owned sender map; no existing live map, no
    # password map, and no delivery or lookup against arbitrary backends.
    need(re.fullmatch(r"(hash|lmdb):/etc/postfix/lmr365-conditional-[a-f0-9]{64}-sender",
                      spec) is not None, "untrusted_active_map_spec")
    _, sources = M.build(rules)
    wanted = M.candidate_rows(sources["sender-candidates.txt"])
    need(bool(wanted), "empty_sender_map")
    prefix = ["-c", P.CONFIG]
    code, found = runner(prefix + ["-s", spec], identity)
    need(code == 0 and M.native_rows(found) == wanted,
         "active_map_enumeration_mismatch")
    code, found = runner(prefix + ["-q", "-", spec], identity,
                         ("\n".join(wanted) + "\n").encode("ascii"))
    need(code == 0 and M.native_rows(found) == wanted,
         "active_map_key_mismatch")
    code, found = runner(prefix + ["-q", M.NEGATIVE_KEY, spec], identity)
    need(code == 1 and not found.strip(), "active_map_negative_lookup_failed")


def review_host(parent, config, queue, plan, compiled, identity, guard):
    guard()
    transaction, proof, count, policy, rules = P.review(
        parent, config, queue, plan, compiled)
    guard()
    return transaction, review_digest(proof, identity), count, policy, rules


def apply_reviewed(parent, config, queue, plan, compiled, transaction_sha,
                   approved_evidence, identity, guard, reviewer=review_host,
                   active_lookup=verify_active_map, read_policy=P.postconf_values,
                   read_master=P.inspect_master):
    approved = [None]
    def fresh():
        result = reviewer(parent, config, queue, plan, compiled, identity, guard)
        transaction, evidence, count, policy, rules = result
        need(transaction[0] == transaction_sha and
             evidence == approved_evidence, "reviewed_evidence_changed")
        if approved[0] is None:
            approved[0] = result
        else:
            need(result == approved[0], "review_changed_during_backup")
        return transaction

    def verify(spec):
        guard()
        need(approved[0] is not None, "missing_review_context")
        _, _, _, baseline, rules = approved[0]
        wanted = dict(baseline)
        wanted[T.PARAMETER] = spec
        need(read_policy() == wanted, "effective_policy_changed")
        read_master()
        if spec:
            active_lookup(spec, rules, identity)
        guard()

    return T.apply(config, parent, transaction_sha, T.CONFIRM, 0, identity[1],
                   guard, verify, fresh)


def restore_reviewed(parent, config, backup_sha, identity, guard,
                     read_policy=P.postconf_values, read_master=P.inspect_master):
    def verify(spec):
        guard()
        need(spec == "", "unexpected_restore_map")
        P.inspect_policy(read_policy())
        read_master()
        guard()
    return T.restore(config, parent, backup_sha, T.RESTORE, 0, identity[1],
                     guard, verify)


def output(status, **fields):
    print("CONDITIONAL_OFFLINE_STATUS=" + status)
    for key, value in fields.items():
        print("CONDITIONAL_OFFLINE_" + key.upper() + "=" + str(value))
    print("CONDITIONAL_OFFLINE_SERVICE_STARTED=no")
    print("CONDITIONAL_OFFLINE_MAIL_SENT=no")
    print("CONDITIONAL_OFFLINE_QUEUE_MODIFIED=no")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--review", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--restore", metavar="BACKUP_SHA256")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--compiled-sha256")
    parser.add_argument("--approve-transaction-sha256")
    parser.add_argument("--approve-evidence-sha256")
    parser.add_argument("--confirm")
    parser.add_argument("--maintenance-confirmation")
    args = parser.parse_args(argv)
    descriptors = []
    attempted_write = False
    def timed_out(signum, frame):
        raise Refused("offline_operation_timeout")
    try:
        need(os.geteuid() == 0, "root_required")
        need(args.maintenance_confirmation == MAINTENANCE,
             "explicit_exclusive_maintenance_required")
        if args.restore is not None:
            need(sha(args.restore) and args.confirm == T.RESTORE and
                 all(x is None for x in (args.plan_sha256, args.compiled_sha256,
                                         args.approve_transaction_sha256,
                                         args.approve_evidence_sha256)),
                 "invalid_restore_approval")
        else:
            need(sha(args.plan_sha256) and sha(args.compiled_sha256),
                 "candidate_digests_required")
            if args.apply:
                need(sha(args.approve_transaction_sha256) and
                     sha(args.approve_evidence_sha256) and args.confirm == T.CONFIRM,
                     "invalid_apply_approval")
            else:
                need(all(x is None for x in (args.confirm,
                     args.approve_transaction_sha256, args.approve_evidence_sha256)),
                     "unexpected_review_approval")
        os.umask(0o077)
        signal.signal(signal.SIGALRM, timed_out)
        signal.alarm(240)
        descriptors.append(route_lock())
        for path in ("/var/lib", P.CONFIG, P.QUEUE):
            descriptors.append(P.open_directory(path, strict=path != P.QUEUE))
        _, parent, config, queue = descriptors
        identity = mail_identity()
        def guard():
            maintenance(config, queue, identity)
        guard()
        if args.review:
            txn, evidence, count, _, _ = review_host(
                parent, config, queue, args.plan_sha256, args.compiled_sha256,
                identity, guard)
            output("reviewed_offline_experimental", transaction_sha256=txn[0],
                   evidence_sha256=evidence, tls_destinations=count,
                   postfix_changed="no")
        elif args.apply:
            attempted_write = True
            backup = apply_reviewed(parent, config, queue, args.plan_sha256,
                args.compiled_sha256, args.approve_transaction_sha256,
                args.approve_evidence_sha256, identity, guard)
            output("applied_offline_not_started", backup_sha256=backup,
                   postfix_changed="yes")
        else:
            attempted_write = True
            backup = restore_reviewed(parent, config, args.restore, identity, guard)
            output("restored_offline_not_started", backup_sha256=backup,
                   postfix_changed="restored")
        return 0
    except T.RollbackRequired:
        output("manual_recovery_required", postfix_changed="unknown",
               backup_sha256=args.approve_transaction_sha256)
    except (Refused, OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.SubprocessError):
        # Never disclose config values, addresses, SMTP responses, or secrets.
        # An interrupted operation may have retained a recovery snapshot;
        # never falsely claim rollback/unchanged state based on an exit code.
        output("refused_or_failed", postfix_changed="inspect_recovery" if
               attempted_write else "no")
    finally:
        signal.alarm(0)
        for fd in reversed(descriptors):
            os.close(fd)
    return 2


if __name__ == "__main__":
    sys.exit(main())
