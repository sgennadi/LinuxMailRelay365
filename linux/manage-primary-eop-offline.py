#!/usr/bin/env python3
"""Experimental offline primary EOP relayhost transaction.

Requires exclusive maintenance, a stopped default Postfix and empty queues.
Only an existing simple IPv4, no-AUTH, certificate-verified TLS configuration
is eligible. Changes one global relayhost assignment. Never starts, stops,
reloads, sends mail, changes a queue, or touches Exchange. Python 3.6+.
"""
import argparse
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys

_spec = importlib.util.spec_from_file_location(
    "offline_guards", str(Path(__file__).with_name("manage-conditional-postfix-offline.py")))
O = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(O)
P, T, M = O.P, O.T, O.M
Refused = M.Refused
BASE = "linuxmailrelay365-primary-eop-recovery"
FILES = ("main.before", "master.before", "main.after")
MANIFEST = "transaction.json"
CONFIRM = "APPLY_STOPPED_PRIMARY_EOP_RELAYHOST"
RESTORE = "RESTORE_STOPPED_PRIMARY_EOP_RELAYHOST"
CHECK = "CHECK_STOPPED_PRIMARY_EOP"
DNS = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
EMPTY = tuple(sorted(set(P.EMPTY_SETTINGS + (
    "virtual_alias_domains", "virtual_alias_maps", "virtual_mailbox_domains",
    "virtual_mailbox_maps", "relay_domains", "relay_recipient_maps",
    "recipient_canonical_maps", "relocated_maps", "sender_bcc_maps",
    "recipient_bcc_maps", "always_bcc", "header_checks", "body_checks",
    "mime_header_checks", "nested_header_checks", "smtpd_milters", "non_smtpd_milters",
    "smtp_bind_address", "smtp_bind_address6", "proxy_interfaces",
    "smtp_tls_chain_files", "smtp_tls_cert_file", "smtp_tls_key_file",
    "smtp_tls_eccert_file", "smtp_tls_eckey_file", "smtp_tls_dcert_file",
    "smtp_tls_dkey_file", "mailbox_transport", "mailbox_transport_maps",
))))
KEYS = tuple(sorted(set(P.KEYS + EMPTY + (
    "myhostname", "mydomain", "myorigin", "smtp_tls_mandatory_protocols",
))))
HOST = re.compile(DNS)
HOP = re.compile(r"(?:\["+DNS+r"\]|"+DNS+r")(?::[0-9]{1,5})?")
ASSIGNMENT = re.compile(rb"(?mi)^relayhost[ \t]*=[^\r\n]*$")


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def validate_target(mx, domain):
    need(type(mx) is str and len(mx) <= 253 and HOST.fullmatch(mx) and
         mx.endswith(".mail.protection.outlook.com") and
         type(domain) is str and len(domain) <= 253 and HOST.fullmatch(domain),
         "invalid_eop_mx_or_accepted_domain")


def read_policy(runner=M.native_command):
    rc, raw = runner("postconf", ["-c", P.CONFIG, "-x"] + list(KEYS))
    need(rc == 0, "effective_postfix_config_unavailable")
    return P.key_values(raw.decode("utf-8", "strict"), KEYS)


def validate_policy(values, domain):
    need(type(values) is dict and set(values) == set(KEYS), "incomplete_policy")
    ca = P.inspect_policy({key: values[key] for key in P.KEYS})
    need(all(not values[key] for key in EMPTY), "existing_route_or_filter_requires_manual_review")
    need(values["inet_protocols"] == "ipv4", "existing_ipv4_only_required")
    need(all(HOST.fullmatch(values[key]) for key in ("myhostname", "mydomain", "myorigin")),
         "static_mail_identity_required")
    local = [x.lower() for x in re.split(r"[\s,]+", values["mydestination"]) if x]
    need(bool(local) and len(local) <= 40 and all(
        x == "localhost" or HOST.fullmatch(x) for x in local), "static_local_destinations_required")
    need(not any(domain == x or domain.endswith("."+x) for x in local),
         "accepted_domain_may_be_local")
    protocols = values["smtp_tls_mandatory_protocols"]
    excluded = set(x for x in re.split(r"[\s,]+", protocols) if x)
    need(protocols in (">=TLSv1.2", ">=TLSv1.3") or
         excluded == {"!SSLv2", "!SSLv3", "!TLSv1", "!TLSv1.1"},
         "existing_tls12_minimum_required")
    old = values["relayhost"]
    need(not old or (len(old) <= 261 and HOP.fullmatch(old)), "existing_relayhost_requires_manual_review")
    if old and ":" in old:
        need(1 <= int(old.rsplit(":",1)[1]) <= 65535, "invalid_existing_relay_port")
    return ca


def proposed(main, old, mx):
    # Refuse complex continuations, duplicate assignments, macro-dependent
    # hops, and any other references to relayhost rather than guess semantics.
    need(type(main) is bytes and b"\0" not in main and b"\r" not in main and
         not re.search(rb"(?i)\$(?:\{|\()?relayhost\b", main),
         "unsupported_main_syntax_or_relayhost_reference")
    lines = list(ASSIGNMENT.finditer(main))
    need(len(lines) <= 1 and not re.search(rb"(?mi)^[ \t]+relayhost[ \t]*=", main),
         "ambiguous_relayhost_assignment")
    desired = ("relayhost = ["+mx+"]:25").encode("ascii")
    if not lines:
        need(not old, "effective_relayhost_not_literal")
        result = main + (b"" if main.endswith(b"\n") else b"\n") + desired + b"\n"
    else:
        match = lines[0]
        tail = main[match.end():].split(b"\n",2)
        need(len(tail) < 2 or not tail[1].startswith((b" ", b"\t")),
             "relayhost_continuation_requires_manual_review")
        need(match.group().split(b"=",1)[1].strip().decode("ascii") == old,
             "effective_relayhost_not_literal")
        result = main[:match.start()] + desired + main[match.end():]
    need(old not in ("["+mx+"]", "["+mx+"]:25") and result != main and len(result) <= T.LIMIT,
         "no_relayhost_change")
    return result


def snapshot(config, uid):
    return tuple(T.config_file(config, name, uid) for name in ("main.cf", "master.cf"))


def review(config, uid, mx, domain, guard, reader=read_policy, master_check=P.inspect_master,
           ca_digest=P.trust_store_digest):
    validate_target(mx, domain)
    guard()
    (main, main_meta), (master, master_meta) = snapshot(config, uid)
    T.valid_meta(main_meta, False)
    T.valid_meta(master_meta, False)
    need(not re.search(rb"(?i)\$(?:\{|\()?relayhost\b", master), "master_relayhost_reference")
    values = reader()
    ca = validate_policy(values, domain)
    master_check()
    ca_sha = ca_digest(ca)
    need(O.sha(ca_sha), "invalid_trust_store_digest")
    desired = dict(values, relayhost="["+mx+"]:25")
    files = dict(zip(FILES, (main, master, proposed(main, values["relayhost"], mx))))
    info = dict(version=1, mx=mx, accepted_domain=domain, config_identity=T.context(config,uid),
                main_meta=main_meta, master_meta=master_meta, old_relayhost=values["relayhost"],
                ca_sha256=ca_sha, before_policy_sha256=M.digest(M.canonical(values)),
                after_policy_sha256=M.digest(M.canonical(desired)),
                files={key:M.digest(value) for key,value in files.items()})
    guard()
    need(snapshot(config,uid) == ((main,main_meta),(master,master_meta)) and
         reader() == values and ca_digest(ca) == ca_sha, "review_context_drift")
    return M.digest(M.canonical(info)), info, files


def save_backup(parent, sha, info, files, uid):
    need(M.digest(M.canonical(info)) == sha and set(files) == set(FILES) and
         info["files"] == {k:M.digest(v) for k,v in files.items()}, "invalid_backup")
    base = M.open_base(parent,uid,create=True,name=BASE)
    try:
        os.mkdir(sha,0o700,dir_fd=base)
        os.fsync(base)
        folder = os.open(sha,M.DIR_FLAGS,dir_fd=base)
        try:
            M.check_directory(folder,uid,True)
            for name in FILES:
                M.write_file(folder,name,files[name])
            M.write_file(folder,MANIFEST,M.canonical(info))
            os.fsync(folder)
            os.fsync(base)
        finally:
            os.close(folder)
    finally:
        os.close(base)


def load_backup(parent, sha, uid):
    need(O.sha(sha), "invalid_backup_sha")
    base = M.open_base(parent,uid,name=BASE)
    try:
        folder = os.open(sha,M.DIR_FLAGS,dir_fd=base)
        try:
            M.check_directory(folder,uid,True)
            need(set(os.listdir(folder)) == set(FILES)|{MANIFEST}, "incomplete_backup")
            raw = M.read_file(folder,MANIFEST,uid)
            info = M.decode(raw)
            need(type(info) is dict and set(info) == {"version","mx","accepted_domain",
                 "config_identity","main_meta","master_meta","old_relayhost","ca_sha256",
                 "before_policy_sha256","after_policy_sha256","files"} and
                 type(info["version"]) is int and info["version"] == 1 and
                 M.canonical(info) == raw and M.digest(raw) == sha, "invalid_backup_manifest")
            validate_target(info["mx"],info["accepted_domain"])
            need(type(info["old_relayhost"]) is str and
                 (not info["old_relayhost"] or HOP.fullmatch(info["old_relayhost"])),
                 "invalid_backup_old_relayhost")
            for key in ("ca_sha256","before_policy_sha256","after_policy_sha256"):
                need(O.sha(info[key]),"invalid_backup_digest")
            for key in ("main_meta","master_meta"):
                T.valid_meta(info[key],False)
            files = {name:M.read_file(folder,name,uid,T.LIMIT) for name in FILES}
            need(info["files"] == {k:M.digest(v) for k,v in files.items()} and
                 files["main.after"] == proposed(files["main.before"],info["old_relayhost"],info["mx"]),
                 "backup_integrity_mismatch")
            return info,files
        finally:
            os.close(folder)
    finally:
        os.close(base)


def verify(config, uid, info, files, phase, guard, reader=read_policy,
           master_check=P.inspect_master, ca_digest=P.trust_store_digest):
    guard()
    expected_main = files["main."+phase]
    need(T.context(config,uid) == info["config_identity"] and
         snapshot(config,uid) == ((expected_main,info["main_meta"]),
                                  (files["master.before"],info["master_meta"])),
         "configuration_bytes_or_metadata_changed")
    values = reader()
    ca = validate_policy(values,info["accepted_domain"])
    master_check()
    need(M.digest(M.canonical(values)) == info[phase+"_policy_sha256"] and
         ca_digest(ca) == info["ca_sha256"],"effective_policy_or_trust_changed")
    guard()
    need(snapshot(config,uid) == ((expected_main,info["main_meta"]),
                                 (files["master.before"],info["master_meta"])),
         "configuration_changed_after_native_readback")


def restore(config,parent,sha,uid,confirmation,guard,reader=read_policy,
            master_check=P.inspect_master,ca_digest=P.trust_store_digest):
    need(confirmation == RESTORE,"explicit_restore_required")
    info,files = load_backup(parent,sha,uid)
    guard()
    (main,meta),(master,master_meta) = snapshot(config,uid)
    need(T.context(config,uid) == info["config_identity"] and meta == info["main_meta"] and
         (master,master_meta) == (files["master.before"],info["master_meta"]) and
         main in (files["main.before"],files["main.after"]), "unrelated_configuration_drift_blocks_restore")
    phase = "before" if main == files["main.before"] else "after"
    verify(config,uid,info,files,phase,guard,reader,master_check,ca_digest)
    if phase == "after":
        guard()
        need(snapshot(config,uid) == ((main,meta),(master,master_meta)),"drift_before_restore")
        T.atomic_write(config,"main.cf",files["main.before"],meta,uid,True)
    verify(config,uid,info,files,"before",guard,reader,master_check,ca_digest)
    return sha


def apply(config,parent,uid,expected,confirmation,guard,fresh,network,
          reader=read_policy,master_check=P.inspect_master,ca_digest=P.trust_store_digest):
    need(confirmation == CONFIRM and O.sha(expected),"explicit_reviewed_apply_required")
    reviewed = fresh()
    sha,info,files = reviewed
    need(sha == expected,"reviewed_plan_changed")
    network(info)
    need(fresh() == reviewed,"configuration_changed_during_network_check")
    save_backup(parent,sha,info,files,uid)
    need(load_backup(parent,sha,uid) == (info,files),"backup_verification_failed")
    need(fresh() == reviewed,"configuration_changed_during_backup")
    verify(config,uid,info,files,"before",guard,reader,master_check,ca_digest)
    try:
        guard()
        need(snapshot(config,uid) == ((files["main.before"],info["main_meta"]),
                                    (files["master.before"],info["master_meta"])),"drift_before_write")
        T.atomic_write(config,"main.cf",files["main.after"],info["main_meta"],uid,True)
        verify(config,uid,info,files,"after",guard,reader,master_check,ca_digest)
    except Exception:
        try:
            restore(config,parent,sha,uid,RESTORE,guard,reader,master_check,ca_digest)
        except Exception as error:
            raise T.RollbackRequired("manual_recovery_required") from error
        raise
    return sha


def network_check(info):
    def public_resolver(host,port,**kwargs):
        rows = socket.getaddrinfo(host,port,family=socket.AF_INET,**kwargs)
        for row in rows:
            ip=ipaddress.IPv4Address(row[4][0])
            need(ip.is_global and not ip.is_multicast and not ip.is_reserved,
                 "nonpublic_eop_ipv4")
        return rows
    def tls_check(host,port,peer,ctx):
        if hasattr(ssl,"TLSVersion"):
            ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        else:
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        return P.tls_peer(host,port,peer,ctx)
    ca = validate_policy(read_policy(),info["accepted_domain"])
    need(P.trust_store_digest(ca) == info["ca_sha256"],"trust_store_changed")
    P.network_evidence([{"host":info["mx"],"port":25}],ca,P.local_addresses(),
                       resolve=public_resolver,check=tls_check)
    need(P.trust_store_digest(ca) == info["ca_sha256"],"trust_store_changed")


def native_check():
    # Native check may repair directory metadata. It is not read-only.
    spec = importlib.util.spec_from_file_location(
        "postfix_adapter", str(Path(__file__).with_name("smtp-tls-postfix.py")))
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    binary = adapter.trusted_invocation("/usr/sbin/postfix")
    result = subprocess.run([binary, "-c", P.CONFIG, "check"], input=b"",
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=60, env=P.SYSTEM_ENV)
    need(result.returncode == 0, "native_postfix_check_failed")


def check_backup(config,parent,sha,uid,confirmation,guard,checker=native_check,
                 reader=read_policy,master_check=P.inspect_master,ca_digest=P.trust_store_digest):
    need(confirmation == CHECK, "explicit_check_required")
    info,files = load_backup(parent,sha,uid)
    verify(config,uid,info,files,"after",guard,reader,master_check,ca_digest)
    checker()
    verify(config,uid,info,files,"after",guard,reader,master_check,ca_digest)
    return sha


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--review",action="store_true")
    modes.add_argument("--apply",action="store_true")
    modes.add_argument("--restore",metavar="BACKUP_SHA256")
    modes.add_argument("--check",metavar="BACKUP_SHA256")
    parser.add_argument("--mx")
    parser.add_argument("--accepted-domain")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--confirm")
    parser.add_argument("--maintenance-confirmation")
    args=parser.parse_args(argv)
    fds=[]
    attempted=False
    def timeout(*_):
        raise Refused("operation_timeout")
    try:
        need(os.geteuid() == 0 and args.maintenance_confirmation == O.MAINTENANCE,
             "root_and_exclusive_maintenance_required")
        if args.restore is not None or args.check is not None:
            backup_sha = args.restore if args.restore is not None else args.check
            required = RESTORE if args.restore is not None else CHECK
            need(O.sha(backup_sha) and args.confirm == required and
                 all(x is None for x in (args.mx,args.accepted_domain,args.expected_sha256)),
                 "invalid_backup_operation_request")
        else:
            validate_target(args.mx,args.accepted_domain)
            need((args.apply and O.sha(args.expected_sha256) and args.confirm == CONFIRM) or
                 (args.review and args.expected_sha256 is None and args.confirm is None),
                 "invalid_review_or_apply_request")
        os.umask(0o077)
        signal.signal(signal.SIGALRM,timeout)
        signal.alarm(240)
        fds.append(O.route_lock())
        for path in ("/var/lib",P.CONFIG,P.QUEUE):
            fds.append(P.open_directory(path,strict=path != P.QUEUE))
        _,parent,config,queue=fds
        identity=O.mail_identity()
        def guard():
            O.maintenance(config,queue,identity)
        def fresh():
            return review(config,0,args.mx,args.accepted_domain,guard)
        if args.review:
            reviewed=fresh()
            sha,info,_=reviewed
            network_check(info)
            need(fresh()==reviewed,"review_changed_during_network_check")
            print("PRIMARY_EOP_OFFLINE_STATUS=reviewed_experimental")
            print("PRIMARY_EOP_OFFLINE_SHA256="+sha)
            print("PRIMARY_EOP_OFFLINE_OLD_RELAYHOST="+info["old_relayhost"])
            print("PRIMARY_EOP_OFFLINE_NEW_RELAYHOST=["+info["mx"]+"]:25")
            print("PRIMARY_EOP_OFFLINE_POSTFIX_CHANGED=no")
        elif args.apply:
            attempted=True
            sha=apply(config,parent,0,args.expected_sha256,args.confirm,guard,fresh,network_check)
            print("PRIMARY_EOP_OFFLINE_STATUS=applied_offline_not_started")
            print("PRIMARY_EOP_OFFLINE_BACKUP_SHA256="+sha)
            print("PRIMARY_EOP_OFFLINE_POSTFIX_CHANGED=yes")
        elif args.check is not None:
            attempted=True
            sha=check_backup(config,parent,args.check,0,args.confirm,guard)
            print("PRIMARY_EOP_OFFLINE_STATUS=checked_offline_not_started")
            print("PRIMARY_EOP_OFFLINE_BACKUP_SHA256="+sha)
            print("PRIMARY_EOP_OFFLINE_POSTFIX_CHANGED=no")
        else:
            attempted=True
            sha=restore(config,parent,args.restore,0,args.confirm,guard)
            print("PRIMARY_EOP_OFFLINE_STATUS=restored_offline_not_started")
            print("PRIMARY_EOP_OFFLINE_BACKUP_SHA256="+sha)
            print("PRIMARY_EOP_OFFLINE_POSTFIX_CHANGED=restored")
        return 0
    except T.RollbackRequired:
        print("PRIMARY_EOP_OFFLINE_STATUS=manual_recovery_required")
        print("PRIMARY_EOP_OFFLINE_POSTFIX_CHANGED=inspect_recovery")
        if O.sha(args.expected_sha256):
            print("PRIMARY_EOP_OFFLINE_BACKUP_SHA256="+args.expected_sha256)
    except (Refused,OSError,ValueError,TypeError,KeyError,IndexError,subprocess.SubprocessError):
        print("PRIMARY_EOP_OFFLINE_STATUS=refused_or_failed")
        print("PRIMARY_EOP_OFFLINE_POSTFIX_CHANGED="+("inspect_recovery" if attempted else "no"))
    finally:
        signal.alarm(0)
        for fd in reversed(fds):
            os.close(fd)
        print("PRIMARY_EOP_OFFLINE_SERVICE_STARTED=no")
        print("PRIMARY_EOP_OFFLINE_MAIL_SENT=no")
        print("PRIMARY_EOP_OFFLINE_QUEUE_MODIFIED="+("not_verified" if args.check is not None and attempted else "no"))
    return 2


if __name__ == "__main__":
    sys.exit(main())
