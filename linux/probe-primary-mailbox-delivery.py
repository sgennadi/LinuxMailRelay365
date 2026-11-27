#!/usr/bin/env python3
"""Experimental, reviewed two-recipient probe through the running primary Postfix.

Reuses the native sendmail submission and durable run ledger, NOT direct SMTP
submission. No service control, queue flush, retry, credential or config write.
Keep other submissions blocked during acceptance. SMTP acceptance is not inbox
delivery. Missing/ambiguous journal evidence stays unknown.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

HERE=Path(__file__).resolve().parent

def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,str(HERE/filename))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

C=load("primary_probe_offline","manage-primary-mailbox-offline.py")
P=load("primary_probe_existing","review-postfix-m365-delivery.py")
X,A,O=C.X,C.A,C.O
CONFIRM="SEND_REVIEWED_PRIMARY_MAILBOX_TESTS"
KEYS={"run_id","sender","internal","external","accepted_domain","backup_sha256",
      "tenant_id","client_id"}
EMPTY=tuple(sorted(set(P.EMPTY+("always_bcc","sender_bcc_maps","recipient_bcc_maps",
    "masquerade_domains","receive_override_options","message_reject_characters"))))

def need(condition,reason):
    if not condition:
        raise ValueError(reason)

def validate_request(req):
    need(type(req) is dict and set(req)==KEYS and
         all(type(v) is str for v in req.values()),"invalid_request")
    need(P.RUN.fullmatch(req["run_id"]) and X.sha(req["backup_sha256"]),
         "invalid_review_identity")
    A.exact_guid(req["tenant_id"])
    A.exact_guid(req["client_id"])
    for key in ("sender",*P.ROLES):
        value=req[key]
        need(value==value.lower() and len(value)<=254 and P.MAIL.fullmatch(value) and
             ".." not in value and P.DNS.fullmatch(P.domain_of(value)),"invalid_mailbox")
    X.R.parse(X.R.encode({"mailbox":req["sender"],"nonce":"0"*64}))
    domain=req["accepted_domain"]
    need(P.DNS.fullmatch(domain) and len(domain)<=253 and
         P.domain_of(req["sender"])==domain and P.domain_of(req["internal"])==domain and
         P.domain_of(req["external"])!=domain and req["internal"]!=req["external"],
         "recipient_domain_mismatch")
    return req

def policy(read,overrides,req):
    need(not overrides.strip(),"service_specific_override")
    values={key:read(key) for key in EMPTY+("config_directory","multi_instance_enable",
        "multi_instance_directories","queue_directory","mail_owner","default_transport",
        "relay_transport","relayhost","syslog_name","cleanup_service_name","mydestination",
        "relay_domains","m365xoauth2_destination_recipient_limit","sendmail_path")}
    need(all(not values[key] for key in EMPTY),"routing_or_rewrite_override")
    need(all(values[key]==value for key,value in C.SCOPE.items()),"unsupported_instance")
    need(values["default_transport"]==values["relay_transport"]=="m365xoauth2:" and
         not values["relayhost"] and values["syslog_name"]=="postfix" and
         values["cleanup_service_name"]=="cleanup" and
         values["m365xoauth2_destination_recipient_limit"]=="1","route_not_exact")
    for key in ("mydestination","relay_domains"):
        domains=[v.lower() for v in re.split(r"[\s,]+",values[key]) if v]
        need(all(P.DNS.fullmatch(v) or v=="localhost" for v in domains),
             "dynamic_destination_list")
        if key=="mydestination":
            need(not any(P.domain_of(req[role])==d or P.domain_of(req[role]).endswith("."+d)
                         for role in P.ROLES for d in domains),"recipient_may_be_local")
    return values

def running_guard(config,queue,parent,identity):
    O.same_directory(config,O.P.CONFIG)
    O.same_directory(queue,O.P.QUEUE)
    O.same_directory(parent,C.RECOVERY_PARENT)
    O.M.check_directory(config,0)
    O.M.check_directory(parent,0)
    need(O.mail_identity()==identity and not os.listxattr(config) and
         not os.path.exists("/sys/fs/selinux/enforce"),"running_context_changed")
    C.verify_scope(config)
    C.running_status()

def prepare(req,config,queue,parent,adapter=None):
    validate_request(req)
    identity=O.mail_identity()
    def guard():
        running_guard(config,queue,parent,identity)
    info,files=X.load_backup(parent,req["backup_sha256"],0)
    need(info["mailbox"]==req["sender"],"backup_mailbox_mismatch")
    X.verify(config,0,info,files,"after",guard,C.read_native)
    def runtime():
        need(A.digest(A.installed_snapshot(req["sender"],req["tenant_id"],req["client_id"]))==
             info["runtime_sha256"],"installed_runtime_changed")
    runtime()
    adapter=adapter or P.load_adapter()
    pf=adapter.Postfix()
    def current_policy():
        return policy(lambda key:pf.run(pf.postconf,"-h","-x",key),
                      pf.run(pf.postconf,"-P"),req)
    values=current_policy()
    binary=adapter.trusted_binary("/usr/sbin/sendmail")
    need(binary==adapter.trusted_binary(values["sendmail_path"]),"sendmail_identity_mismatch")
    P.verify_postfix_package(binary,adapter)
    def executable_identity():
        st=os.stat(binary)
        return [binary,st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]
    executable=executable_identity()
    need(pf.run(pf.postconf,"-M","m365xoauth2/unix").split()==X.R.PIPE.decode("ascii").split(),
         "pipe_service_not_exact")
    X.verify(config,0,info,files,"after",guard,C.read_native)
    runtime()
    need(current_policy()==values and executable_identity()==executable,
         "probe_dependencies_changed")
    guard()
    need(X.phase(config,0,info,files)=="after","configuration_changed")
    evidence={"version":1,"request_sha256":P.digest(P.canonical(req)),
              "backup_sha256":req["backup_sha256"],"runtime_sha256":info["runtime_sha256"],
              "native_sha256":info["native_after_sha256"],"policy_sha256":P.digest(P.canonical(values)),
              "sendmail_identity":executable}
    return {"status":"review_ready","run_id":req["run_id"],"plan_sha256":P.digest(P.canonical(evidence)),
            "backup_sha256":req["backup_sha256"],"runtime_sha256":info["runtime_sha256"],
            "mail_sent":False,"inbox_verified":False,"recipient_role_proof":"domain_comparison_only",
            "automatic_retry":False,"_binary":binary}

def submit(req,expected,confirm,prepare_fn,runner=subprocess.run):
    need(confirm==CONFIRM and X.sha(expected),"explicit_reviewed_submission_required")
    # Existing implementation reserves the run ID durably before sendmail,
    # rechecks the exact plan for each message and never retries uncertainty.
    return P.submit(req,expected,prepare_fn=prepare_fn,runner=runner)

def journal_rows(started,adapter,runner=subprocess.run):
    try:
        binary=adapter.trusted_binary("/usr/bin/journalctl")
        result=runner([binary,"--no-pager","-o","json","-n","4000",
                       "--since=@"+str(max(0,started-5)),"-t","postfix/cleanup",
                       "-t","postfix/pipe"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                      timeout=25,env=P.ENV)
        if result.returncode or len(result.stdout)>8*1024*1024:
            return [],"journal_unavailable"
        rows=[json.loads(line,object_pairs_hook=P.strict_object) for line in result.stdout.splitlines()]
        return rows,"journal_recent_only"
    except (OSError,ValueError,subprocess.SubprocessError):
        return [],"journal_unavailable"

def verified_messages(rows,kind):
    for row in rows:
        if type(row) is not dict or row.get("SYSLOG_IDENTIFIER")!="postfix/"+kind:
            continue
        exe=row.get("_EXE")
        message=row.get("MESSAGE")
        # Trusted journal metadata, not a message's embedded sender/response.
        if (type(exe) is str and exe in ("/usr/lib/postfix/sbin/"+kind,
            "/usr/libexec/postfix/"+kind,"/usr/lib/postfix/"+kind) and
            row.get("_COMM")==kind and type(message) is str and
            len(message)<=16384 and "\n" not in message and "\r" not in message):
            yield message

def correlate(req,role,rows,queue,attempted):
    # Reuse existing cleanup Message-ID correlation and queue observation.
    observed=P.correlate(req,role,list(verified_messages(rows,"cleanup")),queue,attempted)
    ident=observed.get("queue_id")
    if ident is None:
        return observed
    prefix=ident+": to=<"+req[role]+">,"
    terminal=set()
    last=None
    for line in verified_messages(rows,"pipe"):
        if not line.startswith(prefix):
            continue
        fields,sep,diagnostic=line[len(prefix):].partition(" (")
        state=re.search(r"(?:^|,)\s*status=(sent|deferred|bounced)$",fields)
        dsn=re.search(r"(?:^|,)\s*dsn=([245]\.[0-9]{1,3}\.[0-9]{1,3})(?=,|$)",fields)
        relay=re.search(r"(?:^|,)\s*relay=m365xoauth2(?=,|$)",fields)
        if not state or not dsn or not relay:
            continue
        status=state.group(1)
        code=dsn.group(1)
        if not code.startswith({"sent":"2.","deferred":"4.","bounced":"5."}[status]):
            continue
        if status in ("sent","bounced"):
            terminal.add(status)
        last={"dsn":code,"transport":status}
        if status=="sent":
            last["transport"]=("exchange_smtp_accepted" if sep and diagnostic==
                "delivered via m365xoauth2 service (2.0.0 Accepted by Microsoft 365 SMTP))"
                else "pipe_sent_exchange_unverified")
    if len(terminal)>1 or (terminal and last and last["transport"]=="deferred"):
        observed["transport"]="correlation_unavailable"
    elif last:
        observed.update(last)
    return observed

def trace(req,adapter=None):
    validate_request(req)
    started,events,plan=P.ledger(req,include_plan=True)
    adapter=adapter or P.load_adapter()
    rows,source=journal_rows(started,adapter)
    queue=P.queue_rows(adapter)
    return {"status":"trace_observed","run_id":req["run_id"],"plan_sha256":plan,
            "source":source,"started_unix":started,"request_sha256":P.digest(P.canonical(req)),
            "outcomes":{role:correlate(req,role,rows,queue,events[role])
                                        for role in P.ROLES},
            "inbox_verified":False,"automatic_retry":False}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("preview","submit","trace"))
    parser.add_argument("--expected-sha")
    parser.add_argument("--confirm")
    args=parser.parse_args(argv)
    fds=[]
    run=None
    try:
        need(os.geteuid()==0,"root_required")
        os.umask(0o077)
        A.R.E.trusted_directory(HERE)
        raw=sys.stdin.buffer.read(4097)
        need(0<len(raw)<=4096,"request_size")
        req=validate_request(json.loads(raw,object_pairs_hook=P.strict_object))
        run=req["run_id"]
        if args.action!="submit":
            need(args.expected_sha is None and args.confirm is None,"unexpected_approval")
        else:
            need(X.sha(args.expected_sha) and args.confirm==CONFIRM,"approval_required")
        def expired(*_):
            raise ValueError("probe_timeout")
        signal.signal(signal.SIGALRM,expired)
        signal.alarm(480)
        if args.action=="trace":
            report=trace(req)
        else:
            fds.append(O.route_lock())
            fds.append(A.C.lock())
            for path in (C.RECOVERY_PARENT,O.P.CONFIG,O.P.QUEUE):
                fds.append(O.P.open_directory(path,strict=path!=O.P.QUEUE))
            parent,config,queue=fds[-3:]
            def fresh(request):
                return prepare(request,config,queue,parent)
            if args.action=="preview":
                report=fresh(req)
                report.pop("_binary")
            else:
                report=submit(req,args.expected_sha,args.confirm,fresh)
        print(json.dumps(report))
        return 0
    except Exception:
        # No raw diagnostics, addresses, token or message body. For any
        # uncertain submission retain the run ID and trace; do not resend.
        print(json.dumps({"status":"refused_or_uncertain","run_id":run,
                          "inbox_verified":False,"automatic_retry":False}))
        return 2
    finally:
        signal.alarm(0)
        for fd in reversed(fds):
            os.close(fd)

if __name__=="__main__":
    sys.exit(main())
