#!/usr/bin/env python3
"""CI-only local signing worker for native Postfix pipe; not a delivery transport."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
from email import policy
from email.parser import BytesHeaderParser
import importlib.util
import io
import os
from pathlib import Path
import re
import sys

PRODUCT=Path("/usr/local/libexec/m365_xoauth2_transport.py")
RECIPIENT="probe@lmr365-pipe.invalid"
MAILBOX="lmr365-fixture@example.invalid"
SUCCESS="Local PS256 signing and certificate match verified; no token requested"
NONCE=re.compile(r"\A[a-f0-9]{32}\Z")
LIMIT=32768

def need(condition,reason):
    if not condition:
        raise ValueError(reason)

def message_id(nonce):
    need(type(nonce) is str and NONCE.fullmatch(nonce),"nonce")
    return "<lmr365-pipe-"+nonce+"@lmr365-pipe.invalid>"

def marker(nonce):
    message_id(nonce)
    return "LMR365_PRIMARY_PIPE="+nonce+":postfix_pipe_t:ps256_verified"

def validate_message(raw,recipient,nonce):
    need(recipient==RECIPIENT and 0<len(raw)<=LIMIT,"fixture_envelope")
    headers=BytesHeaderParser(policy=policy.default).parsebytes(raw)
    need(not headers.defects and [str(x) for x in headers.get_all("Message-ID",[])]==
         [message_id(nonce)] and [str(x) for x in headers.get_all("To",[])]==[RECIPIENT],
         "fixture_headers")
    return True

def context_type():
    raw=Path("/proc/self/attr/current").read_bytes().rstrip(b"\0\n")
    fields=raw.decode("ascii").split(":",3)
    need(len(fields)==4 and re.fullmatch(r"[A-Za-z0-9_]+",fields[2]),"context_read")
    return fields[2]

def real_sign():
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(PRODUCT.parent))
    spec=importlib.util.spec_from_file_location("lmr365_fixture_product",str(PRODUCT))
    transport=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    config=transport.load_config()
    need(config.get("mailbox")==MAILBOX and config.get("tenant_id")==
         "11111111-1111-1111-1111-111111111111" and config.get("client_id")==
         "22222222-2222-2222-2222-222222222222" and "signer" not in config and
         config.get("certificate")=="/etc/postfix/m365-oauth/app.crt" and
         config.get("private_key")=="/etc/postfix/m365-oauth/app.key","fixture_identity")
    def forbidden(*args,**kwargs):
        raise RuntimeError("network_forbidden_in_signing_fixture")
    for name in ("acquire_token","send_smtp","check_smtp_auth","submit_acceptance_message"):
        setattr(transport,name,forbidden)
    output,errors=io.StringIO(),io.StringIO()
    with redirect_stdout(output),redirect_stderr(errors):
        rc=transport.run(["--signing-check"])
    need(rc==0 and output.getvalue().strip()==SUCCESS and not errors.getvalue(),
         "signing_result")

def run(argv=None):
    ap=argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("--recipient",required=True)
    ap.add_argument("--nonce",required=True)
    ap.add_argument("--uid",required=True,type=int)
    ap.add_argument("--gid",required=True,type=int)
    args=ap.parse_args(argv)
    stage="identity"
    try:
        need(args.uid>0 and args.gid>0 and
             os.geteuid()==args.uid and os.getegid()==args.gid,"service_account")
        stage="domain"
        need(context_type()=="postfix_pipe_t","not_postfix_pipe_domain")
        stage="message"
        validate_message(sys.stdin.buffer.read(LIMIT+1),args.recipient,args.nonce)
        stage="sign"
        real_sign()
        stage="domain_after"
        need(context_type()=="postfix_pipe_t" and
             os.geteuid()==args.uid and os.getegid()==args.gid,"execution_context_changed")
        print(marker(args.nonce),flush=True)
        return 0
    except Exception:
        print("LMR365_PRIMARY_PIPE_FAIL="+stage,flush=True)
        return 75

if __name__=="__main__":
    sys.exit(run())
