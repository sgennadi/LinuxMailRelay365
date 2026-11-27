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
import socket
import sys

PRODUCT=Path("/usr/local/libexec/m365_xoauth2_transport.py")
RECIPIENT="probe@lmr365-pipe.invalid"
MAILBOX="lmr365-fixture@example.invalid"
SUCCESS="Local PS256 signing and certificate match verified; no token requested"
NONCE=re.compile(r"\A[a-f0-9]{32}\Z")
LIMIT=32768
PORTS=(443,587)

def need(condition,reason):
    if not condition:
        raise ValueError(reason)

def message_id(nonce):
    need(type(nonce) is str and NONCE.fullmatch(nonce),"nonce")
    return "<lmr365-pipe-"+nonce+"@lmr365-pipe.invalid>"

def marker(nonce,network=False,tpm=False):
    message_id(nonce)
    need(not (network and tpm),"ambiguous_fixture_marker")
    result="tcp443_587_verified" if network else "tpm2_ps256_verified" if tpm else "ps256_verified"
    return "LMR365_PRIMARY_PIPE="+nonce+":postfix_pipe_t:"+result

def challenge(nonce,port):
    message_id(nonce)
    need(port in PORTS,"fixture_port")
    return ("LMR365_TCP:"+nonce+":"+str(port)+"\n").encode("ascii")

def recv_exact(sock,size):
    data=b""
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        need(bool(chunk),"fixture_socket_eof")
        data+=chunk
    return data

def network_probe(nonce,port,connect=socket.create_connection):
    request=challenge(nonce,port)
    # Fixed loopback only; never use an address from configuration or mail.
    with connect(("127.0.0.1",port),timeout=5) as conn:
        conn.settimeout(5)
        conn.sendall(request)
        response=b"ACK:"+request
        need(recv_exact(conn,len(response))==response,"fixture_socket_response")

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

def real_sign(tpm_handle=None):
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(PRODUCT.parent))
    spec=importlib.util.spec_from_file_location("lmr365_fixture_product",str(PRODUCT))
    transport=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    config=transport.load_config()
    need(config.get("mailbox")==MAILBOX and config.get("tenant_id")==
         "11111111-1111-1111-1111-111111111111" and config.get("client_id")==
         "22222222-2222-2222-2222-222222222222","fixture_identity")
    if tpm_handle is None:
        need("signer" not in config and
             config.get("certificate")=="/etc/postfix/m365-oauth/app.crt" and
             config.get("private_key")=="/etc/postfix/m365-oauth/app.key","fixture_pem_identity")
    else:
        need(tpm_handle=="0x81010002" and "private_key" not in config and
             config.get("certificate")=="/etc/postfix/m365-oauth/hardware-app.crt" and
             config.get("signer")=={"type":"openssl-provider","provider":"tpm2",
                 "key_ref":"handle:"+tpm_handle,
                 "provider_config":"/etc/postfix/m365-oauth/tpm2.cnf"},
             "fixture_tpm_identity")
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
    ap.add_argument("--network-nonce",required=True)
    ap.add_argument("--uid",required=True,type=int)
    ap.add_argument("--gid",required=True,type=int)
    ap.add_argument("--tpm-handle",choices=["0x81010002"])
    args=ap.parse_args(argv)
    stage="identity"
    try:
        need(args.uid>0 and args.gid>0 and
             os.geteuid()==args.uid and os.getegid()==args.gid,"service_account")
        stage="domain"
        need(context_type()=="postfix_pipe_t","not_postfix_pipe_domain")
        stage="message"
        message_id(args.nonce)
        message_id(args.network_nonce)
        need(args.nonce!=args.network_nonce,"duplicate_fixture_nonce")
        raw=sys.stdin.buffer.read(LIMIT+1)
        try:
            validate_message(raw,args.recipient,args.nonce)
            nonce,network=args.nonce,False
        except ValueError:
            validate_message(raw,args.recipient,args.network_nonce)
            nonce,network=args.network_nonce,True
        if network:
            need(args.tpm_handle is None,"network_not_tpm_receipt")
            for port in PORTS:
                stage="network_"+str(port)
                network_probe(nonce,port)
        else:
            stage="sign"
            real_sign(args.tpm_handle)
        stage="domain_after"
        need(context_type()=="postfix_pipe_t" and
             os.geteuid()==args.uid and os.getegid()==args.gid,"execution_context_changed")
        print(marker(nonce,network,tpm=args.tpm_handle is not None),flush=True)
        return 0
    except Exception:
        print("LMR365_PRIMARY_PIPE_FAIL="+stage,flush=True)
        return 75

if __name__=="__main__":
    sys.exit(run())
