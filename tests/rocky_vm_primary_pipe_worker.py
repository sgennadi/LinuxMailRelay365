#!/usr/bin/env python3
"""CI-only local signing worker for native Postfix pipe; not a delivery transport."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
from email import policy
from email.parser import BytesHeaderParser
import importlib.util
import errno
import io
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys

PRODUCT=Path("/usr/local/libexec/m365_xoauth2_transport.py")
RECIPIENT="probe@lmr365-pipe.invalid"
MAILBOX="lmr365-fixture@example.invalid"
SUCCESS="Local PS256 signing and certificate match verified; no token requested"
NONCE=re.compile(r"\A[a-f0-9]{32}\Z")
LIMIT=32768
PORTS=(443,587)
BROKER_DOMAIN="lmr365_fixture_signer_t"

def need(condition,reason):
    if not condition:
        raise ValueError(reason)

def message_id(nonce):
    need(type(nonce) is str and NONCE.fullmatch(nonce),"nonce")
    return "<lmr365-pipe-"+nonce+"@lmr365-pipe.invalid>"

def marker(nonce,network=False,tpm=False,broker=False):
    message_id(nonce)
    need(sum(bool(value) for value in (network,tpm,broker))<=1,"ambiguous_fixture_marker")
    result=("isolated_tpm2_broker_probe_verified" if broker else
            "tcp443_587_verified" if network else "tpm2_ps256_verified" if tpm else "ps256_verified")
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

# Fixed, non-secret failure classes. Never print arbitrary OpenSSL stderr,
# assertion bytes, identity JSON or an exception containing file contents.
TPM_FAILURES=frozenset(("tpm_device_denied","tpm_device_unverified",
    "tpm_device_missing","tpm_device_missing_on_open","tpm_device_stat_denied",
    "tpm_device_busy","tpm_device_unsupported","tpm_device_io",
    "tpm_device_identity_changed","tpm_config",
    "tpm_provider_signature","tpm_certificate","tpm_signature_mismatch",
    "tpm_io","tpm_sign_unknown","broker_connect","broker_connect_denied","broker_connect_refused",
    "broker_connect_missing","broker_connect_timeout","broker_connect_unsupported",
    "broker_socket_denied","broker_socket_unavailable","broker_peer","broker_response",
    "broker_device_visibility","broker_server_signing"))

class FixtureSignFailure(Exception):
    def __init__(self,reason):
        super().__init__(reason if reason in TPM_FAILURES else "tpm_sign_unknown")

def classify_tpm_error(stderr):
    lines=stderr.strip().splitlines()
    if len(lines)!=1:
        return "tpm_sign_unknown"
    text=lines[0]
    exact={
        "4.3.0 hardware_signature_unavailable_no_pem_fallback":"tpm_provider_signature",
        "4.3.0 hardware_signer_certificate_invalid":"tpm_certificate",
        "4.3.0 hardware_key_does_not_match_entra_certificate":"tpm_signature_mismatch",
        "4.3.0 OAuth signer does not match public certificate":"tpm_signature_mismatch",
        "4.3.0 OpenSSL operation failed; verify the certificate and key":"tpm_certificate",
    }
    if text in exact:
        return exact[text]
    if re.match(r"^4\.3\.0 (?:PermissionError|FileNotFoundError|OSError): ",text):
        return "tpm_io"
    return "tpm_sign_unknown"

def tpm_device_probe():
    # Distinguish missing mount-namespace device from a denied open, a
    # driver error and an identity mismatch. No TPM command is issued.
    path="/dev/tpmrm0"
    try:
        before=os.lstat(path)
    except FileNotFoundError:
        raise FixtureSignFailure("tpm_device_missing") from None
    except PermissionError:
        raise FixtureSignFailure("tpm_device_stat_denied") from None
    except OSError:
        raise FixtureSignFailure("tpm_device_unverified") from None
    if not stat.S_ISCHR(before.st_mode):
        raise FixtureSignFailure("tpm_device_identity_changed")
    try:
        fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    except PermissionError:
        raise FixtureSignFailure("tpm_device_denied") from None
    except FileNotFoundError:
        raise FixtureSignFailure("tpm_device_missing_on_open") from None
    except OSError as error:
        code=error.errno
        reason=("tpm_device_busy" if code in (errno.EBUSY,errno.EAGAIN) else
                "tpm_device_unsupported" if code in (errno.ENODEV,errno.ENXIO,errno.EOPNOTSUPP) else
                "tpm_device_io" if code==errno.EIO else "tpm_device_unverified")
        raise FixtureSignFailure(reason) from None
    try:
        opened=os.fstat(fd)
        current=os.lstat(path)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_rdev)
        if not stat.S_ISCHR(opened.st_mode) or not stat.S_ISCHR(current.st_mode) or \
                identity(before)!=identity(opened) or identity(opened)!=identity(current):
            raise FixtureSignFailure("tpm_device_identity_changed")
    except OSError:
        raise FixtureSignFailure("tpm_device_unverified") from None
    finally:
        os.close(fd)

def real_sign(tpm_handle=None):
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(PRODUCT.parent))
    spec=importlib.util.spec_from_file_location("lmr365_fixture_product",str(PRODUCT))
    transport=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    if tpm_handle is not None:
        tpm_device_probe()
    try:
        config=transport.load_config()
    except Exception:
        if tpm_handle is not None:
            raise FixtureSignFailure("tpm_config") from None
        raise
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
    if tpm_handle is not None and (rc!=0 or output.getvalue().strip()!=SUCCESS or errors.getvalue()):
        raise FixtureSignFailure(classify_tpm_error(errors.getvalue()))
    need(rc==0 and output.getvalue().strip()==SUCCESS and not errors.getvalue(),
         "signing_result")

def broker_address(nonce):
    message_id(nonce)
    return "\0lmr365-tpm-fixture-"+nonce


def broker_request(nonce):
    message_id(nonce)
    return ("LMR365_TPM_FIXTURE:"+nonce+"\n").encode("ascii")


def peer_identity(conn):
    credentials=conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"))
    pid,uid,gid=struct.unpack("3i",credentials)
    context=conn.getsockopt(socket.SOL_SOCKET,getattr(socket,"SO_PEERSEC",31),4096)
    fields=context.rstrip(b"\0\n").decode("ascii").split(":",3)
    need(pid>0 and uid>0 and gid>0 and len(fields)==4 and
         re.fullmatch(r"[A-Za-z0-9_]+_t",fields[2]),"broker_peer_identity")
    return pid,uid,gid,fields[2]


def broker_connect_failure(error):
    code=error.errno
    if isinstance(error,TimeoutError) or code==errno.ETIMEDOUT:
        return "broker_connect_timeout"
    if code in (errno.EACCES,errno.EPERM):
        return "broker_connect_denied"
    if code==errno.ECONNREFUSED:
        return "broker_connect_refused"
    if code==errno.ENOENT:
        return "broker_connect_missing"
    if code in (errno.EAFNOSUPPORT,errno.EPROTONOSUPPORT,errno.EOPNOTSUPP):
        return "broker_connect_unsupported"
    return "broker_connect"


def broker_client(nonce,pid,uid,gid,domain):
    # The real Postfix pipe must retain its original private /dev.
    try:
        os.lstat("/dev/tpmrm0")
    except FileNotFoundError:
        pass
    except OSError:
        raise FixtureSignFailure("broker_device_visibility") from None
    else:
        raise FixtureSignFailure("broker_device_visibility")
    try:
        try:
            client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        except OSError as error:
            raise FixtureSignFailure("broker_socket_denied" if error.errno in
                                     (errno.EACCES,errno.EPERM) else "broker_socket_unavailable") from None
        with client as conn:
            conn.settimeout(65)
            try:
                conn.connect(broker_address(nonce))
            except OSError as error:
                raise FixtureSignFailure(broker_connect_failure(error)) from None
            try:
                need(peer_identity(conn)==(pid,uid,gid,domain),"broker_server_identity")
            except (OSError,ValueError,struct.error):
                raise FixtureSignFailure("broker_peer") from None
            request=broker_request(nonce)
            conn.sendall(request)
            conn.shutdown(socket.SHUT_WR)
            response=b"ACK:"+request
            need(recv_exact(conn,len(response))==response and conn.recv(1)==b"",
                 "broker_response")
    except FixtureSignFailure:
        raise
    except (OSError,ValueError,struct.error):
        raise FixtureSignFailure("broker_response") from None


def broker_fixture_hostname(name):
    # Cloud-init may expose the configured short name or the exact fixture
    # FQDN. Do not accept arbitrary suffixes or production machine names.
    return name in ("rocky-selinux-ci","rocky-selinux-ci.example.invalid")


def run_broker(argv):
    """One-shot disposable proof, not a signing service API.

    Never accepts payload bytes to sign, never exports an assertion or token,
    and never contacts Microsoft. Uses only the fixed synthetic identity.
    """
    ap=argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("--nonce",required=True)
    ap.add_argument("--uid",required=True,type=int)
    ap.add_argument("--gid",required=True,type=int)
    ap.add_argument("--pipe-uid",required=True,type=int)
    ap.add_argument("--pipe-gid",required=True,type=int)
    args=ap.parse_args(argv)
    stage="identity"
    try:
        need(args.uid>0 and args.gid>0 and args.pipe_uid>0 and args.pipe_uid!=args.uid and
             args.pipe_gid>0 and args.pipe_gid!=args.gid and
             os.getresuid()==(args.uid,)*3 and os.getresgid()==(args.gid,)*3 and
             set(os.getgroups())|{args.gid}=={args.gid,args.pipe_gid},
             "disposable_broker_identity")
        stage="hostname"
        need(broker_fixture_hostname(socket.gethostname()),"disposable_broker_hostname")
        stage="enforcing"
        need(Path("/sys/fs/selinux/enforce").read_text().strip()=="1","disposable_broker_enforcing")
        stage="domain"
        need(context_type()==BROKER_DOMAIN,"disposable_broker_domain")
        stage="request_nonce"
        request=broker_request(args.nonce)
        # Distinguish successful TPM operations in the service itself from
        # a successful request from the real Postfix pipe. Both are needed.
        stage="self_sign"
        real_sign("0x81010002")
        print("LMR365_TPM_BROKER_SELF_PS256="+args.nonce,flush=True)
        # Abstract Unix socket: no filesystem labels/ACLs changed. The
        # kernel still enforces SELinux connectto and peer identity.
        stage="listen"
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            listener.settimeout(90)
            listener.bind(broker_address(args.nonce))
            listener.listen(1)
            print("LMR365_TPM_BROKER_READY="+args.nonce,flush=True)
            with listener.accept()[0] as conn:
                conn.settimeout(60)
                stage="peer"
                _,uid,gid,domain=peer_identity(conn)
                need((uid,gid,domain)==(args.pipe_uid,args.pipe_gid,"postfix_pipe_t"),"broker_client_identity")
                stage="request"
                need(recv_exact(conn,len(request))==request and conn.recv(1)==b"",
                     "broker_request_exact")
                stage="sign"
                real_sign("0x81010002")
                stage="reply"
                conn.sendall(b"ACK:"+request)
            print("LMR365_TPM_BROKER_PS256="+args.nonce,flush=True)
        return 0
    except Exception:
        print("LMR365_TPM_BROKER_FAIL="+stage,flush=True)
        return 75


def run(argv=None):
    ap=argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("--recipient",required=True)
    ap.add_argument("--nonce",required=True)
    ap.add_argument("--network-nonce",required=True)
    ap.add_argument("--uid",required=True,type=int)
    ap.add_argument("--gid",required=True,type=int)
    ap.add_argument("--tpm-handle",choices=["0x81010002"])
    ap.add_argument("--broker-pid",type=int)
    ap.add_argument("--broker-uid",type=int)
    ap.add_argument("--broker-gid",type=int)
    ap.add_argument("--broker-domain")
    args=ap.parse_args(argv)
    broker=any(value is not None for value in (args.broker_pid,args.broker_uid,args.broker_gid,args.broker_domain))
    stage="identity"
    try:
        need(args.uid>0 and args.gid>0 and
             os.geteuid()==args.uid and os.getegid()==args.gid,"service_account")
        need(not broker or (args.tpm_handle is None and
             type(args.broker_pid) is int and args.broker_pid>1 and
             type(args.broker_uid) is int and args.broker_uid>0 and args.broker_uid!=args.uid and
             type(args.broker_gid) is int and args.broker_gid>0 and args.broker_gid!=args.gid and
             args.broker_gid not in os.getgroups() and
             args.broker_domain==BROKER_DOMAIN),"broker_arguments")
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
            need(args.tpm_handle is None and not broker,"network_not_tpm_receipt")
            for port in PORTS:
                stage="network_"+str(port)
                network_probe(nonce,port)
        else:
            stage="sign"
            if broker:
                broker_client(nonce,args.broker_pid,args.broker_uid,args.broker_gid,args.broker_domain)
            else:
                real_sign(args.tpm_handle)
        stage="domain_after"
        need(context_type()=="postfix_pipe_t" and
             os.geteuid()==args.uid and os.getegid()==args.gid,"execution_context_changed")
        print(marker(nonce,network,tpm=args.tpm_handle is not None,broker=broker),flush=True)
        return 0
    except FixtureSignFailure as error:
        print("LMR365_PRIMARY_PIPE_FAIL="+str(error),flush=True)
        return 75
    except Exception:
        print("LMR365_PRIMARY_PIPE_FAIL="+stage,flush=True)
        return 75

if __name__=="__main__":
    sys.exit(run_broker(sys.argv[2:]) if sys.argv[1:2]==["--broker-server"] else run())
