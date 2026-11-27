"""Native local signing fixture for the disposable Rocky Enforcing VM only.

Uses actual Postfix pipe, UID/GID and product --signing-check. The delivery
entrypoint is substituted by a CI worker; no Microsoft 365 traffic.
"""
import grp
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import threading
from contextlib import contextmanager
import subprocess
import time
import uuid

HERE=Path(__file__).resolve().parent
MARKER=Path("/run/lmr365-disposable-primary-mailbox-vm")
BOOT=Path("/proc/sys/kernel/random/boot_id")
IDENTITY=Path("/etc/postfix/m365-oauth")
LIBEXEC=Path("/usr/local/libexec")
PRODUCT=LIBEXEC/"m365_xoauth2_transport.py"
SIGNER=LIBEXEC/"m365_hardware_signer.py"
WORKER=LIBEXEC/"lmr365-primary-pipe-fixture.py"
ACCOUNT="m365mailer"
ENV={"LC_ALL":"C","PATH":"/usr/sbin:/usr/bin:/sbin:/bin"}
spec=importlib.util.spec_from_file_location("primary_pipe_fixture_worker",str(HERE/"rocky_vm_primary_pipe_worker.py"))
W=importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)

def need(ok,reason):
    if not ok:
        raise RuntimeError(reason)

def command(*args,data=None,timeout=60):
    return subprocess.run(list(args),input=data,check=True,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,timeout=timeout,env=ENV).stdout

def disposable():
    need(os.geteuid()==0 and os.environ.get("GITHUB_ACTIONS")=="true",
         "disposable_pipe_vm_only")
    st=MARKER.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
         stat.S_IMODE(st.st_mode)==0o600 and MARKER.read_bytes()==BOOT.read_bytes(),
         "pipe_boot_bound_marker_required")
    need(command("/usr/bin/hostname","-s").strip()==b"rocky-selinux-ci" and
         Path("/proc/1/comm").read_text().strip()=="systemd" and
         Path("/sys/fs/selinux/enforce").read_text().strip()=="1",
         "native_pipe_enforcing_guest_required")

def absent_account():
    for lookup in (pwd.getpwnam,grp.getgrnam):
        try:
            lookup(ACCOUNT)
        except KeyError:
            continue
        raise RuntimeError("existing_pipe_fixture_account")

def install_fixture():
    disposable()
    need(all(not os.path.lexists(str(path)) for path in (IDENTITY,PRODUCT,SIGNER,WORKER)),
         "existing_pipe_identity_or_runtime")
    absent_account()
    command("/usr/sbin/useradd","--system","--user-group","--home-dir","/nonexistent",
            "--shell","/sbin/nologin",ACCOUNT)
    account=pwd.getpwnam(ACCOUNT)
    gid=grp.getgrnam(ACCOUNT).gr_gid
    need(account.pw_uid>0 and account.pw_gid==gid and gid>0,"fixture_account_invalid")
    IDENTITY.mkdir(mode=0o750)
    os.chown(str(IDENTITY),0,gid)
    IDENTITY.chmod(0o750)
    key,cert,app=(IDENTITY/"app.key",IDENTITY/"app.crt",IDENTITY/"app.json")
    command("/usr/bin/openssl","req","-x509","-newkey","rsa:3072","-sha256","-nodes",
            "-days","1","-subj","/CN=LinuxMailRelay365-Disposable-Pipe-Fixture",
            "-keyout",str(key),"-out",str(cert))
    app.write_text(json.dumps({"tenant_id":"11111111-1111-1111-1111-111111111111",
        "client_id":"22222222-2222-2222-2222-222222222222","mailbox":W.MAILBOX,
        "certificate":str(cert),"private_key":str(key)}),encoding="ascii")
    for path,mode in ((key,0o640),(cert,0o644),(app,0o640)):
        os.chown(str(path),0,gid)
        path.chmod(mode)
    for source,target,mode in (("m365_xoauth2_transport.py",PRODUCT,"0755"),
            ("m365_hardware_signer.py",SIGNER,"0644"),
            ("rocky_vm_primary_pipe_worker.py",WORKER,"0755")):
        command("/usr/bin/install","-o","root","-g","root","-m",mode,str(HERE/source),str(target))
        need(target.read_bytes()==(HERE/source).read_bytes(),"fixture_source_changed")
    # Only explicitly owned, newly created fixture paths; no policy changes.
    paths=(IDENTITY,key,cert,app,PRODUCT,SIGNER,WORKER)
    command("/usr/sbin/restorecon","-F",*[str(p) for p in paths])
    for path in paths:
        actual=command("/usr/bin/stat","-c","%C",str(path)).strip()
        expected=command("/usr/sbin/matchpathcon","-N","-n",str(path)).strip()
        need(bool(expected) and actual==expected,"fixture_file_context_unverified")
    return account.pw_uid,gid

def trusted_messages(rows,kind,daemon):
    exe=str((Path(daemon)/kind).resolve())
    for row in rows:
        if (type(row) is dict and row.get("_EXE")==exe and row.get("_COMM")==kind and
                row.get("SYSLOG_IDENTIFIER")=="postfix/"+kind and
                type(row.get("MESSAGE")) is str and len(row["MESSAGE"])<=16384 and
                "\n" not in row["MESSAGE"] and "\r" not in row["MESSAGE"]):
            yield row["MESSAGE"]

def journal_receipt(rows,daemon,nonce,network=False):
    expected=W.message_id(nonce)
    ids=set()
    for line in trusted_messages(rows,"cleanup",daemon):
        match=re.fullmatch(r"([A-Za-z0-9]{5,80}): message-id="+re.escape(expected),line)
        if match:
            ids.add(match[1])
    if len(ids)!=1:
        return None
    qid=next(iter(ids))
    prefix=qid+": to=<"+W.RECIPIENT+">,"
    suffix=" (delivered via m365xoauth2 service ("+W.marker(nonce,network)+"))"
    matches=[]
    for line in trusted_messages(rows,"pipe",daemon):
        if not line.startswith(prefix) or not line.endswith(suffix):
            continue
        fields=[part.strip() for part in line[len(prefix):-len(suffix)].split(",")]
        if (fields.count("relay=m365xoauth2")==1 and fields.count("dsn=2.0.0")==1 and
                fields.count("status=sent")==1 and
                all(sum(field.startswith(key+"=") for field in fields)==1
                    for key in ("relay","dsn","status"))):
            matches.append(line)
    return qid if len(matches)==1 else None

def journal(started):
    raw=command("/usr/bin/journalctl","--no-pager","-o","json","-n","4000",
                "--since=@"+str(started),"-t","postfix/cleanup","-t","postfix/pipe",timeout=25)
    need(len(raw)<=8*1024*1024,"fixture_journal_too_large")
    return [json.loads(line) for line in raw.splitlines()]

def wait_receipt(nonce,daemon,started,network=False):
    rows=[]
    until=time.monotonic()+75
    while time.monotonic()<until:
        rows=journal(started)
        qid=journal_receipt(rows,daemon,nonce,network)
        if qid is not None and not command("/usr/sbin/postqueue","-j").strip():
            return qid
        time.sleep(1)
    failures=set()
    for line in trusted_messages(rows,"pipe",daemon):
        failures.update(re.findall(r"LMR365_PRIMARY_PIPE_FAIL=(identity|domain_after|domain|message|sign|network_443|network_587)\b",line))
    print("LMR365_PRIMARY_VM_PIPE_DIAGNOSTIC=cleanup_rows_"+
          str(len(list(trusted_messages(rows,"cleanup",daemon))))+
          "_pipe_rows_"+str(len(list(trusted_messages(rows,"pipe",daemon))))+
          "_failure_"+("-".join(sorted(failures)) or "unobserved"),flush=True)
    raise RuntimeError("native_pipe_network_receipt_unverified" if network else
                       "native_pipe_signing_receipt_unverified")

def port_policy():
    """Read native installed port types, not a claim of domain permission."""
    spec=importlib.util.spec_from_file_location("primary_pipe_port_policy",
        str(HERE/"inspect-primary-mailbox-selinux.py"))
    probe=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    raw=command("/usr/sbin/semanage","port","-l",timeout=30)
    need(len(raw)<=131072,"fixture_port_policy_too_large")
    decoded=raw.decode("utf-8","strict")
    matches=probe.port_matches(decoded,include_generic=True)
    states=probe.port_states(decoded)
    # Only the fixed TCP targets' label names, never the full host policy.
    for port in W.PORTS:
        print("LMR365_PRIMARY_VM_PIPE_PORT_POLICY_"+str(port)+"="+
              ",".join(sorted(matches[port]))+";"+states[str(port)],flush=True)
    need(states=={"443":"expected_type","587":"expected_type"},
         "fixture_port_policy_types_unverified")
    return raw

def serve_challenge(listener,nonce,port):
    with listener.accept()[0] as peer:
        peer.settimeout(5)
        need(peer.getpeername()[0]=="127.0.0.1","fixture_socket_not_loopback")
        request=W.challenge(nonce,port)
        need(W.recv_exact(peer,len(request))==request,"fixture_socket_challenge")
        peer.sendall(b"ACK:"+request)

@contextmanager
def loopback_challenges(nonce):
    """Two pre-bound listeners, one nonce-bound exchange each; no remote IO."""
    sockets={}
    threads=[]
    verified=set()
    failures=set()
    def serve(port,listener):
        try:
            serve_challenge(listener,nonce,port)
            verified.add(port)
        except Exception:
            failures.add(port)
    try:
        for port in W.PORTS:
            listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sockets[port]=listener
            listener.settimeout(90)
            # No SO_REUSEPORT or wildcard bind. Existing listeners fail closed.
            listener.bind(("127.0.0.1",port))
            listener.listen(1)
        for port,listener in sockets.items():
            thread=threading.Thread(target=serve,args=(port,listener),daemon=True)
            thread.start()
            threads.append(thread)
        yield verified
        for thread in threads:
            thread.join(7)
        need(not failures and verified==set(W.PORTS) and
             all(not thread.is_alive() for thread in threads),
             "fixture_tcp_server_receipt_unverified")
    finally:
        for listener in sockets.values():
            listener.close()

def submit_fixture(nonce,daemon,network=False):
    started=int(time.time())-2
    message=("From: "+W.MAILBOX+"\nTo: "+W.RECIPIENT+"\nMessage-ID: "+W.message_id(nonce)+
             "\nSubject: Disposable local pipe fixture\n\nNo external delivery.\n").encode("ascii")
    command("/usr/sbin/sendmail","-i","-f","<>","--",W.RECIPIENT,data=message)
    return wait_receipt(nonce,daemon,started,network)

def run(C,config,queue,policy,guard,baseline,native,files):
    disposable()
    X=C.X
    guard()
    need(X.snapshot(config,0,policy)==baseline and C.read_native()==native,
         "pipe_requires_exact_restored_baseline")
    uid,gid=install_fixture()
    nonce=uuid.uuid4().hex
    network_nonce=uuid.uuid4().hex
    need(network_nonce!=nonce,"duplicate_fixture_nonce")
    original=X.R.PIPE
    target=(str(WORKER)+" --nonce "+nonce+" --network-nonce "+network_nonce+
            " --uid "+str(uid)+" --gid "+str(gid)).encode("ascii")
    fixture=original.replace(str(PRODUCT).encode("ascii"),target)
    need(fixture!=original and files["master.after"].count(original)==1,"fixture_pipe_not_exact")
    candidate=(files["main.after"],files["master.after"].replace(original,fixture))
    for index in (1,0):
        guard()
        X.T.atomic_write(config,X.NAMES[index],candidate[index],baseline[index][1],0,True)
    expected=tuple((candidate[i],baseline[i][1]) for i in range(2))
    guard()
    need(X.snapshot(config,0,policy)==expected,"fixture_candidate_unverified")
    need(command("/usr/sbin/postconf","-h","inet_interfaces").strip()==b"loopback-only" and
         command("/usr/sbin/postconf","-h","default_transport").strip()==b"m365xoauth2:" and
         command("/usr/sbin/postconf","-h","relay_transport").strip()==b"m365xoauth2:",
         "fixture_route_unverified")
    daemon=command("/usr/sbin/postconf","-h","daemon_directory").decode("ascii").strip()
    need(daemon in ("/usr/libexec/postfix","/usr/lib/postfix/sbin","/usr/lib/postfix"),
         "fixture_daemon_directory_unverified")
    command("/usr/sbin/postfix","check")
    guard()
    need(X.snapshot(config,0,policy)==expected,"fixture_native_check_changed_config")
    command("/usr/bin/systemctl","start","postfix.service")
    need(command("/usr/bin/systemctl","is-active","postfix.service").strip()==b"active",
         "fixture_postfix_not_running")
    disposable()
    qid=submit_fixture(nonce,daemon)
    disposable()
    print("LMR365_PRIMARY_VM_PIPE_DOMAIN=postfix_pipe_t",flush=True)
    print("LMR365_PRIMARY_VM_PIPE_PS256=verified_fixture_certificate",flush=True)
    print("LMR365_PRIMARY_VM_PIPE_QUEUE=correlated_and_empty",flush=True)
    print("LMR365_PRIMARY_VM_PIPE_QUEUE_ID="+qid,flush=True)
    # Separate message and receipt: the first result proves signing only.
    # TCP permission is measured against the installed policy's actual port
    # types, with no policy edit, boolean change, TLS or remote connection.
    native_ports=port_policy()
    with loopback_challenges(network_nonce):
        network_qid=submit_fixture(network_nonce,daemon,network=True)
    need(network_qid!=qid and port_policy()==native_ports,
         "fixture_tcp_evidence_changed")
    disposable()
    print("LMR365_PRIMARY_VM_PIPE_TCP443=loopback_verified",flush=True)
    print("LMR365_PRIMARY_VM_PIPE_TCP587=loopback_verified",flush=True)
    print("LMR365_PRIMARY_VM_PIPE_NETWORK_QUEUE_ID="+network_qid,flush=True)
    # No blind recovery after a failed test; the outer runner discards the VM.
    command("/usr/bin/systemctl","stop","postfix.service")
    guard()
    need(X.snapshot(config,0,policy)==expected,"fixture_changed_before_restore")
    for index in (0,1):
        guard()
        X.T.atomic_write(config,X.NAMES[index],baseline[index][0],baseline[index][1],0,True)
    guard()
    need(X.snapshot(config,0,policy)==baseline and C.read_native()==native,
         "pipe_fixture_restore_unverified")
    for path in (IDENTITY/"app.json",IDENTITY/"app.key",IDENTITY/"app.crt",PRODUCT,SIGNER,WORKER):
        path.unlink()
    IDENTITY.rmdir()
    command("/usr/sbin/userdel",ACCOUNT)
    try:
        grp.getgrnam(ACCOUNT)
    except KeyError:
        pass
    else:
        command("/usr/sbin/groupdel",ACCOUNT)
    absent_account()
    guard()
    print("LMR365_PRIMARY_VM_PIPE_BASELINE=restored_exact_bytes",flush=True)
