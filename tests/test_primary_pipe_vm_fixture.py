"""Pure fixture message and journal receipt tests, without system changes."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import socket
import errno
import stat
import threading

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("pipe_vm_fixture",str(HERE/"rocky_vm_primary_pipe_enforcing.py"))
P=importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
W=P.W

class PipeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.nonce="a"*32
        self.daemon="/usr/libexec/postfix"
        self.qid="ABC12345"
        self.message=("To: "+W.RECIPIENT+"\nMessage-ID: "+W.message_id(self.nonce)+"\n\nfixture\n").encode("ascii")

    def row(self,kind,message):
        return {"_EXE":str((Path(self.daemon)/kind).resolve()),"_COMM":kind,
                "SYSLOG_IDENTIFIER":"postfix/"+kind,"MESSAGE":message}

    def cleanup(self,qid=None):
        return self.row("cleanup",(qid or self.qid)+": message-id="+W.message_id(self.nonce))

    def pipe(self):
        return self.row("pipe",self.qid+": to=<"+W.RECIPIENT+
            ">, relay=m365xoauth2, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent "+
            "(delivered via m365xoauth2 service ("+W.marker(self.nonce)+"))")

    def test_exact_fixture_envelope_and_header(self):
        self.assertTrue(W.validate_message(self.message,W.RECIPIENT,self.nonce))
        for raw,recipient,nonce in ((self.message,"other@example.invalid",self.nonce),
            (self.message,W.RECIPIENT,"b"*32),(self.message,W.RECIPIENT,"bad"),
            (self.message.replace(b"\n\n",b"\nMessage-ID: <other@invalid>\n\n"),W.RECIPIENT,self.nonce),
            (b"x"*(W.LIMIT+1),W.RECIPIENT,self.nonce)):
            with self.subTest(recipient=recipient,nonce=nonce),self.assertRaises(ValueError):
                W.validate_message(raw,recipient,nonce)

    def test_network_receipt_distinct_from_signing_receipt(self):
        nonce="b"*32
        cleanup=self.row("cleanup",self.qid+": message-id="+W.message_id(nonce))
        pipe=self.pipe()
        pipe["MESSAGE"]=pipe["MESSAGE"].replace(W.marker(self.nonce),W.marker(nonce,True))
        self.assertEqual(P.journal_receipt([cleanup,pipe],self.daemon,nonce,True),self.qid)
        self.assertIsNone(P.journal_receipt([cleanup,pipe],self.daemon,nonce))
        self.assertIsNone(P.journal_receipt([cleanup,pipe],self.daemon,self.nonce,True))

    def test_hardware_receipt_cannot_be_satisfied_by_pem_or_network(self):
        cleanup,pipe=self.cleanup(),self.pipe()
        self.assertIsNone(P.journal_receipt([cleanup,pipe],self.daemon,self.nonce,tpm=True))
        hardware=dict(pipe,MESSAGE=pipe["MESSAGE"].replace(
            W.marker(self.nonce),W.marker(self.nonce,tpm=True)))
        self.assertEqual(P.journal_receipt([cleanup,hardware],self.daemon,self.nonce,tpm=True),self.qid)
        self.assertIsNone(P.journal_receipt([cleanup,hardware],self.daemon,self.nonce))
        self.assertIsNone(P.journal_receipt([cleanup,hardware],self.daemon,self.nonce,True))
        with self.assertRaises(ValueError):
            W.marker(self.nonce,True,True)

    def test_broker_connect_errno_is_fixed_and_bounded(self):
        for error,code in ((OSError(errno.EACCES,"private path"),"broker_connect_denied"),
                           (OSError(errno.EPERM,"private path"),"broker_connect_denied"),
                           (OSError(errno.ECONNREFUSED,"private path"),"broker_connect_refused"),
                           (OSError(errno.ENOENT,"private path"),"broker_connect_missing"),
                           (TimeoutError("private path"),"broker_connect_timeout"),
                           (OSError(errno.EAFNOSUPPORT,"private path"),"broker_connect_unsupported"),
                           (OSError(errno.EIO,"private path"),"broker_connect")):
            self.assertEqual(W.broker_connect_failure(error),code)
            self.assertIn(code,W.TPM_FAILURES)
            self.assertNotIn("private",code)
            with patch.object(W.os,"lstat",side_effect=FileNotFoundError()), \
                    patch.object(W.socket,"socket") as factory:
                conn=factory.return_value.__enter__.return_value
                conn.connect.side_effect=error
                with self.assertRaisesRegex(W.FixtureSignFailure,"^"+code+"$"):
                    W.broker_client(self.nonce,2,3,4,"unconfined_service_t")
                conn.sendall.assert_not_called()

    def test_broker_fixture_hostname_only_accepts_exact_lab_names(self):
        for hostname in ("rocky-selinux-ci","rocky-selinux-ci.example.invalid"):
            self.assertTrue(W.broker_fixture_hostname(hostname))
        for hostname in ("rocky-selinux-ci.example.org","rocky-selinux-ci.attacker.invalid",
                         "rocky-selinux-ci.example.invalid.","production",""):
            self.assertFalse(W.broker_fixture_hostname(hostname))

    def test_broker_receipt_is_distinct_and_nonce_bound(self):
        self.assertNotEqual(W.marker(self.nonce,tpm=True),W.marker(self.nonce,broker=True))
        self.assertIn("isolated_tpm2_broker_probe_verified",W.marker(self.nonce,broker=True))
        self.assertEqual(W.broker_address(self.nonce),"\0lmr365-tpm-fixture-"+self.nonce)
        self.assertEqual(W.broker_request(self.nonce),("LMR365_TPM_FIXTURE:"+self.nonce+"\n").encode("ascii"))
        for call in (lambda:W.marker(self.nonce,tpm=True,broker=True),
                     lambda:W.marker(self.nonce,network=True,broker=True),
                     lambda:W.broker_request("bad")):
            with self.assertRaises(ValueError):
                call()
        rows=[self.cleanup(),self.pipe()]
        self.assertIsNone(P.journal_receipt(rows,self.daemon,self.nonce,broker=True))
        rows[1]["MESSAGE"]=rows[1]["MESSAGE"].replace(W.marker(self.nonce),W.marker(self.nonce,broker=True))
        self.assertEqual(P.journal_receipt(rows,self.daemon,self.nonce,broker=True),self.qid)
        self.assertIsNone(P.journal_receipt(rows,self.daemon,self.nonce,tpm=True))
        with patch.object(W.os,"lstat",return_value=Mock()),patch.object(W.socket,"socket") as sock:
            with self.assertRaisesRegex(W.FixtureSignFailure,"broker_device_visibility"):
                W.broker_client(self.nonce,2,3,4,"unconfined_service_t")
            sock.assert_not_called()

    def test_tpm_failure_diagnostics_are_bounded_and_never_success(self):
        expected={
            "4.3.0 hardware_signature_unavailable_no_pem_fallback":"tpm_provider_signature",
            "4.3.0 hardware_signer_certificate_invalid":"tpm_certificate",
            "4.3.0 hardware_key_does_not_match_entra_certificate":"tpm_signature_mismatch",
            "4.3.0 PermissionError: fixture path":"tpm_io",
            "4.3.0 unexpected secret value":"tpm_sign_unknown",
            "4.3.0 hardware_signature_unavailable_no_pem_fallback\nextra":"tpm_sign_unknown"}
        for raw,code in expected.items():
            self.assertEqual(W.classify_tpm_error(raw),code)
        self.assertEqual(str(W.FixtureSignFailure("arbitrary private text")),"tpm_sign_unknown")
        device=Mock(st_mode=stat.S_IFCHR|0o660,st_dev=1,st_ino=2,st_rdev=3)
        for error,code in ((PermissionError(errno.EACCES,"fixture"),"tpm_device_stat_denied"),
                           (FileNotFoundError(errno.ENOENT,"fixture"),"tpm_device_missing")):
            with patch.object(W.os,"lstat",side_effect=error), patch.object(W.os,"open") as opener:
                with self.assertRaisesRegex(W.FixtureSignFailure,code):
                    W.tpm_device_probe()
                opener.assert_not_called()
        with patch.object(W.os,"lstat",return_value=device):
            for error,code in ((PermissionError(errno.EACCES,"fixture"),"tpm_device_denied"),
                               (FileNotFoundError(errno.ENOENT,"fixture"),"tpm_device_missing_on_open"),
                               (OSError(errno.EBUSY,"fixture"),"tpm_device_busy"),
                               (OSError(errno.ENODEV,"fixture"),"tpm_device_unsupported"),
                               (OSError(errno.EIO,"fixture"),"tpm_device_io")):
                with patch.object(W.os,"open",side_effect=error) as opener:
                    with self.assertRaisesRegex(W.FixtureSignFailure,code):
                        W.tpm_device_probe()
                    opener.assert_called_once()
            with patch.object(W.os,"open",return_value=17), \
                    patch.object(W.os,"fstat",return_value=device), patch.object(W.os,"close") as close:
                W.tpm_device_probe()
                close.assert_called_once_with(17)
            changed=Mock(st_mode=stat.S_IFCHR|0o660,st_dev=1,st_ino=8,st_rdev=3)
            with patch.object(W.os,"open",return_value=17), \
                    patch.object(W.os,"fstat",return_value=changed), patch.object(W.os,"close") as close:
                with self.assertRaisesRegex(W.FixtureSignFailure,"tpm_device_identity_changed"):
                    W.tpm_device_probe()
                close.assert_called_once_with(17)

    def test_network_client_uses_only_fixed_loopback_ports_and_exact_reply(self):
        for port in W.PORTS:
            conn=Mock()
            conn.__enter__=Mock(return_value=conn)
            conn.__exit__=Mock(return_value=False)
            response=b"ACK:"+W.challenge(self.nonce,port)
            conn.recv.side_effect=[response[:3],response[3:]]
            connect=Mock(return_value=conn)
            W.network_probe(self.nonce,port,connect)
            connect.assert_called_once_with(("127.0.0.1",port),timeout=5)
            conn.sendall.assert_called_once_with(W.challenge(self.nonce,port))
            conn.recv.side_effect=[b"x"*len(response)]
            with self.assertRaises(ValueError):
                W.network_probe(self.nonce,port,connect)
        connect=Mock()
        with self.assertRaises(ValueError):
            W.network_probe(self.nonce,25,connect)
        connect.assert_not_called()

    def test_loopback_server_checks_nonce_without_privileged_bind(self):
        # Exercise actual socket IO on a test-assigned unprivileged port.
        # The VM-only client still uses exact privileged ports 443/587.
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1",0))
            listener.listen(1)
            listener.settimeout(3)
            address=listener.getsockname()
            outcome=[]
            def serve():
                try:
                    P.serve_challenge(listener,self.nonce,443)
                    outcome.append(True)
                except Exception:
                    outcome.append(False)
            thread=threading.Thread(target=serve)
            thread.start()
            try:
                def local_connect(target,timeout):
                    self.assertEqual(target,("127.0.0.1",443))
                    return socket.create_connection(address,timeout=timeout)
                W.network_probe(self.nonce,443,local_connect)
            finally:
                thread.join(8)
            self.assertEqual(outcome,[True])

    def test_trusted_pipe_marker_and_exact_queue_id_required(self):
        cleanup,pipe=self.cleanup(),self.pipe()
        self.assertEqual(P.journal_receipt([cleanup,pipe],self.daemon,self.nonce),self.qid)
        for changed in (dict(pipe,_EXE="/tmp/pipe"),dict(pipe,_COMM="other"),
            dict(pipe,SYSLOG_IDENTIFIER="postfix/smtp"),
            dict(pipe,MESSAGE=pipe["MESSAGE"].replace("status=sent","status=deferred")),
            dict(pipe,MESSAGE=pipe["MESSAGE"].replace("dsn=2.0.0","dsn=4.0.0")),
            dict(pipe,MESSAGE=pipe["MESSAGE"].replace(self.nonce,"b"*32)),
            dict(pipe,MESSAGE=pipe["MESSAGE"].replace("relay=m365xoauth2","relay=smtp")),
            dict(pipe,MESSAGE=pipe["MESSAGE"].replace(W.RECIPIENT,"other@example.invalid")),
            dict(pipe,MESSAGE=pipe["MESSAGE"]+" extra")):
            self.assertIsNone(P.journal_receipt([cleanup,changed],self.daemon,self.nonce))
        for rows in ([pipe],[cleanup],[cleanup,pipe,pipe],
                     [cleanup,self.cleanup("OTHER123"),pipe]):
            self.assertIsNone(P.journal_receipt(rows,self.daemon,self.nonce))

if __name__=="__main__":
    unittest.main()
