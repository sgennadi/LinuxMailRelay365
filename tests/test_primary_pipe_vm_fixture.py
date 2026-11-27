"""Pure fixture message and journal receipt tests, without system changes."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import socket
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
        with patch.object(W.os,"open",side_effect=PermissionError("fixture")) as opener:
            with self.assertRaisesRegex(W.FixtureSignFailure,"tpm_device_denied"):
                W.tpm_device_probe()
            opener.assert_called_once()
        with patch.object(W.os,"open",side_effect=FileNotFoundError("fixture")):
            with self.assertRaisesRegex(W.FixtureSignFailure,"tpm_device_unverified"):
                W.tpm_device_probe()

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
