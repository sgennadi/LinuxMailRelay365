"""Pure fixture message and journal receipt tests, without system changes."""
import importlib.util
from pathlib import Path
import unittest

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
