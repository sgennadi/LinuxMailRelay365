import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("detach",str(pathlib.Path(__file__).resolve().parents[1]/"linux/plan-smtp-tls-detach.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class DetachTests(unittest.TestCase):
    def test_preserves_new_settings(self):
        original=b"relayhost = [new.example]:25\nsmtp_tls_chain_files = "+m.VALUE+b"\n"
        self.assertEqual(m.build(original,b"relayhost = [old.example]:25\n"),b"relayhost = [new.example]:25\n")
    def test_refuses_other_identity(self):
        with self.assertRaises(ValueError):
            m.build(b"smtp_tls_chain_files = /other\n",b"")
