import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("candidate",str(pathlib.Path(__file__).resolve().parents[1]/"linux/smtp-tls-initial-candidate.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class CandidateTests(unittest.TestCase):
    def test_preserves(self):
        original=b"# comment\nrelayhost = [example.org]:25\n"
        self.assertTrue(m.build(original).startswith(original))
        self.assertEqual(m.build(m.build(original)),m.build(original))
    def test_refuses(self):
        for data in (b"smtp_tls_chain_files = /other\n",b"smtp_tls_chain_files =\n continuation\n",b"smtp_tls_chain_files =\nsmtp_tls_chain_files =\n"):
            with self.assertRaises(ValueError):
                m.build(data)
