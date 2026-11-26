import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("renew",str(pathlib.Path(__file__).resolve().parents[1]/"linux/smtp-tls-process-renewal.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class RenewalTests(unittest.TestCase):
    def test_unchanged(self):
        calls=[]
        r=m.process("c","ca","k","domain","trust",lambda *a:"new",lambda:"new",lambda n:calls.append(n),lambda n:self.fail("unexpected activation"))
        self.assertEqual(r["status"],"unchanged")
        self.assertEqual(calls,["new"])
    def test_changed(self):
        calls=[]
        r=m.process("c","ca","k","domain","trust",lambda *a:"new",lambda:"old",lambda n:calls.append("validate"),lambda n:calls.append("activate") or "reloaded")
        self.assertEqual(calls,["validate","activate"])
        self.assertEqual(r["status"],"reloaded")
    def test_invalid(self):
        def invalid(n):
            raise ValueError("invalid")
        with self.assertRaises(ValueError):
            m.process("c","ca","k","domain","trust",lambda *a:"new",lambda:"old",invalid,lambda n:self.fail("unexpected activation"))
