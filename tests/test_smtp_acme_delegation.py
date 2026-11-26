import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("delegation",str(pathlib.Path(__file__).resolve().parents[1]/"linux/inspect-smtp-acme-delegation.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class DelegationTests(unittest.TestCase):
    def test_alias(self):
        r=m.inspect("smtp.example.com",lambda n,t:["validation.example.net."] if n.startswith("_acme") else [],lambda n:n)
        self.assertEqual(r["target"],"validation.example.net")
        self.assertTrue(r["delegated"])
        self.assertFalse(r["automatic_issuance_verified"])
    def test_loop(self):
        with self.assertRaises(ValueError):
            m.inspect("smtp.example.com",lambda n,t:[n],lambda n:n)
