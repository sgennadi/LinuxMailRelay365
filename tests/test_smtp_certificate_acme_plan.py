import importlib.util
import pathlib
import unittest

spec=importlib.util.spec_from_file_location("planner",str(pathlib.Path(__file__).resolve().parents[1]/"linux"/"plan-smtp-certificate-acme.py"))
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class AcmePlanTests(unittest.TestCase):
    def test_independent_name(self):
        p=M.plan(dict(accepted_domain="ariel.ac.il",certificate_name="relay.ariel.ac.il",provider="manual"))
        self.assertEqual(p["challenge"],"_acme-challenge.relay.ariel.ac.il")
        self.assertEqual(p["renewal_method"],"manual")
        self.assertFalse(p["issuance_supported"])
    def test_reject_invalid(self):
        for name in ("relay.evil-ariel.ac.il","*.ariel.ac.il","--bad.ariel.ac.il"):
            with self.assertRaises(ValueError):
                M.plan(dict(accepted_domain="ariel.ac.il",certificate_name=name,provider="manual"))
