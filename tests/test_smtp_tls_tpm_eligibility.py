import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("gate",str(pathlib.Path(__file__).resolve().parents[1]/"linux/smtp-tls-tpm-eligibility.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class EligibilityTests(unittest.TestCase):
    def test_missing_hardware(self):
        self.assertIn("tpm2_not_verified",m.evaluate({}, {})["reasons"])
    def test_signature_is_not_postfix_qualification(self):
        r=m.evaluate({"tpm2_verified":True,"tpm2_provider_loadable":True},{"signature_verified":True})
        self.assertFalse(r["protection_available"])
        self.assertTrue(r["standard_file_key_available"])
