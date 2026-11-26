import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("probe",str(pathlib.Path(__file__).resolve().parents[1]/"linux/probe-smtp-acme-plugins.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class PluginTests(unittest.TestCase):
    def test_registered(self):
        result=m.parse("* dns-azure\nDescription: Azure\n* dns-route53\n")
        self.assertTrue(result["dns-azure"]["registered"])
        self.assertTrue(result["dns-route53"]["registered"])
        self.assertFalse(result["dns-google"]["registered"])
        self.assertFalse(result["dns-azure"]["issuance_verified"])
    def test_description_not_registration(self):
        self.assertFalse(m.parse("Description: dns-azure")["dns-azure"]["registered"])
