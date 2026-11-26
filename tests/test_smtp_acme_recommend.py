import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("recommend",str(pathlib.Path(__file__).resolve().parents[1]/"linux/recommend-smtp-acme-provider.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class RecommendTests(unittest.TestCase):
    def test_hint(self):
        r=m.recommend({"provider_hint":"dns-azure"},{},{"status":"completed","providers":{"dns-azure":{"registered":True}}})
        self.assertEqual(r["recommended_provider"],"dns-azure")
        self.assertFalse(r["automatic_issuance_allowed"])
    def test_delegated(self):
        r=m.recommend({},{"delegated":True,"zone_hint":{"provider_hint":"dns-azure"}},{"status":"completed","providers":{"dns-azure":{"registered":True}}})
        self.assertIsNone(r["recommended_provider"])
    def test_failed_probe(self):
        self.assertIsNone(m.recommend({"provider_hint":"dns-azure"},{},{"status":"probe_failed"})["recommended_provider"])
