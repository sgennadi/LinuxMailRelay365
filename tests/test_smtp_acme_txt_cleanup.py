import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("cleanup",str(pathlib.Path(__file__).resolve().parents[1]/"linux/check-smtp-acme-txt-cleanup.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class CleanupTests(unittest.TestCase):
    def test_preserved(self):
        self.assertTrue(m.compare(["existing"],["existing"])["observed_snapshot_restored"])
    def test_residue(self):
        self.assertEqual(m.compare(["existing"],["existing","new"])["added_count"],1)
    def test_missing(self):
        self.assertEqual(m.compare(["existing"],[])["missing_count"],1)
    def test_unavailable(self):
        self.assertFalse(m.compare(None,[])["txt_cleanup_verified"])
