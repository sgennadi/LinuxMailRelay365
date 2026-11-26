import importlib.util
import pathlib
import tempfile
import unittest
spec=importlib.util.spec_from_file_location("planner",str(pathlib.Path(__file__).resolve().parents[1]/"linux/plan-smtp-tls-systemd.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class UninstallTests(unittest.TestCase):
    def test_absent_and_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)
            src=root/"src"; dst=root/"dst"
            src.mkdir(); dst.mkdir()
            for name in m.UNITS:
                (src/name).write_text("packaged")
            (dst/m.UNITS[0]).write_text("custom")
            plan=m.preview_uninstall(src,dst)
            self.assertTrue(plan["conflict"])
            self.assertEqual(plan["units"][0]["status"],"preserve")
            self.assertTrue(all(u["status"]=="absent" for u in plan["units"][1:]))
            self.assertTrue(plan["preserves_certificates"])
