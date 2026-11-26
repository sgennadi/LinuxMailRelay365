import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("initial",str(pathlib.Path(__file__).resolve().parents[1]/"linux/smtp-tls-initial-deploy.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class DeploymentTests(unittest.TestCase):
    def run_case(self,fail):
        state=[b"old"]
        phases=[]
        def replace(data,expected):
            self.assertEqual(m.digest(state[0]),expected)
            state[0]=data
        def check():
            if fail:
                raise RuntimeError("check failed")
        def journal(phase,*args):
            phases.append(phase)
        args=(m.digest(b"old"),m.digest(b"new"),lambda:state[0],
              lambda _:b"new",lambda:"backup",replace,
              lambda saved,expected:replace(b"old",expected),
              lambda:None,lambda:None,check,lambda:None,journal)
        if fail:
            with self.assertRaises(RuntimeError):
                m.deploy(*args)
            self.assertEqual(state[0],b"old")
            self.assertEqual(phases[-1],"rolled_back")
        else:
            self.assertEqual(m.deploy(*args),"reloaded")
            self.assertEqual(state[0],b"new")
            self.assertEqual(phases[-1],"verified")
    def test_success(self):
        self.run_case(False)
    def test_rollback(self):
        self.run_case(True)
