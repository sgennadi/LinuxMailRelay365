"""Offline request and real local stage/claim/finalize tests."""
import importlib.util
import os
from pathlib import Path
import pwd
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("newapp",str(ROOT/"linux/prepare-multi-mailbox-new-app.py"))
M=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class NewAppTests(unittest.TestCase):
    def req(self):
        return dict(action="preview",tenant="11111111-1111-4111-8111-111111111111",mailbox="alice@example.org",
                    days=365,source_sha="",runtime_sha="",nonce="a"*64,approval="",client="",confirm="")

    def test_request(self):
        r=self.req()
        self.assertEqual(M.request(M.P.encode(r)),r)
        for bad in (dict(r,days=3),dict(r,action="claim"),dict(r,client=r["tenant"]),dict(r,nonce="../x")):
            with self.assertRaises((M.Refused,ValueError)):
                M.request(M.P.encode(bad))

    @unittest.skipUnless(os.geteuid()==0 and os.environ.get("GITHUB_ACTIONS")=="true"
                         and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted","disposable root CI only")
    def test_stage_claim_finalize(self):
        service=pwd.getpwnam("nobody")
        gid=service.pw_gid
        with tempfile.TemporaryDirectory(prefix="lmr365-new-app-",dir="/var/lib") as folder:
            base=Path(folder)
            identities=base/"oauth-identities"
            os.chown(str(base),0,gid)
            os.chmod(str(base),0o750)
            with mock.patch.multiple(M.P,BASE=base,IDENTITIES=identities,SOURCE=base/"source",RUNTIME=base/"runtime",
                                     LOCK=base/"lock",SELINUX=base/"no-selinux"), mock.patch.object(M.I,"IDENTITIES",identities):
                req=self.req()
                def run(action,approval="",client=""):
                    return M.run(dict(req,action=action,approval=approval,client=client,
                                      confirm=M.PHRASES.get(action,"")),gid,service.pw_name)
                preview=run("preview")
                self.assertFalse(identities.exists())
                stage=run("stage",preview["approval_sha"])
                key,cert,identity,pending,claim=M.locations(req)
                self.assertFalse(identity.exists())
                self.assertFalse(claim.exists())
                self.assertEqual(pending.stat().st_mode & 0o777,0o600)
                self.assertEqual(pending.stat().st_gid,0)
                self.assertEqual(run("inspect")["approval_sha"],stage["approval_sha"])
                with self.assertRaisesRegex(M.Refused,"creation_claim_required"):
                    run("finalize",stage["approval_sha"],req["tenant"])
                claimed=run("claim",stage["approval_sha"])
                self.assertTrue(claimed["claimed"])
                with self.assertRaisesRegex(M.Refused,"creation_already_claimed"):
                    run("claim",stage["approval_sha"])
                client="22222222-2222-4222-8222-222222222222"
                saved=run("finalize",stage["approval_sha"],client)
                self.assertEqual(saved["client"],client)
                self.assertEqual(M.I.decode(identity.read_bytes())["client_id"],client)
                self.assertTrue(pending.exists() and claim.exists())
                self.assertFalse((base/"source").exists() or (base/"runtime").exists())
                with self.assertRaisesRegex(M.Refused,"identity_already_finalized"):
                    run("finalize",stage["approval_sha"],client)


if __name__=="__main__":
    unittest.main()
