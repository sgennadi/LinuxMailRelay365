"""Offline request and real local stage/claim/finalize tests."""
import importlib.util
import os
from pathlib import Path
import pwd
import subprocess
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

    def test_tpm_plan_selection_is_exact(self):
        req=dict(self.req(),handle="0x81010001")
        self.assertEqual(M.request(M.P.encode(req)),req)
        for handle in ("", "0x81020001", "../key"):
            with self.assertRaises(M.Refused):
                M.request(M.P.encode(dict(req,handle=handle)))
        with mock.patch.object(M.P,"missing",return_value=True), \
             mock.patch.object(M,"routes",return_value=["",""]), \
             mock.patch.object(M.H,"hardware",return_value=("absent","OpenSSL 3.0.9",set())) as hardware:
            plan=M.preview(req,123)
            self.assertEqual(plan["handle"],req["handle"])
            self.assertNotEqual(plan["approval_sha"],M.preview(dict(req,handle="0x81010002"),123)["approval_sha"])
            hardware.return_value=("absent","OpenSSL 3.0.9",{req["handle"]})
            with self.assertRaisesRegex(M.Refused,"occupied"):
                M.preview(req,123)

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


    @unittest.skipUnless(os.geteuid()==0 and os.environ.get("GITHUB_ACTIONS")=="true"
                         and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted","disposable root CI only")
    def test_tpm_stage_claim_and_finalize_with_mocked_hardware(self):
        service=pwd.getpwnam("nobody")
        gid=service.pw_gid
        req=dict(self.req(),handle="0x81010001")
        with tempfile.TemporaryDirectory(prefix="lmr365-new-tpm-",dir="/var/lib") as folder:
            base=Path(folder)
            identities=base/"oauth-identities"
            os.chown(str(base),0,gid)
            os.chmod(str(base),0o750)
            # Real certificate bytes, but only mocked TPM commands and
            # service-account hardware proof. Test-only PEM is outside identity root.
            pub=base/"test.crt"
            subprocess.run(["/usr/bin/openssl","req","-x509","-newkey","rsa:2048","-nodes",
                            "-days","30","-subj","/CN=Mock TPM","-keyout",str(base/"test.key"),
                            "-out",str(pub)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            handles=set()
            def persist(handle,work):
                handles.add(handle)
            def command(argv,**kwargs):
                Path(argv[argv.index("-out")+1]).write_bytes(pub.read_bytes())
                return b""
            def lock():
                return os.open(str(base/"mock-hardware-lock"),os.O_CREAT|os.O_RDWR,0o600)
            with mock.patch.multiple(M.P,BASE=base,IDENTITIES=identities,SOURCE=base/"source",RUNTIME=base/"runtime",
                                      LOCK=base/"lock",SELINUX=base/"no-selinux"), \
                 mock.patch.object(M.I,"IDENTITIES",identities), \
                 mock.patch.object(M.H,"hardware",side_effect=lambda _: (M.P.directory_state(gid),"OpenSSL 3",set(handles))), \
                 mock.patch.object(M.H,"persist",side_effect=persist) as create, \
                 mock.patch.object(M.T,"lock",side_effect=lock), \
                 mock.patch.object(M.T,"read_capabilities",side_effect=lambda:set(handles)), \
                 mock.patch.object(M.T,"check_hardware"),mock.patch.object(M.T,"check_runtime_files"), \
                 mock.patch.object(M.T,"provider_ready"),mock.patch.object(M.T,"run_command",side_effect=command), \
                 mock.patch.object(M.T,"verify_service_signature") as proof:
                def run(action,approval="",client=""):
                    return M.run(dict(req,action=action,approval=approval,client=client,
                                      confirm=M.PHRASES.get(action,"")),gid,service.pw_name)
                preview=run("preview")
                stage=run("stage",preview["approval_sha"])
                key,cert,identity,pending,claim=M.locations(req)
                provider,attempt=M.tpm_paths(req)
                self.assertFalse(key.exists() or identity.exists())
                self.assertEqual(attempt.stat().st_mode & 0o777,0o600)
                self.assertEqual(attempt.stat().st_gid,0)
                self.assertEqual(stage["handle"],req["handle"])
                self.assertEqual(run("inspect")["approval_sha"],stage["approval_sha"])
                with self.assertRaisesRegex(M.Refused,"destination_exists"):
                    run("stage",preview["approval_sha"])
                with self.assertRaisesRegex(M.Refused,"creation_claim_required"):
                    run("finalize",stage["approval_sha"],req["tenant"])
                saved_provider=provider.read_bytes()
                provider.write_bytes(b"modified")
                with self.assertRaisesRegex(M.Refused,"provider_config_changed"):
                    run("inspect")
                provider.write_bytes(saved_provider)
                claimed=run("claim",stage["approval_sha"])
                self.assertTrue(claimed["claimed"])
                with self.assertRaisesRegex(M.Refused,"creation_already_claimed"):
                    run("claim",stage["approval_sha"])
                client="22222222-2222-4222-8222-222222222222"
                saved=run("finalize",stage["approval_sha"],client)
                config=M.I.decode(identity.read_bytes())
                self.assertEqual(saved["client"],client)
                self.assertEqual(config["signer"]["key_ref"],"handle:"+req["handle"])
                self.assertEqual(config["signer"]["provider_config"],str(provider))
                self.assertNotIn("private_key",config)
                self.assertFalse(key.exists() or (base/"source").exists() or (base/"runtime").exists())
                self.assertTrue(attempt.exists() and pending.exists() and claim.exists())
                create.assert_called_once()
                self.assertGreaterEqual(proof.call_count,3)


    @unittest.skipUnless(os.geteuid()==0 and os.environ.get("GITHUB_ACTIONS")=="true"
                         and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted","disposable root CI only")
    def test_labeled_software_stage_claim_recovery_and_policy_drift(self):
        # Real files/xattrs and RSA proof; synthetic labels, not kernel enforcement.
        service=pwd.getpwnam("nobody")
        gid=service.pw_gid
        attr="user.lmr365_test_context"
        with tempfile.TemporaryDirectory(prefix="lmr365-new-label-",dir="/var/lib") as folder:
            base=Path(folder)
            identities=base/"oauth-identities"
            mode=base/"mock-enforce"
            mode.write_text("1")
            os.chown(str(base),0,gid)
            os.chmod(str(base),0o750)
            base_label="system_u:object_r:etc_t:s0"
            secret_label="system_u:object_r:cert_t:s0"
            os.setxattr(str(base),attr,base_label.encode("ascii")+b"\0")
            overrides={}
            def query(path,kind):
                return overrides.get(path,secret_label if path.name.endswith((".key",".pending",".claim")) else base_label)
            with mock.patch.multiple(M.P,BASE=base,IDENTITIES=identities,SOURCE=base/"source",RUNTIME=base/"runtime",
                                     LOCK=base/"lock",SELINUX=mode,LABEL_ATTR=attr), \
                 mock.patch.object(M.I,"IDENTITIES",identities),mock.patch.object(M.P,"query_label",side_effect=query):
                req=self.req()
                def run(action,approval="",client=""):
                    return M.run(dict(req,action=action,approval=approval,client=client,
                                      confirm=M.PHRASES.get(action,"")),gid,service.pw_name)
                preview=run("preview")
                self.assertEqual(preview["selinux_mode"],"enforcing")
                self.assertFalse(identities.exists())
                key,cert,identity,pending,claim=M.locations(req)
                overrides[claim]=base_label
                with self.assertRaisesRegex(M.Refused,"stale_stage_plan"):
                    run("stage",preview["approval_sha"])
                self.assertFalse(identities.exists())
                overrides.clear()
                stage=run("stage",preview["approval_sha"])
                self.assertEqual(stage["selinux_policy_sha"],preview["selinux_policy_sha"])
                self.assertEqual(M.I.decode(pending.read_bytes())["selinux_policy_sha"],stage["selinux_policy_sha"])
                self.assertFalse(identity.exists() or claim.exists())
                for path in (key,cert,pending,identities):
                    self.assertEqual(M.P.checked_context(os.getxattr(str(path),attr)),query(path,"file"))
                self.assertEqual(pending.stat().st_mode & 0o777,0o600)
                self.assertEqual(pending.stat().st_gid,0)
                overrides[claim]=base_label
                with self.assertRaisesRegex(M.Refused,"pending_selinux_policy_changed"):
                    run("claim",stage["approval_sha"])
                self.assertFalse(claim.exists())
                overrides.clear()
                mode.write_text("0")
                with self.assertRaisesRegex(M.Refused,"pending_selinux_policy_changed"):
                    run("inspect")
                mode.write_text("1")
                claimed=run("claim",stage["approval_sha"])
                self.assertTrue(claimed["claimed"])
                self.assertEqual(M.P.checked_context(os.getxattr(str(claim),attr)),secret_label)
                self.assertEqual(claim.stat().st_mode & 0o777,0o600)
                before={p:(p.read_bytes(),os.getxattr(str(p),attr)) for p in (key,cert,pending,claim)}
                client="22222222-2222-4222-8222-222222222222"
                with self.assertRaisesRegex(M.Refused,"creation_already_claimed"):
                    run("claim",stage["approval_sha"])
                overrides[identity]=secret_label
                with self.assertRaisesRegex(M.Refused,"pending_selinux_policy_changed"):
                    run("finalize",stage["approval_sha"],client)
                self.assertFalse(identity.exists())
                overrides.clear()
                os.setxattr(str(pending),attr,base_label.encode("ascii")+b"\0")
                with self.assertRaisesRegex(M.Refused,"existing_context_mismatch"):
                    run("inspect")
                os.setxattr(str(pending),attr,before[pending][1])
                result=run("finalize",stage["approval_sha"],client)
                self.assertEqual(result["selinux_policy_sha"],stage["selinux_policy_sha"])
                self.assertEqual(M.I.decode(identity.read_bytes())["client_id"],client)
                self.assertEqual(M.P.checked_context(os.getxattr(str(identity),attr)),base_label)
                self.assertEqual(before,{p:(p.read_bytes(),os.getxattr(str(p),attr)) for p in before})
                self.assertEqual(mode.read_text(),"1")
                self.assertFalse((base/"source").exists() or (base/"runtime").exists())
                with self.assertRaisesRegex(M.Refused,"tpm_selinux"):
                    M.app_policy(dict(req,handle="0x81010001"))


if __name__=="__main__":
    unittest.main()
