"""Isolated preview and real RSA provisioning; never touch real mail files."""
import importlib.util
import os
from pathlib import Path
import pwd
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prepare", str(ROOT/"linux/prepare-multi-mailbox-identity.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class PrepareTests(unittest.TestCase):
    def req(self):
        return dict(tenant="11111111-1111-4111-8111-111111111111",
                    client="22222222-2222-4222-8222-222222222222", mailbox="alice@example.org",
                    days=365, source_sha="", nonce="a"*64, approval="", confirm="")

    def test_request_guard(self):
        req = self.req()
        self.assertEqual(M.request(M.encode(req)), req)
        for bad in (dict(req, days=True), dict(req, days=366), dict(req, mailbox="../bad"),
                    dict(req, mailbox="alice%bad@example.org"),
                    dict(req, approval="b"*64), dict(req, key_path="/tmp/key"),
                    dict(req, tenant="00000000-0000-0000-0000-000000000000")):
            with self.assertRaises((M.Refused, ValueError)):
                M.request(M.encode(bad))

    def test_selinux_context_validation(self):
        self.assertEqual(M.checked_context(b"system_u:object_r:etc_t:s0\0"),"system_u:object_r:etc_t:s0")
        for bad in (b"system_u:object_r:unlabeled_t:s0",b"system_u:object_r:default_t:s0",
                    b"system_u:object_r:tmp_t:s0",b"system_u:object_r:etc_t:s0\n",
                    b"system_u:system_r:etc_t:s0",b""):
            with self.assertRaises(M.Refused):
                M.checked_context(bad)

    @unittest.skipUnless(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
                         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
                         "requires disposable root CI")
    def test_real_key_certificate_service_signature_and_no_overwrite(self):
        service = pwd.getpwnam("nobody")
        gid = service.pw_gid
        with tempfile.TemporaryDirectory(prefix="lmr365-identity-ci-", dir="/var/lib") as folder:
            base = Path(folder)
            identities = base/"oauth-identities"
            source, runtime = base/"source.tsv", base/"runtime.tsv"
            os.chown(str(base), 0, gid)
            os.chmod(str(base), 0o750)
            with mock.patch.multiple(M, BASE=base, IDENTITIES=identities, SOURCE=source,
                                     RUNTIME=runtime, LOCK=base/"lock", SELINUX=base/"no-selinux"), \
                    mock.patch.object(M.I, "IDENTITIES", identities):
                req = self.req()
                preview = M.plan(req, gid)
                self.assertFalse(identities.exists())
                self.assertFalse(preview["changes"])
                with self.assertRaisesRegex(M.Refused, "plan_changed"):
                    M.apply(dict(req, approval="f"*64, confirm=M.CONFIRM), gid, service.pw_name)
                self.assertFalse(identities.exists())
                saved = M.apply(dict(req, approval=preview["plan_sha"], confirm=M.CONFIRM), gid, service.pw_name)
                key, cert, identity = M.paths(req)
                self.assertEqual(saved["status"], "prepared")
                self.assertTrue(saved["changes"])
                self.assertEqual(saved["plan_sha"], preview["plan_sha"])
                self.assertFalse(source.exists())
                self.assertFalse(runtime.exists())
                self.assertFalse(saved["cloud_changed"])
                self.assertFalse(saved["mail_sent"])
                self.assertEqual({p.name for p in identities.iterdir()}, {key.name, cert.name, identity.name})
                for p in (key, cert, identity):
                    self.assertEqual(p.stat().st_mode & 0o777, 0o640)
                    self.assertEqual(p.stat().st_gid, gid)
                    self.assertEqual(p.stat().st_nlink, 1)
                before = {p: p.read_bytes() for p in (key, cert, identity)}
                with self.assertRaisesRegex(M.Refused, "destination_already_exists"):
                    M.apply(dict(req, approval=preview["plan_sha"], confirm=M.CONFIRM), gid, service.pw_name)
                self.assertEqual(before, {p: p.read_bytes() for p in before})
                req2 = dict(req, nonce="b"*64)
                M.paths(req2)[2].symlink_to(base/"missing")
                with self.assertRaisesRegex(M.Refused, "destination_already_exists"):
                    M.plan(req2, gid)
                (base/"no-selinux").touch()
                with self.assertRaisesRegex(M.Refused, "selinux"):
                    M.plan(req2, gid)


    @unittest.skipUnless(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
                         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
                         "requires disposable root CI")
    def test_labeled_software_identity_no_relabel_of_existing_files(self):
        # Exercise real file-descriptor xattr operations without pretending
        # to control the runner's kernel SELinux state or policy.
        service = pwd.getpwnam("nobody")
        gid = service.pw_gid
        attr = "user.lmr365_test_context"
        with tempfile.TemporaryDirectory(prefix="lmr365-labeled-ci-", dir="/var/lib") as folder:
            base = Path(folder)
            identities = base/"oauth-identities"
            mode = base/"mock-enforce"
            mode.write_text("1")
            os.chown(str(base),0,gid)
            os.chmod(str(base),0o750)
            base_label="system_u:object_r:etc_t:s0"
            key_label="system_u:object_r:cert_t:s0"
            os.setxattr(str(base),attr,base_label.encode("ascii")+b"\0")
            policy_overrides={}
            def query(path,kind):
                return policy_overrides.get(path,key_label if path.suffix==".key" else base_label)
            with mock.patch.multiple(M,BASE=base,IDENTITIES=identities,SOURCE=base/"source",
                                     RUNTIME=base/"runtime",LOCK=base/"lock",SELINUX=mode,LABEL_ATTR=attr), \
                 mock.patch.object(M.I,"IDENTITIES",identities),mock.patch.object(M,"query_label",side_effect=query):
                req=self.req()
                preview=M.plan(req,gid)
                self.assertFalse(identities.exists())
                self.assertEqual(preview["selinux_mode"],"enforcing")
                key,cert,identity=M.paths(req)
                policy_overrides[key]=base_label
                with self.assertRaisesRegex(M.Refused,"plan_changed"):
                    M.apply(dict(req,approval=preview["plan_sha"],confirm=M.CONFIRM),gid,service.pw_name)
                self.assertFalse(identities.exists())
                policy_overrides.clear()
                saved=M.apply(dict(req,approval=preview["plan_sha"],confirm=M.CONFIRM),gid,service.pw_name)
                self.assertEqual(saved["selinux_policy_sha"],preview["selinux_policy_sha"])
                self.assertEqual(M.checked_context(os.getxattr(str(key),attr)),key_label)
                for path in (base,identities,cert,identity):
                    self.assertEqual(M.checked_context(os.getxattr(str(path),attr)),base_label)
                self.assertEqual(mode.read_text(),"1")
                before={path:(path.read_bytes(),os.getxattr(str(path),attr)) for path in (key,cert,identity)}
                req2=dict(req,nonce="b"*64)
                preview2=M.plan(req2,gid)
                os.setxattr(str(identities),attr,key_label.encode("ascii")+b"\0")
                with self.assertRaisesRegex(M.Refused,"existing_context_mismatch"):
                    M.apply(dict(req2,approval=preview2["plan_sha"],confirm=M.CONFIRM),gid,service.pw_name)
                self.assertEqual(before,{path:(path.read_bytes(),os.getxattr(str(path),attr)) for path in before})
                self.assertFalse(any(p.exists() for p in M.paths(req2)))
                self.assertEqual(mode.read_text(),"1")


if __name__ == "__main__":
    unittest.main()
