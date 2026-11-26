"""Guarded same-app certificate registration evidence and real local proof."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pair", str(ROOT/"linux/review-multi-mailbox-graph-pair.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class PairTests(unittest.TestCase):
    def req(self):
        return dict(action="inspect", scope="source", source_sha="a"*64, runtime_sha="",
                    donor_mailbox="alice@example.org", donor_sha="b"*64, donor_cert_sha="c"*64,
                    candidate_file="mbx-"+"d"*32+".json", nonce="e"*64, pair_sha="", object_id="", confirm="")

    def test_request_guard(self):
        req = self.req()
        self.assertEqual(M.request(M.encode(req)), req)
        for bad in (dict(req, candidate_file="../bad.json"), dict(req, object_id="11111111-1111-4111-8111-111111111111"),
                    dict(req, action="proof"), dict(req, scope="runtime"), dict(req, private_key="/tmp/key")):
            with self.assertRaises(M.Refused):
                M.request(M.encode(bad))

    def test_hardware_rs256_fixed_claims_and_no_pem_fallback(self):
        from types import SimpleNamespace
        handle="handle:0x81010001"
        spec=dict(type="openssl-provider",provider="tpm2",key_ref=handle,provider_config="/fixed/donor.tpm2.cnf")
        context=dict(active={"signer":spec},active_der=b"public DER",group=123)
        app="33333333-3333-4333-8333-333333333333"
        calls=[]
        def command(argv,**kwargs):
            calls.append((argv,kwargs))
            if "pkeyutl" in argv:
                self.assertEqual(argv[argv.index("-inkey")+1],handle)
                self.assertIn("rsa_padding_mode:pkcs1",argv)
                self.assertNotIn("rsa_padding_mode:pss",argv)
                return b"x"*256
            if "x509" in argv:
                self.assertEqual(kwargs["input_data"],context["active_der"])
                return b"-----BEGIN PUBLIC KEY-----"
            self.assertIn("-verify",argv)
            return b"Verified OK"
        with mock.patch.object(M,"tpm_service_prefix",return_value=["/usr/sbin/runuser","-u","m365mailer","--"]), \
             mock.patch.object(M.T,"check_hardware"),mock.patch.object(M.T,"check_runtime_files"), \
             mock.patch.object(M.T,"provider_ready"),mock.patch.object(M.T,"read_capabilities",return_value={handle[7:]}), \
             mock.patch.object(M.T,"run_command",side_effect=command):
            jwt=M.tpm_proof(context,app,now=1000)
            head,payload,sig=jwt.split(".")
            def decode(s):
                return base64.urlsafe_b64decode(s+"="*((-len(s))%4))
            self.assertEqual(json.loads(decode(head))["alg"],"RS256")
            self.assertEqual(json.loads(decode(payload)),dict(aud=M.E.POP_AUDIENCE,iss=app,nbf=970,exp=1570))
            self.assertEqual(calls[0][0][:4],["/usr/sbin/runuser","-u","m365mailer","--"])
            self.assertEqual(calls[0][1]["input_data"],(head+"."+payload).encode("ascii"))
            self.assertEqual(calls[0][1]["env"]["OPENSSL_CONF"],spec["provider_config"])
            self.assertEqual(len(calls),3)
            self.assertEqual(decode(sig),b"x"*256)

    @unittest.skipUnless(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
                         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
                         "requires disposable root CI")
    def test_real_pair_and_proof_no_mail_or_configuration_change(self):
        with tempfile.TemporaryDirectory(prefix="lmr365-graph-pair-", dir="/var/lib") as folder:
            root = Path(folder)
            identities = root/"oauth-identities"
            identities.mkdir(mode=0o700)
            source, runtime = root/"source.tsv", root/"runtime.tsv"
            req = self.req()
            tenant, client = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
            def make(name, mailbox):
                path = identities/name
                key, cert = path.with_suffix(".key"), path.with_suffix(".crt")
                subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                "-days", "30", "-subj", "/CN=CI", "-keyout", str(key), "-out", str(cert)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                path.write_bytes(M.encode(dict(tenant_id=tenant, client_id=client, mailbox=mailbox,
                                               certificate=str(cert), private_key=str(key))))
                for p in (key, cert, path):
                    p.chmod(0o640)
                    os.chown(str(p), 0, os.getgid())
                return path, M.I.digest(path.read_bytes()), M.I.digest(M.E.der_from_pem(cert.read_bytes()))
            donor, req["donor_sha"], req["donor_cert_sha"] = make("alice.json", "alice@example.org")
            candidate, _, _ = make(req["candidate_file"], "bob@example.org")
            raw = (M.A.HEADER+"\n"+"alice\talice@example.org\talice@example.org\t"+str(donor)+"\n").encode("ascii")
            source.write_bytes(raw)
            source.chmod(0o600)
            req["source_sha"] = M.I.digest(raw)
            with mock.patch.multiple(M, IDENTITIES=identities, SOURCE=source, RUNTIME=runtime), \
                    mock.patch.object(M.A, "IDENTITIES", str(identities)+"/"), \
                    mock.patch.object(M.A, "SAFE_PATH", re.compile(re.escape(str(root)) + r"/[A-Za-z0-9_./-]{1,240}\Z")):
                before = {p: p.read_bytes() for p in identities.iterdir()}
                with mock.patch.object(M.E, "make_proof", side_effect=AssertionError("preview must not sign")):
                    receipt, _ = M.inspect(req, os.getgid())
                self.assertEqual(receipt["candidate_mailbox"], "bob@example.org")
                self.assertEqual((receipt["donor_signer"],receipt["candidate_signer"]),("software","software"))
                proof_req = dict(req, action="proof", pair_sha=receipt["pair_sha"],
                                 object_id="33333333-3333-4333-8333-333333333333", confirm=M.CONFIRM)
                with self.assertRaisesRegex(M.Refused, "pair_changed"):
                    M.proof(dict(proof_req, pair_sha="f"*64), os.getgid())
                jwt = M.proof(proof_req, os.getgid())
                head, payload, signature = jwt.split(".")
                def decode(text):
                    return base64.urlsafe_b64decode(text + "="*((-len(text))%4))
                self.assertEqual(json.loads(decode(payload))["iss"], proof_req["object_id"])
                self.assertEqual(json.loads(decode(payload))["aud"], M.E.POP_AUDIENCE)
                public = root/"public"
                public.write_bytes(subprocess.check_output(["/usr/bin/openssl","x509","-in",
                                      str(donor.with_suffix(".crt")),"-pubkey","-noout"]))
                sig = root/"sig"
                sig.write_bytes(decode(signature))
                check = subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(public),
                                        "-signature", str(sig)], input=(head+"."+payload).encode("ascii"),
                                       stdout=subprocess.PIPE, check=True)
                self.assertIn(b"Verified OK", check.stdout)
                self.assertEqual(before, {p: p.read_bytes() for p in identities.iterdir()})
                self.assertEqual(source.read_bytes(), raw)
                self.assertFalse(runtime.exists())
                # Convert the candidate into a managed TPM identity. The
                # fixture software key is removed; hardware calls are mocked.
                software=json.loads(candidate.read_bytes())
                candidate.with_suffix(".key").unlink()
                conf=candidate.with_suffix(".tpm2.cnf")
                conf.write_bytes(M.T.PROVIDER_TEMPLATE.encode("ascii"))
                conf.chmod(0o640)
                os.chown(str(conf),0,os.getgid())
                hardware=dict(software)
                del hardware["private_key"]
                hardware["signer"]=dict(type="openssl-provider",provider="tpm2",
                    key_ref="handle:0x81010001",provider_config=str(conf))
                candidate.write_bytes(M.encode(hardware))
                with mock.patch.object(M,"candidate_tpm_proof",side_effect=AssertionError("preview cannot sign")):
                    mixed,_=M.inspect(req,os.getgid())
                self.assertEqual(mixed["candidate_signer"],"hardware")
                self.assertNotEqual(mixed["pair_sha"],receipt["pair_sha"])
                with self.assertRaisesRegex(M.Refused,"pair_changed"):
                    M.proof(proof_req,os.getgid())
                mixed_req=dict(proof_req,pair_sha=mixed["pair_sha"])
                with mock.patch.object(M,"candidate_tpm_proof") as candidate_check:
                    self.assertEqual(len(M.proof(mixed_req,os.getgid()).split(".")),3)
                    candidate_check.assert_called_once()
                conf.write_bytes(b"unreviewed provider")
                with self.assertRaisesRegex(M.Refused,"managed_tpm_provider_config_required"):
                    M.inspect(req,os.getgid())
                conf.write_bytes(M.T.PROVIDER_TEMPLATE.encode("ascii"))
                changed = json.loads(candidate.read_bytes())
                changed["client_id"] = "44444444-4444-4444-8444-444444444444"
                candidate.write_bytes(M.encode(changed))
                with self.assertRaisesRegex(M.Refused, "different_entra_application"):
                    M.proof(proof_req, os.getgid())


if __name__ == "__main__":
    unittest.main()
