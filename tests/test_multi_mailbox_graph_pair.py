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
                changed = json.loads(candidate.read_bytes())
                changed["client_id"] = "44444444-4444-4444-8444-444444444444"
                candidate.write_bytes(M.encode(changed))
                with self.assertRaisesRegex(M.Refused, "different_entra_application"):
                    M.proof(proof_req, os.getgid())


if __name__ == "__main__":
    unittest.main()
