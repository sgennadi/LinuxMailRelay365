"""Public-only Entra Graph addKey bridge tests; no real private key or cloud."""
import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "linux" / "export-hardware-oauth-cert.py"
SPEC = importlib.util.spec_from_file_location("entra_oauth_public", str(SOURCE))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def pem(data):
    encoded = base64.b64encode(data).decode("ascii")
    return ("-----BEGIN CERTIFICATE-----\n" + encoded +
            "\n-----END CERTIFICATE-----\n").encode("ascii")


class EntraPublicCertificateTests(unittest.TestCase):
    def setUp(self):
        self.root = M.ROOTS["sidecar"]
        self.tenant = "11111111-1111-1111-1111-111111111111"
        self.client = "22222222-2222-2222-2222-222222222222"
        self.object_id = "33333333-3333-3333-3333-333333333333"
        self.active = {"tenant_id": self.tenant, "client_id": self.client,
                       "mailbox": "sender@example.org",
                       "certificate": str(self.root / "app.crt"),
                       "private_key": str(self.root / "app.key")}
        self.stage = {"tenant_id": self.tenant, "client_id": self.client,
                      "mailbox": "sender@example.org",
                      "certificate": str(self.root / "hardware-app.crt"),
                      "signer": {"type": "openssl-provider", "provider": "tpm2",
                                 "key_ref": "handle:0x81010001",
                                 "provider_config": str(self.root / "tpm2.cnf")}}
        self.active_raw = json.dumps(self.active).encode("ascii")
        self.stage_raw = json.dumps(self.stage).encode("ascii")
        self.old_der = b"0" + b"A" * 299
        self.new_der = b"0" + b"B" * 299
        self.fixture = contextlib.ExitStack()
        self.addCleanup(self.fixture.close)
        self.fixture.enter_context(mock.patch.object(M.os, "geteuid", return_value=0))
        self.fixture.enter_context(mock.patch.object(M.grp, "getgrnam",
                                  return_value=SimpleNamespace(gr_gid=66)))
        self.fixture.enter_context(mock.patch.object(M, "trusted_directory"))
        self.read = self.fixture.enter_context(mock.patch.object(
            M, "read_identity", side_effect=[
                (self.active_raw, self.active), (self.stage_raw, self.stage)]))
        def cert_for(path, *_args, **_kwargs):
            name = Path(path).name
            return (pem(self.old_der) if name == "app.crt"
                    else pem(self.new_der) if name == "hardware-app.crt"
                    else b"not-the-actual-key")
        self.fixture.enter_context(mock.patch.object(M, "secure_read",
                                                     side_effect=cert_for))

    def plan(self):
        return M.inventory("sidecar")

    def test_inventory_only_public_der_and_sha(self):
        x = self.plan()
        self.assertEqual(x["active_cert_sha"], M.digest(self.old_der))
        self.assertEqual(x["candidate_cert_sha"], M.digest(self.new_der))
        self.assertEqual(x["active_sha"], M.digest(self.active_raw))
        self.assertEqual(x["stage_sha"], M.digest(self.stage_raw))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            M.print_inventory(x)
        report = buf.getvalue()
        self.assertIn("ENTRA_OAUTH_PRIVATE_KEY_EXPORTED=no", report)
        self.assertIn("ENTRA_OAUTH_ENTRA_CONTACTED=no", report)
        self.assertIn("ENTRA_OAUTH_ROUTING_IDENTITY_UNCHANGED=yes", report)
        self.assertIn("ENTRA_OAUTH_ACTIVE_CERT_DER_BASE64=", report)
        self.assertNotIn("sender@example.org", report)
        self.assertNotIn("not-the-actual-key", report)

    def test_different_client_or_sender_refused(self):
        self.stage["mailbox"] = "different@example.org"
        with self.assertRaisesRegex(M.Refused, "mismatch"):
            self.plan()

    def test_never_export_pem_private_key(self):
        raw = pem(self.old_der)
        self.assertEqual(M.der_from_pem(raw), self.old_der)
        with self.assertRaises(M.Refused):
            M.der_from_pem(raw + b"-----BEGIN PRIVATE KEY-----\n")
        with self.assertRaises(M.Refused):
            M.der_from_pem(raw + raw)

    def test_ephemeral_existing_pem_proof_signed_locally(self):
        x = self.plan()
        calls = []
        def fake_runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout=b"S" * 256)
        jwt = M.make_proof(x, self.object_id, x["active_sha"], x["stage_sha"],
                           x["active_cert_sha"], x["candidate_cert_sha"],
                           command_runner=fake_runner, now=1700000000)
        self.assertEqual(len(calls), 1)
        command, details = calls[0]
        self.assertEqual(command[:4], ["/usr/bin/openssl", "dgst", "-sha256", "-sign"])
        self.assertEqual(command[-1], str(self.root / "app.key"))
        self.assertEqual(details["stderr"], M.subprocess.DEVNULL)
        header, claims, _ = jwt.split(".")
        def parse(encoded):
            return json.loads(base64.urlsafe_b64decode(
                encoded + "=" * (-len(encoded) % 4)).decode("ascii"))
        self.assertEqual(parse(header)["alg"], "RS256")
        self.assertEqual(parse(claims)["iss"], self.object_id)
        self.assertEqual(parse(claims)["aud"], M.POP_AUDIENCE)
        self.assertEqual(parse(claims)["exp"] - parse(claims)["nbf"], 600)
        self.assertNotIn("not-the-actual-key", jwt)
        self.assertNotIn(str(self.root / "app.key"), jwt)

    def test_sha_drift_rejected_before_signing(self):
        x = self.plan()
        with mock.patch.object(M.subprocess, "run") as run:
            with self.assertRaisesRegex(M.Refused, "changed_repreview"):
                M.make_proof(x, self.object_id, "a" * 64, x["stage_sha"],
                             x["active_cert_sha"], x["candidate_cert_sha"])
            run.assert_not_called()

    def test_hardware_current_identity_is_not_replaced_by_pem_fallback(self):
        x = self.plan()
        x["active"] = dict(x["active"], signer=self.stage["signer"])
        x["active"].pop("private_key")
        with self.assertRaisesRegex(M.Refused, "existing_software_private_key"):
            M.make_proof(x, self.object_id, x["active_sha"], x["stage_sha"],
                         x["active_cert_sha"], x["candidate_cert_sha"])

    def test_source_does_not_transmit_private_key_or_change_tenant(self):
        text = SOURCE.read_text(encoding="utf-8")
        for denied in ("Connect-MgGraph", "PATCH /applications",
                       "removeKey", "tpm2_evictcontrol", "smtp.office365.com",
                       "subprocess.Popen", "-----BEGIN RSA PRIVATE KEY-----"):
            self.assertNotIn(denied, text)


if __name__ == "__main__":
    unittest.main()
