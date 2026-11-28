"""Offline tests for the disabled primary TPM broker protocol candidate."""
import base64
import copy
import hashlib
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
import m365_tpm_broker_protocol as B


class PrimaryBrokerProtocolTests(unittest.TestCase):
    def setUp(self):
        self.nonce = "a" * 32
        self.now = 1760000000
        self.der = b"synthetic certificate DER for protocol unit tests"
        self.config = {
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "mailbox": "fixture@example.invalid",
            "certificate": str(B.CERTIFICATE),
            "_identity_path": str(B.IDENTITY),
            "signer": {"type": "openssl-provider", "provider": "tpm2",
                       "key_ref": "handle:0x81010002",
                       "provider_config": str(B.PROVIDER_CONFIG)},
        }
        self.endpoint = B.require_primary_identity(self.config)
        self.header = {"alg": "PS256", "typ": "JWT",
                       "x5t#S256": B.transport.base64url(hashlib.sha256(self.der).digest())}
        self.claims = {"aud": self.endpoint, "iss": self.config["client_id"],
                       "sub": self.config["client_id"],
                       "jti": "12345678-1234-4234-8234-123456789abc",
                       "iat": self.now, "nbf": self.now - 60, "exp": self.now + 600}

    def assertion(self, header=None, claims=None, signature=None):
        def enc(obj):
            return B.transport.base64url(json.dumps(obj, separators=(",", ":")).encode("ascii"))
        return ".".join((enc(self.header if header is None else header),
                         enc(self.claims if claims is None else claims),
                         B.transport.base64url(b"s" * 256 if signature is None else signature)))

    def test_fixed_operation_and_canonical_framing(self):
        raw = B.encode_request(self.nonce)
        self.assertEqual(B.decode_request(raw), self.nonce)
        obj = json.loads(raw)
        for key in ("payload", "key", "key_ref", "identity", "tenant", "aud", "path", "mailbox"):
            bad = dict(obj, **{key: "untrusted"})
            with self.assertRaises(B.BrokerProtocolError):
                B.decode_request(B.frame(bad, B.REQUEST_LIMIT))
        for bad in (raw[:-1], raw + b"\n", raw.replace(b'"v":1', b'"v":true'),
                    raw.replace(b'"v":1', b'"v":2'),
                    raw.replace(b'"v":1', b'"v":1,"v":1'),
                    raw.replace(b"primary_assertion", b"sign"),
                    raw.replace(b":", b": ", 1), b"x" * 257):
            with self.assertRaises(B.BrokerProtocolError):
                B.decode_request(bad)
        with self.assertRaises(B.BrokerProtocolError):
            B.encode_request("A" * 32)

    def test_request_and_identity_fail_before_hardware_invocation(self):
        raw = B.encode_request(self.nonce)
        with patch.object(B.transport, "make_client_assertion") as sign:
            with self.assertRaises(B.BrokerProtocolError):
                B.issue_primary_assertion(raw + b"x", self.config, self.now)
            for key, value in (("_identity_path", "/tmp/app.json"),
                               ("certificate", "/tmp/cert.pem"), ("private_key", "/tmp/key")):
                config = dict(self.config, **{key: value})
                with self.assertRaises(B.BrokerProtocolError):
                    B.issue_primary_assertion(raw, config, self.now)
            for key, value in (("provider", "pkcs11"), ("key_ref", "/tmp/tpm2-app.key"),
                               ("provider_config", "/tmp/provider.cnf"),
                               ("key_ref", "handle:0x80010002")):
                config = copy.deepcopy(self.config)
                config["signer"][key] = value
                with self.assertRaises(B.BrokerProtocolError):
                    B.issue_primary_assertion(raw, config, self.now)
            sign.assert_not_called()

    def test_roundtrip_requires_certificate_signature_verification(self):
        jwt = self.assertion()
        with patch.object(B.transport, "make_client_assertion",
                          return_value=(self.endpoint, jwt)) as sign, \
                patch.object(B.transport, "run_openssl", return_value=self.der), \
                patch.object(B.transport, "verify_assertion_signature") as verify:
            raw = B.issue_primary_assertion(B.encode_request(self.nonce), self.config, self.now)
            sign.assert_called_once_with(self.config, now=self.now)
            self.assertEqual(B.verify_primary_response(raw, self.nonce, self.config, self.now),
                             (self.endpoint, jwt))
            verify.assert_called_once_with(self.config, jwt)
            with self.assertRaises(B.BrokerProtocolError):
                B.verify_primary_response(raw, "b" * 32, self.config, self.now)
            self.assertEqual(verify.call_count, 1)
            verify.side_effect = B.transport.TransientError("must not leak test signature")
            with self.assertRaisesRegex(B.BrokerProtocolError, "^broker_response_signature_invalid$"):
                B.verify_primary_response(raw, self.nonce, self.config, self.now)

    def test_strict_header_claims_and_clock(self):
        bad_jwts = [
            self.assertion(header=dict(self.header, alg="RS256")),
            self.assertion(header=dict(self.header, kid="extra")),
            self.assertion(header=dict(self.header, **{"x5t#S256": "wrong"})),
            self.assertion(claims=dict(self.claims, aud="https://example.invalid/token")),
            self.assertion(claims=dict(self.claims, iss="another-app")),
            self.assertion(claims=dict(self.claims, sub="another-app")),
            self.assertion(claims=dict(self.claims, scope="arbitrary")),
            self.assertion(claims=dict(self.claims, jti="not-a-uuid")),
            self.assertion(claims=dict(self.claims, exp=self.now + 601)),
            self.assertion(claims=dict(self.claims, iat=True)),
            self.assertion(claims=dict(self.claims, iat=self.now - 61,
                                       nbf=self.now - 121, exp=self.now + 539)),
            self.assertion(claims=dict(self.claims, iat=self.now + 6,
                                       nbf=self.now - 54, exp=self.now + 606)),
        ]
        with patch.object(B.transport, "run_openssl", return_value=self.der), \
                patch.object(B.transport, "verify_assertion_signature") as verify:
            for jwt in bad_jwts:
                raw = B.encode_response(self.nonce, jwt)
                with self.assertRaises(B.BrokerProtocolError):
                    B.verify_primary_response(raw, self.nonce, self.config, self.now)
            verify.assert_not_called()
        for signature in (b"s" * 127, b"s" * 1025):
            with self.assertRaises(B.BrokerProtocolError):
                B.encode_response(self.nonce, self.assertion(signature=signature))
        with self.assertRaises(B.BrokerProtocolError):
            B.encode_response(self.nonce, self.assertion() + "=")

    def test_no_fallback_or_raw_error_leak(self):
        with patch.object(B.transport, "make_client_assertion",
                          side_effect=B.HardwareSignerError("secret-path")) as sign:
            with self.assertRaisesRegex(B.BrokerProtocolError, "^broker_hardware_assertion_failed$"):
                B.issue_primary_assertion(B.encode_request(self.nonce), self.config, self.now)
            self.assertEqual(sign.call_count, 1)


if __name__ == "__main__":
    unittest.main()
