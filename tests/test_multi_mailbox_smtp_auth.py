"""No real tenant or SMTP traffic in tests."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
import urllib.error

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("auth_probe",str(ROOT/"linux/check-multi-mailbox-smtp-auth.py"))
M=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class AuthTests(unittest.TestCase):
    def req(self):
        return dict(scope="source",map_sha="a"*64,login="alice",mailbox="alice@example.org",
                    tenant="11111111-1111-4111-8111-111111111111",client="22222222-2222-4222-8222-222222222222",
                    identity_sha="b"*64,certificate_sha="c"*64,signer="software",nonce="d"*64,confirm=M.CONFIRM)

    def test_request(self):
        r=self.req()
        self.assertEqual(M.request(M.encode(r)),r)
        for bad in (dict(r,confirm=""),dict(r,scope="elsewhere"),dict(r,recipient="bob@example.org"),
                    dict(r,identity_sha="bad"),dict(r,mailbox="bad")):
            with self.assertRaises(M.Refused):
                M.request(M.encode(bad))

    def test_auth_only_and_no_raw_secret_result(self):
        transport=mock.Mock()
        config={"tenant_id":self.req()["tenant"],"mailbox":"alice@example.org"}
        transport.make_client_assertion.return_value=("endpoint","assertion-secret")
        token=mock.Mock(return_value="token-secret")
        with mock.patch.object(M,"checked_config",return_value=config):
            self.assertEqual(M.worker(self.req(),"unused",123,transport,token),"authenticated")
            transport.verify_assertion_signature.assert_called_once_with(config,"assertion-secret")
            transport.check_smtp_auth.assert_called_once_with(config,"token-secret")
            transport.send_smtp.assert_not_called()
            transport.submit_acceptance_message.assert_not_called()
            transport.check_smtp_auth.side_effect=Exception("secret-server-response")
            self.assertEqual(M.worker(self.req(),"unused",123,transport,token),"smtp_failed")
            transport.check_smtp_auth.side_effect=Exception("Microsoft 365 staged XOAUTH2 authentication failed (SMTP 535)")
            self.assertEqual(M.worker(self.req(),"unused",123,transport,token),"smtp_rejected_535")
            token.side_effect=urllib.error.HTTPError("url",401,"secret",{},None)
            self.assertEqual(M.worker(self.req(),"unused",123,transport,token),"token_http_401")

    def test_changed_config_never_requests_token(self):
        t=mock.Mock()
        t.make_client_assertion.return_value=("endpoint","assertion")
        token=mock.Mock()
        with mock.patch.object(M,"checked_config",side_effect=[{"a":1},{"a":2}]):
            self.assertEqual(M.worker(self.req(),"unused",123,t,token),"identity_changed")
        token.assert_not_called()
        t.check_smtp_auth.assert_not_called()

    def test_redirects_disallowed_and_endpoint_fixed(self):
        self.assertIsNone(M.NoRedirect().redirect_request(None,None,302,"",{},"https://example.org"))
        with self.assertRaises(M.Refused):
            M.token_for_assertion({"tenant_id":self.req()["tenant"]},"https://example.org","secret")

    def test_cli_delivery_gate_unchanged(self):
        transport=(ROOT/"linux/m365_xoauth2_transport.py").read_text(encoding="utf-8")
        self.assertIn("Mapped identity permits local config/signing checks only",transport)
        self.assertNotIn("send_smtp(",(ROOT/"linux/check-multi-mailbox-smtp-auth.py").read_text(encoding="utf-8"))


if __name__=="__main__":
    unittest.main()
