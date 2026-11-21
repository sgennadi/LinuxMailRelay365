"""No-network, root-only multi-mailbox ingress receipt tests."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1] / "linux"
SPEC = importlib.util.spec_from_file_location("m365_ingress_proof",
                                            str(BASE / "refresh-multi-mailbox-proof.py"))
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)
AUDIT_SPEC = importlib.util.spec_from_file_location(
    "m365_map_audit_for_proof", str(BASE / "audit-oauth-sender-map.py"))
audit = importlib.util.module_from_spec(AUDIT_SPEC)
AUDIT_SPEC.loader.exec_module(audit)

MAIL = "alice@example.org"
IDENTITY = "/etc/linuxmailrelay365/oauth-identities/alice.json"
ROW = "alice\t" + MAIL + "\t" + MAIL + "\t" + IDENTITY
MAP_BYTES = (audit.HEADER + "\n" + ROW + "\n").encode("ascii")
IDENTITY_BYTES = json.dumps({
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "client_id": "22222222-2222-2222-2222-222222222222",
    "mailbox": MAIL,
    "certificate": "/etc/linuxmailrelay365/oauth-identities/cert.pem",
    "signer": {"provider": "tpm2", "key_ref": "dummy"}
}).encode("ascii")
MAP_SHA = hashlib.sha256(MAP_BYTES).hexdigest()


class FakeIngress:
    def __init__(self):
        self.status = "ingress_config_consistent_not_live_verified"
        self.postfix_values = {
            "default_transport": "m365multi:",
            "relay_transport": "m365multi:",
            "m365multi_destination_recipient_limit": "1",
            "m365multi_destination_concurrency_limit": "2"
        }

    def assess(self, rows, auditor):
        return {"OVERALL": self.status, "SERVICES": "all_report_active",
                "FROM_GUARD_SHA_PIN": "configured_pinned_only"}

    def read_postconf(self, name):
        return self.postfix_values.get(name)


class IngressProofTests(unittest.TestCase):
    def setUp(self):
        self.ingress = FakeIngress()
        self.metadata = [1, 2, 3, 4, 5, 33188, 0, 0]

    def runner(self, map_sha=MAP_SHA, ttl_now=10000):
        def read(path, limit, mode, gid):
            self.assertEqual(gid, 4242)
            self.assertEqual(mode, 0o640)
            return MAP_BYTES if path == str(proof.RUNTIME) else IDENTITY_BYTES
        with tempfile.TemporaryDirectory() as root:
            original = proof.CONF
            conf = Path(root)
            (conf / "master.cf").write_bytes(
                b"m365multi unix - n n - 2 pipe\n"
                b"  flags=q user=m365mailer argv=/usr/bin/python3 "
                b"/usr/local/libexec/linuxmailrelay365-multi-oauth/m365-multi-mailbox-transport.py"
                b" --recipient ${recipient} --envelope-sender ${sender}"
                b" --sasl-login ${sasl_username} --sasl-method ${sasl_method}"
                b" --expected-map-sha256 " + MAP_SHA.encode("ascii") + b"\n")
            with mock.patch.object(proof, "CONF", conf), \
                 mock.patch.object(proof.grp, "getgrnam",
                    return_value=SimpleNamespace(gr_gid=4242)):
                return proof.inspect(map_sha, now=ttl_now, audit=audit,
                    ingress=self.ingress, reader=read,
                    config_meta=lambda path: self.metadata)

    def test_positive_receipt_contains_no_identities(self):
        receipt = self.runner()
        self.assertEqual(receipt["map_sha256"], MAP_SHA)
        self.assertEqual(receipt["issued_at"], 10000)
        self.assertEqual(receipt["expires_at"], 10000 + proof.LIFETIME)
        self.assertEqual(receipt["mailboxes"], 1)
        self.assertEqual(receipt["main_meta"], self.metadata)
        self.assertNotIn(MAIL, str(receipt))
        self.assertNotIn(IDENTITY, str(receipt))

    def test_map_mismatch_rejected(self):
        with self.assertRaises(proof.Refused):
            self.runner("a" * 64)

    def test_noncompliant_ingress_rejected(self):
        self.ingress.status = "not_ready"
        with self.assertRaises(proof.Refused):
            self.runner()

    def test_wrong_postfix_route_rejected(self):
        self.ingress.postfix_values["relay_transport"] = "smtp:[other]:25"
        with self.assertRaises(proof.Refused):
            self.runner()

    def test_unprivileged_refresh_denied_without_side_effects(self):
        with mock.patch.object(proof.os, "geteuid", return_value=1001):
            with self.assertRaises(proof.Refused):
                proof.publish({"version": 1})
        with mock.patch.object(proof.os, "geteuid", return_value=1001), \
             mock.patch.object(proof, "inspect") as inspect:
            self.assertEqual(proof.main(["--map-sha256", MAP_SHA,
                                         "--confirm", proof.CONFIRM]), 2)
            inspect.assert_not_called()

    def test_confirmation_required_before_reading_identity(self):
        with mock.patch.object(proof.os, "geteuid", return_value=0), \
             mock.patch.object(proof, "inspect") as inspect:
            self.assertEqual(proof.main(["--map-sha256", MAP_SHA,
                                         "--confirm", "WRONG"]), 2)
            inspect.assert_not_called()

    def test_no_mail_service_or_cloud_actions_in_proof(self):
        code = (BASE / "refresh-multi-mailbox-proof.py").read_text(encoding="utf-8")
        for forbidden in ("smtp.office365.com", "sendmail(", "New-InboundConnector",
                          "systemctl restart", "postfix reload", "ufw allow"):
            self.assertNotIn(forbidden, code)
        self.assertIn("REFRESH_PRIVILEGED_MULTI_INGRESS_PROOF", code)
        self.assertIn("LIFETIME = 120", code)


if __name__ == "__main__":
    unittest.main()
