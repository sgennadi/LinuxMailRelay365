"""Root-managed primary broker identity rules; no writes to /etc or TPM."""
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
import m365_tpm_broker_identity as I


class PrimaryBrokerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = pathlib.Path(self.temp.name)
        self.folder.chmod(0o750)
        self.owner = os.getuid()
        self.group = self.folder.stat().st_gid
        self.raw = {
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "mailbox": "fixture@example.invalid",
            "certificate": str(I.protocol.CERTIFICATE),
            "signer": {"type": "openssl-provider", "provider": "tpm2",
                       "key_ref": "handle:0x81010002",
                       "provider_config": str(I.protocol.PROVIDER_CONFIG)}
        }
        self.write_identity()
        self.write("hardware-app.crt", b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n", 0o644)
        self.write("tpm2.cnf", I.MANAGED_PROVIDER)
        self.fd = os.open(str(self.folder), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def write(self, name, data, mode=0o640):
        path = self.folder / name
        path.write_bytes(data)
        path.chmod(mode)

    def write_identity(self):
        self.write("app.json", json.dumps(self.raw).encode("ascii"))

    def read(self):
        return I.snapshot_directory(self.fd, self.group, self.owner)

    def test_snapshot_is_stable_and_config_is_not_mutable_cache(self):
        snapshot = self.read()
        self.assertTrue(snapshot.matches(self.read()))
        config = snapshot.configuration()
        self.assertEqual(config["_identity_path"], str(I.protocol.IDENTITY))
        config["signer"]["key_ref"] = "changed"
        self.assertEqual(snapshot.configuration()["signer"]["key_ref"], "handle:0x81010002")
        self.assertNotIn("fixture", repr(snapshot))
        self.raw["mailbox"] = "changed@example.invalid"
        self.write_identity()
        self.assertFalse(snapshot.matches(self.read()))

    def test_reject_wrong_modes_symlinks_hardlinks_fifo_and_oversize(self):
        path = self.folder / "app.json"
        for mode in (0o644, 0o660, 0o600, 0o4640):
            path.chmod(mode)
            with self.assertRaises(I.IdentityError):
                self.read()
        path.chmod(0o640)
        linked = self.folder / "linked.json"
        os.link(str(path), str(linked))
        with self.assertRaises(I.IdentityError):
            self.read()
        path.unlink()
        path.symlink_to(linked)
        with self.assertRaises(I.IdentityError):
            self.read()
        path.unlink()
        os.mkfifo(str(path), 0o640)
        with self.assertRaises(I.IdentityError):
            self.read()
        path.unlink()
        self.write("app.json", b"x" * (I.MAX_IDENTITY + 1))
        with self.assertRaises(I.IdentityError):
            self.read()

    def test_reject_nonmanaged_provider_and_nonapplication_handle(self):
        self.write("tpm2.cnf", I.MANAGED_PROVIDER + b"\n.include /tmp/alternate.cnf\n")
        with self.assertRaisesRegex(I.IdentityError, "^broker_provider_not_managed_template$"):
            self.read()
        self.write("tpm2.cnf", I.MANAGED_PROVIDER)
        for handle in ("handle:0x81020000", "handle:0x8101ABCD"):
            self.raw["signer"]["key_ref"] = handle
            self.write_identity()
            with self.assertRaisesRegex(I.IdentityError, "^broker_tpm_handle_window$"):
                self.read()

    def test_reject_unsafe_directory_and_multiple_certificate_blocks(self):
        self.folder.chmod(0o770)
        with self.assertRaises(I.IdentityError):
            self.read()
        self.folder.chmod(0o750)
        cert = self.folder / "hardware-app.crt"
        self.write("hardware-app.crt", cert.read_bytes() * 2, 0o644)
        with self.assertRaisesRegex(I.IdentityError, "^broker_certificate_format$"):
            self.read()

    def test_mutation_after_signing_discards_result(self):
        before = self.read()
        self.raw["mailbox"] = "rotated@example.invalid"
        self.write_identity()
        after = self.read()
        nonce = "a" * 32
        raw = I.protocol.encode_request(nonce)
        with patch.object(I, "read_primary_snapshot", side_effect=[before, after]), \
                patch.object(I.protocol, "issue_primary_assertion", return_value=b"opaque") as issue:
            with self.assertRaisesRegex(I.IdentityError, "^broker_identity_changed$"):
                I.issue_from_active_primary(raw)
            issue.assert_called_once_with(raw, before.configuration())
        with patch.object(I, "read_primary_snapshot", side_effect=[before, before]), \
                patch.object(I.protocol, "issue_primary_assertion", return_value=b"opaque"):
            self.assertEqual(I.issue_from_active_primary(raw), b"opaque")
        with patch.object(I, "read_primary_snapshot") as load:
            with self.assertRaises(I.protocol.BrokerProtocolError):
                I.issue_from_active_primary(raw + b"x")
            load.assert_not_called()

    def test_verification_rejects_changed_snapshot(self):
        before = self.read()
        self.raw["mailbox"] = "rotated@example.invalid"
        self.write_identity()
        after = self.read()
        with patch.object(I.protocol, "decode_response"), \
                patch.object(I, "read_primary_snapshot", side_effect=[before, after]), \
                patch.object(I.protocol, "verify_primary_response", return_value=("endpoint", "opaque")):
            with self.assertRaisesRegex(I.IdentityError, "^broker_identity_changed$"):
                I.verify_from_active_primary(b"opaque", "a" * 32)

    def test_production_loader_requires_real_nonroot_group_and_fixed_directory(self):
        with patch.object(I.grp, "getgrnam", return_value=Mock(gr_gid=0)), \
                patch.object(I, "open_identity_directory") as opened:
            with self.assertRaisesRegex(I.IdentityError, "^broker_identity_group_invalid$"):
                I.read_primary_snapshot()
            opened.assert_not_called()
        with patch.object(I.grp, "getgrnam", side_effect=KeyError()):
            with self.assertRaisesRegex(I.IdentityError, "^broker_identity_group_missing$"):
                I.read_primary_snapshot()


if __name__ == "__main__":
    unittest.main()
