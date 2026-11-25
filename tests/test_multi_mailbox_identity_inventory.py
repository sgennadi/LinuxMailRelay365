"""Multi-mailbox read-only inventory tests. No live services or credentials."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "multi_identity_inventory", str(ROOT / "linux/inspect-multi-mailbox-identities.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
TENANT = "11111111-1111-4111-8111-111111111111"
CLIENT = "22222222-2222-4222-8222-222222222222"
MAIL = "alice@example.org"
PATH = str(M.IDENTITIES / "alice.json")
CERT = str(M.IDENTITIES / "alice.crt")
HEADER = M.A.HEADER + "\n"


class InventoryTests(unittest.TestCase):
    def identity(self):
        return dict(tenant_id=TENANT, client_id=CLIENT, mailbox=MAIL, certificate=CERT,
                    private_key=str(M.IDENTITIES / "alice.key"))

    def test_only_public_certificate_read_and_metadata_returned(self):
        raw = json.dumps(self.identity()).encode("ascii")
        public_der = b"0" + b"a" * 300
        with mock.patch.object(M.E, "trusted_directory"), \
                mock.patch.object(M.E, "secure_read", side_effect=[raw, b"public-pem"]) as read, \
                mock.patch.object(M.E, "der_from_pem", return_value=public_der):
            result = M.identity_row("alice", MAIL, MAIL, PATH, 66)
        self.assertEqual(result["tenant"], TENANT)
        self.assertEqual(result["client"], CLIENT)
        self.assertEqual(result["certificate_sha256"], M.digest(public_der))
        self.assertEqual(result["status"], "public_certificate_read")
        self.assertEqual([str(call[0][0]) for call in read.call_args_list], [PATH, CERT])
        self.assertNotIn("alice.key", str(result))
        self.assertNotIn(CERT, str(result))

    def test_bad_certificate_does_not_erase_verified_identity_metadata(self):
        data = self.identity()
        data["certificate"] = "/etc/shadow"
        raw = json.dumps(data).encode("ascii")
        with mock.patch.object(M.E, "trusted_directory"), \
                mock.patch.object(M.E, "secure_read", return_value=raw) as read:
            result = M.identity_row("alice", MAIL, MAIL, PATH, 66)
        self.assertEqual(result["status"], "certificate_unverified")
        self.assertEqual(result["client"], CLIENT)
        self.assertEqual(result["certificate_sha256"], "")
        self.assertEqual(read.call_count, 1)

    def test_duplicate_json_and_inline_credentials_refused(self):
        data = json.dumps(self.identity()).encode("ascii")
        for raw in (data[:-1] + b',"mailbox":"alice@example.org"}',
                    data[:-1] + b',"client_secret":"hidden"}'):
            with mock.patch.object(M.E, "trusted_directory"), \
                    mock.patch.object(M.E, "secure_read", return_value=raw):
                result = M.identity_row("alice", MAIL, MAIL, PATH, 66)
            self.assertEqual(result["status"], "unverified")
            self.assertEqual(result["client"], "")
            self.assertNotIn("hidden", str(result))

    def test_source_and_runtime_never_inferred_from_one_another(self):
        raw = (HEADER + "alice\t" + MAIL + "\t" + MAIL + "\t" + PATH + "\n").encode("ascii")
        with mock.patch.object(M, "read_optional", side_effect=[raw, None]), \
                mock.patch.object(M, "identity_row", return_value={"fixture":"row"}):
            source = M.map_snapshot(M.SOURCE, False, 66)
            runtime = M.map_snapshot(M.RUNTIME, True, 66)
        self.assertEqual(source["status"], "ok")
        self.assertEqual(runtime["status"], "absent")
        self.assertEqual(M.relation(source, runtime), "source_only")
        self.assertEqual(M.relation(source, source), "same")
        self.assertEqual(M.relation(source, dict(source, sha256="b"*64)), "different")

    def test_runtime_rejects_alias_sender_and_ambiguous_owners(self):
        row = "alice\t" + MAIL + "\t" + MAIL + "\t" + PATH + "\n"
        for raw in (HEADER + row + row,
                    HEADER + row.replace("\t" + MAIL + "\t", "\talias@example.org\t", 1)):
            with mock.patch.object(M, "read_optional", return_value=raw.encode("ascii")), \
                    mock.patch.object(M, "identity_row") as identity:
                self.assertEqual(M.map_snapshot(M.RUNTIME, True, 66)["status"], "unverified")
                identity.assert_not_called()

    def test_drift_fails_closed(self):
        with mock.patch.object(M, "sample", side_effect=[{"first": 1}, {"second": 2}]):
            with self.assertRaisesRegex(M.Refused, "inventory_changed_during_read"):
                M.inventory(66)

    def test_installed_marker_is_exact_and_separate_from_runtime(self):
        runtime = dict(status="ok", sha256="a"*64, rows=[])
        main, master = b"main", b"master"
        marker = json.dumps(dict(version=1, runtime_map_sha256="a"*64,
            active={"main.cf":M.digest(main),"master.cf":M.digest(master)})).encode("ascii")
        with mock.patch.object(M, "read_optional", return_value=marker), \
                mock.patch.object(M.E, "trusted_directory"), \
                mock.patch.object(M.E, "secure_read", side_effect=[main, master, main, b"changed"]):
            self.assertEqual(M.marker_snapshot(runtime), "matches_marker")
            self.assertEqual(M.marker_snapshot(runtime), "mismatch")
        with mock.patch.object(M, "read_optional", return_value=None):
            self.assertEqual(M.marker_snapshot(runtime), "missing_marker")


if __name__ == "__main__":
    unittest.main()
