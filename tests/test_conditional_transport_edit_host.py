"""Edit CLI orchestration and approval contract, no real host writes."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("edit_host", "linux/manage-conditional-transport-edit.py")
S = H.sibling("test_switch", "conditional-transport-edit-transaction.py")
I = H.sibling("test_inventory", "inspect-conditional-transport-recovery.py")
F = load("edit_host_fixture", "tests/test_conditional_transport_edit_transaction.py")
A, B = "a" * 64, "b" * 64


class EditHostTests(unittest.TestCase):
    def setUp(self):
        self.fixture = F.MultiTransportSwitchTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        f = self.fixture.f
        self.host = H.EditHost(S, I, f.fd, f.parent, (f.uid, f.gid), f.uid, f.guard)

    def test_strict_arguments(self):
        common = ["--maintenance-confirmation", I.O.MAINTENANCE]
        for args in (["--review", A], ["--review-recovery"],
                     ["--switch", A, "--approve-review-sha256", B,
                      "--approve-plan-sha256", A, "--confirm", S.BEGIN],
                     ["--commit", A, "--approve-review-sha256", B, "--confirm", S.COMMIT],
                     ["--rollback", A, "--approve-review-sha256", B, "--confirm", S.ROLLBACK]):
            H.validate_args(H.arguments(args + common), S, I.O.MAINTENANCE)
        for args in (["--review", A, "--confirm", S.BEGIN],
                     ["--switch", A, "--confirm", S.BEGIN],
                     ["--rollback", A, "--approve-review-sha256", B, "--confirm", S.COMMIT],
                     ["--commit", A, "--approve-review-sha256", B,
                      "--approve-plan-sha256", A, "--confirm", S.COMMIT]):
            with self.assertRaises(S.Refused):
                H.validate_args(H.arguments(args + common), S, I.O.MAINTENANCE)

    def test_pending_can_be_discovered_without_revision(self):
        self.assertIsNone(self.host.pending())
        f = self.fixture
        revision = f.begin()
        observation, receipt = self.host.pending()
        self.assertEqual(receipt["old_revision"], f.old)
        self.assertEqual(receipt["new_revision"], revision)
        self.assertEqual(receipt["layout"], "new")
        self.assertEqual(receipt["commit_candidate"], "yes")
        self.assertEqual(receipt["rollback_candidate"], "yes")
        self.assertTrue(S.R.valid_sha(receipt["review_sha256"]))
        self.assertNotIn("old_record", receipt)
        self.assertNotIn("new_journal", receipt)
        with self.assertRaisesRegex(S.Refused, "edit_recovery_review_changed"):
            self.host.resolve(revision, A, "commit")
        with patch.object(self.host, "verify_generation", side_effect=f.native):
            self.assertEqual(self.host.resolve(revision, receipt["review_sha256"], "rollback"), f.old)
        self.assertIsNone(self.host.pending())

    def test_review_receipt_excludes_private_hashes_and_credentials(self):
        f = self.fixture
        baseline = ({"sender_dependent_default_transport_maps": "fixture"},
                    {}, {}, {}, {})
        with patch.object(I.H, "state", return_value=baseline), \
                patch.object(I.H, "backend_for", return_value="hash"), \
                patch.object(I.H.P, "local_addresses", return_value=set()), \
                patch.object(I.H, "network", return_value=(A, 2)), \
                patch.object(self.host, "verify_policy", return_value=True):
            review = self.host.review_edit(f.old, f.rules)
            receipt = self.host.review_receipt(f.old, review)
        self.assertEqual(receipt["retain_indices"], "0,1")
        self.assertEqual(receipt["new_plan"], f.new["plan"])
        self.assertEqual(receipt["tls_destinations"], 2)
        self.assertNotIn("state", receipt)
        self.assertNotIn("map_ids", receipt)
        self.assertNotIn("private", receipt)

    def test_switch_refuses_stale_approval_before_candidate_preparation(self):
        f = self.fixture
        review = {"private": f.reviewed, "token": B}
        with patch.object(self.host, "review_edit", return_value=review), \
                patch.object(S, "begin") as begin:
            with self.assertRaisesRegex(S.Refused, "edit_review_changed"):
                self.host.switch(f.old, {"rules": f.rules, "credentials": []}, A, f.new["plan"])
            begin.assert_not_called()


if __name__ == "__main__":
    unittest.main()
