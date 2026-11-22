"""Static fail-closed contracts for disposable Rocky STARTTLS test cleanup.

These tests do NOT modify local Postfix, run daemons, or bypass SELinux.
Runtime behaviour must additionally pass the experimental Rocky KVM job.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TLS = (ROOT / "tests/rocky_vm_tls_auth_enforcing.sh").read_text(encoding="utf-8")
KVM = (ROOT / "tests/rocky_vm_boot_enforcing.sh").read_text(encoding="utf-8")
SIDECAR = (ROOT / "tests/rocky_vm_isolated_postfix_enforcing.sh").read_text(
    encoding="utf-8")


class RockyTlsCleanupContractTests(unittest.TestCase):
    def test_snapshot_happens_before_test_reconfigures_postfix(self):
        self.assertIn('baseline=/var/lib/lmr365-ci-postfix-baseline', TLS)
        self.assertIn('sudo install -o root -g root -m 0700 -d "$baseline"', TLS)
        self.assertIn('sudo cp -p -- "/etc/postfix/$name" "$baseline/$name"', TLS)
        self.assertIn('LMR365_LAB_PREEXISTING_SMTP_2525_REFUSED', TLS)
        self.assertLess(
            TLS.index('sudo cp -p -- "/etc/postfix/$name" "$baseline/$name"'),
            TLS.index('sudo postconf -M ' + "'2525/inet=2525"))

    def test_cleanup_must_restore_both_original_configs_and_labels(self):
        cleanup = TLS.split('if test "$mode" = --cleanup; then', 1)[1].split(
            'if test "$mode" = --setup; then', 1)[0]
        for item in (
            'sudo systemctl stop lmr365-ci-auth.service postfix.service',
            'LMR365_LAB_BASELINE_PARENT_UNTRUSTED',
            'LMR365_LAB_BASELINE_FILE_UNTRUSTED',
            'LMR365_LAB_PRIMARY_CONFIG_CHANGED_TYPE',
            'LMR365_LAB_TEMP_RESTORE_PATH_EXISTS',
            'sudo cp -p -- "$baseline/$name" "$candidate"',
            'sudo cmp -s -- "$candidate" "$baseline/$name"',
            'sudo mv -T -- "$candidate" "/etc/postfix/$name"',
            'sudo restorecon -F "/etc/postfix/$name"',
            'sudo cmp -s -- "/etc/postfix/$name" "$baseline/$name"',
            'LMR365_LAB_2525_SERVICE_LEFT_IN_MASTER_CF',
            'sudo postfix check',
            'LMR365_LAB_POSTFIX_BASELINE=restored_exact_bytes',
        ):
            with self.subTest(item=item):
                self.assertIn(item, cleanup)

    def test_cleanup_refuses_unknown_service_and_removes_baseline(self):
        cleanup = TLS.split('if test "$mode" = --cleanup; then', 1)[1].split(
            'if test "$mode" = --setup; then', 1)[0]
        self.assertIn('LMR365_LAB_2525_NOT_OUR_SERVICE', cleanup)
        self.assertIn('sudo rm -f -- "$baseline/main.cf" "$baseline/master.cf"', cleanup)
        self.assertIn('sudo rmdir -- "$baseline"', cleanup)
        self.assertIn('LMR365_LAB_2525_MASTER_CF_ENTRY_REMOVED=yes', cleanup)
        self.assertLess(cleanup.index('sudo postfix check'),
                        cleanup.index('sudo rm -f -- "$baseline/main.cf"'))

    def test_vm_must_require_cleanup_proof_before_sidecar(self):
        self.assertIn('grep -Fxq "LMR365_LAB_POSTFIX_BASELINE=restored_exact_bytes"', KVM)
        self.assertIn('grep -Fxq "LMR365_LAB_2525_MASTER_CF_ENTRY_REMOVED=yes"', KVM)
        self.assertLess(
            KVM.index('LMR365_GUEST_POSTFIX_CONFIG_RESTORED=exact_pre_tls_baseline'),
            KVM.index('LMR365_GUEST_POSITIVE_ISOLATED_POSTFIX=verified_under_enforcing'))

    def test_sidecar_refuses_leftover_submission_listener(self):
        self.assertIn('LMR365_POSITIVE_SIDECAR_INHERITED_TEST_SMTP_2525', SIDECAR)
        self.assertIn('LMR365_POSITIVE_SIDECAR_UNEXPECTED_SMTP_2525', SIDECAR)
        self.assertIn("sudo postconf -M '2525/inet'", SIDECAR)
        self.assertIn("sudo ss -H -ltn '( sport = :2525 )'", SIDECAR)


if __name__ == "__main__":
    unittest.main()
