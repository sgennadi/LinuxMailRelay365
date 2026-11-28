"""Verify the native candidate workflow cannot silently skip acceptance."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class NativeBrokerInstallContractTests(unittest.TestCase):
    def test_workflow_runs_only_explicit_disposable_candidate(self):
        workflow = (ROOT / ".github/workflows/rocky-enforcing-vm.yml").read_text()
        shell = (ROOT / "tests/rocky_vm_boot_enforcing.sh").read_text()
        fixture = (ROOT / "tests/rocky_vm_primary_broker_install.py").read_text()
        self.assertIn("LMR365_KVM_TPM_BROKER_INSTALL_ACCEPTANCE: " +
                      "${{ github.ref_name == 'feature/primary-tpm-broker-protocol' }}", workflow)
        self.assertIn("LMR365_KVM_TPM_BROKER_INSTALL_ACCEPTANCE=true timeout 1200", shell)
        for marker in ("REVIEW=verified", "APPLY=all_seven_native_stages",
                       "PS256=verified_startup", "RESTART=new_verified_invocation",
                       "ROLLBACK=all_seven_native_stages", "BASELINE=restored",
                       "CLOUD_TESTED=no", "REBOOT_TESTED=no", "PHYSICAL_TPM_TESTED=no"):
            full = "LMR365_BROKER_INSTALL_" + marker
            self.assertIn("'" + full + "'", shell)
            self.assertIn(full, fixture)
        self.assertIn('F.disposable()', fixture)
        self.assertIn("coordinator.apply(journal, approved, C.tx.APPLY)", fixture)
        self.assertIn("coordinator.rollback(journal, approved, C.tx.ROLLBACK)", fixture)
        self.assertNotIn("setenforce", fixture)


if __name__ == "__main__":
    unittest.main()
