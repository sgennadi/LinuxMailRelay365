"""Guard the opt-in real Enforcing queue acceptance path, not a simulation."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class QueueVmContract(unittest.TestCase):
    def test_same_commit_vm_is_fail_closed(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        vm = (ROOT / ".github/workflows/rocky-enforcing-vm.yml").read_text(encoding="utf-8")
        boot = (ROOT / "tests/rocky_vm_boot_enforcing.sh").read_text(encoding="utf-8")
        fixture = (ROOT / "tests/smoke_native_sendmail_queue_preview.py").read_text(encoding="utf-8")
        gate = ci.split("  rc19-queue-enforcing-vm:", 1)[1].split("  rc18-rocky-enforcing-vm:", 1)[0]
        self.assertIn("queue-acceptance: true", gate)
        self.assertIn("uses: ./.github/workflows/rocky-enforcing-vm.yml", gate)
        self.assertNotIn("continue-on-error", gate)
        self.assertIn("default: false", vm)
        self.assertIn("tests/rocky_vm_kvm_probe.sh", vm)
        self.assertLess(boot.index("LMR365_GUEST_SENDMAIL_RECOVERY_POST_REBOOT=verified_unchanged"),
                        boot.index("LMR365_CI_KVM_QUEUE_FIXTURE=1"))
        self.assertIn("unshare --mount --net --propagation private", boot)
        self.assertIn('diff -u "$work/sendmail-after-reboot" "$work/sendmail-after-queue-test"', boot)
        for marker in ('systemd-detect-virt", "--vm"', 'selinux_enforcing_required',
                       'vm_marker_boot_mismatch', 'vm_original_queue_not_empty',
                       'mount", "--bind"', 'chcon", "--reference=" + path',
                       'matchpathcon", "-V"', 'vm_private_spool_not_verified'):
            self.assertIn(marker, fixture)
        self.assertNotIn("setenforce", fixture)
        self.assertNotIn("os.unlink(", fixture)
        self.assertNotIn("shutil.rmtree(", fixture)


if __name__ == "__main__":
    unittest.main()
