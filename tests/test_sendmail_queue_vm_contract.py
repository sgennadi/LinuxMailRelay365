"""Guard the opt-in real Enforcing queue acceptance path, not a simulation."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[1]


class QueueVmContract(unittest.TestCase):
    def test_mountinfo_recognizes_exact_same_device_bind(self):
        spec = importlib.util.spec_from_file_location(
            "queue_vm_fixture", ROOT / "tests/smoke_native_sendmail_queue_preview.py")
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        path = "/var/spool/mqueue"
        root = "24 1 253:0 / / rw - xfs /dev/vda1 rw"
        unrelated = "25 24 253:0 /var/spool/other /var/spool/mqueue-other rw - xfs /dev/vda1 rw"
        bind = "26 24 253:0 /var/spool/lmr365-ci-queue-test /var/spool/mqueue rw - xfs /dev/vda1 rw"
        self.assertEqual(fixture.vm_mount_records(root + "\n" + unrelated, path), [])
        self.assertEqual(fixture.vm_mount_records(root + "\n" + bind, path), [26])
        for record in (bind + "\n" + bind.replace("26 24", "27 24"),
                       bind.replace(path + " rw", path + "/nested rw"),
                       "broken"):
            with self.assertRaises(AssertionError):
                fixture.vm_mount_records(root + "\n" + record, path)
        with self.assertRaises(AssertionError):
            fixture.vm_mount_records(root, "/var/spool/arbitrary")


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
        self.assertIn("len(mounted()) == 1", fixture)
        self.assertIn("(mounted_stat.st_dev, mounted_stat.st_ino)", fixture)
        self.assertIn("(private_stat.st_dev, private_stat.st_ino)", fixture)
        self.assertIn("vm_fixture_aliases_original", fixture)
        self.assertIn("vm_private_spool_mountinfo_unverified", fixture)
        self.assertIn("vm_private_spool_inode_unverified", fixture)
        self.assertNotIn("setenforce", fixture)
        self.assertNotIn("os.unlink(", fixture)
        self.assertNotIn("shutil.rmtree(", fixture)


if __name__ == "__main__":
    unittest.main()
