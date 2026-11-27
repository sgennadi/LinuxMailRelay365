import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fixture", ROOT / "tests/rocky_vm_smtp_client_tls_enforcing.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class BootRecoveryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.boot = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        self.unit = M.BOOT_UNITS[1]
        self.row = {"_SYSTEMD_UNIT": self.unit, "_BOOT_ID": self.boot.replace("-", ""),
                    "MESSAGE": "TLS_TRANSACTION=restored", "__MONOTONIC_TIMESTAMP": "100"}

    def test_current_boot_before_postfix_required(self):
        M.verify_boot_event([self.row], self.unit, "TLS_TRANSACTION=restored", self.boot, 101)
        for cutoff in (0, 99, 100):
            with self.assertRaises(ValueError):
                M.verify_boot_event([self.row], self.unit, "TLS_TRANSACTION=restored", self.boot, cutoff)

    def test_old_boot_wrong_unit_or_duplicate_refused(self):
        for rows in ([], [dict(self.row, _BOOT_ID="old")], [dict(self.row, _SYSTEMD_UNIT="other")],
                     [dict(self.row, MESSAGE="TLS_TRANSACTION=unchanged")], [self.row,self.row]):
            with self.assertRaises(ValueError):
                M.verify_boot_event(rows, self.unit, "TLS_TRANSACTION=restored", self.boot, 101)

    def test_vm_requires_actual_reboot_and_peer_check(self):
        script = (ROOT / "tests/rocky_vm_boot_enforcing.sh").read_text()
        self.assertIn("--prepare-reboot", script)
        self.assertIn("--verify-reboot", script)
        self.assertIn('test "$client_tls_new_boot" != "$client_tls_boot"', script)
        self.assertIn("LMR365_VM_CLIENT_TLS_REBOOT_ORDER=verified_before_postfix", script)
        self.assertIn("LMR365_VM_CLIENT_TLS_BOOT_RECOVERY=presented_verified", script)
