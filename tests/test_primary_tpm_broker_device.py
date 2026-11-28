"""Device stage tests: no real TPM access, chown, chmod or policy mutation."""
import pathlib
import sys
import unittest
from unittest.mock import Mock, patch
from contextlib import contextmanager

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
import m365_tpm_broker_device as D


class DeviceStageTests(unittest.TestCase):
    def setUp(self):
        self.before = D.Evidence("12345678-1234-4234-8234-123456789abc",
            12, 33, 253, "/sys/devices/platform/tpm/tpmrm/tpmrm0",
            "system_u:object_r:tpm_device_t:s0", 0, 810, 0o600)
        self.spec = D.Spec(self.before, 812, 813)
        self.current = self.before
        self.guard, self.account = Mock(), Mock()
        self.changes = []
        self.stage = D.DeviceStage(self.spec, self.guard, lambda: self.current,
                                   self.change, self.account)

    def change(self, before, after):
        self.assertEqual(self.current, before)
        self.changes.append((before, after))
        self.current = after

    def test_install_and_rollback_preserve_everything_except_reviewed_dac(self):
        plan = self.stage.stage_plan()
        self.assertEqual(self.stage.probe(), plan["before"])
        self.stage.mutate("install")
        self.assertEqual(self.current, self.before._replace(gid=813, mode=0o660))
        self.assertEqual(self.stage.probe(), plan["after"])
        self.stage.mutate("rollback")
        self.assertEqual(self.current, self.before)
        self.assertEqual(self.stage.probe(), plan["before"])
        self.assertEqual(self.changes, [(self.before, self.stage.after),
                                       (self.stage.after, self.before)])

    def test_same_boot_node_and_exact_label_required(self):
        for change in ({"boot": "22345678-1234-4234-8234-123456789abc"},
                       {"inode": 34}, {"rdev": 254}, {"fsdev": 13},
                       {"sysfs": "/sys/devices/other/tpmrm0"},
                       {"label": "system_u:object_r:other_t:s0"},
                       {"gid": 814}, {"mode": 0o644}):
            self.current = self.before._replace(**change)
            with self.assertRaisesRegex(D.Refused, "foreign_or_partial"):
                self.stage.probe()
            with self.assertRaisesRegex(D.Refused, "before_state_changed"):
                self.stage.mutate("install")
        self.assertEqual(self.changes, [])

    def test_partial_chown_before_chmod_not_treated_as_success(self):
        self.current = self.before._replace(gid=813)
        with self.assertRaisesRegex(D.Refused, "foreign_or_partial"):
            self.stage.probe()
        for direction in ("install", "rollback"):
            with self.assertRaises(D.Refused):
                self.stage.mutate(direction)
        self.assertEqual(self.changes, [])

    def test_guard_or_signer_identity_failure_prevents_dac_change(self):
        self.guard.side_effect = D.Refused("maintenance")
        with self.assertRaisesRegex(D.Refused, "maintenance"):
            self.stage.mutate("install")
        self.guard.side_effect = None
        self.account.side_effect = D.Refused("account_changed")
        with self.assertRaisesRegex(D.Refused, "account_changed"):
            self.stage.mutate("install")
        self.assertEqual(self.changes, [])

    def test_invalid_spec_refuses_shared_group_root_or_raw_tpm(self):
        for bad in (self.spec._replace(signer_gid=810),
                    self.spec._replace(signer_uid=0),
                    self.spec._replace(baseline=self.before._replace(mode=0o666)),
                    self.spec._replace(baseline=self.before._replace(
                        sysfs="/sys/devices/platform/tpm/tpm0"))):
            with self.assertRaises(D.Refused):
                D.validate(bad)

    def test_native_change_uses_pinned_descriptor_and_checks_intermediate(self):
        @contextmanager
        def pin():
            yield 7, 9
        intermediate = self.before._replace(gid=813)
        with patch.object(D, "pinned_node", pin), \
             patch.object(D, "observe_pinned", side_effect=[
                 self.before, intermediate, self.stage.after]), \
             patch.object(D, "check_pinned", return_value=(Mock(), "/proc/self/fd/9")), \
             patch.object(D.os, "chown") as chown, patch.object(D.os, "chmod") as chmod, \
             patch.object(D.policy, "enforcing"):
            D.change_native(self.before, self.stage.after)
            chown.assert_called_once_with("/proc/self/fd/9", 0, 813)
            chmod.assert_called_once_with("/proc/self/fd/9", 0o660)

    def test_native_change_refuses_different_inode_before_mutation(self):
        @contextmanager
        def pin():
            yield 7, 9
        with patch.object(D, "pinned_node", pin), \
             patch.object(D, "observe_pinned", return_value=self.before._replace(inode=44)), \
             patch.object(D.os, "chown") as chown, patch.object(D.os, "chmod") as chmod:
            with self.assertRaisesRegex(D.Refused, "before_state_changed"):
                D.change_native(self.before, self.stage.after)
            chown.assert_not_called()
            chmod.assert_not_called()

    def test_native_change_cannot_change_other_device_or_selinux_label(self):
        for bad in (self.stage.after._replace(inode=44),
                    self.stage.after._replace(rdev=99),
                    self.stage.after._replace(sysfs="/sys/devices/other/tpmrm0")):
            with patch.object(D, "pinned_node") as pin:
                with self.assertRaisesRegex(D.Refused, "change_scope"):
                    D.change_native(self.before, bad)
                pin.assert_not_called()

    def test_review_refuses_unstable_device(self):
        with self.assertRaisesRegex(D.Refused, "evidence_changed"):
            D.prepare_spec(812, 813, Mock(side_effect=[
                self.before, self.before._replace(inode=44)]))


if __name__ == "__main__":
    unittest.main()
