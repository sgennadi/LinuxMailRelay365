import importlib.util
import pathlib
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("timer", ROOT / "tests/rocky_vm_smtp_tls_renewal.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class TimerRenewalEvidenceTests(unittest.TestCase):
    def state(self, **kwargs):
        data = {"ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0",
                "ExecMainStartTimestampMonotonic": "100", "ExecMainExitTimestampMonotonic": "200"}
        data.update(kwargs)
        return data

    def test_completed_requires_new_execution(self):
        self.assertTrue(M.completed(self.state(), 99))
        self.assertFalse(M.completed(self.state(), 100))
        self.assertFalse(M.completed(self.state(ExecMainExitTimestampMonotonic="0")))
        self.assertFalse(M.completed(self.state(ActiveState="activating")))

    def test_refusal_requires_nonzero_exit(self):
        state = self.state(ActiveState="failed", Result="exit-code", ExecMainStatus="1")
        self.assertTrue(M.completed(state, failure=True))
        self.assertFalse(M.completed(state))
        self.assertFalse(M.completed(dict(state, ExecMainStatus="0"), failure=True))
        self.assertFalse(M.completed(dict(state, Result="timeout"), failure=True))

    def test_only_fixture_command_and_required_markers(self):
        self.assertIn("manage-smtp-tls-process-renewal.py --profile", M.COMMAND)
        self.assertNotIn("certbot", M.COMMAND)
        shell = (ROOT / "tests/rocky_vm_boot_enforcing.sh").read_text()
        for marker in ("TIMER_RENEWAL=presented_verified", "RENEWAL_UNCHANGED=verified",
                       "RENEWAL_MIXED=refused", "RENEWAL_REFUSAL=presented_verified",
                       "RENEWAL_REAL_CA=no"):
            self.assertIn("LMR365_VM_CLIENT_TLS_" + marker, shell)

    def test_raw_dbus_timestamp_uses_uint64_microseconds(self):
        fixture = Mock()
        path = "/org/freedesktop/systemd1/unit/linuxmailrelay365_2dsmtp_2dacme_2drenew_2etimer"
        fixture.run.side_effect = [('o "' + path + '"\n').encode(), b"t 11133612\n"]
        self.assertEqual(M.timer_trigger_usec(fixture), 11133612)
        self.assertEqual(fixture.run.call_args_list[0].args[-3:], ("LoadUnit", "s", M.TIMER))
        self.assertEqual(fixture.run.call_args.args, (
            "busctl", "--system", "get-property", "org.freedesktop.systemd1", path,
            "org.freedesktop.systemd1.Timer", "LastTriggerUSecMonotonic"))

    def test_invalid_timestamp_and_object_rejected(self):
        path = b'o "/org/freedesktop/systemd1/unit/fixture_2etimer"\n'
        for value in (b"11.133612s", b"t -1\n", b"u 12\n", b"t 18446744073709551616\n",
                      b"t 12\nt 13\n", b"t 01\n"):
            fixture = Mock()
            fixture.run.side_effect = [path, value]
            with self.subTest(value=value), self.assertRaises(ValueError):
                M.timer_trigger_usec(fixture)
        fixture = Mock()
        fixture.run.return_value = b'o "/unrelated"\n'
        with self.assertRaises(ValueError):
            M.timer_trigger_usec(fixture)
        fixture.run.assert_called_once()

    def test_timer_trigger_must_be_new_and_precede_service(self):
        state = self.state(ExecMainStartTimestampMonotonic="120")
        with patch.object(M, "properties", return_value={"Unit": M.SERVICE}), \
             patch.object(M, "timer_trigger_usec", return_value=110):
            self.assertEqual(M.verify_timer_trigger(Mock(), state, 100), 110)
            with self.assertRaises(ValueError):
                M.verify_timer_trigger(Mock(), state, 110)
            with self.assertRaises(ValueError):
                M.verify_timer_trigger(Mock(), self.state(), 100)
        with patch.object(M, "properties", return_value={"Unit": "other.service"}), \
             patch.object(M, "timer_trigger_usec", return_value=110):
            with self.assertRaises(ValueError):
                M.verify_timer_trigger(Mock(), state, 100)
