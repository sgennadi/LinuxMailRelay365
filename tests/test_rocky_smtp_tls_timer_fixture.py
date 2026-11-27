import importlib.util
import pathlib
import unittest

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
