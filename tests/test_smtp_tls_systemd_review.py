import importlib.util
import pathlib
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("systemd_review", ROOT / "linux/review-smtp-tls-systemd.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class SystemdReviewTests(unittest.TestCase):
    def setUp(self):
        names = [M.TIMER, M.SERVICE, *M.RECOVERY]
        self.units = [{"name": name, "status": "unchanged"} for name in names]
        self.runtime = [{"name": "helper.py", "status": "unchanged"}]
        self.states = {name: {"LoadState": "loaded", "FragmentPath": str(M.UNIT_DIR / name),
                             "DropInPaths": "", "NeedDaemonReload": "no", "Job": "0",
                             "ActiveState": "inactive", "UnitFileState": "enabled"} for name in names}

    def eligible(self, action):
        return M.eligibility(action, self.runtime, self.units, self.states)[0]

    def test_overrides_block_live(self):
        self.states[M.SERVICE]["DropInPaths"] = "/foreign/override.conf"
        self.assertFalse(self.eligible("enable-timer"))

    def test_recovery_and_inactive_service_required(self):
        self.states[M.RECOVERY[0]]["UnitFileState"] = "disabled"
        self.assertFalse(self.eligible("renew-now"))
        self.states[M.RECOVERY[0]]["UnitFileState"] = "enabled"
        self.states[M.SERVICE]["ActiveState"] = "activating"
        self.assertFalse(self.eligible("enable-timer"))
        self.states[M.SERVICE]["ActiveState"] = "inactive"
        self.assertTrue(self.eligible("enable-timer"))

    def test_stop_preserves_control_despite_runtime_conflict(self):
        self.runtime[0]["status"] = "conflict"
        self.assertTrue(self.eligible("disable-timer"))
        self.states[M.TIMER]["FragmentPath"] = "/foreign/timer"
        self.assertFalse(self.eligible("stop-timer"))

    def test_install_requires_disabled_inactive_units(self):
        self.assertFalse(self.eligible("install"))
        for state in self.states.values():
            state["UnitFileState"] = "disabled"
        self.assertTrue(self.eligible("install"))
        self.runtime[0]["status"] = "conflict"
        self.assertFalse(self.eligible("install"))

    def test_stale_review_never_mutates(self):
        with patch.object(M, "create_runtime") as create, patch.object(M.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                M.execute("install", "a"*64, lambda _: {"plan_sha256": "b"*64, "apply_supported": True})
            create.assert_not_called()
            run.assert_not_called()

    def test_fixed_manager_action(self):
        with patch.object(M.subprocess, "run", return_value=Mock(returncode=0)) as run:
            result = M.execute("disable-timer", "a"*64,
                lambda _: {"plan_sha256": "a"*64, "apply_supported": True})
        self.assertEqual(run.call_args.args[0][-3:], ["disable-timer", "--confirm", "MANAGE_TLS_UNITS"])
        self.assertEqual(result["status"], "command_accepted")
