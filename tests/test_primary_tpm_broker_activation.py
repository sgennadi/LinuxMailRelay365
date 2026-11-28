"""Lifecycle stage tests; all native commands and live process evidence mocked."""
import json
import pathlib
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
import m365_tpm_broker_activation as A


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.spec = A.Spec("a" * 64, "b" * 64, 812, 813, 814)
        self.present, self.enabled, self.running, self.received = True, False, False, True
        self.calls = []
        self.guard = Mock()
        self.process = Mock()
        self.sandbox = dict(A.SANDBOX, DeviceAllow="/dev/tpmrm0 rw",
                            BindPaths="/dev/tpmrm0:/dev/tpmrm0")
        self.stage = A.ActivationStage(self.spec, self.guard, self.native, Mock(),
            lambda spec: self.present, lambda: self.enabled, self.process)

    def status(self):
        return dict(LoadState="loaded" if self.present else "not-found",
                    ActiveState="active" if self.running else "inactive",
                    SubState="running" if self.running else "dead",
                    MainPID="123" if self.running else "0", ControlPID="0",
                    Result="success", InvocationID="a" * 32 if self.running else "",
                    UnitFileState="enabled" if self.enabled else
                                  ("disabled" if self.present else ""),
                    FragmentPath=str(A.UNIT_PATH) if self.present else "",
                    DropInPaths="", NeedDaemonReload="no",
                    ControlGroup="/system.slice/" + A.UNIT if self.running else "")

    def journal_row(self):
        status = self.status()
        return {"MESSAGE": A.READY, "_SYSTEMD_UNIT": A.UNIT,
                "_SYSTEMD_INVOCATION_ID": status["InvocationID"],
                "_PID": status["MainPID"], "_UID": "812", "_GID": "813",
                "_EXE": str(A.bootstrap.EXECUTABLE)}

    def native(self, tool, args):
        self.calls.append((tool, args))
        if tool == A.JOURNALCTL:
            return json.dumps(self.journal_row()).encode("ascii") + b"\n" if self.received else b""
        if args[0] == "show":
            values = dict(self.status(), **self.sandbox)
            return "".join(key[2:] + "=" + values[key[2:]] + "\n"
                           for key in args[3:]).encode("ascii")
        if args == ["daemon-reload"]:
            return b""
        if args == ["enable", A.UNIT]:
            self.enabled = True
        elif args == ["start", A.UNIT]:
            self.running = True
        elif args == ["stop", A.UNIT]:
            self.running = False
        elif args == ["disable", A.UNIT]:
            self.enabled = False
        else:
            self.fail("unexpected native operation")
        return b""

    def changes(self):
        return [args for tool, args in self.calls if tool == A.SYSTEMCTL and args[0] != "show"]

    def test_install_enable_ready_and_reverse_stop_disable(self):
        plan = self.stage.stage_plan()
        self.assertEqual(self.stage.probe(), plan["before"])
        self.stage.mutate("install")
        self.assertEqual(self.stage.probe(), plan["after"])
        self.stage.mutate("rollback")
        self.assertEqual(self.stage.probe(), plan["before"])
        self.assertEqual(self.changes(), [["daemon-reload"], ["enable", A.UNIT],
                                         ["start", A.UNIT], ["stop", A.UNIT],
                                         ["disable", A.UNIT]])
        self.process.assert_called()

    def test_absent_unit_allowed_only_as_baseline(self):
        self.present = False
        self.assertFalse(self.stage.state())
        with self.assertRaisesRegex(A.Refused, "unexpected_state"):
            self.stage.mutate("install")
        self.assertEqual(self.changes(), [])

    def test_partial_activation_never_guesses_success_or_removal(self):
        for enabled, running in ((True, False), (False, True)):
            self.enabled, self.running = enabled, running
            for direction in ("install", "rollback"):
                with self.assertRaisesRegex(A.Refused, "partial_or_foreign"):
                    self.stage.mutate(direction)
        self.assertEqual(self.changes(), [])

    def test_current_invocation_receipt_and_exact_process_required(self):
        self.enabled = self.running = True
        self.received = False
        with self.assertRaisesRegex(A.Refused, "ready_receipt_missing"):
            self.stage.probe()
        self.received = True
        self.process.side_effect = A.Refused("process_identity")
        with self.assertRaisesRegex(A.Refused, "process_identity"):
            self.stage.mutate("rollback")
        self.assertEqual(self.changes(), [])

    def test_sandbox_drift_refuses_before_enable(self):
        self.sandbox["DeviceAllow"] = "/dev/tpm0 rw"
        with self.assertRaisesRegex(A.Refused, "sandbox_unverified"):
            self.stage.mutate("install")
        self.assertEqual(self.changes(), [["daemon-reload"]])

    def test_receipt_rejects_wrong_invocation_pid_uid_domain_executable_and_duplicates(self):
        self.running = True
        row = self.journal_row()
        status = self.status()
        self.assertTrue(A.receipt(json.dumps(row).encode(), self.spec, status))
        for key, value in (("_SYSTEMD_INVOCATION_ID", "b" * 32), ("_PID", "124"),
                           ("_UID", "0"), ("_GID", "814"), ("_EXE", "/usr/bin/python3"),
                           ("MESSAGE", "other")):
            changed = dict(row, **{key: value})
            with self.assertRaisesRegex(A.Refused, "receipt_unverified"):
                A.receipt(json.dumps(changed).encode(), self.spec, status)
        raw = json.dumps(row).encode()
        with self.assertRaisesRegex(A.Refused, "ambiguous_ready_receipt"):
            A.receipt(raw + b"\n" + raw, self.spec, status)

    def test_guard_refusal_precedes_systemctl(self):
        self.guard.side_effect = A.Refused("maintenance")
        with self.assertRaisesRegex(A.Refused, "maintenance"):
            self.stage.mutate("install")
        self.assertEqual(self.calls, [])

    def test_start_timeout_does_not_claim_success(self):
        self.received = False
        with patch.object(A, "WAIT_SECONDS", 0):
            with self.assertRaisesRegex(A.Refused, "ready_timeout"):
                self.stage.mutate("install")
        self.assertTrue(self.enabled and self.running)
        with self.assertRaisesRegex(A.Refused, "receipt_missing"):
            self.stage.probe()


if __name__ == "__main__":
    unittest.main()
