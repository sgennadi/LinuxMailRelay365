"""Policy-stage strict inventory, artifact approval and guarded rollback tests."""
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
import m365_tpm_broker_policy as P


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.pp = b"synthetic pp"
        self.cil = b"synthetic lmr365_tpm_signer_t"
        self.baseline = (("100", "base", "pp", True, "a" * 64),
                         ("200", "other", "cil", False, "b" * 64))
        self.old_label = "system_u:object_r:bin_t:s0"
        self.spec = P.Spec(self.baseline, self.old_label, P.sha_bytes(self.pp),
                           P.sha_bytes(self.cil), "c" * 64)
        self.installed = False
        self.actual = self.old_label
        self.calls = []
        self.guard = Mock()
        self.stage = P.PolicyStage(self.spec, self.pp, self.guard,
                                   self.run, Mock(), lambda sha: self.actual)

    def inventory(self):
        return self.stage.after if self.installed else self.baseline

    def run(self, name, args, cwd=None):
        self.calls.append((name, args))
        if name == "semodule" and args == ["-lfull", "-m"]:
            return "".join("{} {} {} {}sha256:{}\n".format(
                p, n, lang, "" if enabled else "disabled ", sha)
                for p, n, lang, enabled, sha in self.inventory()).encode("ascii")
        if name == "matchpathcon":
            return (P.LABEL if self.installed else self.old_label).encode("ascii") + b"\n"
        if name == "pp":
            return self.cil
        if name == "semodule" and args[:3] == ["-X", "400", "-i"]:
            self.installed = True
            return b""
        if name == "semodule" and args == ["-X", "400", "-r", P.MODULE]:
            self.installed = False
            return b""
        if name == "restorecon":
            self.assertEqual(args, ["-F", str(P.EXECUTABLE)])
            self.actual = P.LABEL if self.installed else self.old_label
            return b""
        self.fail("unexpected command " + name)

    def test_checksums_and_disabled_state_are_mandatory(self):
        self.assertEqual(P.parse_inventory(
            ("100 base pp " + "a" * 64 + "\n200 other cil disabled sha256:" +
             "b" * 64 + "\n").encode("ascii")), self.baseline)
        for raw in (b"", b"100 base pp\n", b"100 base pp wrong\n",
                    b"100 base pp enabled " + b"a" * 64,
                    (("100 base pp " + "a" * 64 + "\n") * 2).encode("ascii")):
            with self.assertRaises(P.Refused):
                P.parse_inventory(raw)

    def test_exact_install_and_rollback(self):
        # Mock only scratch storage and commands, never load SELinux on CI host.
        with tempfile.TemporaryDirectory() as folder:
            context = Mock()
            context.__enter__ = Mock(return_value=folder)
            context.__exit__ = Mock(return_value=False)
            with patch.object(P.tempfile, "TemporaryDirectory", return_value=context), \
                 patch.object(P, "write_artifact"), patch.object(P, "read_artifact", return_value=self.pp):
                self.assertEqual(self.stage.probe(), self.stage.stage_plan()["before"])
                self.stage.mutate("install")
                self.assertEqual(self.stage.probe(), self.stage.stage_plan()["after"])
                self.stage.mutate("rollback")
                self.assertEqual(self.stage.probe(), self.stage.stage_plan()["before"])
        self.assertEqual([args[:3] for name, args in self.calls
                          if name == "semodule" and args[:1] == ["-X"]],
                         [["-X", "400", "-i"], ["-X", "400", "-r"]])
        self.assertEqual(self.actual, self.old_label)

    def test_foreign_policy_or_partial_label_refused_without_mutation(self):
        self.installed = True
        # The module was loaded but the expected executable label is absent.
        with self.assertRaisesRegex(P.Refused, "partial_label"):
            self.stage.mutate("rollback")
        self.actual = P.LABEL
        self.baseline = self.baseline + (("400", "foreign", "pp", True, "d" * 64),)
        self.installed = False
        with self.assertRaisesRegex(P.Refused, "inventory_or_context_changed"):
            self.stage.mutate("install")
        self.assertFalse(any(n in ("restorecon", "pp") or "-i" in a or "-r" in a
                             for n, a in self.calls))

    def test_existing_module_or_wrong_artifact_cannot_be_approved(self):
        for bad in (self.spec._replace(baseline=self.baseline +
                     (("400", P.MODULE, "pp", True, "c" * 64),)),
                    self.spec._replace(baseline_label=P.LABEL)):
            with self.assertRaises(P.Refused):
                P.PolicyStage(bad, self.pp, Mock())
        with self.assertRaisesRegex(P.Refused, "unapproved_artifact"):
            P.PolicyStage(self.spec, b"changed", Mock())

    def test_guard_failure_precedes_native_commands(self):
        self.guard.side_effect = P.Refused("maintenance_required")
        with self.assertRaises(P.Refused):
            self.stage.mutate("install")
        self.assertEqual(self.calls, [])

    def test_missing_runtime_refuses_install_but_allows_baseline_probe(self):
        self.actual = None
        self.assertEqual(self.stage.probe(), self.stage.stage_plan()["before"])
        with self.assertRaisesRegex(P.Refused, "runtime_required"):
            self.stage.mutate("install")

    def test_compiler_drift_blocks_policy_load(self):
        self.cil = b"changed compiler output"
        with tempfile.TemporaryDirectory() as folder:
            context = Mock()
            context.__enter__ = Mock(return_value=folder)
            context.__exit__ = Mock(return_value=False)
            with patch.object(P.tempfile, "TemporaryDirectory", return_value=context), \
                 patch.object(P, "write_artifact"), patch.object(P, "read_artifact", return_value=self.pp):
                with self.assertRaisesRegex(P.Refused, "compiler_drift"):
                    self.stage.mutate("install")
        self.assertFalse(self.installed)
        self.assertFalse(any("-i" in args for name, args in self.calls))


if __name__ == "__main__":
    unittest.main()
