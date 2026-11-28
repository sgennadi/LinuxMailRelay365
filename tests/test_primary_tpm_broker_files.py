"""Native filesystem tests on disposable temporary directories, never /etc."""
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
import m365_tpm_broker_files as F


class FileStageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.parents = {}
        self.payloads = {}
        for stage in F.TARGETS:
            directory = self.root / stage
            directory.mkdir(mode=0o700)
            fd = os.open(str(directory), F.DIR_FLAGS)
            self.addCleanup(os.close, fd)
            self.parents[stage] = fd
            self.payloads[stage] = {name: ("fixture " + name).encode("ascii")
                                    for name in F.MODES[stage]}
        self.guard = Mock()
        self.verify = Mock()
        self.backend = F.FileStages(self.parents, self.payloads, "a" * 32,
                                    self.guard, self.verify, os.getuid(), os.getgid())

    def target(self, stage):
        return self.root / stage / F.TARGETS[stage]

    def test_all_three_native_file_stages_and_reverse_removal(self):
        for stage in ("runtime", "udev_rule", "unit"):
            plan = self.backend.stage_plan(stage)
            self.assertEqual(self.backend.probe(stage), plan["before"])
            self.backend.mutate(stage, "install")
            self.assertEqual(self.backend.probe(stage), plan["after"])
            target = self.target(stage)
            if stage == "runtime":
                self.assertEqual(set(p.name for p in target.iterdir()), set(F.MODES[stage]))
                for name, raw in self.payloads[stage].items():
                    self.assertEqual((target / name).read_bytes(), raw)
                    self.assertEqual((target / name).stat().st_mode & 0o777, F.MODES[stage][name])
            else:
                self.assertEqual(target.read_bytes(), self.payloads[stage][target.name])
        for stage in ("unit", "udev_rule", "runtime"):
            self.backend.mutate(stage, "rollback")
            self.assertEqual(self.backend.probe(stage), self.backend.stage_plan(stage)["before"])
            self.assertEqual(list((self.root / stage).iterdir()), [])

    def test_never_overwrite_or_remove_foreign_contents(self):
        target = self.target("unit")
        target.write_bytes(b"foreign")
        target.chmod(0o644)
        for direction in ("install", "rollback"):
            with self.assertRaisesRegex(F.Refused, "stage_not_expected"):
                self.backend.mutate("unit", direction)
        self.assertEqual(target.read_bytes(), b"foreign")

    def test_symlink_hardlink_and_runtime_extra_file_refused(self):
        other = self.root / "unrelated"
        other.write_bytes(b"keep")
        target = self.target("unit")
        target.symlink_to(other)
        with self.assertRaises(F.Refused):
            self.backend.mutate("unit", "install")
        target.unlink()
        os.link(str(other), str(target))
        with self.assertRaises(F.Refused):
            self.backend.probe("unit")
        target.unlink()
        self.backend.mutate("runtime", "install")
        extra = self.target("runtime") / "extra.py"
        extra.write_bytes(b"keep")
        with self.assertRaisesRegex(F.Refused, "runtime_inventory"):
            self.backend.mutate("runtime", "rollback")
        self.assertEqual(extra.read_bytes(), b"keep")
        self.assertEqual(other.read_bytes(), b"keep")

    def test_guard_refusal_precedes_any_filesystem_write(self):
        self.guard.side_effect = F.Refused("maintenance_required")
        with self.assertRaisesRegex(F.Refused, "maintenance_required"):
            self.backend.mutate("runtime", "install")
        self.assertEqual(list((self.root / "runtime").iterdir()), [])

    def test_parent_replacement_or_permission_drift_refused(self):
        (self.root / "unit").chmod(0o770)
        with self.assertRaises(F.Refused):
            self.backend.mutate("unit", "install")
        self.assertFalse(self.target("unit").exists())

    def test_exclusive_rename_collision_preserves_both_objects(self):
        original = F.rename_exclusive
        def race(fd, old, new):
            target = self.target("unit")
            target.write_bytes(b"concurrent")
            target.chmod(0o644)
            original(fd, old, new)
        with patch.object(F, "rename_exclusive", side_effect=race):
            with self.assertRaises(OSError):
                self.backend.mutate("unit", "install")
        self.assertEqual(self.target("unit").read_bytes(), b"concurrent")
        with self.assertRaisesRegex(F.Refused, "partial_stage_requires_review"):
            self.backend.probe("unit")
        self.assertEqual(len(list((self.root / "unit").iterdir())), 2)

    def test_interrupted_detach_never_guesses_rollback_success(self):
        self.backend.mutate("runtime", "install")
        with patch.object(self.backend, "_remove", side_effect=RuntimeError("interrupted")):
            with self.assertRaises(RuntimeError):
                self.backend.mutate("runtime", "rollback")
        self.assertFalse(self.target("runtime").exists())
        with self.assertRaisesRegex(F.Refused, "partial_stage_requires_review"):
            self.backend.probe("runtime")
        self.assertEqual(len(list((self.root / "runtime").iterdir())), 1)

    def test_exact_plan_and_real_file_stages_with_durable_transaction(self):
        journal_dir = self.root / "journal"
        journal_dir.mkdir(mode=0o700)
        fd = os.open(str(journal_dir), F.DIR_FLAGS)
        self.addCleanup(os.close, fd)
        journal = F.tx.Journal(fd, owner=os.getuid())
        other = {}
        plans = []
        for stage in F.tx.STAGES:
            if stage in F.TARGETS:
                plans.append(self.backend.stage_plan(stage))
            else:
                plans.append({"name": stage, "before": F.tx.digest([stage, 0]),
                              "after": F.tx.digest([stage, 1])})
                other[stage] = plans[-1]["before"]
        plan = {"preview": "b" * 64, "stages": plans}
        approved = F.tx.digest(plan)
        def probe(stage):
            return self.backend.probe(stage) if stage in F.TARGETS else other[stage]
        def mutate(stage, direction):
            if stage in F.TARGETS:
                self.backend.mutate(stage, direction)
            else:
                other[stage] = F.tx.digest([stage, 1 if direction == "install" else 0])
        with journal.exclusive():
            F.tx.begin(journal, plan, approved, F.tx.APPLY, lambda: None, probe)
            self.assertEqual(F.tx.resume_install(journal, approved, F.tx.APPLY,
                                                lambda: None, probe, mutate)["phase"], "installed")
            self.assertEqual(F.tx.rollback(journal, approved, F.tx.ROLLBACK,
                                           lambda: None, probe, mutate)["phase"], "rolled_back")


if __name__ == "__main__":
    unittest.main()
