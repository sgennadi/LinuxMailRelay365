"""Exercise durable journal and actual file mutations only in a temp directory."""
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
import m365_tpm_broker_transaction as T


class Interrupted(BaseException):
    pass


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.root.chmod(0o700)
        self.fd = os.open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.journal = T.Journal(self.fd, owner=os.getuid())
        self.plan = {"preview": "a" * 64, "stages": [
            {"name": name, "before": T.digest([name, "absent"]),
             "after": T.digest([name, "installed"])} for name in T.STAGES]}
        self.approval = T.digest(self.plan)
        self.actions = []
        self.interrupt = None

    def guard(self):
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)

    def probe(self, name):
        path = self.root / name
        if not path.exists():
            state = "absent"
        else:
            state = path.read_text()
        return T.digest([name, state])

    def mutate(self, name, direction):
        self.actions.append((name, direction))
        state = self.journal.read()
        self.assertEqual(state["pending"], {"name": name, "direction": direction})
        if self.interrupt == (name, direction, "before"):
            raise Interrupted()
        path = self.root / name
        if direction == "install":
            with path.open("x") as stream:
                stream.write("installed")
                stream.flush()
                os.fsync(stream.fileno())
        else:
            path.unlink()
        os.fsync(self.fd)
        if self.interrupt == (name, direction, "after"):
            raise Interrupted()

    def begin(self):
        return T.begin(self.journal, self.plan, self.approval, T.APPLY, self.guard, self.probe)

    def install(self):
        return T.resume_install(self.journal, self.approval, T.APPLY,
                                self.guard, self.probe, self.mutate)

    def undo(self):
        return T.rollback(self.journal, self.approval, T.ROLLBACK,
                          self.guard, self.probe, self.mutate)

    def test_install_and_remove_exact_reverse_order(self):
        with self.journal.exclusive():
            self.begin()
            result = self.install()
            self.assertEqual(result["phase"], "installed")
            self.assertEqual(self.install(), result)
            result = self.undo()
            self.assertEqual(result["phase"], "rolled_back")
            self.assertEqual(self.undo(), result)
            self.assertEqual(self.actions, [(n, "install") for n in T.STAGES] +
                             [(n, "rollback") for n in reversed(T.STAGES)])
            self.assertTrue(all(not (self.root / name).exists() for name in T.STAGES))

    def test_crash_after_install_mutation_recovers_without_repeating(self):
        with self.journal.exclusive():
            self.begin()
            self.interrupt = ("policy", "install", "after")
            with self.assertRaises(Interrupted):
                self.install()
        self.journal = T.Journal(self.fd, owner=os.getuid())
        self.interrupt = None
        with self.journal.exclusive():
            state = self.journal.read()
            self.assertEqual(state["completed"], 2)
            self.assertEqual(state["pending"]["name"], "policy")
            self.assertEqual(self.install()["phase"], "installed")
        self.assertEqual(self.actions.count(("policy", "install")), 1)

    def test_rollback_after_forward_intent_does_not_install_missing_stage(self):
        with self.journal.exclusive():
            self.begin()
            self.interrupt = ("policy", "install", "before")
            with self.assertRaises(Interrupted):
                self.install()
            self.interrupt = None
            self.assertEqual(self.undo()["phase"], "rolled_back")
            self.assertNotIn(("policy", "rollback"), self.actions)
            self.assertNotIn(("udev_rule", "install"), self.actions)

    def test_crash_after_rollback_mutation_resumes_without_repeating(self):
        with self.journal.exclusive():
            self.begin()
            self.install()
            self.interrupt = ("device", "rollback", "after")
            with self.assertRaises(Interrupted):
                self.undo()
        self.interrupt = None
        self.journal = T.Journal(self.fd, owner=os.getuid())
        with self.journal.exclusive():
            self.assertEqual(self.undo()["phase"], "rolled_back")
        self.assertEqual(self.actions.count(("device", "rollback")), 1)

    def test_partial_or_foreign_state_is_not_guessed_or_removed(self):
        with self.journal.exclusive():
            self.begin()
            self.interrupt = ("runtime", "install", "before")
            with self.assertRaises(Interrupted):
                self.install()
            (self.root / "runtime").write_text("foreign")
            self.interrupt = None
            actions = list(self.actions)
            for operation in (self.install, self.undo):
                with self.assertRaisesRegex(T.Refused, "foreign_or_partial"):
                    operation()
            self.assertEqual(self.actions, actions)
            self.assertEqual((self.root / "runtime").read_text(), "foreign")

    def test_completed_stage_drift_blocks_next_mutation(self):
        with self.journal.exclusive():
            self.begin()
            self.interrupt = ("runtime", "install", "before")
            with self.assertRaises(Interrupted):
                self.install()
            (self.root / "account").unlink()
            self.interrupt = None
            with self.assertRaisesRegex(T.Refused, "unexpected_stage_state"):
                self.install()

    def test_approval_stale_state_lock_and_unsafe_permissions(self):
        with self.journal.exclusive():
            with self.assertRaises(T.Refused):
                T.begin(self.journal, self.plan, "b" * 64, T.APPLY, self.guard, self.probe)
            state = self.begin()
            with self.assertRaisesRegex(T.Refused, "existing_state"):
                self.begin()
            with self.assertRaisesRegex(T.Refused, "busy"):
                with T.Journal(self.fd, owner=os.getuid()).exclusive():
                    self.fail("second transaction entered")
            self.assertEqual(self.journal.read(), state)
            (self.root / T.STATE).chmod(0o644)
            with self.assertRaisesRegex(T.Refused, "unsafe_file"):
                self.journal.read()

    def test_unknown_stage_and_noop_plan_refused(self):
        bad = dict(self.plan, stages=[dict(s) for s in self.plan["stages"]])
        bad["stages"][0]["name"] = "arbitrary"
        with self.assertRaises(T.Refused):
            T.validate_plan(bad)
        bad["stages"][0]["name"] = T.STAGES[0]
        bad["stages"][0]["after"] = bad["stages"][0]["before"]
        with self.assertRaises(T.Refused):
            T.validate_plan(bad)


if __name__ == "__main__":
    unittest.main()
