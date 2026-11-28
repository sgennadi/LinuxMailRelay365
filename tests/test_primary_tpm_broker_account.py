"""Account-stage exact state tests with simulated native account operations."""
import pathlib
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
import m365_tpm_broker_account as A


class AccountStageTests(unittest.TestCase):
    def setUp(self):
        self.spec = A.Spec(812, 813, 815, 816, ())
        self.p = {A.MAIL: ("x", "815", "816", "", "/nonexistent", "/sbin/nologin")}
        self.g = {A.MAIL: ("x", "816", "")}
        self.s = {}
        self.gs = {A.MAIL: ("!", "", "")}

    def inventory(self):
        return self.p, self.g, self.s, self.gs

    def classify(self, spec=None):
        return A.classify_local(spec or self.spec, self.inventory())

    def create_group(self):
        self.g[A.SIGNER] = ("x", "813", "")
        self.gs[A.SIGNER] = ("!", "", "")

    def create_user(self):
        self.p[A.SIGNER] = ("x", "812", "813", A.COMMENT, A.HOME, A.SHELL)
        self.s[A.SIGNER] = ("!!", "20000", "", "", "", "", "", "")
        self.g[A.MAIL] = ("x", "816", A.SIGNER)
        self.gs[A.MAIL] = ("!", "", A.SIGNER)

    def delete_user(self):
        del self.p[A.SIGNER]
        del self.s[A.SIGNER]
        self.g[A.MAIL] = ("x", "816", "")
        self.gs[A.MAIL] = ("!", "", "")

    def delete_group(self):
        del self.g[A.SIGNER]
        del self.gs[A.SIGNER]

    def backend(self, run=None, guard=None, idle=None):
        return A.AccountStage(self.spec, guard or Mock(), self.classify, idle or Mock(),
                              run or Mock())

    def test_exact_states_and_partial_not_resumable(self):
        backend = self.backend()
        self.assertEqual(self.classify(), "absent")
        self.assertEqual(backend.probe(), backend.stage_plan()["before"])
        self.create_group()
        self.assertEqual(self.classify(), "group_only")
        with self.assertRaisesRegex(A.Refused, "partial_requires_review"):
            backend.probe()
        self.create_user()
        self.assertEqual(self.classify(), "installed")
        self.assertEqual(backend.probe(), backend.stage_plan()["after"])

    def test_native_command_order_and_exact_rollback(self):
        actions = []
        def run(name, args):
            actions.append((name, args))
            {"groupadd": self.create_group, "useradd": self.create_user,
             "userdel": self.delete_user, "groupdel": self.delete_group}[name]()
        guard, idle = Mock(), Mock()
        backend = self.backend(run, guard, idle)
        backend.mutate("install")
        backend.mutate("rollback")
        self.assertEqual([n for n, unused in actions],
                         ["groupadd", "useradd", "userdel", "groupdel"])
        self.assertEqual(actions[0][1], ["--system", "--gid", "813", A.SIGNER])
        self.assertIn("--no-create-home", actions[1][1])
        self.assertIn("--no-log-init", actions[1][1])
        self.assertEqual(actions[2][1], [A.SIGNER])
        self.assertEqual(self.classify(), "absent")
        self.assertGreaterEqual(guard.call_count, 4)
        self.assertGreaterEqual(idle.call_count, 4)

    def test_auto_removed_private_group_is_not_deleted_twice(self):
        self.create_group()
        self.create_user()
        def remove(name, args):
            self.assertEqual(name, "userdel")
            self.delete_user()
            self.delete_group()
        backend = self.backend(remove)
        backend.mutate("rollback")
        self.assertEqual(self.classify(), "absent")

    def test_drift_locked_password_shell_group_and_alias_refused(self):
        self.create_group()
        self.create_user()
        original = self.s[A.SIGNER]
        for changed in (("hash",) + original[1:], original[:5] + ("7",) + original[6:]):
            self.s[A.SIGNER] = changed
            with self.assertRaises(A.Refused):
                self.classify()
        self.s[A.SIGNER] = original
        old = self.p[A.SIGNER]
        self.p[A.SIGNER] = old[:-1] + ("/bin/bash",)
        with self.assertRaises(A.Refused):
            self.classify()
        self.p[A.SIGNER] = old
        self.p["foreign"] = ("x", "900", "813", "", "/", "/bin/bash")
        with self.assertRaises(A.Refused):
            self.classify()
        del self.p["foreign"]
        self.g["foreign"] = ("x", "900", A.SIGNER)
        with self.assertRaises(A.Refused):
            self.classify()

    def test_occupied_uid_or_gid_and_unreviewed_members_refused(self):
        self.p["foreign"] = ("x", "812", "900", "", "/", "/bin/bash")
        with self.assertRaises(A.Refused):
            self.classify()
        del self.p["foreign"]
        self.g["foreign"] = ("x", "813", "")
        with self.assertRaises(A.Refused):
            self.classify()
        del self.g["foreign"]
        self.g[A.MAIL] = ("x", "816", "foreign")
        self.gs[A.MAIL] = ("!", "", "foreign")
        with self.assertRaises(A.Refused):
            self.classify()

    def test_partial_group_after_interruption_never_auto_removed(self):
        calls = []
        def run(name, args):
            calls.append(name)
            if name == "groupadd":
                self.create_group()
            else:
                raise RuntimeError("interrupted")
        backend = self.backend(run)
        with self.assertRaises(RuntimeError):
            backend.mutate("install")
        self.assertEqual(calls, ["groupadd", "useradd"])
        for direction in ("install", "rollback"):
            with self.assertRaises(A.Refused):
                backend.mutate(direction)
        self.assertEqual(calls, ["groupadd", "useradd"])

    def test_guard_and_idle_failure_precede_any_native_command(self):
        runner = Mock()
        for guard, idle in ((Mock(side_effect=A.Refused("maintenance")), Mock()),
                            (Mock(), Mock(side_effect=A.Refused("process_in_use")))):
            with self.assertRaises(A.Refused):
                self.backend(runner, guard, idle).mutate("install")
        runner.assert_not_called()

    def test_review_requires_distinct_system_ids_and_exact_mail_group(self):
        for spec in (self.spec._replace(uid=0), self.spec._replace(uid=1000),
                     self.spec._replace(uid=815), self.spec._replace(gid=816),
                     self.spec._replace(mail_members=("foreign",))):
            with self.assertRaises(A.Refused):
                A.validate(spec)
        self.assertNotEqual(A.AccountStage(self.spec, Mock()).stage_plan(),
            A.AccountStage(self.spec._replace(uid=814), Mock()).stage_plan())

    def test_local_database_parser_refuses_duplicate_or_malformed_rows(self):
        self.assertEqual(A.rows("name:x:123:\n", 4), {"name": ("x", "123", "")})
        for raw in ("name:x:123:\nname:x:124:\n", "name:x:123\n",
                    "bad name:x:123:\n"):
            with self.assertRaises(A.Refused):
                A.rows(raw, 4)


if __name__ == "__main__":
    unittest.main()
