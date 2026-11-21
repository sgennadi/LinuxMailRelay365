"""Offline fail-closed tests for the experimental SELinux fcontext manager."""
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "lmr365_fcontext", ROOT_DIR / "linux/manage-rhel-selinux-sidecar-context.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class FcontextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = pathlib.Path(self.temp.name)
        self.patches = [
            mock.patch.object(m, "ROOT", root),
            mock.patch.object(m, "ACTIVE", root / "active.json"),
            mock.patch.object(m, "LOCK", root / "operation.lock"),
            mock.patch.object(m, "environment", return_value=None),
            mock.patch.object(m, "unit_stopped", return_value=None),
            # Only production may create root-owned operation locks. These
            # sandboxed unit tests execute as a non-root CI user.
            mock.patch.object(m, "acquire_lock",
                              side_effect=lambda: os.open(str(m.LOCK), os.O_RDWR | os.O_CREAT, 0o600)),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.rules = {}
        self.unrelated = "/tmp/not-lmr(/.*)?    all files    system_u:object_r:etc_t:s0\n"
        self.fail_after = None
        self.calls = []
        self.patcher = mock.patch.object(m, "run", side_effect=self.fake_run)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def raw(self):
        return self.unrelated + "".join(
            "{} = {}\n".format(dest, self.rules[dest])
            for dest in sorted(self.rules))

    def fake_run(self, argv, timeout=40):
        self.calls.append(tuple(argv))
        if self.fail_after and argv[:3] == ["semanage", "fcontext", "-a"] \
                and argv[-1] == self.fail_after:
            raise m.Refused("injected_failure")
        if argv == ["semanage", "fcontext", "-l", "-C"]:
            return self.raw()
        if argv[:4] == ["semanage", "fcontext", "-a", "-e"]:
            source, dest = argv[4:]
            self.rules[dest] = source
            return ""
        if argv[:4] == ["semanage", "fcontext", "-d", "-e"]:
            source, dest = argv[4:]
            if self.rules.get(dest) != source:
                raise m.Refused("wrong_owner")
            del self.rules[dest]
            return ""
        if argv[:2] == ["restorecon", "-RF"]:
            return ""
        raise AssertionError("unexpected command: " + repr(argv))

    def apply(self):
        m.apply(m.digest(self.raw()))

    def test_parser_rejects_custom_collision(self):
        raw = "/etc/linuxmailrelay365/sidecar-postfix = /wrong/source\n"
        with self.assertRaises(m.Refused):
            m.verify_custom(raw, set(), m.unrelated_digest(raw))

    def test_policy_drift_before_apply_is_refused(self):
        with self.assertRaisesRegex(m.Refused, "changed_since_review"):
            m.apply("0" * 64)
        self.assertEqual(self.rules, {})
        self.assertFalse(m.ACTIVE.exists())

    def test_three_equivalences_apply_with_journal(self):
        self.apply()
        self.assertEqual(self.rules, {dest: source for source, dest in m.PATHS})
        self.assertEqual(m.read_journal()["phase"], "active")
        self.assertEqual(m.read_journal()["after_sha"], m.digest(self.raw()))

    def test_collision_fails_without_writes(self):
        self.rules[m.PATHS[0][1]] = "/etc/foreign"
        with self.assertRaises(m.Refused):
            self.apply()
        self.assertEqual(len(self.rules), 1)
        self.assertFalse(m.ACTIVE.exists())

    def test_partial_failed_add_is_rolled_back(self):
        self.fail_after = m.PATHS[1][1]
        with self.assertRaisesRegex(m.Refused, "injected_failure"):
            self.apply()
        self.assertEqual(self.rules, {})
        self.assertFalse(m.ACTIVE.exists())

    def test_second_apply_refuses_adoption(self):
        self.apply()
        with self.assertRaisesRegex(m.Refused, "existing_managed"):
            self.apply()

    def test_status_detects_external_change(self):
        self.apply()
        self.rules[m.PATHS[1][1]] = "/etc/foreign"
        with self.assertRaises(m.Refused):
            m.verify_custom(self.raw(), {dest for _, dest in m.PATHS},
                            m.read_journal()["unrelated_sha"])

    def test_relabel_requires_existing_managed_state(self):
        with self.assertRaisesRegex(m.Refused, "no_complete"):
            m.relabel()

    def test_restore_requires_reviewed_sha(self):
        self.apply()
        with self.assertRaisesRegex(m.Refused, "changed_since_restore"):
            m.restore("0" * 64)
        self.assertEqual(len(self.rules), 3)

    def test_restore_removes_only_managed_rules(self):
        self.apply()
        self.assertFalse(any(os.path.lexists(dest) for _, dest in m.PATHS))
        m.restore(m.digest(self.raw()))
        self.assertEqual(self.rules, {})
        self.assertFalse(m.ACTIVE.exists())
        self.assertIn("/tmp/not-lmr", self.raw())

    def test_restore_blocks_foreign_policy_change(self):
        self.apply()
        self.unrelated += "/tmp/foreign(/.*)? all files system_u:object_r:var_t:s0\n"
        with self.assertRaisesRegex(m.Refused, "unrelated_custom"):
            m.restore(m.digest(self.raw()))
        self.assertEqual(len(self.rules), 3)

    def test_check_only_has_no_writes(self):
        m.check_only()
        self.assertFalse(m.ACTIVE.exists())
        self.assertFalse(m.ROOT.joinpath("operation.lock").exists())
        self.assertEqual(self.rules, {})


if __name__ == "__main__":
    unittest.main()
