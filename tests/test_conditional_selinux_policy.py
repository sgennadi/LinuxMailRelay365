"""SELinux label policy review tests; no relabel or production activation."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "conditional_selinux_policy",
    str(ROOT / "linux/inspect-conditional-postfix-activation.py"))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
LABEL = b"system_u:object_r:postfix_etc_t:s0\0"


class LabelPolicyTests(unittest.TestCase):
    def test_exact_file_policy_queries(self):
        calls = []
        def command(tool, args):
            calls.append((tool, args))
            return LABEL[:-1].decode("ascii") + "\n"
        with patch.object(P.T, "config_file",
                          return_value=(b"fixture", {"mode": 0o644, "gid": 0,
                                                     "selinux": LABEL.hex()})):
            self.assertEqual(P.review_selinux_labels(1, "a"*64, "lmdb", 0, command),
                             LABEL.hex())
        self.assertEqual(calls, [
            ("matchpathcon", ["-N", "-n", "-m", "file", "/etc/postfix/main.cf"]),
            ("matchpathcon", ["-N", "-n", "-m", "file", "/etc/postfix/master.cf"]),
            ("matchpathcon", ["-N", "-n", "-m", "file",
                "/etc/postfix/lmr365-conditional-" + "a"*64 + "-sender.lmdb"])])

    def test_unknown_custom_or_missing_labels_fail_closed(self):
        def command(*args):
            return LABEL[:-1].decode("ascii") + "\n"
        for meta in ({}, {"selinux": b"system_u:object_r:etc_t:s0\0".hex()}):
            with patch.object(P.T, "config_file", return_value=(b"fixture", meta)):
                with self.assertRaises(P.Refused):
                    P.review_selinux_labels(1, "a"*64, "hash", 0, command)
        for raw in ("", "<<none>>\n", "garbage\n", "u:r:t:s0\nu:r:t:s0\n"):
            with self.assertRaises(P.Refused):
                P.policy_file_label("/etc/postfix/main.cf", lambda *args: raw)
        with self.assertRaises(P.Refused):
            P.policy_file_label("/etc/shadow", command)


if __name__ == "__main__":
    unittest.main()
