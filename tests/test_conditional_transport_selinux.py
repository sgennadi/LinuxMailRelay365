"""Multi-transport SELinux metadata review: synthetic labels, no relabel."""
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "multi_labels", str(ROOT / "linux/inspect-conditional-transport-selinux.py"))
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)
LABEL = "system_u:object_r:postfix_etc_t:s0"
ENCODED = (LABEL + "\0").encode("ascii").hex()
RULES = [
    dict(selector="exact-envelope-sender", pattern="one@example.org",
         host="smtp.example.net", port=2526, tls="starttls", auth="password"),
    dict(selector="envelope-sender-domain", pattern="other.example.org",
         host="smtp.example.net", port=465, tls="implicit", auth="none"),
    dict(selector="exact-envelope-sender", pattern="three@example.org",
         host="smtp.example.net", port=587, tls="starttls", auth="password"),
]


class MultiLabelTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.fd = os.open(str(self.root), L.M.DIR_FLAGS)
        self.addCleanup(os.close, self.fd)
        self.uid, self.gid = os.getuid(), os.getgid()
        for name in ("main.cf", "master.cf"):
            self.write(name, 0o644)
        self.calls = []

    def write(self, name, mode):
        path = self.root / name
        path.write_bytes(b"fixture")
        path.chmod(mode)

    def command(self, tool, args):
        self.calls.append((tool, args))
        return LABEL + "\n"

    def observe(self, installed=False, backend="hash"):
        return L.observe(self.fd, RULES, backend, self.uid, self.gid, installed,
                         lambda: None, self.command)

    def test_both_backends_and_distinct_password_destinations(self):
        for backend in ("hash", "lmdb"):
            self.calls.clear()
            plan, sources, labels = L.policy_labels(RULES, backend, self.command)
            suffix = L.M.MAP_SUFFIX[backend]
            self.assertEqual(sources, ("lmr365-" + plan + "-sender-transport",
                "lmr365-" + plan[:20] + "-1-sasl", "lmr365-" + plan[:20] + "-3-sasl"))
            self.assertEqual(set(labels), {".", "main.cf", "master.cf"} |
                             {name + suffix for name in sources})
            self.assertEqual(self.calls[0], ("matchpathcon",
                ["-N", "-n", "-m", "dir", "/etc/postfix"]))
            self.assertEqual([call[1][-1] for call in self.calls[1:]],
                ["/etc/postfix/" + name for name in ("main.cf", "master.cf") +
                 tuple(source + suffix for source in sources)])
            self.assertEqual(set(labels.values()), {ENCODED})

    def test_new_plan_does_not_create_any_files(self):
        with patch.object(L.T, "file_label", return_value=ENCODED):
            reviewed = self.observe()
        self.assertEqual(set(reviewed["identities"]), {".", "main.cf", "master.cf"})
        self.assertEqual(set(p.name for p in self.root.iterdir()), {"main.cf", "master.cf"})

    def test_existing_map_review_reads_metadata_only(self):
        _, sources = L.destinations(RULES, "lmdb")
        for name in sources:
            self.write(name + ".lmdb", 0o640)
        with patch.object(L.T, "file_label", return_value=ENCODED), \
                patch.object(L.T, "config_file", side_effect=AssertionError("content read")):
            reviewed = self.observe(installed=True, backend="lmdb")
        self.assertEqual(len(reviewed["identities"]), 6)

    def test_existing_destination_and_source_refused(self):
        _, sources = L.destinations(RULES, "hash")
        with patch.object(L.T, "file_label", return_value=ENCODED):
            for name in (sources[0], sources[0] + ".db"):
                self.write(name, 0o640)
                with self.assertRaises(L.Refused):
                    self.observe()
                (self.root / name).unlink()

    def test_missing_mismatched_and_generic_labels_refused(self):
        for label in (None, ("system_u:object_r:other_t:s0\0").encode("ascii").hex()):
            with patch.object(L.T, "file_label", return_value=label):
                with self.assertRaises(L.Refused):
                    self.observe()
        for raw in ("", "<<none>>\n", "u:r:default_t:s0\n",
                    "u:r:etc_t:s0\n", LABEL + "\n" + LABEL + "\n"):
            with self.assertRaises(L.Refused):
                L.policy_labels(RULES, "hash", lambda *args: raw)

    def test_policy_change_refuses_before_acceptance(self):
        calls = []
        def changing(tool, args):
            calls.append(args)
            return (LABEL if len(calls) <= 6 else
                    "system_u:object_r:postfix_map_t:s0") + "\n"
        with patch.object(L.T, "file_label", return_value=ENCODED):
            with self.assertRaisesRegex(L.Refused, "selinux_policy_or_metadata_changed"):
                L.observe(self.fd, RULES, "hash", self.uid, self.gid, False,
                          lambda: None, changing)

    def test_symlink_and_wrong_map_permissions_refused(self):
        _, sources = L.destinations(RULES, "hash")
        for name in sources:
            self.write(name + ".db", 0o640)
        with patch.object(L.T, "file_label", return_value=ENCODED):
            path = self.root / (sources[0] + ".db")
            path.chmod(0o644)
            with self.assertRaises(L.Refused):
                self.observe(installed=True)
            path.unlink()
            path.symlink_to(self.root / "main.cf")
            with self.assertRaises(OSError):
                self.observe(installed=True)

    def test_invalid_rules_never_query_policy(self):
        for rules in ([], RULES + [RULES[0]], [dict(RULES[0], auth="oauth2")]):
            self.calls.clear()
            with self.assertRaises(L.Refused):
                L.policy_labels(rules, "hash", self.command)
            self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
