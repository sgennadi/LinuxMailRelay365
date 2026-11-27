import importlib.util
import pathlib
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("adapter", ROOT / "linux/smtp-tls-postfix.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class TrustedInvocationTests(unittest.TestCase):
    def test_multicall_symlink_retains_name(self):
        path = pathlib.Path("/usr/sbin/restorecon")
        directory = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        link = SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777)
        with patch.object(M.Path, "lstat", autospec=True, side_effect=lambda p: link if p == path else directory), \
             patch.object(M.Path, "stat", return_value=directory), \
             patch.object(M, "trusted_binary", return_value="/usr/sbin/setfiles") as verify:
            self.assertEqual(M.trusted_invocation(str(path)), str(path))
            verify.assert_called_once_with(str(path))

    def test_untrusted_link_refused(self):
        link = SimpleNamespace(st_uid=1000, st_mode=stat.S_IFLNK | 0o777)
        with patch.object(M.Path, "lstat", return_value=link), patch.object(M, "trusted_binary") as verify:
            with self.assertRaises(ValueError):
                M.trusted_invocation("/usr/sbin/restorecon")
            verify.assert_not_called()

    def test_writable_parent_refused(self):
        path = pathlib.Path("/usr/sbin/restorecon")
        link = SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777)
        directory = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777)
        with patch.object(M.Path, "lstat", autospec=True, side_effect=lambda p: link if p == path else directory), \
             patch.object(M, "trusted_binary") as verify:
            with self.assertRaises(ValueError):
                M.trusted_invocation(str(path))
            verify.assert_not_called()

    def test_resolved_target_validation_required(self):
        directory = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        with patch.object(M.Path, "lstat", return_value=directory), \
             patch.object(M.Path, "stat", return_value=directory), \
             patch.object(M, "trusted_binary", side_effect=ValueError("untrusted target")):
            with self.assertRaises(ValueError):
                M.trusted_invocation("/usr/sbin/restorecon")

    def test_relative_path_refused(self):
        with self.assertRaises(ValueError):
            M.trusted_invocation("restorecon")

    def test_selinux_callers_preserve_invocation(self):
        for name in ("preview-smtp-tls-selinux-relabel.py", "apply-smtp-tls-selinux-relabel.py",
                     "check-smtp-tls-selinux.py", "review-smtp-tls-selinux.py",
                     "manage-smtp-tls-process-renewal.py"):
            self.assertIn("trusted_invocation", (ROOT / "linux" / name).read_text(), name)
