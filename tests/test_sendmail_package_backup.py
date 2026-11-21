"""Strict root-only config snapshots with the packaged Sendmail /etc/mail exception."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "sendmail_package_snapshot", str(ROOT / "linux/foreign-mta-config-backup.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PackagedSendmailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "etc").mkdir(mode=0o755)
        self.mail = self.root / "etc" / "mail"
        self.mail.mkdir(mode=0o755)
        os.chmod(str(self.mail), 0o2755)
        self.uid, self.gid = os.getuid(), os.getgid()

    def fake_accounts(self, name):
        if name == "smmta":
            return SimpleNamespace(pw_uid=self.uid, pw_gid=self.gid)
        if name == "smmsp":
            return SimpleNamespace(pw_uid=self.uid + 100000, pw_gid=self.gid + 100000)
        raise KeyError(name)

    def fake_groups(self, name):
        if name == "smmsp":
            return SimpleNamespace(gr_gid=self.gid)
        raise KeyError(name)

    def test_exact_package_owner_and_mode_accepted_for_read_only_backup(self):
        if self.uid == 0:
            self.skipTest("test requires nonroot disposable CI identity")
        with patch("pwd.getpwnam", side_effect=self.fake_accounts), \
             patch("grp.getgrnam", side_effect=self.fake_groups):
            st = m.safe_packaged_sendmail_dir(self.mail, owner_uid=0)
            self.assertTrue(stat.S_ISDIR(st.st_mode))
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o2755)
            self.assertTrue(m.safe_config_dir(self.mail, "sendmail", self.root, 0))

    def test_other_directory_or_mta_cannot_use_package_exception(self):
        if self.uid == 0:
            self.skipTest("test requires nonroot disposable CI identity")
        with patch("pwd.getpwnam", side_effect=self.fake_accounts), \
             patch("grp.getgrnam", side_effect=self.fake_groups):
            with self.assertRaises(m.Refused):
                m.safe_config_dir(self.mail, "exim", self.root, 0)
            with self.assertRaises(m.Refused):
                m.safe_config_dir(self.root / "etc", "sendmail", self.root, 0)

    def test_wrong_package_account_does_not_pass(self):
        if self.uid == 0:
            self.skipTest("test requires nonroot disposable CI identity")
        def unavailable(_):
            raise KeyError("unknown service user")
        with patch("pwd.getpwnam", side_effect=unavailable), \
             patch("grp.getgrnam", side_effect=self.fake_groups):
            with self.assertRaisesRegex(m.Refused, "untrusted_sendmail"):
                m.safe_packaged_sendmail_dir(self.mail, 0)

    def test_world_writable_or_unexpected_mode_blocks(self):
        if self.uid == 0:
            self.skipTest("test requires nonroot disposable CI identity")
        with patch("pwd.getpwnam", side_effect=self.fake_accounts), \
             patch("grp.getgrnam", side_effect=self.fake_groups):
            for mode in (0o2775, 0o2757, 0o0755, 0o2777):
                with self.subTest(mode=oct(mode)):
                    os.chmod(str(self.mail), mode)
                    with self.assertRaises(m.Refused):
                        m.safe_packaged_sendmail_dir(self.mail, 0)

    def test_symlink_mail_path_is_never_followed(self):
        if self.uid == 0:
            self.skipTest("test requires nonroot disposable CI identity")
        link = self.root / "mail-link"
        link.symlink_to(self.mail, target_is_directory=True)
        with patch("pwd.getpwnam", side_effect=self.fake_accounts), \
             patch("grp.getgrnam", side_effect=self.fake_groups):
            with self.assertRaises(m.Refused):
                m.safe_packaged_sendmail_dir(link, 0)


if __name__ == "__main__":
    unittest.main()
