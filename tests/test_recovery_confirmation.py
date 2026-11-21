"""Restoring primary Postfix requires an explicit Linux-side typed token.

The automatic installer rollback path is kept independently available.
Tests never create, replace or restore a system backup.
"""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RECOVERY = ROOT / "linux" / "mail-config-recovery.sh"
INSTALLER = ROOT / "linux" / "install-postfix-m365-xoauth2.sh"
ASSETS = ROOT / "src" / "LinuxMailRelay365" / "EmbeddedAssets.cs"
ID = "20261118T202030Z-abcdef123456"


class RestoreConfirmationTests(unittest.TestCase):
    def run_recovery(self, *args):
        return subprocess.run(
            ["bash", str(RECOVERY)] + list(args),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=8)

    def test_restore_without_explicit_confirmation_is_refused_before_disk_io(self):
        for args in (
            ("--restore", ID),
            ("--restore", ID, "--confirm", "WRONG_PHRASE"),
            ("--restore", ID, "--confirm", ""),
            ("--restore", "../etc/postfix", "--confirm", "RESTORE_POSTFIX_CONFIGURATION"),
        ):
            with self.subTest(args=args):
                result = self.run_recovery(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("RESTORE_ERROR=", result.stderr)
                self.assertNotIn("RESTORED_BACKUP_ID=", result.stdout)

    def test_root_cli_confirm_and_installer_rollback_are_distinct(self):
        script = RECOVERY.read_text(encoding="utf-8")
        installer = INSTALLER.read_text(encoding="utf-8")
        assets = ASSETS.read_text(encoding="utf-8")
        self.assertIn('RESTORE_POSTFIX_CONFIGURATION|AUTO_ROLLBACK_AFTER_FAILED_INSTALL', script)
        self.assertIn('restore "$2" ;;', script)
        self.assertIn('--confirm AUTO_ROLLBACK_AFTER_FAILED_INSTALL', installer)
        self.assertIn('command == "--restore" ? " --confirm RESTORE_POSTFIX_CONFIGURATION"', assets)
        self.assertIn('BuildRecoveryBundle("--restore", backupId)', (
            ROOT / "src" / "LinuxMailRelay365" / "MainForm.cs").read_text(encoding="utf-8"))
        self.assertIn("ConfirmDestructive", (
            ROOT / "src" / "LinuxMailRelay365" / "MainForm.cs").read_text(encoding="utf-8"))

    def test_syntax_and_existing_backup_list_verify_contract(self):
        for path in (RECOVERY, INSTALLER):
            proc = subprocess.run(
                ["bash", "-n", str(path)], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, universal_newlines=True, timeout=8)
            self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.run_recovery("--self-test").returncode, 0)
        source = RECOVERY.read_text(encoding="utf-8")
        for keyword in ("--backup)", "--list)", "--verify)", "BACKUP_STATUS=verified",
                        "Pre-restore safety snapshot not created"):
            self.assertIn(keyword, source)


if __name__ == "__main__":
    unittest.main()
