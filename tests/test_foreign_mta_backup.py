"""Exim/Sendmail root-only configuration backup is verifiable and non-mutating."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "linux" / "foreign-mta-config-backup.py"
spec = importlib.util.spec_from_file_location("foreign_mta_backup", str(PATH))
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class ForeignMtaBackupTests(unittest.TestCase):
    def fixture(self, temporary, mta):
        root = Path(temporary)
        (root / "etc").mkdir()
        if mta == "sendmail":
            source = root / "etc" / "mail"
            source.mkdir()
            (source / "sendmail.cf").write_text(
                "O DaemonPortOptions=Port=smtp,Addr=127.0.0.1\nDSrelay.test\n")
            (source / "access").write_text("Connect:127.0.0.1 RELAY\n")
        else:
            source = root / "etc" / "exim4"
            source.mkdir()
            (source / "update-exim4.conf.conf").write_text(
                "dc_eximconfig_configtype='smarthost'\n")
            (source / "passwd.client").write_text("sample.invalid:user:never-output-this\n")
            os.chmod(str(source / "passwd.client"), 0o640)
        return root, root / "backups", source

    def test_roundtrip_and_no_primary_modification(self):
        for mta in ("exim", "sendmail"):
            with self.subTest(mta=mta), tempfile.TemporaryDirectory() as directory:
                root, backups, config = self.fixture(directory, mta)
                original = {p.name: p.read_bytes() for p in config.iterdir()}
                backup_id, info = snapshot.backup(
                    mta, root=root, base=backups, owner_uid=os.getuid())
                self.assertEqual(info["files"], len(original))
                self.assertEqual(snapshot.listed(
                    mta, base=backups, owner_uid=os.getuid()), [backup_id])
                accepted = snapshot.verify(backups / mta / backup_id, mta,
                                           owner_uid=os.getuid())
                self.assertEqual(accepted["sha256"], info["sha256"])
                self.assertEqual({p.name: p.read_bytes() for p in config.iterdir()},
                                 original)
                for f in (backups / mta / backup_id).iterdir():
                    self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)

    def test_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, backups, config = self.fixture(directory, "sendmail")
            link = config / "unsafe.cf"
            link.symlink_to(config / "sendmail.cf")
            with self.assertRaises(snapshot.Refused):
                snapshot.backup("sendmail", root=root, base=backups,
                                owner_uid=os.getuid())

    def test_manifest_and_archive_tampering_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, backups, config = self.fixture(directory, "exim")
            bid, _ = snapshot.backup("exim", root=root, base=backups,
                                     owner_uid=os.getuid())
            folder = backups / "exim" / bid
            archive = folder / "config.tar.gz"
            with archive.open("ab") as target:
                target.write(b"tampered")
            with self.assertRaises(snapshot.Refused):
                snapshot.verify(folder, "exim", owner_uid=os.getuid())
            self.assertEqual(snapshot.listed("exim", backups, os.getuid()), [])

    def test_missing_and_nonregular_config_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            with self.assertRaises(snapshot.Refused):
                snapshot.selected_files("sendmail", root=root, owner_uid=os.getuid())
            with self.assertRaises(snapshot.Refused):
                snapshot.selected_files("unknown", root=root, owner_uid=os.getuid())

    def test_listing_missing_dir_does_not_modify_filesystem(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            absent = root / "archive-root"
            self.assertEqual(snapshot.listed(
                "exim", base=absent, owner_uid=os.getuid()), [])
            self.assertFalse(absent.exists())

    def test_wizard_excludes_postfix_recovery_for_foreign_mta(self):
        source = (ROOT / "src" / "LinuxMailRelay365" / "MainForm.cs").read_text()
        resources = (ROOT / "src" / "LinuxMailRelay365" / "EmbeddedAssets.cs").read_text()
        project = (ROOT / "src" / "LinuxMailRelay365" /
                   "LinuxMailRelay365.csproj").read_text()
        for fragment in ("BackupForeignMtaAsync", "ListForeignMtaBackupsAsync",
                         "VerifyForeignMtaBackupAsync", "RequirePostfixBackup",
                         'inspectedMail?.Mta == "postfix"',
                         "FOREIGN_BACKUP_RESTORE_ENABLED=no"):
            self.assertIn(fragment, source)
        self.assertIn("BuildForeignMtaBackupBundle", resources)
        self.assertIn("foreign-mta-config-backup.py", project)
        self.assertNotIn("RestoreForeignMtaAsync", source)

    def test_cli_restoration_and_nonroot_are_refused(self):
        source = PATH.read_text()
        self.assertNotIn("--restore", source)
        self.assertNotIn("systemctl restart ", source)
        self.assertNotIn("systemctl stop ", source)
        self.assertNotIn("postconf -e ", source)
        self.assertNotIn("mail from:", source.lower())
        self.assertIn("FOREIGN_BACKUP_RESTORE_ENABLED=no", source)
        proc = subprocess.run([sys.executable, str(PATH), "--mta", "exim",
                               "--self-test"], capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bad = subprocess.run([sys.executable, str(PATH), "--mta", "exim",
                              "--restore", "someid"], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
