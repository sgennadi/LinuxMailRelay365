"""Read-only recovery archive integrity/permission checks, Python 3.6 compatible."""
import hashlib
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "audit-sidecar-auth-archives.py"
spec = importlib.util.spec_from_file_location("lmr365_backup_audit", str(SCRIPT))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SidecarArchiveIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "auth-backups"
        self.root.mkdir(mode=0o700)
        self.user = os.geteuid()

    def make_archive(self):
        archive = self.root / "recovery.aBcD1234"
        archive.mkdir(mode=0o700)
        auth = archive / "smtp-auth"
        auth.mkdir(mode=0o700)
        for name in module.REQUIRED:
            item = archive / name
            item.write_bytes(b"synthetic-CI-fixture-no-credentials\n")
            item.chmod(0o600)
        for original, manifest in (
            ("main.cf.auth", "smtp-auth/main.cf.auth.sha256"),
            ("master.cf.auth", "smtp-auth/master.cf.auth.sha256"),
        ):
            val = hashlib.sha256((archive / original).read_bytes()).hexdigest()
            (archive / manifest).write_text(val + "\n", encoding="ascii")
        auth.chmod(0o711)
        return archive

    def test_absent_archive_is_safe_empty_result(self):
        self.root.rmdir()
        report = module.audit(root=self.root, uid=self.user)
        self.assertEqual(report["AUTH_TLS_ARCHIVE_STATUS"], "not_created")
        self.assertEqual(report["CHANGES_APPLIED"], "no")

    def test_verified_root_only_archive_and_digest(self):
        archive = self.make_archive()
        self.assertEqual(module.archive_integrity(archive, self.user), "verified")
        result = module.audit(root=self.root, uid=self.user)
        self.assertEqual(result["AUTH_TLS_ARCHIVE_STATUS"], "verified_root_only")
        self.assertEqual(result["AUTH_TLS_ARCHIVE_COUNT"], "1")
        self.assertEqual(result["CHANGES_APPLIED"], "no")

    def test_public_config_and_certificate_can_remain_0644(self):
        archive = self.make_archive()
        for name in ("main.cf.auth", "master.cf.auth",
                     "linuxmailrelay365-smtp-auth.service",
                     "smtp-auth/fullchain.pem", "smtp-auth/dovecot.conf"):
            (archive / name).chmod(0o644)
        self.assertEqual(module.archive_integrity(archive, self.user), "verified")
        self.assertEqual(module.audit(root=self.root, uid=self.user)
                         ["AUTH_TLS_ARCHIVE_STATUS"], "verified_root_only")

    def test_corruption_or_bad_fingerprint_is_not_accepted(self):
        archive = self.make_archive()
        (archive / "main.cf.auth").write_bytes(b"tampered without changing manifest")
        report = module.audit(root=self.root, uid=self.user)
        self.assertEqual(report["AUTH_TLS_ARCHIVE_STATUS"], "incomplete_or_tampered")
        self.assertEqual(report["AUTH_TLS_ARCHIVE_FAILURE_REASON"], "fingerprint_mismatch")

    def test_symlink_and_missing_private_files_fail_closed(self):
        archive = self.make_archive()
        secret = archive / "smtp-auth/passwd"
        secret.unlink()
        secret.symlink_to(archive / "main.cf.auth")
        self.assertEqual(module.archive_integrity(archive, self.user),
                         "missing_or_unsafe_file")
        self.assertEqual(module.audit(root=self.root, uid=self.user)
                         ["AUTH_TLS_ARCHIVE_STATUS"], "incomplete_or_tampered")

    def test_publicly_traversable_archive_base_is_rejected(self):
        self.make_archive()
        self.root.chmod(0o755)
        self.assertEqual(module.audit(root=self.root, uid=self.user)
                         ["AUTH_TLS_ARCHIVE_STATUS"], "unsafe_root_directory")

    def test_publicly_readable_archive_entry_is_rejected(self):
        archive = self.make_archive()
        (archive / "smtp-auth/privkey.pem").chmod(0o644)
        self.assertEqual(module.archive_integrity(archive, self.user),
                         "missing_or_unsafe_file")

    def test_unexpected_entry_is_not_ignored(self):
        self.make_archive()
        (self.root / "unaudited-copy").write_bytes(b"unsafe")
        self.assertEqual(module.audit(root=self.root, uid=self.user)
                         ["AUTH_TLS_ARCHIVE_STATUS"], "unexpected_entry_manual_review")

    def test_no_destructive_or_plaintext_output(self):
        code = SCRIPT.read_text(encoding="utf-8")
        for bad in ("os.remove(", "shutil.rmtree(", "unlink(", "systemctl",
                    "setenforce", "semanage port -a", "smtp.login(", "sendmail(",
                    "private_key.read_bytes()", "passwd.read_bytes()"):
            self.assertNotIn(bad, code)
        self.assertIn("AUTH_TLS_ARCHIVE_POLICY", code)
        self.assertIn("manual_retention_required", code)
        gui = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        embedded = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text(encoding="utf-8")
        project = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text(encoding="utf-8")
        self.assertIn("BuildAuthArchiveAuditBundle", embedded)
        self.assertIn("InspectAuthArchivesAsync", gui)
        self.assertIn("audit-sidecar-auth-archives.py", project)


if __name__ == "__main__":
    unittest.main()
