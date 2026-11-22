"""Read-only disaster-recovery scope tests, Python 3.6+ and RHEL compatible."""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "recovery-scope-audit.py"
spec = importlib.util.spec_from_file_location("lmr_recovery_scope", str(SCRIPT))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def fake_status(path, directory=False):
    if path.is_symlink():
        return "unsafe_or_untrusted"
    if directory:
        return "present" if path.is_dir() else "missing"
    return "present" if path.is_file() else "missing"


class RecoveryScopeTests(unittest.TestCase):
    def test_cli_is_readonly_and_checks_custom_port(self):
        for port in (1024, 2525, 46500, 65535):
            p = subprocess.run(
                [sys.executable, str(SCRIPT), "--smtp-port", str(port)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=8)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("CHANGES_APPLIED=no", p.stdout)
            self.assertIn("SIDECAR_FULL_RESTORE_VERIFIED=no", p.stdout)
        for port in (25, 587, 1023, 65536, "invalid"):
            p = subprocess.run([sys.executable, str(SCRIPT), "--smtp-port", str(port)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=8)
            self.assertNotEqual(p.returncode, 0)
        p = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=8)
        self.assertEqual(p.returncode, 0)
        self.assertIn("RECOVERY_SCOPE_SELF_TEST=pass", p.stdout)

    def test_symlinks_are_unsafe_and_reports_do_not_expose_values(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            secret = root / "private"
            secret.write_text("SECRET_NEVER_ECHO")
            link = root / "link"
            link.symlink_to(secret)
            self.assertEqual(recovery.status(link), "unsafe_or_untrusted")
            report = recovery.audit(46500)
            self.assertNotIn("SECRET_NEVER_ECHO", str(report))
            self.assertNotIn("/etc/linuxmailrelay365", str(report))
            self.assertEqual(report["BACKUP_SCOPE"], "primary_postfix_config_only")

    def test_only_counts_external_dependencies(self):
        with tempfile.TemporaryDirectory() as folder:
            cfg = pathlib.Path(folder) / "main.cf"
            cfg.write_text(
                "smtp_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt\n"
                "smtp_tls_key_file = /etc/postfix/m365-oauth/app.key\n"
                "smtp_tls_policy_maps = hash:/etc/linuxmailrelay365/tls-policy\n"
                "sender_canonical_maps = regexp:/etc/linuxmailrelay365/sidecar-postfix/sender.map\n"
                "smtp_sasl_password_maps = dynamic-token\n")
            with patch.object(recovery, "status", side_effect=fake_status):
                external, unknown = recovery.external_refs(cfg)
            self.assertEqual(external, "3")
            self.assertEqual(unknown, "1")

    def test_archive_candidates_are_not_called_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            folder_ok = root / "20261118T102030Z-abcdef123456"
            folder_ok.mkdir()
            for name in ("config.tar.gz", "SHA256SUMS", "state.txt"):
                (folder_ok / name).write_text("fixture")
            (root / "20261118T102030Z-fedcba654321").mkdir()
            with patch.object(recovery, "status", side_effect=fake_status):
                self.assertEqual(recovery.backup_candidates(root), "1")
            self.assertFalse(recovery.BACKUP_ID.fullmatch("../../etc/passwd"))

    def test_inventory_never_claims_complete_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            keys = ("primary", "sidecar", "auth", "queue", "unit",
                    "backups", "exim", "exim_rhel", "sendmail")
            paths = {k: root / k for k in keys}
            for key in ("primary", "sidecar", "auth", "queue", "backups"):
                paths[key].mkdir()
            for name in ("main.cf", "master.cf"):
                (paths["primary"] / name).write_text("myhostname = ci.example\n")
                (paths["sidecar"] / name).write_text("myhostname = ci.example\n")
            (paths["sidecar"] / "smtp-port").write_text("46500\n")
            paths["unit"].write_text("[Unit]\n")
            with patch.object(recovery, "status", side_effect=fake_status):
                report = recovery.audit(46500, roots=paths)
                self.assertEqual(report["SIDECAR_CONFIGURATION"], "yes")
                self.assertEqual(report["PRIMARY_POSTFIX_CONFIG"], "present")
                self.assertEqual(report["SIDECAR_FULL_RESTORE_VERIFIED"], "no")
                self.assertEqual(report["RECOVERY_ASSESSMENT"],
                                 "requires_manual_external_backup_and_live_restore")
                (paths["sidecar"] / "smtp-port").write_text("2525\n")
                self.assertEqual(recovery.audit(46500, roots=paths)[
                    "SIDECAR_CONFIGURATION"], "port_mismatch")

    def test_no_mutation_commands(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for banned in ("systemctl start ", "systemctl stop ", "postconf -e",
                       "apt-get install", "dnf install", "setenforce 0",
                       "tar -x", "shutil.rmtree", ".unlink(", "smtplib"):
            self.assertNotIn(banned, source)


if __name__ == "__main__":
    unittest.main()
