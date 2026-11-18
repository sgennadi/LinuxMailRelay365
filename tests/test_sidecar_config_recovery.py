"""Offline scoped SMTP sidecar backup/restore acceptance tests (Python 3.6+).

Uses a temporary synthetic Linux filesystem; NEVER invokes real systemctl,
postfix or postqueue, and never touches real service/config paths.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "linux" / "sidecar-config-recovery.py"
spec = importlib.util.spec_from_file_location("lmr365_scoped_recovery", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fake_units():
    return {name: {"active": False, "enabled": False} for name in mod.UNITS}


class ScopedRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lmr365-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.original_root = mod.ROOT
        self.original_base = mod.BASE
        self.original_lock = mod.LOCK
        self.original_uid = mod.OWNER_UID
        mod.ROOT = self.root
        mod.BASE = self.root / "var/backups/linuxmailrelay365-sidecar"
        mod.LOCK = self.root / "run/sidecar.lock"
        mod.OWNER_UID = os.getuid()
        self.addCleanup(self.reset_module)
        (self.root / "var/backups").mkdir(parents=True)
        (self.root / "run").mkdir()
        self.conf = self.root / mod.CONF / "sidecar-postfix"
        self.conf.mkdir(parents=True)
        for name, data in (("main.cf", "myhostname = relay.example.org\n"),
                           ("master.cf", "46500 inet n - n - - smtpd\n"),
                           ("smtp-port", "46500\n")):
            (self.conf / name).write_text(data, encoding="ascii")
        self.identity = self.root / mod.CONF / "sidecar-identity"
        self.identity.mkdir()
        (self.identity / "app.json").write_text('{"clientId":"fixture-only"}\n')
        (self.identity / "app.json").chmod(0o600)
        self.queue = self.root / mod.QUEUE
        self.queue.mkdir(parents=True)

    def reset_module(self):
        mod.ROOT = self.original_root
        mod.BASE = self.original_base
        mod.LOCK = self.original_lock
        mod.OWNER_UID = self.original_uid

    def fake_command(self, argv, **kwargs):
        if argv[0] == "postqueue" and "-j" in argv:
            return ""
        if argv[0] == "ss" and "-ltn" in argv:
            return ""
        if argv[0] == "postconf" and "-h" in argv:
            return {
                "queue_directory": str(self.root / mod.QUEUE),
                "data_directory": str(self.root / "var/lib/linuxmailrelay365-sidecar"),
                "inet_interfaces": "127.0.0.1",
            }[argv[-1]]
        if argv[0] == "postconf" and "-n" in argv:
            return "queue_directory = " + str(self.root / mod.QUEUE)
        if argv[0] == "postconf" and "-M" in argv:
            return "46500 inet n - n - - smtpd\npickup unix n - n 60 1 pickup"
        if argv[0] == "systemctl" and argv[1] == "daemon-reload":
            return ""
        raise AssertionError("Unexpected system command in synthetic test: " +
                             " ".join(argv))

    def patch_runtime(self):
        self.enterContext(patch.object(mod.os, "geteuid", return_value=0))
        self.enterContext(patch.object(mod, "service_state", side_effect=fake_units))
        self.enterContext(patch.object(mod, "command", side_effect=self.fake_command))

    def enterContext(self, context):
        # unittest.TestCase.enterContext is unavailable on Python 3.6.
        value = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        return value

    def test_selftest_and_rootless_refusal_before_mutation(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=8)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("CHANGES_APPLIED=no", proc.stdout)
        for argv in (("--restore", "20261118T112233Z-abcdef123456"),
                     ("--restore", "../passwd", "--confirm",
                      "RESTORE_ISOLATED_RELAY_CONFIGURATION")):
            proc = subprocess.run([sys.executable, str(SCRIPT)] + list(argv),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True, timeout=8)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("SIDECAR_RECOVERY_ERROR", proc.stdout)

    def test_scoped_verified_snapshot_never_contains_queue_or_primary_mta(self):
        self.patch_runtime()
        name = mod.backup()
        self.assertTrue(mod.ID.fullmatch(name))
        manifest = mod.verify_snapshot(name)
        self.assertEqual(manifest["scope"], "isolated_config_no_queue")
        self.assertEqual(manifest["backup_id"], name)
        paths = [x["path"] for x in manifest["entries"]]
        self.assertIn(mod.CONF + "/sidecar-postfix/main.cf", paths)
        self.assertIn(mod.CONF + "/sidecar-identity/app.json", paths)
        self.assertFalse(any(x.startswith("etc/postfix") for x in paths))
        self.assertFalse(any(x.startswith(mod.QUEUE) for x in paths))
        self.assertNotIn(b"fixture-only", (mod.BASE / name / "manifest.json").read_bytes())

    def test_email_named_account_hashes_and_rotation_snapshots_are_scoped(self):
        self.patch_runtime()
        accounts = self.root / mod.CONF / "generated-accounts"
        accounts.mkdir()
        credential = accounts / "notifications@example.org.hash"
        credential.write_text("SHA512-hash-fixture-no-plaintext\n")
        credential.chmod(0o600)
        rotation = self.root / "var/lib/linuxmailrelay365-smtp-account-recovery"
        rotation.mkdir(parents=True)
        rotated = rotation / "old-hashes.backup"
        rotated.write_text("test-rotation-history\n")
        rotated.chmod(0o600)
        name = mod.backup()
        manifest = mod.verify_snapshot(name)
        paths = {entry["path"] for entry in manifest["entries"]}
        self.assertIn(mod.CONF + "/generated-accounts/notifications@example.org.hash",
                      paths)
        self.assertIn("var/lib/linuxmailrelay365-smtp-account-recovery/old-hashes.backup",
                      paths)
        self.assertNotIn("test-rotation-history", str(manifest))

    def test_backup_rejects_symlinked_credential(self):
        self.patch_runtime()
        (self.identity / "app.key").symlink_to("/etc/shadow")
        with self.assertRaises(mod.Refused):
            mod.backup()
        self.assertFalse(any(mod.BASE.iterdir())) if mod.BASE.exists() else None

    def test_archive_tamper_is_refused(self):
        self.patch_runtime()
        name = mod.backup()
        archive = mod.BASE / name / "config.tar.gz"
        bits = bytearray(archive.read_bytes())
        bits[-12] ^= 0x01
        archive.write_bytes(bits)
        with self.assertRaises(mod.Refused):
            mod.verify_snapshot(name)

    def test_offline_restore_creates_emergency_snapshot_and_does_not_start_services(self):
        self.patch_runtime()
        baseline = (self.conf / "main.cf").read_text()
        backup_id = mod.backup()
        (self.conf / "main.cf").write_text("myhostname = changed.example.org\n")
        expected, _ = mod.current_state()
        mod.restore(backup_id, expected)
        self.assertEqual((self.conf / "main.cf").read_text(), baseline)
        self.assertEqual(len(list(mod.BASE.glob("20*"))), 2)
        self.assertFalse((self.root / "etc/postfix").exists())

    def test_failed_postfix_validation_rolls_back_every_file(self):
        self.patch_runtime()
        backup_id = mod.backup()
        changed = "myhostname = modified.example.org\n"
        (self.conf / "main.cf").write_text(changed)
        expected, _ = mod.current_state()
        def command(argv, **kwargs):
            if argv[0] == "postconf" and "-M" in argv:
                raise mod.Refused("simulated_postfix_master_config_invalid")
            return self.fake_command(argv, **kwargs)
        with patch.object(mod, "command", side_effect=command):
            with self.assertRaises(mod.Refused):
                mod.restore(backup_id, expected)
        self.assertEqual((self.conf / "main.cf").read_text(), changed)
        self.assertEqual(len(list(mod.BASE.glob("20*"))), 2)

    def test_restore_fails_closed_when_sidecar_running_or_queue_nonempty(self):
        self.patch_runtime()
        backup_id = mod.backup()
        expected, _ = mod.current_state()
        running = fake_units()
        running[mod.SIDECAR]["active"] = True
        with patch.object(mod, "service_state", return_value=running):
            with self.assertRaises(mod.Refused):
                mod.restore(backup_id, expected)
        (self.queue / "maildrop").mkdir()
        (self.queue / "maildrop" / "queue-message").write_text("do not change")
        with self.assertRaises(mod.Refused):
            mod.restore(backup_id, expected)
        self.assertTrue((self.queue / "maildrop" / "queue-message").exists())

    def test_primary_queue_and_public_listener_are_never_accepted(self):
        self.patch_runtime()
        backup_id = mod.backup()
        expected, _ = mod.current_state()
        cases = [
            ("queue_directory", "/var/spool/postfix"),
            ("data_directory", "/var/lib/postfix"),
            ("inet_interfaces", "all"),
            ("inet_interfaces", "127.0.0.1, 8.8.8.8"),
        ]
        for name, value in cases:
            with self.subTest(parameter=name, value=value):
                def bad_command(argv, **kwargs):
                    if argv[0] == "postconf" and "-h" in argv and argv[-1] == name:
                        return value
                    return self.fake_command(argv, **kwargs)
                with patch.object(mod, "command", side_effect=bad_command):
                    with self.assertRaises(mod.Refused):
                        mod.restore(backup_id, expected)
                self.assertEqual(len(list(mod.BASE.glob("20*"))), 1)

    def test_manually_running_smtp_listener_refuses_restore(self):
        self.patch_runtime()
        backup_id = mod.backup()
        expected, _ = mod.current_state()
        def bound_socket(argv, **kwargs):
            if argv[0] == "ss":
                self.assertIn(":46500", " ".join(argv))
                return "LISTEN 0 100 127.0.0.1:46500 0.0.0.0:*"
            return self.fake_command(argv, **kwargs)
        with patch.object(mod, "command", side_effect=bound_socket):
            with self.assertRaises(mod.Refused) as error:
                mod.restore(backup_id, expected)
        self.assertIn("still_listening", str(error.exception))
        self.assertEqual(len(list(mod.BASE.glob("20*"))), 1)

    def test_multiple_postfix_smtp_listeners_fail_offline_validation(self):
        self.patch_runtime()
        backup_id = mod.backup()
        (self.conf / "main.cf").write_text("myhostname = modified.example.org\n")
        expected, _ = mod.current_state()
        def command(argv, **kwargs):
            if argv[0] == "postconf" and "-M" in argv:
                return "46500 inet n - n - - smtpd\n25 inet n - n - - smtpd"
            return self.fake_command(argv, **kwargs)
        with patch.object(mod, "command", side_effect=command):
            with self.assertRaises(mod.Refused):
                mod.restore(backup_id, expected)
        self.assertEqual((self.conf / "main.cf").read_text(),
                         "myhostname = modified.example.org\n")
        self.assertEqual(len(list(mod.BASE.glob("20*"))), 2)

    def test_invalid_paths_and_unauthorized_roots(self):
        for name in ("etc/postfix/main.cf", "../../etc/passwd",
                     "etc/linuxmailrelay365/../postfix/main.cf",
                     "/etc/linuxmailrelay365/main.cf", "var/spool/linuxmailrelay365-sidecar"):
            with self.subTest(path=name):
                with self.assertRaises(mod.Refused):
                    mod.rooted(name)

    def test_source_does_not_restore_primary_mta(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("systemctl restart postfix", source)
        self.assertNotIn("systemctl stop postfix", source)
        self.assertNotIn("systemctl restart exim", source)
        self.assertNotIn("systemctl stop sendmail", source)
        self.assertNotIn("tarfile.extractall", source)
        self.assertIn("stop_sidecar_auth_health_and_timer_before_offline_restore", source)
        self.assertIn("SIDECAR_SERVICES_STARTED", source)
        self.assertIn('sidecar_queue_directory_must_be_isolated', source)
        self.assertNotIn('command(["postfix"', source)
        self.assertIn('command(["postconf", "-c", config, "-M"])', source)


if __name__ == "__main__":
    unittest.main()
