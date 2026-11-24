"""Source and guard tests; no host configuration or services are modified."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "tests/rocky_vm_sendmail_product_restore.py"
spec = importlib.util.spec_from_file_location("lmr365_native_product_fixture", str(FILE))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class ProductRestoreFixtureTests(unittest.TestCase):
    def test_refuse_before_subprocess_or_product_import(self):
        with mock.patch.object(fixture.dual.single, "verify_disposable",
                               side_effect=RuntimeError("CI_ROOT_ONLY")), \
                mock.patch.object(fixture, "load_module") as loader, \
                mock.patch.object(fixture.subprocess, "run") as runner:
            for action in (lambda: fixture.run("bad"),
                           lambda: fixture.interrupt_child("bad", "bad"),
                           lambda: fixture.native_command("--pending-inspect")):
                with self.assertRaisesRegex(RuntimeError, "CI_ROOT_ONLY"):
                    action()
            loader.assert_not_called()
            runner.assert_not_called()

    def test_malformed_duplicate_and_oversized_receipts_refused(self):
        self.assertEqual(fixture.parse_fields("STATE=ok\n"), {"STATE": "ok"})
        for text in ("STATE=ok\nSTATE=ok\n", "bad\n", "a=bad\n",
                     "STATE=\n", "STATE=\0\n", "A=" + "x" * 8192):
            with self.subTest(text=text[:40]), self.assertRaises(RuntimeError):
                fixture.parse_fields(text)

    def test_actual_cli_and_abrupt_exit_required(self):
        with mock.patch.object(fixture.dual.single, "verify_disposable"), \
                mock.patch.object(fixture.subprocess, "run", return_value=
                                  subprocess.CompletedProcess([], 91, "", "")) as runner:
            fixture.native_command("--interrupt", "archive", "sha",
                                   child=True, expected_code=91)
            args, kwargs = runner.call_args
            self.assertEqual(args[0][-3:], ["--interrupt", "archive", "sha"])
            self.assertNotIn("--mta", args[0])
            self.assertEqual(kwargs["timeout"], 240)
            with self.assertRaisesRegex(RuntimeError, "CLI_EXIT_91"):
                fixture.native_command("--pending-inspect")

    def test_wired_before_sendmail_start_with_attested_vm(self):
        source = FILE.read_text(encoding="utf-8")
        for text in ("product.apply_sendmail_v2(", "os._exit(EXIT_AFTER_FIRST_REPLACE)",
                     '"--sendmail-v2-apply"', '"--sendmail-v2-rollback-plan"',
                     '"--sendmail-v2-rollback-apply"', '"--pending-inspect"',
                     "fingerprint_package_selinux", "product.native_static_config_check",
                     "pending_restore_requires_manual_recovery"):
            self.assertIn(text, source)
        self.assertNotIn("systemctl start", source)
        self.assertNotIn("clear_verified_pending(", source)
        shell = (ROOT / "tests/rocky_vm_sendmail_systemd_enforcing.sh").read_text()
        after = shell.split("LMR365_SENDMAIL_VM_DUAL_OFFLINE_CONFIG_RECOVERY=verified_disposable_only", 1)[1]
        self.assertLess(after.index("rocky_vm_sendmail_product_restore.py"),
                        after.index("systemctl start sendmail.service"))
        boot = (ROOT / "tests/rocky_vm_boot_enforcing.sh").read_text()
        self.assertIn("linux/restore-foreign-mta-config.py", boot)
        self.assertIn("/home/ci/rocky_vm_sendmail_product_restore.py", boot)
        workflow = (ROOT / ".github/workflows/rocky-enforcing-vm.yml").read_text()
        self.assertIn("feature/post-rc17-sendmail-v2", workflow)
        self.assertIn("linux/restore-foreign-mta-config.py", workflow)


if __name__ == "__main__":
    unittest.main()
