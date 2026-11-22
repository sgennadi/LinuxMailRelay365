"""Unit-only fail-closed contract for disposable Sendmail two-config KVM test.

No root requirement, /etc/mail modification, SMTP or real SELinux access.
"""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "lmr365_kvm_dual_sendmail", str(ROOT / "tests/rocky_vm_sendmail_stopped_dual_config_restore.py"))
dual = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dual)


class DualSendmailFailClosedTests(unittest.TestCase):
    def test_only_two_exact_root_configs_allowed(self):
        self.assertEqual(
            dual.selected_path("etc/mail/sendmail.cf"), Path("/etc/mail/sendmail.cf"))
        self.assertEqual(
            dual.selected_path("etc/mail/submit.cf"), Path("/etc/mail/submit.cf"))
        for bad in ("../etc/mail/sendmail.cf", "/etc/mail/submit.cf",
                    "etc/mail/aliases", "etc/mail/submit.cf/../sendmail.cf",
                    "", None, 123, ["etc/mail/submit.cf"]):
            with self.subTest(name=repr(bad)):
                with self.assertRaisesRegex(RuntimeError, "TARGET_NOT_ALLOWLISTED"):
                    dual.selected_path(bad)

    def test_unknown_concurrent_edits_are_never_reclassified_as_expected(self):
        original = b"original cf data\n"
        self.assertEqual(dual.state_class(original, original), "restored")
        self.assertEqual(dual.state_class(original + dual.MARKER, original),
                         "controlled_edit")
        for changed in (original + b"other", original + dual.MARKER + b"other",
                        b"", b"malicious replacement", original[:-1]):
            with self.subTest(changed=repr(changed)):
                with self.assertRaisesRegex(RuntimeError, "UNKNOWN_CONCURRENT_CHANGE"):
                    dual.state_class(changed, original)

    def test_single_file_atomic_writer_rejects_outside_allowlist(self):
        for target in (Path("/etc/aliases"), Path("/etc/mail/aliases"),
                       Path("/tmp/sendmail.cf"), Path("/etc/mail/../etc/mail/submit.cf"),
                       "/etc/mail/sendmail.cf"):
            with self.subTest(target=repr(target)):
                with self.assertRaisesRegex(RuntimeError,
                                            "RESTORE_TARGET_NOT_ALLOWLISTED"):
                    dual.single.atomic_write(b"test", b"before", None, None,
                                             destination=target)

    def test_no_implicit_production_restore(self):
        self.assertEqual(len(dual.TARGET_NAMES), 2)
        self.assertTrue(all(path.startswith("etc/mail/") for path in dual.TARGET_NAMES))
        self.assertNotIn("etc/mail/aliases", dual.TARGET_NAMES)


if __name__ == "__main__":
    unittest.main()
