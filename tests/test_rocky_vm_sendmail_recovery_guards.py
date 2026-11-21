"""Fail-closed unit tests for disposable-only Sendmail recovery fixture.

Does not touch /etc/mail or start any daemon. Tests parsing and root guards.
"""
import importlib.util
from pathlib import Path
import os
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "lmr365_kvm_sendmail_recovery",
    str(ROOT / "tests/rocky_vm_sendmail_stopped_config_restore.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class DisposableRecoveryGuardTests(unittest.TestCase):
    def test_rocky_release_with_quoted_values(self):
        cases = (
            'NAME="Rocky Linux"\nID="rocky"\nVERSION_ID="9.9"\n',
            'ID=rocky\nVERSION_ID=9.9\n',
            'VERSION_ID="9.9"\nID=rocky\nPRETTY_NAME="Rocky Linux"\n',
        )
        for data in cases:
            with self.subTest(data=data):
                self.assertTrue(helper.validate_rocky_release(data))

    def test_unsupported_distros_and_versions_refuse(self):
        cases = (
            'ID=almalinux\nVERSION_ID=9.9\n',
            'ID=rocky\nVERSION_ID=9.8\n',
            'ID=rocky\nVERSION_ID=10.0\n',
            'ID=rocky\n',
            'VERSION_ID=9.9\n',
            '',
        )
        for data in cases:
            with self.subTest(data=data):
                with self.assertRaisesRegex(
                        RuntimeError, "UNEXPECTED_ROCKY_GUEST_VERSION"):
                    helper.validate_rocky_release(data)

    def test_duplicate_release_id_refused(self):
        with self.assertRaisesRegex(RuntimeError, "DUPLICATE_OS_RELEASE_ID"):
            helper.validate_rocky_release(
                'ID=rocky\nID="rocky"\nVERSION_ID="9.9"\n')

    def test_unprivileged_host_must_refuse_before_guest_probe(self):
        with mock.patch.object(helper.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "CI_ROOT_ONLY"):
                helper.verify_disposable()

    def test_root_without_ci_marker_must_refuse_before_guest_probe(self):
        with mock.patch.object(helper.os, "geteuid", return_value=0):
            with mock.patch.dict(helper.os.environ, {"GITHUB_ACTIONS": "false"}):
                with self.assertRaisesRegex(RuntimeError, "CI_ROOT_ONLY"):
                    helper.verify_disposable()

    def test_oversized_payload_is_refused_before_any_disk_access(self):
        with self.assertRaisesRegex(RuntimeError, "BAD_RESTORATION_BYTES"):
            helper.atomic_write("not bytes", b"original", None, b"context")
        with self.assertRaisesRegex(RuntimeError, "BAD_RESTORATION_BYTES"):
            helper.atomic_write(b"new", "not bytes", None, b"context")


if __name__ == "__main__":
    unittest.main()
