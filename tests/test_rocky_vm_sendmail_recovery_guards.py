"""Fail-closed unit tests for disposable-only Sendmail recovery fixture.

Does not touch /etc/mail or start any daemon. Tests parsing and root guards.
"""
import importlib.util
from pathlib import Path
import os
import re
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "lmr365_kvm_sendmail_recovery",
    str(ROOT / "tests/rocky_vm_sendmail_stopped_config_restore.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


reboot_spec = importlib.util.spec_from_file_location(
    "lmr365_kvm_recovery_reboot_guards",
    str(ROOT / "tests/rocky_vm_sendmail_post_reboot_check.py"))
reboot = importlib.util.module_from_spec(reboot_spec)
reboot_spec.loader.exec_module(reboot)


class PostRebootReadOnlyGuardTests(unittest.TestCase):
    def test_nonroot_reboot_probe_refuses_without_host_inspection(self):
        with mock.patch.object(reboot.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "ROOT_DISPOSABLE_CI_REQUIRED"):
                reboot.verify_guest()

    def test_root_without_ci_confirmation_refuses(self):
        with mock.patch.object(reboot.os, "geteuid", return_value=0):
            with mock.patch.dict(reboot.os.environ, {"GITHUB_ACTIONS": "false"}):
                with self.assertRaisesRegex(RuntimeError, "ROOT_DISPOSABLE_CI_REQUIRED"):
                    reboot.verify_guest()

    def test_symlinked_snapshot_identity_refused_before_read(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"
            source.write_text("20261121T005501Z-abcdef012345\\n", encoding="ascii")
            link = Path(td) / "identity"
            link.symlink_to(source)
            module = SimpleNamespace(ID=re.compile(
                r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$"))
            with mock.patch.object(reboot, "ID_FILE", link):
                with self.assertRaisesRegex(RuntimeError, "SNAPSHOT_ID_NOT_ROOT_PRIVATE"):
                    reboot.snapshot_id_from_root_file(module)

    def test_wrong_snapshot_identity_is_rejected_without_archive_reads(self):
        fake = SimpleNamespace(
            lstat=lambda: SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                                          st_uid=0, st_nlink=1, st_size=12),
            read_text=lambda encoding="ascii": "../etc/mail\\n")
        module = SimpleNamespace(ID=re.compile(
            r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$"))
        with mock.patch.object(reboot, "ID_FILE", fake):
            with self.assertRaisesRegex(RuntimeError, "SNAPSHOT_ID_INVALID"):
                reboot.snapshot_id_from_root_file(module)


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
