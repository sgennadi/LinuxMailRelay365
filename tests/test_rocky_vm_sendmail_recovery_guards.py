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



class PostRebootListenerGuardTests(unittest.TestCase):
    """Pure string tests; never bind a port or inspect actual host sockets."""

    def test_exact_postfix_ipv4_listener_accepted_with_unrelated_ssh(self):
        capture = (
            "LISTEN 0 4096 127.0.0.1:25 0.0.0.0:*\n"
            "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n")
        self.assertEqual(
            reboot.require_only_primary_postfix_listener(capture),
            "loopback_ipv4_25_only")

    def test_ipv6_wildcard_ipv4_wildcard_and_public_bind_refused(self):
        for addr in ("0.0.0.0", "[::]", "192.0.2.15", "[2001:db8::1]"):
            with self.subTest(address=addr):
                capture = "LISTEN 0 4096 %s:25 0.0.0.0:*\n" % addr
                with self.assertRaisesRegex(
                        RuntimeError, "UNEXPECTED_SMTP_LISTENER"):
                    reboot.require_only_primary_postfix_listener(capture)

    def test_ipv6_loopback_mismatches_explicit_ipv4_fixture(self):
        with self.assertRaisesRegex(
                RuntimeError, "UNEXPECTED_SMTP_LISTENER"):
            reboot.require_only_primary_postfix_listener(
                "LISTEN 0 4096 [::1]:25 [::]:*\n")

    def test_additional_submission_and_custom_port_refused(self):
        base = "LISTEN 0 4096 127.0.0.1:25 0.0.0.0:*\n"
        for port in (465, 587, 2525, 2526):
            with self.subTest(port=port):
                capture = base + ("LISTEN 0 4096 127.0.0.1:%d 0.0.0.0:*\n"
                                  % port)
                with self.assertRaisesRegex(
                        RuntimeError, "UNEXPECTED_SMTP_LISTENER"):
                    reboot.require_only_primary_postfix_listener(capture)

    def test_missing_duplicate_and_garbage_listeners_refused(self):
        primary = "LISTEN 0 4096 127.0.0.1:25 0.0.0.0:*\n"
        for capture, error in (
                ("", "MISSING_OR_DUPLICATE_PRIMARY"),
                (primary + primary, "MISSING_OR_DUPLICATE_PRIMARY"),
                ("garbled\n", "UNPARSEABLE_TCP_LISTENER"),
                ("LISTEN 0 4096 broken 0.0.0.0:*\n",
                 "INVALID_TCP_LISTENER_ADDRESS")):
            with self.subTest(capture=capture):
                with self.assertRaisesRegex(RuntimeError, error):
                    reboot.require_only_primary_postfix_listener(capture)


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



class PackageSELinuxFingerprintTests(unittest.TestCase):
    """Synthetic fixture: SELinux xattrs are mocked, not modified on the host."""

    def fixture(self, td):
        root = Path(td)
        mail = root / "etc" / "mail"
        mail.mkdir(parents=True)
        conf = mail / "sendmail.cf"
        conf.write_bytes(b"# test-only config\n")
        tools_dir = mail / "smrsh"
        tools_dir.mkdir()
        link = tools_dir / "procmail"
        link.symlink_to("/usr/bin/procmail")
        def owner(st):
            return {"uid": st.st_uid, "gid": st.st_gid}
        def file_entry(path):
            st = path.lstat()
            return dict(owner(st), size=st.st_size, sha256="0" * 64,
                        mode=stat.S_IMODE(st.st_mode))
        def dir_entry(path):
            st = path.lstat()
            return dict(owner(st), kind="directory",
                        mode=stat.S_IMODE(st.st_mode))
        st = link.lstat()
        manifest = {
            "version": 2, "mta": "sendmail",
            "files": {"etc/mail/sendmail.cf": file_entry(conf)},
            "objects": {
                "etc/mail": dir_entry(mail),
                "etc/mail/smrsh": dir_entry(tools_dir),
                "etc/mail/smrsh/procmail": dict(
                    owner(st), kind="symlink", target=os.readlink(link)),
            },
        }
        return root, manifest, link

    @staticmethod
    def fake_label(path, name, follow_symlinks=True):
        if name != "security.selinux" or follow_symlinks:
            raise AssertionError("SELinux probe must use lgetxattr")
        return b"system_u:object_r:etc_t:s0\x00"

    def test_full_v2_label_fingerprint_stable_and_no_symlink_follow(self):
        with tempfile.TemporaryDirectory() as td:
            root, manifest, _ = self.fixture(td)
            with mock.patch.object(reboot.os, "getxattr",
                                   side_effect=self.fake_label) as getter:
                count, first = reboot.fingerprint_package_selinux(manifest, root)
                self.assertEqual((count, len(first)), (4, 64))
                self.assertEqual(
                    (count, first), reboot.fingerprint_package_selinux(manifest, root))
                self.assertEqual(getter.call_count, 8)
                self.assertTrue(all(
                    call.kwargs == {"follow_symlinks": False}
                    for call in getter.call_args_list))

    def test_v2_label_drift_changes_fingerprint(self):
        with tempfile.TemporaryDirectory() as td:
            root, manifest, link = self.fixture(td)
            with mock.patch.object(reboot.os, "getxattr",
                                   side_effect=self.fake_label):
                baseline = reboot.fingerprint_package_selinux(manifest, root)
            def different_label(path, name, follow_symlinks=True):
                self.fake_label(path, name, follow_symlinks)
                return (b"system_u:object_r:mail_spool_t:s0\x00"
                        if Path(path) == link else
                        b"system_u:object_r:etc_t:s0\x00")
            with mock.patch.object(reboot.os, "getxattr",
                                   side_effect=different_label):
                changed = reboot.fingerprint_package_selinux(manifest, root)
            self.assertEqual(changed[0], baseline[0])
            self.assertNotEqual(changed[1], baseline[1])

    def test_unreadable_and_empty_labels_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root, manifest, link = self.fixture(td)
            for bad in (b"", OSError("missing")):
                def failing_label(path, name, follow_symlinks=True):
                    self.fake_label(path, name, follow_symlinks)
                    if Path(path) == link:
                        if isinstance(bad, Exception):
                            raise bad
                        return bad
                    return b"system_u:object_r:etc_t:s0\x00"
                with self.subTest(label=repr(bad)):
                    with mock.patch.object(reboot.os, "getxattr",
                                           side_effect=failing_label):
                        with self.assertRaisesRegex(
                                RuntimeError,
                                "PACKAGE_LABEL_(EMPTY_OR_OVERSIZED|UNREADABLE)"):
                            reboot.fingerprint_package_selinux(manifest, root)

    def test_changed_package_symlink_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root, manifest, link = self.fixture(td)
            link.unlink()
            link.symlink_to("/other/target")
            with mock.patch.object(reboot.os, "getxattr",
                                   side_effect=self.fake_label):
                with self.assertRaisesRegex(
                        RuntimeError, "PACKAGE_LABEL_LINK_CHANGED"):
                    reboot.fingerprint_package_selinux(manifest, root)

    def test_bad_manifest_or_traversal_refused_without_xattrs(self):
        with tempfile.TemporaryDirectory() as td:
            root, manifest, _ = self.fixture(td)
            malformed = [
                dict(manifest, version=1),
                dict(manifest, objects={"etc/mail": []}),
                dict(manifest, objects={}),
                dict(manifest, files={
                    "../etc/mail/sendmail.cf": next(iter(manifest["files"].values()))}),
            ]
            with mock.patch.object(reboot.os, "getxattr",
                                   side_effect=AssertionError("unexpected xattr read")):
                for candidate in malformed:
                    with self.subTest(candidate=candidate):
                        with self.assertRaisesRegex(
                                RuntimeError,
                                "INVALID_PACKAGE_LABEL_(MANIFEST|OBJECT_SET|PATH)"):
                            reboot.fingerprint_package_selinux(candidate, root)

    def test_symlinked_etc_parent_is_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            root, manifest, _ = self.fixture(td)
            etc = root / "etc"
            # Construct a fully valid-looking snapshot under a different tree.
            target = Path(outside) / "etc"
            etc.rename(target)
            etc.symlink_to(target, target_is_directory=True)
            with mock.patch.object(reboot.os, "getxattr",
                                   side_effect=AssertionError("unsafe xattr read")):
                with self.assertRaisesRegex(
                        RuntimeError, "PACKAGE_LABEL_PARENT_NOT_DIRECTORY"):
                    reboot.fingerprint_package_selinux(manifest, root)


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
