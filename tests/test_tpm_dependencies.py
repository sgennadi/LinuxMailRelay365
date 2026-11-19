"""No host RPM, TPM, MTA or repository changes are permitted by these tests."""
import importlib.util
from pathlib import Path
from unittest import mock
import io
import contextlib
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "linux" / "manage-tpm-dependencies.py"
SPEC = importlib.util.spec_from_file_location("manage_tpm_dependencies", str(SOURCE))
MANAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANAGER)


def os_info(version="9", ident="rhel"):
    return {"ID": ident, "VERSION_ID": version}


def mock_plan(version="9", profile="runtime", installed=None, tpm=(" /dev/tpmrm0", "2")):
    installed = set(installed or ())
    return MANAGER.make_plan(os_info(version), profile,
                             check_installed=lambda pkg: pkg in installed,
                             tpm_probe=lambda: (tpm[0].strip(), tpm[1]))


class TpmDependencyTests(unittest.TestCase):
    def test_rhel8_requested_runtime_and_build_headers(self):
        runtime, _ = mock_plan("8", "runtime")
        self.assertEqual(runtime["packages"],
                         ["tpm2-tss", "tpm2-abrmd", "tpm2-tools"])
        build, _ = mock_plan("8", "build-prereqs")
        for package in ("tpm2-tss", "tpm2-tss-devel", "tpm2-abrmd",
                        "tpm2-tools", "openssl-devel", "autoconf-archive"):
            self.assertIn(package, build["packages"])
        self.assertNotIn("tpm2-openssl", build["packages"])

    def test_rhel9_pkcs11_without_native_provider(self):
        plan, _ = mock_plan("9", "pkcs11")
        self.assertIn("tpm2-pkcs11", plan["missing"])
        self.assertIn("pkcs11-provider", plan["missing"])
        self.assertIn("p11-kit", plan["missing"])
        self.assertNotIn("tpm2-openssl", plan["packages"])
        with self.assertRaisesRegex(ValueError, "requires_rhel10"):
            mock_plan("9", "native-provider")

    def test_rhel10_official_native_provider(self):
        plan, _ = mock_plan("10", "native-provider")
        self.assertIn("tpm2-openssl", plan["missing"])

    def test_compatible_rhel_variants(self):
        for ident in ("rhel", "ol", "rocky", "almalinux"):
            with self.subTest(os=ident):
                self.assertEqual(MANAGER.distro(os_info("9.4", ident)), (ident, 9))
        for ident in ("ubuntu", "debian", "centos"):
            with self.subTest(os=ident):
                with self.assertRaisesRegex(ValueError, "unsupported_os"):
                    MANAGER.distro(os_info("9", ident))

    def test_plan_sha_binds_actual_missing_packages_and_device(self):
        a, x = mock_plan("9", "pkcs11")
        b, y = mock_plan("9", "pkcs11")
        c, z = mock_plan("9", "pkcs11", installed={"tpm2-tools"})
        d, w = mock_plan("9", "pkcs11", tpm=("none", "unknown"))
        self.assertEqual((a, x), (b, y))
        self.assertNotEqual(x, z)
        self.assertNotEqual(x, w)
        self.assertEqual(len(x), 64)

    def test_explicit_install_requires_root_tpm_and_exact_sha(self):
        plan, sha = mock_plan("9", "runtime")
        with mock.patch.object(MANAGER.os, "geteuid", return_value=0), \
                mock.patch.object(MANAGER.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "approval"):
                MANAGER.install(plan, sha, "wrong", sha)
            with self.assertRaisesRegex(ValueError, "approval"):
                MANAGER.install(plan, sha, MANAGER.CONFIRM, "0" * 64)
            self.assertFalse(run.called)
        with mock.patch.object(MANAGER.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(ValueError, "root_required"):
                MANAGER.install(plan, sha, MANAGER.CONFIRM, sha)
        absent, hash2 = mock_plan("9", "runtime", tpm=("none", "unknown"))
        with mock.patch.object(MANAGER.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "tpm2_hardware"):
                MANAGER.install(absent, hash2, MANAGER.CONFIRM, hash2)

    def test_approved_install_has_allowlisted_dnf_command_only(self):
        plan, sha = mock_plan("9", "runtime")
        fake_rpm = mock.Mock(return_value=True)
        fake_result = mock.Mock(returncode=0)
        with mock.patch.object(MANAGER.os, "geteuid", return_value=0), \
                mock.patch.object(MANAGER.shutil, "which", return_value="/usr/bin/dnf"), \
                mock.patch.object(MANAGER, "rpm_installed", fake_rpm), \
                mock.patch.object(MANAGER.subprocess, "run", return_value=fake_result) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            MANAGER.install(plan, sha, MANAGER.CONFIRM, sha)
        args = run.call_args[0][0]
        self.assertEqual(args[:3], ["/usr/bin/dnf", "-y", "install"])
        self.assertEqual(args[3:], plan["missing"])
        self.assertNotIn("--nogpgcheck", args)
        self.assertNotIn("--enablerepo", args)

    def test_read_only_default_and_custom_file_apply_is_blocked(self):
        with mock.patch.object(MANAGER, "make_plan",
                               return_value=mock_plan("9", "runtime")), \
                mock.patch.object(MANAGER, "read_os_release", return_value=os_info("9")), \
                mock.patch.object(MANAGER, "install") as apply, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(MANAGER.main(["--profile", "runtime"]), 0)
            self.assertIn("TPM_DEPS_APPLIED=no", out.getvalue())
            self.assertFalse(apply.called)
            self.assertEqual(MANAGER.main(["--apply", "--os-release-file", "/tmp/x"]), 2)
            self.assertFalse(apply.called)


if __name__ == "__main__":
    unittest.main()
