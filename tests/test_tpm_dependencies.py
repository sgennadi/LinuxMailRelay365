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
    def test_auto_profile_rhel10_prefers_vendor_native_provider(self):
        plan, _ = mock_plan("10", "auto")
        self.assertEqual(plan["selected_profile"], "native-provider")
        self.assertEqual(plan["selection_reason"], "rhel10_native_tpm2_openssl")
        self.assertIn("tpm2-openssl", plan["missing"])

    def test_auto_profile_rhel9_requires_existing_openssl3_module(self):
        runtime, runtime_sha = mock_plan("9", "auto")
        self.assertEqual(runtime["selected_profile"], "runtime")
        self.assertNotIn("pkcs11-provider", runtime["packages"])
        pkcs, pkcs_sha = mock_plan("9", "auto", installed={"pkcs11-provider"})
        self.assertEqual(pkcs["selected_profile"], "pkcs11")
        self.assertIn("tpm2-pkcs11", pkcs["packages"])
        self.assertNotEqual(runtime_sha, pkcs_sha)

    def test_auto_profile_rhel8_only_offers_runtime(self):
        plan, _ = mock_plan("8", "auto")
        self.assertEqual(plan["selected_profile"], "runtime")
        self.assertNotIn("tpm2-openssl", plan["packages"])

    def test_plan_hash_includes_resource_manager_and_actual_tool(self):
        def plan(device, utility):
            return MANAGER.make_plan(
                os_info("10"), "auto",
                check_installed=lambda package: False,
                tpm_probe=lambda: (device, "2"),
                utility_probe=lambda: utility)
        a, h1 = plan("/dev/tpmrm0", False)
        b, h2 = plan("/dev/tpm0", False)
        c, h3 = plan("/dev/tpmrm0", True)
        self.assertTrue(a["resource_manager"])
        self.assertFalse(b["resource_manager"])
        self.assertFalse(a["tpm2_getcap_present"])
        self.assertNotEqual(h1, h2)
        self.assertNotEqual(h1, h3)

    def test_auto_plan_reports_unverified_signer(self):
        plan, digest = mock_plan("9", "auto")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            MANAGER.emit(plan, digest)
        self.assertIn("TPM_DEPS_SELECTED_PROFILE=runtime", out.getvalue())
        self.assertIn("TPM_DEPS_PROVIDER_NEXT=manual_vendor_review_no_auto_source_build",
                      out.getvalue())
        self.assertIn("TPM_DEPS_HARDWARE_KEY_READY=not_verified", out.getvalue())

    def test_missing_getcap_after_rpm_reports_failure(self):
        plan, digest = mock_plan("10", "runtime", installed=MANAGER.BASE)
        with mock.patch.object(MANAGER.os, "geteuid", return_value=0), \
                mock.patch.object(MANAGER, "tpm_getcap_ready", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "tpm2_getcap_missing"):
                MANAGER.install(plan, digest, MANAGER.CONFIRM, digest)

    def test_approved_auto_profile_validates_resolved_package_set(self):
        plan, digest = mock_plan("10", "auto")
        commands = []
        def run(argv, **kw):
            commands.append(argv)
            return mock.Mock(returncode=0)
        with mock.patch.object(MANAGER.os, "geteuid", return_value=0), \
             mock.patch.object(MANAGER.shutil, "which", return_value="/usr/bin/dnf"), \
             mock.patch.object(MANAGER, "rpm_installed", return_value=True), \
             mock.patch.object(MANAGER, "tpm_getcap_ready", return_value=True), \
             mock.patch.object(MANAGER.subprocess, "run", side_effect=run), \
             contextlib.redirect_stdout(io.StringIO()):
            MANAGER.install(plan, digest, MANAGER.CONFIRM, digest)
        self.assertEqual(commands[0][:3], ["/usr/bin/dnf", "-y", "install"])
        self.assertIn("tpm2-openssl", commands[0])

    def test_provider_doctor_reports_only_fixed_nonsecret_statuses(self):
        plan, _ = mock_plan("10", "auto", tpm=("/dev/tpmrm0", "2"))
        plan["tpm2_getcap_present"] = True
        commands = []
        def run(argv, **kw):
            commands.append((argv, kw))
            if argv == ["/usr/bin/openssl", "version"]:
                return mock.Mock(returncode=0, stdout=b"OpenSSL 3.0.7 1 Nov 2022\n")
            if "tpm2_getcap" in " ".join(argv):
                return mock.Mock(returncode=0, stdout=b"secret-output-that-must-not-leak")
            if argv[-1] == "tpm2":
                return mock.Mock(returncode=0, stdout=b"Providers:\n  default\n  tpm2\n")
            return mock.Mock(returncode=1, stdout=b"PRIVATE CERT NOT VALID")
        with mock.patch.object(MANAGER.pwd, "getpwnam", return_value=object()):
            status = MANAGER.provider_doctor(plan, runner=run,
                                            runuser="/usr/sbin/runuser")
        self.assertEqual(status["OPENSSL3"], "available")
        self.assertEqual(status["SERVICE_USER"], "present")
        self.assertEqual(status["TPM2_PROVIDER"], "loaded_as_m365mailer")
        self.assertEqual(status["PKCS11_PROVIDER"], "not_loadable")
        self.assertEqual(status["TPM2_DEVICE_AS_SERVICE"], "read_verified")
        self.assertEqual(len(commands), 4)
        self.assertEqual(commands[1][0][:5],
                         ["/usr/sbin/runuser", "-u", "m365mailer", "--", "/usr/bin/openssl"])
        for argv, kw in commands:
            self.assertNotIn("MAIL FROM", " ".join(argv))
            self.assertNotIn("tpm2_clear", " ".join(argv))
            self.assertNotIn("tpm2_evictcontrol", " ".join(argv))
            self.assertEqual(kw["env"]["OPENSSL_CONF"], "/dev/null")
            self.assertEqual(kw["stderr"], MANAGER.subprocess.DEVNULL)
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            MANAGER.emit_provider_doctor(status)
        self.assertIn("TPM_DEPS_DIAG_TPM2_PROVIDER=loaded_as_m365mailer", printed.getvalue())
        self.assertIn("TPM_DEPS_DIAG_PS256_SIGNATURE_VERIFIED=no", printed.getvalue())
        self.assertNotIn("secret-output-that-must-not-leak", printed.getvalue())
        self.assertNotIn("PRIVATE CERT", printed.getvalue())

    def test_provider_doctor_missing_openssl3_cannot_claim_signature(self):
        plan, _ = mock_plan("9", "auto")
        calls = []
        def run(argv, **kw):
            calls.append(argv)
            return mock.Mock(returncode=0, stdout=b"OpenSSL 1.1.1k 1 Jan 2021")
        status = MANAGER.provider_doctor(plan, runner=run, runuser="/usr/sbin/runuser")
        self.assertEqual(status["OPENSSL3"], "missing_or_unsupported")
        self.assertEqual(status["TPM2_PROVIDER"], "not_tested")
        self.assertEqual(len(calls), 1)

    def test_provider_doctor_refuses_missing_service_identity(self):
        plan, _ = mock_plan("10", "auto")
        def run(argv, **kw):
            return mock.Mock(returncode=0, stdout=b"OpenSSL 3.0.7\n")
        with mock.patch.object(MANAGER.pwd, "getpwnam", side_effect=KeyError):
            status = MANAGER.provider_doctor(plan, runner=run,
                                            runuser="/usr/sbin/runuser")
        self.assertEqual(status["SERVICE_USER"], "missing")
        self.assertEqual(status["TPM2_PROVIDER"], "not_tested")

    def test_provider_inspection_rejects_unapproved_write_and_nonroot(self):
        with mock.patch.object(MANAGER.os, "geteuid", return_value=1000), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(MANAGER.main(["--inspect-provider"]), 2)
        with mock.patch.object(MANAGER.os, "geteuid", return_value=0), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(MANAGER.main(["--inspect-provider", "--apply"]), 2)

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
                mock.patch.object(MANAGER, "tpm_getcap_ready", return_value=True), \
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
