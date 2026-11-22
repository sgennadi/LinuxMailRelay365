
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "platform-compat.py"

spec = importlib.util.spec_from_file_location("linuxmailrelay365_platform", SCRIPT)
assert spec is not None and spec.loader is not None
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)


class PlatformCompatibilityTests(unittest.TestCase):
    def test_rhel_family_release_ids_and_version_major(self):
        for os_id, version in (
            ("rhel", "8.10"), ("rhel", "9.6"), ("rhel", "10.0"),
            ("ol", "8.10"), ("ol", "9.6"), ("ol", "10.1"),
            ("rocky", "8.10"), ("rocky", "9.6"), ("rocky", "10.1"),
            ("almalinux", "8.10"), ("almalinux", "9.6"),
            ("almalinux", "10.0"),
        ):
            with self.subTest(os_id=os_id, version=version):
                result = platform.distro_info({"ID": os_id, "VERSION_ID": version})
                self.assertEqual(result[0], "rhel")
                self.assertEqual(result[1], version.split(".")[0])
                self.assertEqual(result[2], "candidate")

    def test_centos_stream_supported_but_legacy_centos_rejected(self):
        self.assertEqual(platform.distro_info({
            "ID": "centos", "NAME": "CentOS Stream", "VERSION_ID": "9"})[2],
                         "candidate")
        self.assertEqual(platform.distro_info({
            "ID": "centos", "NAME": "CentOS Linux", "VERSION_ID": "8"})[2],
                         "manual_review")

    def test_ubuntu_debian_and_unverified_distros(self):
        for name, version in (
            ("ubuntu", "20.04"), ("ubuntu", "22.04"),
            ("ubuntu", "24.04"), ("ubuntu", "26.04"),
            ("debian", "11"), ("debian", "12"), ("debian", "13"),
        ):
            with self.subTest(name=name, version=version):
                self.assertEqual(platform.distro_info(
                    {"ID": name, "VERSION_ID": version})[2], "candidate")
        for name, version in (("fedora", "42"), ("ol", "7.9"),
                              ("rocky", "7.9"), ("unknown", "10")):
            self.assertEqual(platform.distro_info(
                {"ID": name, "VERSION_ID": version})[2], "manual_review")

    def test_os_release_parsing_never_evaluates_shell(self):
        content = (
            'NAME="Oracle Linux Server"\n'
            'ID="ol"\n'
            'VERSION_ID="10.1"\n'
            'ID_LIKE="fedora rhel"\n'
            'PRETTY_NAME="$(touch /tmp/no-commands-should-run)"\n'
        )
        info = platform.parse_os_release(content)
        self.assertEqual(info["ID"], "ol")
        self.assertEqual(info["VERSION_ID"], "10.1")
        self.assertIn("$(touch", info["PRETTY_NAME"])

    def test_dovecot_versions_report_unsupported_instead_of_guessing(self):
        self.assertEqual(platform.dovecot_compat("2.3.21 (47349e2482)"),
                         "2_3_compatible")
        self.assertEqual(platform.dovecot_compat("2.4.1"),
                         "2_4_auth_only_candidate")
        self.assertEqual(platform.dovecot_compat("2.5.0"), "unsupported_version")
        self.assertEqual(platform.dovecot_compat(""), "missing")

    def test_selinux_port_label_uses_selected_port_not_hardcoded_2525(self):
        rules = (
            "smtp_port_t tcp 25, 465, 587, 2525-2527\n"
            "http_port_t tcp 80, 443, 8080, 8443\n"
        )
        self.assertEqual(platform.parse_selinux_ports(rules, 2526),
                         ("allowed", "smtp_port_t"))
        self.assertEqual(platform.parse_selinux_ports(rules, 2529),
                         ("unmapped", "none"))
        self.assertEqual(platform.parse_selinux_ports(rules, 8443),
                         ("conflict", "other_type"))
        self.assertEqual(platform.parse_selinux_ports(
            "smtp_port_t tcp 24680\nhttp_port_t tcp 8080\n", 24680),
            ("allowed", "smtp_port_t"))

    def test_cli_custom_ports_and_read_only_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            mock_release = Path(directory) / "os-release"
            mock_release.write_text('ID="ol"\nVERSION_ID="10.1"\n', encoding="utf-8")
            for port in (1024, 2525, 2526, 46500, 65535):
                with self.subTest(port=port):
                    proc = subprocess.run(
                        [sys.executable, str(SCRIPT), "--os-release-file",
                         str(mock_release), "--smtp-port", str(port)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        universal_newlines=True, timeout=8)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertIn(f"SMTP_PORT={port}\n", proc.stdout)
                    self.assertIn("OS_FAMILY=rhel\n", proc.stdout)
                    self.assertIn("CHANGES_APPLIED=no\n", proc.stdout)
                    self.assertIn("MICROSOFT365_DELIVERY_VERIFIED=no\n", proc.stdout)
                    self.assertIn("SMTP_AUTH_TLS_CONFIGURED=not_verified\n",
                                  proc.stdout)
            for port in ("0", "25", "587", "65536", "xyz"):
                with self.subTest(blocked_port=port):
                    proc = subprocess.run(
                        [sys.executable, str(SCRIPT), "--os-release-file",
                         str(mock_release), "--smtp-port", port],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        universal_newlines=True, timeout=8)
                    self.assertNotEqual(proc.returncode, 0)


class PlatformWizardContractTests(unittest.TestCase):
    def test_read_only_probe_embedded_in_single_exe(self):
        proj = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text()
        embed = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text()
        wizard = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text()
        self.assertIn("linux/platform-compat.py", proj)
        self.assertIn("BuildPlatformCompatBundle(int smtpPort)", embed)
        self.assertIn("python3 \\", embed)
        self.assertIn("InspectPlatformAsync", wizard)
        self.assertIn("EmbeddedAssets.BuildPlatformCompatBundle(port)", wizard)
        self.assertIn("SmtpIngressPort.Supported", wizard)
        self.assertNotIn("semanage port -a", wizard)
        self.assertNotIn("ufw allow", wizard)


if __name__ == "__main__":
    unittest.main()
