"""Contracts for safe, RHEL 8-10 SELinux SMTP port-label preparation."""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "manage-rhel-selinux-port.py"
spec = importlib.util.spec_from_file_location("lmr365_selinux_port", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class RhelPortManagerTests(unittest.TestCase):
    def test_rhel_families_and_centos_stream(self):
        for distro in ("rhel", "ol", "rocky", "almalinux"):
            for ver in ("8.9", "9.6", "10.1"):
                self.assertTrue(mod.os_supported('ID={}\nVERSION_ID="{}"\n'.format(distro, ver)))
        self.assertTrue(mod.os_supported('ID=centos\nVERSION_ID=9\nNAME="CentOS Stream"\n'))
        self.assertFalse(mod.os_supported('ID=centos\nVERSION_ID=8\nNAME="CentOS Linux"\n'))
        self.assertFalse(mod.os_supported('ID=ubuntu\nVERSION_ID=24.04\n'))
        self.assertFalse(mod.os_supported('ID="$(setenforce 0)"\nVERSION_ID=9\n'))

    def test_conflicting_and_unmapped_custom_port(self):
        raw = "smtp_port_t tcp 25, 465, 587, 2525-2528\nhttp_port_t tcp 80, 443, 8080\n"
        self.assertEqual(mod.port_type(2526, raw), "smtp_port_t")
        self.assertEqual(mod.port_type(8080, raw), "other_type")
        self.assertEqual(mod.port_type(46500, raw), "unmapped")

    def test_must_not_change_system_for_unknown_or_conflicting_type(self):
        with patch.object(mod, "environment", return_value="enforcing"), \
             patch.object(mod, "inspect", return_value=("other_type", "raw", "custom")):
            with self.assertRaisesRegex(mod.Refused, "port_owned"):
                mod.preflight(SimpleNamespace(smtp_port=46500))
        with patch.object(mod, "environment", return_value="enforcing"), \
             patch.object(mod, "inspect", return_value=("other_type", "raw", "custom")):
            with self.assertRaisesRegex(mod.Refused, "port_not_unmapped"):
                mod.apply(SimpleNamespace(smtp_port=46500, expect_policy_sha256="x"*64))

    def test_reviewed_sha_and_typed_confirmation_are_required(self):
        for action in ("--apply", "--restore"):
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), action, "--smtp-port", "46500"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("typed_confirmation_and_reviewed_sha_required", proc.stdout)

    def test_python3_parser_and_no_unsafe_behaviors(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("RHEL_PORT_MANAGER_PARSER=ready", proc.stdout)
        src = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("ADD_REVIEWED_RHEL_SMTP_PORT", src)
        self.assertIn("REMOVE_MANAGED_RHEL_SMTP_PORT", src)
        self.assertIn("port_is_busy(args.smtp_port)", src)
        self.assertIn("sha != data[\"after\"]", src)
        for item in ("setenforce", "audit2allow -M", "firewall-cmd --add", "ufw allow"):
            self.assertNotIn(item, src if item != "setenforce" else src.split('"""\n')[1])


if __name__ == "__main__":
    unittest.main()
