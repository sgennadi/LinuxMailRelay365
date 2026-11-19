"""Read-only and approved clean host Postfix package bootstrap contracts."""
import importlib.util
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "linux" / "prepare-clean-postfix.py"
spec = importlib.util.spec_from_file_location("lmr365_clean_postfix", str(SCRIPT))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CleanPostfixTests(unittest.TestCase):
    def test_no_apply_without_exact_approval(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--apply",
            "--smtp-port", "2525"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicit_package_approval_required", result.stderr)

    def test_read_only_validation(self):
        with patch.object(module, "platform", return_value=("ubuntu", "24", "apt-get")), \
             patch.object(module.shutil, "which", return_value=None):
            state = module.inspect(2525)
            self.assertFalse(state["ready"])
            self.assertEqual(state["sha"], "")

    def test_no_foreign_mta_or_default_port_mutations(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for expected in ("INSTALL_CLEAN_POSTFIX_PACKAGES",
                         '"mask", "--runtime", unit',
                         '"disable", unit',
                         "postfix@-.service",
                         "--verify-prepared",
                         "postfix_config_hashes",
                         "CLEAN_POSTFIX_PREPARED_VERIFIED=yes",
                         "existing_mta_unit_", "existing_mta_package",
                         "smtp_socket_already_open", "existing_service_start_policy",
                         "ISOLATED_RELAY_INSTALLED=no",
                         "postfix_prepared_for_isolated_relay"):
            self.assertIn(expected, text)
        for prohibited in ("systemctl enable postfix", "systemctl restart postfix",
                           "setenforce 0", "ufw allow", "firewall-cmd --add-port"):
            self.assertNotIn(prohibited, text)

    def test_verify_requires_root_owned_marker_and_exact_port(self):
        with patch.object(module.os, "geteuid", return_value=1000):
            with self.assertRaises(ValueError):
                module.verify_prepared(2525)
        with self.assertRaises(ValueError):
            module.verify_prepared(25)
        with patch.object(module.os, "geteuid", return_value=0), \
             patch.object(module.MARKER, "lstat", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                module.verify_prepared(2525)

    def test_port_bounds(self):
        for bad in (25, 0, 65536):
            with self.assertRaises(ValueError):
                module.inspect(bad)


if __name__ == "__main__":
    unittest.main()
