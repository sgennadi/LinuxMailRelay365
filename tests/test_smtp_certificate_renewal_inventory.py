import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("renewal", ROOT / "linux/inspect-smtp-certificate-renewal.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class RenewalInventoryTests(unittest.TestCase):
    def test_manual_and_hook_detection(self):
        self.assertEqual(M.inspect_config("[renewalparams]\nauthenticator = manual\n"), ("manual", False))
        self.assertEqual(M.inspect_config("pre_hook = secret\n[renewalparams]\nauthenticator=manual\n"), ("manual_hook_unverified", True))
        self.assertEqual(M.inspect_config("[renewalparams]\nauthenticator=dns-azure\ndeploy_hook=secret\n"), ("dns_plugin_configured", True))

    def test_ambiguous_config(self):
        for text in ("[renewalparams]\nauthenticator=manual\nauthenticator=dns-azure",
                     "[renewalparams]\nauthenticator=manual\n[renewalparams]\n"):
            self.assertEqual(M.inspect_config(text), ("ambiguous", None))

    def test_scopes_and_secret_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "relay.conf").write_text("placeholder")
            (root / "invalid name.conf").write_text("placeholder")
            with patch.object(M, "trusted_directory"), patch.object(M, "read_config", return_value="[renewalparams]\nauthenticator=dns-google\ndns_google_credentials=secret-path\n"):
                status, rows = M.inventory_scope(root, "managed")
            self.assertEqual(status, "present")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["scope"], "managed")
            self.assertEqual(rows[0]["renewal_test"], "not_run")
            self.assertNotIn("secret-path", json.dumps(rows))

    def test_refuse_symlink_and_unsafe_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "source").write_text("synthetic")
            (root / "link.conf").symlink_to(root / "source")
            with self.assertRaises(OSError):
                M.read_config(root / "link.conf")
            with patch.object(M, "trusted_directory", side_effect=ValueError):
                self.assertEqual(M.inventory_scope(root, "system"), ("unverified", []))
                self.assertEqual(M.profile_state(root / "profile.json"), "unverified")

    def test_timer_allowlist(self):
        completed = subprocess.CompletedProcess([], 0, b"LoadState=loaded\nActiveState=active\nUnitFileState=enabled\nResult=success\nEnvironment=secret\n", b"")
        with patch.object(M.subprocess, "run", return_value=completed) as run:
            states = M.timer_state()
        self.assertEqual(len(states), 5)
        self.assertEqual(run.call_count, 5)
        self.assertNotIn("secret", json.dumps(states))
        self.assertTrue(all(call.args[0][1] == "show" for call in run.call_args_list))

    def test_timer_timeout_and_read_only_contract(self):
        with patch.object(M.subprocess, "run", side_effect=subprocess.TimeoutExpired("systemctl", 5)):
            self.assertTrue(all(not state for state in M.timer_state().values()))
        with patch.object(M, "inventory_scope", side_effect=[("absent", []), ("present", [{"scope": "managed"}])]), patch.object(M, "profile_state", return_value="protected_file_present_unvalidated"), patch.object(M, "timer_state", return_value={}):
            report = M.inventory()
        self.assertEqual(report["status"], "read_only_inventory")
        self.assertEqual(report["system_config"], "absent")
        self.assertEqual(report["lineages"], [{"scope": "managed"}])
        self.assertFalse(report["automatic_renewal_verified"])
        self.assertFalse(report["activation_supported_by_inspector"])
