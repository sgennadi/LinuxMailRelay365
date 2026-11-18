"""No secrets or SMTP messages in optional health webhook events."""
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "linux" / "manage-health-alerts.py"
spec = importlib.util.spec_from_file_location("lmr365_health_webhook", str(SOURCE))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class HealthAlertContracts(unittest.TestCase):
    def test_https_public_fqdn_and_limits_required(self):
        settings = {"url": "https://hooks.example.org/webhook?key=secret",
                    "timeout_seconds": 8, "repeat_hours": 24}
        good = mod.validate_config(settings)
        self.assertEqual(good["timeout"], 8)
        for bad in ("http://hooks.example.org/hook", "https://127.0.0.1/hook",
                    "https://user:pass@hooks.example.org/hook",
                    "https://relay.local/hook", "https://hooks.example.org:8080/hook",
                    "https://hooks.example.org/path#fragment", "https://localhost/hook",
                    "https://hooks.example.org/\nInjected: yes"):
            with self.subTest(bad=bad):
                with self.assertRaises(mod.Refused):
                    mod.validate_config(dict(settings, url=bad))
        for wrong in (0, 18, True):
            with self.assertRaises(mod.Refused):
                mod.validate_config(dict(settings, timeout_seconds=wrong))

    def test_redacted_alert_payload_includes_only_aggregate_metrics(self):
        input_values = {
            "HEALTH_STATUS": "attention",
            "HEALTH_ALERTS": "low_queue_disk_space,smtp_service_inactive",
            "QUEUE_MESSAGES": "42",
            "QUEUE_DEFERRED": "3",
            "MICROSOFT365_DELIVERY_VERIFIED": "no",
            "recipient": "private@tenant.example.org", "token": "do-not-copy",
            "QUEUE_OLDEST_AGE_MIN": "40", "M365_CERT_REMAINING_DAYS": "12",
            "TLS_SERVER_CERT_REMAINING_DAYS": "33", "QUEUE_FREE_MIB": "600",
            "raw_host": "privatehost"
        }
        value = mod.filtered_health(input_values)
        encoded = json.dumps(value)
        self.assertEqual(value["codes"], ["low_queue_disk_space", "smtp_service_inactive"])
        self.assertEqual(value["severity"], "attention")
        for secret in ("private@tenant", "do-not-copy", "privatehost", "token", "recipient"):
            self.assertNotIn(secret, encoded)
        with self.assertRaises(mod.Refused):
            mod.filtered_health(dict(input_values, HEALTH_ALERTS="danger;curl evil"))

    def test_dedupe_same_condition_and_send_on_recovery(self):
        settings = {"repeat": 24}
        unhealthy = {"HEALTH_STATUS": "attention", "HEALTH_ALERTS": "queue_disk_unknown",
                     "CUSTOM_SMTP_PORT": "46500"}
        healthy = {"HEALTH_STATUS": "local_preflight_only", "HEALTH_ALERTS": "none",
                   "CUSTOM_SMTP_PORT": "46500"}
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / "state.json"
            with patch.object(mod, "config", return_value=settings), \
                 patch.object(mod, "STATE", state), \
                 patch.object(mod, "ensure_state_dir"), \
                 patch.object(mod, "health_snapshot", return_value=unhealthy), \
                 patch.object(mod, "webhook_send") as sender:
                mod.dispatch(46500, now=1000)
                mod.dispatch(46500, now=1010)
                self.assertEqual(sender.call_count, 1)
                sender.assert_called_with(settings, mod.filtered_health(unhealthy))
            with patch.object(mod, "config", return_value=settings), \
                 patch.object(mod, "STATE", state), \
                 patch.object(mod, "ensure_state_dir"), \
                 patch.object(mod, "health_snapshot", return_value=healthy), \
                 patch.object(mod, "webhook_send") as sender:
                mod.dispatch(46500, now=1200)
                self.assertEqual(sender.call_count, 1)
                self.assertEqual(sender.call_args[0][1]["severity"], "resolved")

    def test_no_postfix_changes_and_explicit_confirmation(self):
        src = SOURCE.read_text(encoding="utf-8")
        self.assertIn("ENABLE_SMTP_HEALTH_WEBHOOK", src)
        self.assertIn("DISABLE_SMTP_HEALTH_WEBHOOK", src)
        self.assertIn("PinnedHTTPS", src)
        self.assertIn("server_hostname=self.host", src)
        self.assertIn("ExecStartPost=-/usr/bin/python3", src)
        for forbidden in ("postfix reload", "postconf -e", "ufw allow",
                          "systemctl enable --now", "Set-TransportConfig"):
            self.assertNotIn(forbidden, src)
        proc = subprocess.run([sys.executable, str(SOURCE), "--enable",
                               "--smtp-port", "46500"], capture_output=True,
                              text=True, timeout=7)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("reviewed_sha_and_confirmation_required", proc.stdout)
        self.assertEqual(subprocess.run(
            [sys.executable, str(SOURCE), "--self-test"],
            capture_output=True, text=True, timeout=7).returncode, 0)


if __name__ == "__main__":
    unittest.main()
