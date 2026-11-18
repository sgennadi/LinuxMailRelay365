"""Foreign primary Exim/Sendmail preservation acceptance contracts (Python 3.6+)."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "linux" / "guard-foreign-mta.py"
spec = importlib.util.spec_from_file_location("lmr_foreign_mta", str(GUARD))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ForeignMtaPreservationTests(unittest.TestCase):
    def cli(self, path, *args):
        return subprocess.run(["bash", str(path)] + list(args),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=8)

    def opts(self, direct):
        args = ["--check-only", "--smtp-port", "46252",
                "--mx-host", "mytenant.mail.protection.outlook.com",
                "--accepted-domain", "example.org", "--fixed-sender", "alerts@example.org",
                "--preserve-primary-mta", "exim", "--sidecar-hostname", "relay.example.org"]
        if not direct:
            args.extend(["--public-ip", "8.8.8.8"])
        return args

    def test_guard_parses_python_36_and_is_read_only(self):
        result = subprocess.run([sys.executable, str(GUARD), "--self-test"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CHANGES_APPLIED=no", result.stdout)
        source = GUARD.read_text(encoding="utf-8")
        for prohibited in ("setenforce 0", "systemctl stop ", "systemctl restart ",
                           "dnf install", "apt-get install", "rm -rf", "postconf -e",
                           "shutil.rmtree("):
            self.assertNotIn(prohibited, source)

    def test_unit_absence_only_accepted_after_not_found_check(self):
        class R:
            def __init__(self, code, stdout):
                self.returncode = code
                self.stdout = stdout
        with mock.patch.object(mod, "command", side_effect=[
                R(3, "unknown\n"), R(0, "not-found\n")]) as run:
            self.assertEqual(mod.unit_status("exim4.service"), "inactive")
            self.assertEqual(run.call_count, 2)
        with mock.patch.object(mod, "command", side_effect=[
                R(3, "unknown\n"), R(0, "loaded\n")]):
            with self.assertRaises(mod.Refused):
                mod.unit_status("exim4.service")

    def test_service_rejects_multiple_active_mtas(self):
        service_states = {
            "postfix.service": "active", "exim4.service": "active",
            "exim.service": "inactive", "sendmail.service": "inactive",
        }
        with mock.patch.object(mod, "unit_status", side_effect=lambda k: service_states[k]):
            with self.assertRaises(mod.Refused):
                mod.service_snapshot("exim")

    def test_pre_and_post_mta_fingerprint_detects_changes(self):
        good = "a" * 64
        with mock.patch.object(mod.os, "geteuid", return_value=0), \
             mock.patch.object(mod.shutil, "which", return_value="/usr/sbin/postfix"), \
             mock.patch.object(mod, "service_snapshot", return_value=("exim4.service", "1234")), \
             mock.patch.object(mod, "bounded_config_digest", return_value=good), \
             mock.patch.object(mod, "listen_port25_snapshot", return_value=good):
            baseline = mod.guard("exim", "relay.example.org")
            self.assertEqual(len(baseline), 64)
            self.assertEqual(mod.guard("exim", "relay.example.org", baseline), baseline)
            with self.assertRaises(mod.Refused):
                mod.guard("exim", "different.example.org", baseline)
            with mock.patch.object(mod, "service_snapshot", return_value=("exim4.service", "5678")):
                with self.assertRaises(mod.Refused):
                    mod.guard("exim", "relay.example.org", baseline)
        with self.assertRaises(mod.Refused):
            mod.guard("postfix", "relay.example.org")

    def test_installers_opt_in_and_check_only(self):
        for direct, name in (
            (True, "install-direct-send-sidecar.sh"),
            (False, "install-connector-sidecar.sh"),
        ):
            path = ROOT / "linux" / name
            with self.subTest(name=name):
                syntax = subprocess.run(["bash", "-n", str(path)], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, universal_newlines=True)
                self.assertEqual(syntax.returncode, 0, syntax.stderr)
                args = self.opts(direct)
                check = self.cli(path, *args)
                self.assertEqual(check.returncode, 0, check.stderr)
                self.assertIn("FOREIGN_PRIMARY_MTA_PRESERVATION=requires_live_root_guard", check.stdout)
                self.assertIn("CHANGES_APPLIED=no", check.stdout)
                source = path.read_text(encoding="utf-8")
                self.assertIn("guard-foreign-mta.py", source)
                self.assertIn("--expect-sha256", source)
                self.assertIn("foreign_primary_mta_changed_or_unverified", source)
                self.assertIn("PRESERVE_EXISTING_", source)
                self.assertIn("active_foreign_mta_requires_preservation_mode", source)
                self.assertIn("PRIMARY_MTA_STOP_OR_RESTART=no", source)
                self.assertIn("PRIMARY_MTA_QUEUE_MODIFIED=no", source)

    def test_invalid_foreign_mode_and_explicit_hostname_rejected(self):
        for direct, name in (
            (True, "install-direct-send-sidecar.sh"),
            (False, "install-connector-sidecar.sh"),
        ):
            path = ROOT / "linux" / name
            for k, v in (("--preserve-primary-mta", "postfix"),
                         ("--sidecar-hostname", "localhost"),
                         ("--sidecar-hostname", "bad..name")):
                args = self.opts(direct)
                args[args.index(k) + 1] = v
                with self.subTest(name=name, option=k, value=v):
                    result = self.cli(path, *args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("invalid_foreign_mta_or_explicit_sidecar_hostname",
                                  result.stderr)

    def test_apply_refuses_without_separate_foreign_confirmation(self):
        for direct, name in (
            (True, "install-direct-send-sidecar.sh"),
            (False, "install-connector-sidecar.sh"),
        ):
            path = ROOT / "linux" / name
            args = self.opts(direct)
            args[0] = "--apply"
            args.extend(["--confirm-accepted-domain", "TENANT_DOMAIN_CHECKED"])
            if not direct:
                args.extend(["--confirm-connector", "TENANT_CONNECTOR_CHECKED"])
            result = self.cli(path, *args)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("foreign_mta_explicit_preservation_confirmation_required",
                          result.stderr)
            self.assertNotIn("INSTALLED=yes", result.stdout)

    def test_gui_embeds_guard_and_requires_fqdn(self):
        assets = (ROOT / "src" / "LinuxMailRelay365" / "EmbeddedAssets.cs").read_text()
        form = (ROOT / "src" / "LinuxMailRelay365" / "MainForm.cs").read_text()
        project = (ROOT / "src" / "LinuxMailRelay365" /
                   "LinuxMailRelay365.csproj").read_text()
        self.assertIn("ForeignMtaGuard", assets)
        self.assertIn("Encode(ForeignMtaGuard)", assets)
        self.assertIn("PRESERVE_EXISTING_", assets)
        self.assertIn("sidecarHostname", assets)
        self.assertIn("foreignSidecarHostname", form)
        self.assertIn("var foreign = ForeignMtaOptions();", form)
        self.assertIn("linux/guard-foreign-mta.py", project)


if __name__ == "__main__":
    unittest.main()
