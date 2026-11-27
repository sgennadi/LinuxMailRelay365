import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dryrun", ROOT / "linux/review-smtp-acme-dry-run.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class ReviewedDryRunTests(unittest.TestCase):
    CONFIG = "[renewalparams]\nauthenticator=dns-cloudflare\nserver=" + M.PRODUCTION + "\ndns_cloudflare_credentials=/private/credentials\n"

    def test_known_dns_provider(self):
        self.assertEqual(M.parse_config(self.CONFIG)[2], "dns-cloudflare")

    def test_refuse_hooks_unknown_options_duplicate_and_other_ca(self):
        for config in (self.CONFIG + "deploy_hook=unsafe\n",
                       self.CONFIG + "authenticator=dns-google\n",
                       self.CONFIG + "installer=nginx\n",
                       self.CONFIG + "unknown_option=yes\n",
                       self.CONFIG.replace(M.PRODUCTION, "https://other.example.org/acme"),
                       self.CONFIG.replace("dns-cloudflare", "manual")):
            with self.assertRaises(ValueError):
                M.parse_config(config)

    def test_duplicate_profile_fields(self):
        with self.assertRaises(ValueError):
            M.no_duplicates([("domain", "a"), ("domain", "b")])

    def test_changed_plan_never_executes(self):
        with patch.object(M.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                M.execute("b" * 64, lambda: ({"plan_sha256": "a" * 64}, [], {}))
            run.assert_not_called()

    def test_test_result_and_timeout(self):
        args = ["/usr/bin/certbot", "renew", "--dry-run", "--server", M.STAGING]
        prepare = lambda: ({"plan_sha256": "a" * 64, "activation_requested": False}, args, {})
        for code, status in ((0, "dry_run_passed"), (1, "dry_run_failed")):
            with patch.object(M.subprocess, "run", return_value=subprocess.CompletedProcess(args, code)) as run:
                result = M.execute("a" * 64, prepare)
                self.assertEqual(result["status"], status)
                self.assertFalse(result["activation_requested"])
                self.assertEqual(run.call_args.args[0], args)
        with patch.object(M.subprocess, "run", side_effect=subprocess.TimeoutExpired(args, 600)):
            self.assertEqual(M.execute("a" * 64, prepare)["status"], "outcome_unverified")

    def test_gui_uses_only_reviewed_dry_run(self):
        source = ROOT / "src/LinuxMailRelay365"
        assets = (source / "EmbeddedAssets.cs").read_text()
        main = (source / "MainForm.DeliveryMiniWizard.cs").read_text()
        dialog = (source / "SmtpRenewalInventoryDialog.cs").read_text()
        project = (source / "LinuxMailRelay365.csproj").read_text()
        self.assertIn("review-smtp-acme-dry-run.py", project)
        self.assertIn("BuildSmtpAcmeDryRun", assets)
        self.assertIn("BuildSmtpAcmeDryRun", main)
        self.assertIn("dns_challenge_writes_possible", dialog)
        self.assertIn("plan_sha256", dialog)
        self.assertIn("activation_requested", dialog)
