"""Read-only first-install preview tests: all host evidence mocked."""
import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "linux"))
spec = importlib.util.spec_from_file_location(
    "broker_install_preview", str(ROOT / "linux/inspect-primary-tpm-broker-install.py"))
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class InstallPreviewTests(unittest.TestCase):
    def baseline(self):
        result = dict.fromkeys(B.POSTFIX_KEYS, "")
        result.update({
            "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead",
            "MainPID": "0", "PrivateDevices": "yes", "DevicePolicy": "closed"
        })
        return result

    def test_refuses_live_or_weakened_postfix(self):
        baseline = self.baseline()
        B.require_postfix_baseline(baseline)
        for key, value in (("ActiveState", "active"), ("MainPID", "5"),
                           ("PrivateDevices", "no"), ("DevicePolicy", "auto"),
                           ("DeviceAllow", "/dev/tpmrm0 rw"), ("BindPaths", "/dev"),
                           ("RootDirectory", "/other"), ("TemporaryFileSystem", "/tmp")):
            with self.assertRaises(B.Refused):
                B.require_postfix_baseline(dict(baseline, **{key: value}))

    def test_policy_inventory_refuses_existing_module_at_any_priority(self):
        self.assertEqual(B.policy_inventory("100 base pp\n200 other cil\n"),
                         [("100", "base", "pp"), ("200", "other", "cil")])
        for raw in ("", "100 lmr365_tpm_signer pp\n", "400 lmr365_tpm_signer cil\n",
                    "oops base pp\n", "100 base pp\n100 base pp\n"):
            with self.assertRaises(B.Refused):
                B.policy_inventory(raw)

    def test_no_install_on_existing_path_even_dangling_symlink(self):
        with patch.object(B.os.path, "lexists", return_value=True), \
             patch.object(B, "command") as run:
            with self.assertRaisesRegex(B.Refused, "^broker_existing_destination$"):
                B.absent_install()
            run.assert_not_called()

    def test_plan_is_readonly_and_requires_two_matching_observations(self):
        snapshot = Mock()
        snapshot.approval_digest.return_value = "a" * 64
        snapshot.matches.return_value = True
        with patch.object(B, "platform", return_value="boot"), \
             patch.object(B, "source_hashes", return_value={"artifact": "b" * 64}), \
             patch.object(B, "dependencies", return_value="OpenSSL 3"), \
             patch.object(B, "absent_install", return_value=[("100", "base", "pp")]), \
             patch.object(B, "mail_account", return_value=[20, 30]), \
             patch.object(B.identity, "read_primary_snapshot", return_value=snapshot), \
             patch.object(B, "device_evidence", return_value={"device": "253:0"}) as dev, \
             patch.object(B, "postfix_evidence", return_value=self.baseline()), \
             patch.object(B, "command") as run:
            self.assertRegex(B.prepare(), r"^[a-f0-9]{64}$")
            self.assertEqual(dev.call_count, 2)
            run.assert_not_called()
            dev.side_effect = [{"device": "253:0"}, {"device": "253:1"}]
            with self.assertRaisesRegex(B.Refused, "^broker_preview_baseline_changed$"):
                B.prepare()

    def test_parser_refuses_apply_and_reports_no_changes(self):
        with patch.object(B, "prepare") as prepare:
            with self.assertRaises(SystemExit):
                B.main(["--apply"])
            prepare.assert_not_called()
        with patch.object(B, "prepare", return_value="a" * 64), patch("builtins.print") as out:
            self.assertEqual(B.main(["--preview"]), 0)
            messages = [call[0][0] for call in out.call_args_list]
            self.assertIn("PRIMARY_TPM_BROKER_APPLY_SUPPORTED=no", messages)
            self.assertIn("PRIMARY_TPM_BROKER_EXCLUSIVE_TPM_REVIEW=required", messages)
            self.assertIn("CHANGES_APPLIED=no", messages)

    def test_udev_candidate_only_one_device_and_no_trigger(self):
        rule = (ROOT / "linux/udev" / B.RULE).read_text(encoding="ascii")
        lines = [line for line in rule.splitlines() if line and not line.startswith("#")]
        self.assertEqual(lines, [
            'SUBSYSTEM=="tpmrm", KERNEL=="tpmrm0", OWNER:="root", '
            'GROUP:="lmr365-tpm-signer", MODE:="0660", TAG+="systemd"'])
        self.assertNotIn("RUN", rule)


if __name__ == "__main__":
    unittest.main()
