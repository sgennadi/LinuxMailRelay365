"""Static candidate deployment and isolated launcher tests; no host mutation."""
import configparser
import importlib.util
import pathlib
import re
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
LINUX = ROOT / "linux"
UNIT = LINUX / "systemd/linuxmailrelay365-primary-tpm-broker.service"
TE = LINUX / "selinux/lmr365_tpm_signer.te"
FC = LINUX / "selinux/lmr365_tpm_signer.fc"
spec = importlib.util.spec_from_file_location(
    "broker_bootstrap_candidate", str(LINUX / "m365_tpm_broker_bootstrap.py"))
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class BrokerDeploymentTests(unittest.TestCase):
    def test_unit_exact_sandbox_and_restart_bounds(self):
        unit = configparser.ConfigParser(interpolation=None, strict=True)
        unit.optionxform = str
        unit.read_string(UNIT.read_text(encoding="ascii"))
        self.assertEqual(set(unit.sections()), {"Unit", "Service", "Install"})
        self.assertEqual(dict(unit["Service"]), {
            "Type": "exec", "User": "lmr365-tpm-signer",
            "Group": "lmr365-tpm-signer", "SupplementaryGroups": "m365mailer",
            "ExecStart": str(B.EXECUTABLE) + " -I -B " + str(B.RUNTIME / "bootstrap.py"),
            "SELinuxContext": "system_u:system_r:lmr365_tpm_signer_t:s0",
            "PrivateDevices": "yes", "DevicePolicy": "closed",
            "DeviceAllow": "/dev/tpmrm0 rw",
            "BindPaths": "/dev/tpmrm0:/dev/tpmrm0",
            "NoNewPrivileges": "yes", "ProtectSystem": "strict",
            "ProtectHome": "yes", "PrivateTmp": "yes",
            "RestrictAddressFamilies": "AF_UNIX",
            "CapabilityBoundingSet": "", "AmbientCapabilities": "",
            "UMask": "0077", "Restart": "on-failure", "RestartSec": "5s",
            "TimeoutStartSec": "30s", "TimeoutStopSec": "15s",
            "KillMode": "control-group", "StandardOutput": "journal",
            "StandardError": "journal",
        })
        self.assertEqual(unit["Unit"]["BindsTo"], "dev-tpmrm0.device")
        self.assertEqual(unit["Unit"]["After"], "systemd-udev-trigger.service dev-tpmrm0.device")
        self.assertEqual(unit["Unit"]["ConditionSecurity"], "selinux")
        self.assertEqual(unit["Unit"]["StartLimitIntervalSec"], "60")
        self.assertEqual(unit["Unit"]["StartLimitBurst"], "5")
        self.assertEqual(dict(unit["Install"]), {"WantedBy": "multi-user.target"})

    def test_policy_only_new_explicit_postfix_allow_is_connectto(self):
        te = TE.read_text(encoding="ascii")
        self.assertIn("policy_module(lmr365_tpm_signer, 1.0.0)", te)
        self.assertIn("init_daemon_domain(lmr365_tpm_signer_t, lmr365_tpm_signer_exec_t)", te)
        self.assertIn("dev_rw_tpm(lmr365_tpm_signer_t)", te)
        self.assertEqual(re.findall(r"^allow postfix_\S+.*$", te, re.M),
            ["allow postfix_pipe_t lmr365_tpm_signer_t:unix_stream_socket connectto;"])
        for forbidden in ("permissive ", "unconfined_service_t", "dev_rw_tpm(postfix",
                          "corenet_", "tcp_socket", "udp_socket"):
            self.assertNotIn(forbidden, te)
        self.assertEqual(FC.read_text(encoding="ascii").splitlines(), [
            "/usr/local/libexec/lmr365-tpm-broker/python3 -- gen_context(system_u:object_r:lmr365_tpm_signer_exec_t,s0)"])

    def test_bootstrap_fails_before_import_on_invalid_runtime(self):
        with patch.object(B.sys, "argv", ["bootstrap.py"]), \
             patch.object(B, "verify_runtime", side_effect=B.LaunchError("private detail")), \
             patch.object(B, "verify_device") as device, \
             patch.object(B.sys, "path", []) as imports, \
             patch("builtins.print") as log:
            self.assertEqual(B.main(), 75)
            device.assert_not_called()
            self.assertEqual(imports, [])
            self.assertEqual(log.call_args[0], ("LMR365_TPM_BROKER_BOOTSTRAP_FAILED",))

    def test_bootstrap_refuses_nonisolated_or_root_before_paths(self):
        for isolated, no_bytecode, uid in ((False, True, 42), (True, False, 42), (True, True, 0)):
            with patch.object(B.sys, "flags", Mock(isolated=isolated)), \
                 patch.object(B.sys, "dont_write_bytecode", no_bytecode), \
                 patch.object(B.os, "geteuid", return_value=uid), \
                 patch.object(B.os, "getegid", return_value=42), \
                 patch.object(B.os, "readlink") as readlink:
                with self.assertRaisesRegex(B.LaunchError, "^broker_isolated_nonroot_python_required$"):
                    B.verify_runtime()
                readlink.assert_not_called()

    def test_fixture_policy_is_not_reused_as_production_domain(self):
        self.assertNotIn("lmr365_fixture_signer", TE.read_text(encoding="ascii"))
        self.assertNotIn("lmr365_fixture_signer", UNIT.read_text(encoding="ascii"))
        self.assertNotIn("ExecStartPre=", UNIT.read_text(encoding="ascii"))
        self.assertNotIn("ExecStartPost=", UNIT.read_text(encoding="ascii"))


if __name__ == "__main__":
    unittest.main()
