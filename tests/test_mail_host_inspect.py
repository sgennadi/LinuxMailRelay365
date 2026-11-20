"""Linux mail-host discovery regression: systemd inactive is not an error."""
import importlib.util
import pathlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "linux" / "inspect-mail-host.py"
spec = importlib.util.spec_from_file_location("inspect_mail_host", str(SOURCE))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MailHostInspectorTests(unittest.TestCase):
    def test_systemctl_inactive_nonzero_exit_is_valid_status(self):
        def process(argv, **kwargs):
            return SimpleNamespace(returncode=3, stdout="inactive\n", stderr="")
        with patch.object(module.shutil, "which", return_value="/usr/bin/systemctl"), \
             patch.object(module.subprocess, "run", side_effect=process):
            self.assertEqual(module.call(["systemctl", "is-active", "exim.service"]), "inactive")
            self.assertFalse(module.service_state("exim.service"))
            self.assertIsNone(module.call(["postconf", "-h", "myhostname"]))

    def test_missing_unit_status_and_failed_service(self):
        def process(argv, **kwargs):
            return SimpleNamespace(returncode=4, stdout="unknown\n", stderr="")
        with patch.object(module.shutil, "which", return_value="/usr/bin/systemctl"), \
             patch.object(module.subprocess, "run", side_effect=process):
            self.assertFalse(module.service_state("sendmail.service"))
        self.assertIsNone(module.service_state("postfix.service",
                                            lambda _: "failed"))

    def test_multiple_active_mta_is_not_automatically_selected(self):
        def fake(argv):
            name = argv[-1]
            return "active" if name in ("postfix.service", "exim.service") else "inactive"
        self.assertEqual(module.mta_status(fake), ("unknown", "manual_review"))

    def test_exim_literal_port_and_interface_audit(self):
        self.assertEqual(module.exim_ports("exim",
            lambda _: "daemon_smtp_ports = smtp : submission : 2525"), "25,587,2525")
        self.assertEqual(module.exim_ports("exim",
            lambda _: "daemon_smtp_ports = " + chr(36) + "{ports}"), "dynamic_or_unverified")
        self.assertEqual(module.exim_ports("exim",
            lambda _: "daemon_smtp_ports = 0"), "dynamic_or_unverified")
        self.assertEqual(module.exim_ports("exim", lambda _: None), "unverified")
        self.assertEqual(module.exim_bind_policy("127.0.0.1 ::1"), "loopback_declared")
        self.assertEqual(module.exim_bind_policy("0.0.0.0"), "non_loopback_declared_requires_review")
        self.assertEqual(module.exim_bind_policy(chr(36) + "{interface}"), "dynamic_or_unverified")

    def test_compiled_sendmail_host_flags_are_codes_only(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "sendmail.cf"
            path.write_text(
                "O DaemonPortOptions=Port=smtp,Addr=127.0.0.1,Name=MTA\n"
                "O DaemonPortOptions=Port=submission,Addr=::1,Name=MSA\n"
                "DS[hidden-relay.example.org]\n"
                "DMexample.org\n", encoding="utf-8")
            self.assertEqual(module.sendmail_cf_summary(path),
                             ("loopback_declared", "declared", "declared"))
            path.write_text(
                "O DaemonPortOptions=Port=smtp,Name=MTA\n"
                "#DSignored\nDS\nDM\n", encoding="utf-8")
            self.assertEqual(module.sendmail_cf_summary(path),
                             ("non_loopback_or_default_requires_review", "not_declared", "not_declared"))
            path.write_text("DSrelay\nDSdifferent\n", encoding="utf-8")
            self.assertEqual(module.sendmail_cf_summary(path),
                             ("unverified", "unverified", "unverified"))
            link = pathlib.Path(temp) / "link.cf"
            link.symlink_to(path)
            self.assertEqual(module.sendmail_cf_summary(link),
                             ("unverified", "unverified", "unverified"))

    def test_exim_debian_hint_is_not_an_effective_route_proof(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "update-exim4.conf.conf"
            path.write_text("dc_eximconfig_configtype='smarthost'\n"
                            "dc_smarthost='hidden.example.org::587'\n", encoding="utf-8")
            self.assertEqual(module.exim_debian_router_hint(path),
                             "template_declares_smarthost_requires_router_review")
            path.write_text("dc_eximconfig_configtype='internet'\n", encoding="utf-8")
            self.assertEqual(module.exim_debian_router_hint(path),
                             "template_only_no_verified_router")


if __name__ == "__main__":
    unittest.main()
