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

    def test_postfix_master_cf_configured_ports_are_distinct_from_outbound_unix(self):
        raw = ("smtp inet n - n - - smtpd\n"
               "smtp unix - - n - - smtp\n"
               "submission/inet=submission inet n - n - - smtpd\n"
               "postlog unix-dgram n - n - 1 postlogd\n"
               "127.0.0.1:2526 inet n - n - - smtpd\n")
        self.assertEqual(module.postfix_ports(lambda _: raw), "25,587,2526")
        self.assertEqual(module.postfix_ports(lambda _: "smtp unix - - n - - smtp\n"),
                         "none_configured")
        self.assertEqual(module.postfix_ports(lambda _: None), "unverified")
        self.assertEqual(module.postfix_ports(lambda _: "custom inet n - n - - smtpd\n"),
                         "dynamic_or_unverified")

    def test_sendmail_compiled_daemon_options_custom_ports(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "sendmail.cf"
            path.write_text("O DaemonPortOptions=Name=MTA, Port=smtp, Addr=0.0.0.0\n"
                            "O DaemonPortOptions=Port=2526, Name=SECONDARY\n"
                            "O DaemonPortOptions=Name=MSA, Port=submission\n",
                            encoding="utf-8")
            self.assertEqual(module.sendmail_cf_ports(path), "25,587,2526")
            path.write_text("O DaemonPortOptions=Name=MTA\n", encoding="utf-8")
            self.assertEqual(module.sendmail_cf_ports(path), "25")
            path.write_text("O DaemonPortOptions=Port=$macro\n", encoding="utf-8")
            self.assertEqual(module.sendmail_cf_ports(path), "dynamic_or_unverified")
            path.write_text("DSrelay\n", encoding="utf-8")
            self.assertEqual(module.sendmail_cf_ports(path), "unverified")
            link = pathlib.Path(temp) / "alias.cf"
            link.symlink_to(path)
            self.assertEqual(module.sendmail_cf_ports(link), "unverified")

    def test_gui_inspection_consumes_configured_ports_without_mutation(self):
        assets = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text(encoding="utf-8")
        gui = (ROOT / "src/LinuxMailRelay365/MailHostInspection.cs").read_text(encoding="utf-8")
        main = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        for key in ("MAIL_HOST_SMTP_CONFIG_PORTS", "MAIL_HOST_SMTP_CONFIG_SOURCE"):
            self.assertIn(key, gui)
            self.assertIn(key, (ROOT / "linux/inspect-mail-host.py").read_text(encoding="utf-8"))
        self.assertIn("--configured-ports", assets)
        self.assertIn("ConfiguredSmtpPorts()", gui)
        self.assertIn("alreadyConfigured.Contains(selected)", main)
        self.assertIn("inspectedHost.ConfiguredSmtpPortSource", main)

    def test_exim_tls_auth_statuses_are_not_live_verification(self):
        options = {"tls_advertise_hosts": "*",
                   "tls_certificate": "/etc/exim4/mail.pem",
                   "tls_privatekey": "/etc/exim4/mail.key",
                   "auth_advertise_hosts": "*"}
        def runner(argv):
            return argv[-1] + " = " + options[argv[-1]]
        self.assertEqual(module.exim_security_declarations("exim", runner),
                         ("starttls_cert_key_declared_unverified",
                          "auth_hosts_declared_backend_unverified"))
        options["tls_privatekey"] = ""
        options["auth_advertise_hosts"] = ""
        self.assertEqual(module.exim_security_declarations("exim", runner),
                         ("partial_tls_declaration", "auth_not_advertised"))
        options["tls_certificate"] = chr(36) + "{lookup{anything}}"
        self.assertEqual(module.exim_security_declarations("exim", runner)[0],
                         "dynamic_or_unverified")
        self.assertEqual(module.exim_security_declarations("exim", lambda _: None),
                         ("unverified", "unverified"))

    def test_bounded_nofollow_reader_detects_file_change(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            config = pathlib.Path(folder) / "sendmail.cf"
            config.write_text("O AuthMechanisms=LOGIN\n", encoding="utf-8")
            self.assertEqual(module.limited_config_text(config),
                             "O AuthMechanisms=LOGIN\n")
            self.assertIsNone(module.limited_config_text(config, limit=5))
            config.write_text("", encoding="utf-8")
            self.assertIsNone(module.limited_config_text(config))
            config.write_text("O AuthMechanisms=LOGIN\n", encoding="utf-8")
            link = pathlib.Path(folder) / "linked"
            link.symlink_to(config)
            self.assertIsNone(module.limited_config_text(link))

    def test_sendmail_tls_auth_cf_are_declarations_only(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "sendmail.cf"
            path.write_text("O ServerCertFile=/etc/mail.crt\n"
                            "O ServerKeyFile=/etc/mail.key\n"
                            "O AuthMechanisms=PLAIN LOGIN\n", encoding="utf-8")
            self.assertEqual(module.sendmail_cf_security(path),
                             ("server_cert_key_declared_unverified",
                              "mechanisms_declared_backend_unverified"))
            path.write_text("O ServerCertFile=/etc/mail.crt\n", encoding="utf-8")
            self.assertEqual(module.sendmail_cf_security(path),
                             ("partial_tls_declaration", "mechanisms_not_observed"))
            path.write_text("O AuthMechanisms=PLAIN\n"
                            "O AuthMechanisms=LOGIN\n", encoding="utf-8")
            self.assertEqual(module.sendmail_cf_security(path),
                             ("unverified", "unverified"))
            link = pathlib.Path(folder) / "linked.cf"
            link.symlink_to(path)
            self.assertEqual(module.sendmail_cf_security(link),
                             ("unverified", "unverified"))
            self.assertIsNone(module.limited_config_text(link))

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
