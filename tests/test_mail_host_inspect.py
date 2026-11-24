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



    def test_route_map_probe_never_returns_credentials_or_lookup_content(self):
        self.assertEqual(module.postfix_role_state(
            "smtp_sasl_auth_enable", "no"), "not_declared")
        self.assertEqual(module.postfix_role_state(
            "smtp_sender_dependent_authentication", "no"), "not_declared")
        self.assertEqual(module.postfix_role_state(
            "smtp_sasl_auth_enable", "yes"), "declared")
        self.assertEqual(module.postfix_role_state(
            "smtp_sasl_auth_enable", "unexpected"), "unverified")
        self.assertEqual(module.postfix_role_state(
            "smtp_sasl_password_maps", "hash:/etc/postfix/private/auth"),
            "declared")
        self.assertEqual(module.postfix_role_state(
            "transport_maps", "hash:/etc/postfix/transport"),
            "declared")
        self.assertEqual(module.postfix_role_state(
            "transport_maps", None), "unverified")

    def test_postfix_effective_role_probe_is_read_only_and_presence_only(self):
        responses = {
            ("hostname", "-f"): "mail.example.org",
            ("hostname", "-s"): "mail",
            ("hostname", "-d"): "example.org",
            ("systemctl", "is-active", "postfix.service"): "active",
            ("systemctl", "is-active", "postfix@-.service"): "inactive",
            ("systemctl", "is-active", "exim.service"): "inactive",
            ("systemctl", "is-active", "exim4.service"): "inactive",
            ("systemctl", "is-active", "sendmail.service"): "inactive",
            ("postconf", "-M"): "smtp inet n - n - - smtpd",
            ("postconf", "-h", "mydestination"): "$myhostname, localhost.$mydomain",
            ("postconf", "-h", "smtp_sasl_password_maps"): "hash:/PRIVATE/PASSWORDS",
            ("postconf", "-h", "sender_dependent_default_transport_maps"):
                "hash:/PRIVATE/ROUTING",
            ("postconf", "-h", "smtp_sasl_auth_enable"): "no",
            ("postconf", "-h", "smtp_sender_dependent_authentication"): "yes",
            ("postconf", "-h", "smtp_tls_policy_maps"): "",
        }
        calls = []
        def fake(argv):
            calls.append(tuple(argv))
            return responses.get(tuple(argv))
        result = module.inspect(fake)
        self.assertEqual(result["MAIL_HOST_MTA"], "postfix")
        self.assertEqual(result["MAIL_HOST_SMTP_CONFIG_PORTS"], "25")
        self.assertEqual(result["MAIL_HOST_POSTFIX_ROLE_SMTP_SASL_PASSWORD_MAPS"],
                         "declared")
        self.assertEqual(result["MAIL_HOST_POSTFIX_ROLE_SENDER_DEPENDENT_DEFAULT_TRANSPORT_MAPS"],
                         "declared")
        self.assertEqual(result["MAIL_HOST_POSTFIX_ROLE_SMTP_SASL_AUTH_ENABLE"],
                         "not_declared")
        self.assertEqual(result["MAIL_HOST_POSTFIX_ROLE_SMTP_SENDER_DEPENDENT_AUTHENTICATION"],
                         "declared")
        self.assertEqual(result["MAIL_HOST_POSTFIX_ROLE_SMTP_TLS_POLICY_MAPS"],
                         "not_declared")
        self.assertNotIn("/PRIVATE/", repr(result))
        self.assertTrue(all(call[0] in ("hostname", "systemctl", "postconf")
                            for call in calls))
        self.assertTrue(all(call[:2] in (
            ("postconf", "-h"), ("postconf", "-M"))
            for call in calls if call[0] == "postconf"))

    def test_map_inventory_does_not_probe_remote_dynamic_or_password_map(self):
        observed = []
        def metadata(path, suffix):
            observed.append((path, suffix))
            return True
        for value in ("ldap:/etc/postfix/secret", "proxy:hash:/etc/postfix/map",
                      "hash:/etc/postfix/../outside", "hash:/var/lib/map",
                      "hash:$config_directory/map", "hash:/etc/postfix/a, mysql:/etc/postfix/b",
                      "inline:{hidden=value}", " ".join(["hash:/etc/postfix/a"] * 9)):
            self.assertEqual(module.postfix_map_inventory(value, metadata),
                             "complex_or_remote")
        self.assertEqual(observed, [])
        self.assertEqual(module.postfix_map_inventory(None, metadata), "unverified")
        self.assertEqual(module.postfix_map_inventory("", metadata), "empty")
        self.assertEqual(module.postfix_map_inventory("hash:/etc/postfix/r", metadata),
                         "local_indexed_root_metadata")
        self.assertEqual(observed, [("/etc/postfix/r", ".db")])
        self.assertEqual(module.postfix_map_inventory("pcre:/etc/postfix/r", metadata),
                         "local_text_root_metadata")
        self.assertEqual(module.postfix_map_inventory(
            "hash:/etc/postfix/r, pcre:/etc/postfix/t", metadata),
            "local_mixed_root_metadata")
        self.assertEqual(module.postfix_map_inventory("hash:/etc/postfix/r",
                         lambda *_: False), "local_metadata_unverified")
        self.assertNotIn("smtp_sasl_password_maps", module.POSTFIX_MAP_INVENTORY_KEYS)

    def test_map_metadata_refuses_symlink_writable_hardlink_and_missing_db(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            folder = root / "etc" / "postfix"
            folder.mkdir(parents=True)
            source = folder / "route"
            source.write_text("NEVER READ THIS\n")
            database = folder / "route.db"
            database.write_bytes(b"not a real map: only stat is under test")
            check = lambda: module.root_owned_map_metadata(
                "/etc/postfix/route", ".db", root, os.getuid())
            self.assertTrue(check())
            database.unlink()
            self.assertFalse(check())
            database.symlink_to(source)
            self.assertFalse(check())
            database.unlink()
            os.link(source, database)
            self.assertFalse(check())
            database.unlink()
            database.write_bytes(b"db")
            source.chmod(0o666)
            self.assertFalse(check())
            source.chmod(0o600)
            folder.chmod(0o777)
            self.assertFalse(check())
            folder.chmod(0o755)
            self.assertTrue(check())
            actual = folder.with_name("postfix-real")
            folder.rename(actual)
            folder.symlink_to(actual, target_is_directory=True)
            self.assertFalse(check())

    def test_metadata_report_is_presence_only_no_map_content(self):
        responses = {
            ("hostname", "-f"): "mail.example.org",
            ("hostname", "-s"): "mail",
            ("hostname", "-d"): "example.org",
            ("systemctl", "is-active", "postfix.service"): "active",
            ("systemctl", "is-active", "postfix@-.service"): "inactive",
            ("systemctl", "is-active", "exim.service"): "inactive",
            ("systemctl", "is-active", "exim4.service"): "inactive",
            ("systemctl", "is-active", "sendmail.service"): "inactive",
            ("postconf", "-h", "transport_maps"): "ldap:/PRIVATE/SECRET",
            ("postconf", "-h", "sender_dependent_relayhost_maps"): "",
            ("postconf", "-h", "smtp_sasl_password_maps"): "hash:/PRIVATE/PASS",
        }
        report = module.inspect(lambda argv: responses.get(tuple(argv)))
        self.assertEqual(report["MAIL_HOST_POSTFIX_MAP_META_TRANSPORT_MAPS"],
                         "complex_or_remote")
        self.assertEqual(report["MAIL_HOST_POSTFIX_MAP_META_SENDER_DEPENDENT_RELAYHOST_MAPS"],
                         "empty")
        self.assertNotIn("MAIL_HOST_POSTFIX_MAP_META_SMTP_SASL_PASSWORD_MAPS", report)
        self.assertNotIn("/PRIVATE/", repr(report))


if __name__ == "__main__":
    unittest.main()
