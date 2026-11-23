"""Offline regression suite for guarded arbitrary SMTP Postfix relay migration.

All external actions and Postfix configuration writes are mocked. Tests never
touch /etc/postfix, contact an SMTP endpoint or send a message.
"""
import contextlib
import importlib.util
import io
import pathlib
import socket
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "linux" / "manage-custom-relay.py"
SPEC = importlib.util.spec_from_file_location("lmr_custom_postfix_route", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class Result:
    def __init__(self, code=0, output=b""):
        self.returncode = code
        self.stdout = output


class CustomPostfixRouteTests(unittest.TestCase):
    def request(self, **updates):
        request = dict(host="smtp.example.org", port=2525, tls="starttls",
                       auth_mode="none", operation="preview",
                       expected_sha="", expected_resolution_sha="", username="", secret="",
                       plaintext_approval="")
        request.update(updates)
        # Existing synthetic Apply fixtures represent reviewed DNS evidence.
        if (request["operation"] == "apply" and
                request["expected_sha"] == "a"*64 and
                "expected_resolution_sha" not in updates):
            request["expected_resolution_sha"] = "b"*64
        return mod.config(request)

    def test_ports_tls_modes_and_destination_validation(self):
        for port in (25, 465, 587, 2525, 10025, 65535):
            with self.subTest(port=port):
                self.assertEqual(self.request(port=port)["port"], port)
        for bad in ("host;whoami", "bad\nhost", "-evil.example",
                    "broken..name", "[::1]", "999.999.999.999", ""):
            with self.subTest(host=bad), self.assertRaises(ValueError):
                self.request(host=bad)
        for change in (dict(port=0), dict(port=65536), dict(port="25"),
                       dict(tls="tls_off"), dict(auth_mode="xoauth2"),
                       dict(operation="drop"), dict(expected_sha="a"*64),
                       dict(plaintext_approval="I_ACCEPT_UNENCRYPTED_OUTBOUND_SMTP")):
            with self.subTest(changes=change), self.assertRaises(ValueError):
                self.request(**change)

    def test_auth_password_and_plaintext_consent(self):
        for mode in ("starttls", "implicit"):
            self.request(tls=mode, auth_mode="password")
            self.request(tls=mode, auth_mode="password", operation="apply",
                         expected_sha="a"*64, username="admin@example.org",
                         secret="one-use-approved-credential")
        self.request(tls="plain", auth_mode="none", operation="apply",
                     expected_sha="a"*64,
                     plaintext_approval="I_ACCEPT_UNENCRYPTED_OUTBOUND_SMTP")
        for change in (
                dict(tls="plain", auth_mode="password"),
                dict(tls="plain", operation="apply", expected_sha="a"*64),
                dict(operation="apply", expected_sha="a"*64,
                     auth_mode="password", username="user", secret="bad\npassword"),
                dict(auth_mode="none", username="unrequested"),
                dict(auth_mode="none", secret="unrequested"),
                dict(auth_mode="password", username="user", secret="password"),
                dict(operation="apply", expected_sha="bad"),
                dict(operation="apply", expected_sha="a"*64, auth_mode="password",
                     username="admin@example.org", secret="")):
            with self.subTest(changes=change), self.assertRaises(ValueError):
                self.request(**change)

    def test_conflicting_transport_and_foreign_credentials_refused(self):
        values = {"smtp_tls_secure_cert_match": "nexthop, dot-nexthop",
                  "smtp_sender_dependent_authentication": "no",
                  "default_transport": "smtp"}
        def conflict(extra):
            data = dict(values, **extra)
            with mock.patch.object(mod, "postconf",
                                   side_effect=lambda name: data.get(name, "")), \
                 mock.patch.object(mod, "outbound_master_overrides", return_value=False):
                return mod.route_conflicts()
        self.assertFalse(conflict({}))
        self.assertFalse(conflict({"smtp_sasl_password_maps": mod.MANAGED_MAP}))
        for attr in ("transport_maps", "sender_dependent_relayhost_maps",
                     "smtp_tls_policy_maps", "smtp_fallback_relay",
                     "smtp_sasl_password_maps"):
            with self.subTest(attribute=attr):
                self.assertTrue(conflict({attr: "hash:/etc/postfix/custom"}))
        self.assertTrue(conflict({"smtp_sender_dependent_authentication": "yes"}))
        self.assertTrue(conflict({"smtp_tls_secure_cert_match": "hostname"}))

    def test_preview_reports_only_status_and_no_config_mutation(self):
        request = self.request(host="SMTP.example.org", port=465, tls="implicit",
                               auth_mode="password")
        with mock.patch.object(mod, "prerequisites", return_value="a"*64), \
             mock.patch.object(mod, "route_conflicts", return_value=False), \
             mock.patch.object(mod, "queue_state", return_value="empty"), \
             mock.patch.object(mod, "scope_status", return_value="verified"), \
             mock.patch.object(mod, "client_sasl_status", return_value="ready"), \
             mock.patch.object(mod, "outbound_destination_evidence",
                               return_value=("no", "b"*64)), \
                          mock.patch.object(mod, "postconf", side_effect=lambda name: {
                 "smtp_sasl_auth_enable": "yes",
                 "smtp_sasl_password_maps": mod.MANAGED_MAP,
                 "smtp_tls_security_level": "secure"}.get(name, "")), \
             mock.patch.object(mod, "update_postconf") as write, \
             mock.patch.object(mod, "verified_backup") as backup:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                mod.preview(request)
        self.assertIn("CUSTOM_ROUTE_HOST=smtp.example.org", output.getvalue())
        self.assertIn("CUSTOM_ROUTE_PORT=465", output.getvalue())
        self.assertIn("CUSTOM_ROUTE_APPLY_ALLOWED=yes", output.getvalue())
        self.assertIn("CUSTOM_ROUTE_CONFIG_CHANGED=no", output.getvalue())
        self.assertNotIn("username", output.getvalue())
        write.assert_not_called()
        backup.assert_not_called()

    def test_unknown_local_loop_nonempty_queue_or_unverified_sasl_blocked(self):
        for scenario in (
                dict(host="localhost"),
                dict(host="127.0.0.1"),
                 dict(risk="unverified"),
                dict(queue="nonempty"),
                dict(conflict=True),
                dict(scope="unverified"),
                dict(auth_mode="password", sasl="missing")):
            with self.subTest(case=scenario):
                request = self.request(host=scenario.get("host", "relay.example.org"),
                                       auth_mode=scenario.get("auth_mode", "none"))
                with mock.patch.object(mod, "prerequisites", return_value="a"*64), \
                     mock.patch.object(mod, "route_conflicts",
                                       return_value=scenario.get("conflict", False)), \
                     mock.patch.object(mod, "queue_state",
                                       return_value=scenario.get("queue", "empty")), \
                     mock.patch.object(mod, "scope_status",
                                       return_value=scenario.get("scope", "verified")), \
                     mock.patch.object(mod, "client_sasl_status",
                                       return_value=scenario.get("sasl", "ready")), \
                     mock.patch.object(mod, "outbound_destination_evidence",
                                             return_value=(scenario.get("risk",
                                                 "yes" if scenario.get("host") in
                                                 ("localhost", "127.0.0.1") else "no"), "b"*64)), \
                                          mock.patch.object(mod, "postconf", return_value=""):
                    capture = io.StringIO()
                    with contextlib.redirect_stdout(capture):
                        mod.preview(request)
                self.assertIn("CUSTOM_ROUTE_APPLY_ALLOWED=no", capture.getvalue())

    def test_apply_refuses_stale_sha_or_nonempty_queue_without_backup(self):
        req = self.request(operation="apply", expected_sha="a"*64)
        for stale, queue in (("b"*64, "empty"), ("a"*64, "nonempty")):
            with self.subTest(stale=stale, queue=queue), \
                 mock.patch.object(mod, "prerequisites", return_value=stale), \
                 mock.patch.object(mod, "route_conflicts", return_value=False), \
                 mock.patch.object(mod, "queue_state", return_value=queue), \
                 mock.patch.object(mod, "scope_status", return_value="verified"), \
                 mock.patch.object(mod, "outbound_destination_evidence",
                                   return_value=("no", "b"*64)), \
                                  mock.patch.object(mod, "verified_backup") as backup:
                with self.assertRaises(RuntimeError):
                    mod.apply(req)
                backup.assert_not_called()

    def test_auto_rollback_when_credentials_db_mutation_fails(self):
        req = self.request(auth_mode="password", operation="apply",
                           expected_sha="a"*64, username="mail@example.org",
                           secret="ONE-USE-DO-NOT-PRINT")
        backup = "20261123T020101Z-abcdef123456"
        with mock.patch.object(mod, "prerequisites", return_value="a"*64), \
             mock.patch.object(mod, "route_conflicts", return_value=False), \
             mock.patch.object(mod, "queue_state", return_value="empty"), \
             mock.patch.object(mod, "scope_status", return_value="verified"), \
             mock.patch.object(mod, "client_sasl_status", return_value="ready"), \
             mock.patch.object(mod, "outbound_destination_evidence",
                               return_value=("no", "b"*64)), \
                          mock.patch.object(mod, "fingerprint", return_value="a"*64), \
             mock.patch.object(mod, "inbound_snapshot", return_value=(b"x", ())), \
             mock.patch.object(mod.pathlib.Path, "is_file", return_value=True), \
             mock.patch.object(mod, "verified_backup", return_value=backup), \
             mock.patch.object(mod, "prepare_password_map",
                               side_effect=RuntimeError("synthetic failure")) as build, \
             mock.patch.object(mod, "restore_backup", return_value=True) as rollback:
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture):
                with self.assertRaises(RuntimeError):
                    mod.apply(req)
        build.assert_called_once()
        rollback.assert_called_once_with(backup)
        self.assertIn("CUSTOM_ROUTE_ROLLBACK=ok", capture.getvalue())
        self.assertNotIn(req["secret"], capture.getvalue())
        self.assertNotIn(req["username"], capture.getvalue())

    def test_postcheck_must_preserve_inbound_local_mail(self):
        req = self.request(operation="apply", expected_sha="a"*64)
        backup = "20261123T020101Z-abcdef123456"
        calls = []
        def postconf(name):
            return {"relayhost": "[smtp.example.org]:2525",
                    "smtp_sasl_auth_enable": "no",
                    "smtp_tls_wrappermode": "no",
                    "smtp_tls_security_level": "secure"}.get(name, "")
        with mock.patch.object(mod, "prerequisites", return_value="a"*64), \
             mock.patch.object(mod, "route_conflicts", return_value=False), \
             mock.patch.object(mod, "queue_state", return_value="empty"), \
             mock.patch.object(mod, "scope_status", return_value="verified"), \
             mock.patch.object(mod, "outbound_destination_evidence",
                               return_value=("no", "b"*64)), \
                          mock.patch.object(mod, "fingerprint", return_value="a"*64), \
             mock.patch.object(mod, "inbound_snapshot",
                               side_effect=[(b"before", ()), (b"different", ())]), \
             mock.patch.object(mod.pathlib.Path, "is_file", return_value=True), \
             mock.patch.object(mod, "verified_backup", return_value=backup), \
             mock.patch.object(mod, "update_postconf",
                               side_effect=lambda k, v: calls.append((k, v))), \
             mock.patch.object(mod, "postconf", side_effect=postconf), \
             mock.patch.object(mod, "run", return_value=Result()), \
             mock.patch.object(mod, "restore_backup", return_value=True) as rollback:
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture):
                with self.assertRaises(RuntimeError):
                    mod.apply(req)
        self.assertIn(("relayhost", "[smtp.example.org]:2525"), calls)
        self.assertNotIn("inet_interfaces", [k for k, _ in calls])
        self.assertNotIn("mydestination", [k for k, _ in calls])
        rollback.assert_called_once_with(backup)
        self.assertIn("CUSTOM_ROUTE_ROLLBACK=ok", capture.getvalue())

    def test_read_only_diff_captures_root_owned_credential_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            main, master, password = (
                pathlib.Path(tmp)/"main.cf", pathlib.Path(tmp)/"master.cf",
                pathlib.Path(tmp)/"lmr365-custom-sasl.db")
            main.write_text("relayhost = [old.example.org]:587\n")
            master.write_text("smtp inet n - y - - smtpd\n")
            password.write_bytes(b"synthetic-hash-db")
            actual_stat = pathlib.Path.stat
            def root_stat(path, *args, **kwargs):
                from types import SimpleNamespace
                found = actual_stat(path, *args, **kwargs)
                return SimpleNamespace(
                    st_uid=0, st_mode=(found.st_mode & ~0o077),
                    st_size=found.st_size)
            with mock.patch.object(mod, "MAIN", main), \
                 mock.patch.object(mod, "MASTER", master), \
                 mock.patch.object(mod, "MAP", password), \
                 mock.patch.object(pathlib.Path, "stat", autospec=True,
                                   side_effect=root_stat):
                previous = mod.fingerprint()
                password.write_bytes(b"changed-synthetic-db")
                updated = mod.fingerprint()
            self.assertNotEqual(previous, updated)
            self.assertEqual(len(previous), 64)


if __name__ == "__main__":
    unittest.main()
